import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import List
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

# Import Assignment 2 feature extraction function
from feature_extraction import FEATURE_COLUMNS, extract_url_features

logger = logging.getLogger("phishing-api")

# ------------------------------------------------------------------------------
# 0. CONFIGURATION (read from environment variables, with safe defaults)
# ------------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "8192"))                 # request size limit
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "20"))                   # requests per window per client
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
MAX_CONCURRENT_INFERENCES = int(os.getenv("MAX_CONCURRENT_INFERENCES", "4"))

# ------------------------------------------------------------------------------
# 1. INITIALIZE FASTAPI
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Phishing URL Detection API",
    description="Offline-capable API that parses URL mechanics to evaluate threat probability.",
    version="1.0.0",
)

# ------------------------------------------------------------------------------
# 2. CONSISTENT JSON ERRORS (no stack traces, no internal details)
# ------------------------------------------------------------------------------
def error_response(status_code: int, message: str, headers: dict | None = None) -> JSONResponse:
    # "detail" is kept as a plain string so the front end can keep reading it.
    return JSONResponse(
        status_code=status_code,
        content={"error": True, "status": status_code, "message": message, "detail": message},
        headers=headers,
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return error_response(exc.status_code, message, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    message = "Invalid request."
    if errors:
        message = str(errors[0].get("msg", message)).replace("Value error, ", "")
    return error_response(status.HTTP_422_UNPROCESSABLE_ENTITY, message)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server error")  # full details stay in the server log only
    return error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error.")

# ------------------------------------------------------------------------------
# 3. MIDDLEWARE (the last one added is the outermost, so CORS goes last)
# ------------------------------------------------------------------------------

# 3a. Request size limit, enforced on the back end
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length is None:
            return error_response(status.HTTP_411_LENGTH_REQUIRED, "Content-Length header is required.")
        if not content_length.isdigit():
            return error_response(status.HTTP_400_BAD_REQUEST, "Invalid Content-Length header.")
        if int(content_length) > MAX_BODY_BYTES:
            return error_response(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Request body is too large.")
    return await call_next(request)


# 3b. DEFENCE 1: rate limiting (sliding window per client IP)
_hits = defaultdict(deque)
_hits_lock = threading.Lock()


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/api/predict":
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        limited = False
        retry_after = 1
        with _hits_lock:
            window = _hits[client_ip]
            while window and now - window[0] > RATE_LIMIT_WINDOW:
                window.popleft()
            if len(window) >= RATE_LIMIT_MAX:
                limited = True
                retry_after = max(1, int(RATE_LIMIT_WINDOW - (now - window[0])) + 1)
            else:
                window.append(now)
        if limited:
            return error_response(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"Too many requests. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


# 3c. CORS: only our own front end (added last so even 429/413 responses carry CORS headers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# ------------------------------------------------------------------------------
# 4. LOAD MODEL ONCE AT SERVER STARTUP
# ------------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_pipeline.joblib")
pipeline = None

try:
    if os.path.exists(MODEL_PATH):
        pipeline = joblib.load(MODEL_PATH)
        print(f"[*] Successfully loaded ML pipeline from '{MODEL_PATH}'")
    else:
        print(f"[!] Warning: Model file not found at '{MODEL_PATH}'. Running without loaded pipeline.")
except Exception as e:
    print(f"[!] Critical Error loading model pipeline: {e}")

# DEFENCE 2: cap on simultaneous predictions (denial-of-service protection)
inference_slots = threading.BoundedSemaphore(MAX_CONCURRENT_INFERENCES)

# ------------------------------------------------------------------------------
# 5. PYDANTIC SCHEMAS
# ------------------------------------------------------------------------------
class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Full URL to scan. Must start with http:// or https://",
        json_schema_extra={"example": "http://paypal-secure-login.verify-account.xyz/login"},
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL must not be empty.")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("URL must not contain spaces or control characters.")
        try:
            parsed = urlparse(value)
            host = parsed.hostname
        except ValueError:
            raise ValueError("Enter a valid URL starting with http:// or https://")
        if parsed.scheme not in ("http", "https") or not host:
            raise ValueError("Enter a valid URL starting with http:// or https://")
        return value


class URLResponse(BaseModel):
    url: str
    verdict: str
    is_phishing: bool
    risk_score_pct: float
    trust_score_pct: float
    risk_flags: List[str]

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "http://paypal-secure-login.verify-account.xyz/login",
                "verdict": "PHISHING / MALICIOUS",
                "is_phishing": True,
                "risk_score_pct": 100.0,
                "trust_score_pct": 0.0,
                "risk_flags": ["Suspicious Security Keywords (5)"],
            }
        }
    }


class ErrorResponse(BaseModel):
    error: bool = True
    status: int
    message: str
    detail: str

# ------------------------------------------------------------------------------
# 6. API ROUTES
# ------------------------------------------------------------------------------
@app.get("/", status_code=status.HTTP_200_OK, summary="API root", description="Basic welcome message.")
def root():
    return {
        "message": "Welcome to the Phishing URL Detection API",
        "documentation": "Visit /docs for interactive OpenAPI testing",
        "status": "online",
    }


# Method 1: GET - health check
@app.get(
    "/api/health",
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Reports whether the service is online and whether the model loaded at startup.",
)
def health_check():
    return {
        "status": "online",
        "model_loaded": pipeline is not None,
        "service": "Phishing URL Detector Engine",
    }


# Method 2: POST - scan a URL
@app.post(
    "/api/predict",
    response_model=URLResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a URL for phishing",
    description=(
        "Runs the URL through the trained model and returns a verdict, risk and trust scores, "
        "and diagnostic flags. Input is validated (http/https only, max 2048 characters), "
        "rate limited per client, and capped by a concurrency limit."
    ),
    responses={
        413: {"model": ErrorResponse, "description": "Request body too large"},
        422: {"model": ErrorResponse, "description": "Invalid URL"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Server busy or model not loaded"},
    },
)
def predict_url(payload: URLRequest):
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model pipeline is not loaded on backend server.",
        )

    # Reject excess concurrent work instead of queueing it up
    if not inference_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server is busy. Please retry shortly.",
            headers={"Retry-After": "2"},
        )

    try:
        url_string = payload.url

        # 1. Wrap string in DataFrame and extract static features
        raw_df = pd.DataFrame([{"url": url_string}])
        feature_df = extract_url_features(raw_df, url_column="url")
        X_input = feature_df[["url"] + FEATURE_COLUMNS]

        # 2. Predict probability and binary class
        prediction = int(pipeline.predict(X_input)[0])
        probabilities = pipeline.predict_proba(X_input)

        phishing_prob = (
            float(probabilities[0][1])
            if len(probabilities.shape) > 1 and probabilities.shape[1] > 1
            else float(prediction)
        )
        risk_score = round(phishing_prob * 100, 2)
        trust_score = round((1.0 - phishing_prob) * 100, 2)

        # 3. Diagnostic heuristic threat tags
        row = X_input[FEATURE_COLUMNS].iloc[0]
        risk_flags = []
        if row.get("is_ip_address", 0) == 1:
            risk_flags.append("Raw IPv4 Address Host")
        if row.get("is_shortened", 0) == 1:
            risk_flags.append("Known URL Shortener Domain")
        if row.get("count_suspicious_keywords", 0) > 0:
            risk_flags.append(f"Suspicious Security Keywords ({int(row.get('count_suspicious_keywords'))})")
        if row.get("domain_has_prefix_suffix_hyphen", 0) == 1:
            risk_flags.append("Domain Prefix/Suffix Hyphen Deception")
        if row.get("domain_entropy", 0) > 3.8:
            risk_flags.append(f"High Domain Randomness / Entropy ({row.get('domain_entropy'):.2f})")
        if row.get("count_at", 0) > 0:
            risk_flags.append("Embedded Authentication Symbol (@)")

        verdict = "PHISHING / MALICIOUS" if prediction == 1 else "LEGITIMATE / SAFE"

        return URLResponse(
            url=url_string,
            verdict=verdict,
            is_phishing=bool(prediction == 1),
            risk_score_pct=risk_score,
            trust_score_pct=trust_score,
            risk_flags=risk_flags if risk_flags else ["No immediate heuristic risk flags triggered"],
        )

    except Exception:
        logger.exception("Prediction failed")  # details stay in the server log
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unable to process this URL.",
        )
    finally:
        inference_slots.release()


# ------------------------------------------------------------------------------
# 7. LOCAL SERVER RUNNER
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)