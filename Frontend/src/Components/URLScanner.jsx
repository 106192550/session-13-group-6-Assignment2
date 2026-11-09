import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  LinearProgress,
  CircularProgress,
  Chip,
  Alert,
  Paper,
  Divider,
  Stack,
  InputAdornment,
} from '@mui/material';
import {
  Search as SearchIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  ReportProblem as ReportProblemIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
} from 'recharts';
import { scanUrl } from '../services/api';

const URLScanner = () => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const handleScan = async (e) => {
    e.preventDefault();
    const cleanUrl = urlInput.trim();

    if (!cleanUrl) {
      setError('Please enter a valid URL string to analyze.');
      return;
    }

    if (cleanUrl.length > 2048) {
      setError('URL exceeds maximum allowed length of 2048 characters.');
      return;
    }

    try {
      const u = new URL(cleanUrl);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error('bad');
    } catch {
      setError('Enter a full URL starting with http:// or https://');
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await scanUrl(cleanUrl);
      setResult(data);
      setHistory((h) =>
        [
          ...h,
          { label: `#${h.length + 1}`, url: data.url, risk: data.risk_score_pct },
        ].slice(-10)
      );
    } catch (err) {
      setError(err.message || 'Failed to scan URL. Please check backend status.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setUrlInput('');
    setResult(null);
    setError(null);
  };

  // Helper for dynamic score colors
  const getScoreColor = (riskScore) => {
    if (riskScore >= 70) return 'error';
    if (riskScore >= 35) return 'warning';
    return 'success';
  };

  return (
    <Box sx={{ maxWidth: 850, mx: 'auto', p: { xs: 2, md: 4 } }}>
      {/* Title & Header Section */}
      <Box sx={{ textAlign: 'center', mb: 4 }}>
        <Typography variant="h4" component="h1" fontWeight="bold" color="primary" gutterBottom>
          <SecurityIcon sx={{ fontSize: 36, verticalAlign: 'middle', mr: 1 }} />
          Phishing URL Threat Scanner
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Air-gapped offline machine learning engine for real-time URL lexical threat detection
        </Typography>
      </Box>

      {/* Input Form Card */}
      <Card elevation={3} sx={{ mb: 4, borderRadius: 2 }}>
        <CardContent sx={{ p: 3 }}>
          <form onSubmit={handleScan}>
            <Stack spacing={2}>
              <TextField
                fullWidth
                variant="outlined"
                label="Target URL Address"
                placeholder="e.g. http://login-verify-secure-account.com/update"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                disabled={loading}
                error={Boolean(error)}
                inputProps={{ maxLength: 2048 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon color="action" />
                    </InputAdornment>
                  ),
                }}
              />

              {/* Scan is first in the code so Tab reaches it first; row-reverse keeps it on the right */}
              <Stack
                direction={{ xs: 'column-reverse', sm: 'row-reverse' }}
                spacing={2}
                justifyContent="flex-start"
              >
                <Button
                  type="submit"
                  variant="contained"
                  color="primary"
                  size="large"
                  disabled={loading || !urlInput.trim()}
                  startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SecurityIcon />}
                >
                  {loading ? 'Analyzing Mechanics...' : 'Scan URL Threat'}
                </Button>
                {result && (
                  <Button
                    variant="outlined"
                    color="secondary"
                    onClick={handleReset}
                    startIcon={<RefreshIcon />}
                    disabled={loading}
                  >
                    Clear Result
                  </Button>
                )}
              </Stack>
            </Stack>
          </form>
        </CardContent>
      </Card>

      {/* Error Alert Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Loading Bar */}
      {loading && (
        <Paper elevation={1} sx={{ p: 3, textAlign: 'center', borderRadius: 2, mb: 4 }}>
          <CircularProgress size={40} sx={{ mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            Parsing URL Structure & Executing Machine Learning Pipeline...
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Extracting 18 static lexical features (lengths, domain entropy, protocol flags)
          </Typography>
        </Paper>
      )}

      {/* Result Display Card */}
      {result && !loading && (
        <Card
          elevation={4}
          sx={{
            borderRadius: 2,
            borderLeft: 6,
            borderColor: result.is_phishing ? 'error.main' : 'success.main',
          }}
        >
          <CardContent sx={{ p: { xs: 2, md: 4 } }}>
            {/* Verdict Header */}
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              {result.is_phishing ? (
                <WarningIcon color="error" sx={{ fontSize: 44, mr: 2 }} />
              ) : (
                <CheckCircleIcon color="success" sx={{ fontSize: 44, mr: 2 }} />
              )}
              <Box sx={{ minWidth: 0 }}>
                <Typography
                  variant="h5"
                  fontWeight="bold"
                  color={result.is_phishing ? 'error.main' : 'success.main'}
                >
                  {result.verdict}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ wordBreak: 'break-all' }}>
                  Target: <strong>{result.url}</strong>
                </Typography>
              </Box>
            </Box>

            <Divider sx={{ my: 3 }} />

            {/* Risk & Trust Gauge */}
            <Box sx={{ mb: 4 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1, mb: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">
                  Threat Risk Level: {result.risk_score_pct}%
                </Typography>
                <Typography variant="subtitle1" fontWeight="bold" color="text.secondary">
                  Trust Rating: {result.trust_score_pct}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={result.risk_score_pct}
                color={getScoreColor(result.risk_score_pct)}
                sx={{ height: 12, borderRadius: 6 }}
              />
            </Box>

            {/* Chart 1: how confident is this verdict? */}
            <Box sx={{ mb: 4 }}>
              <Typography variant="h6" fontWeight="bold">
                Verdict confidence
              </Typography>
              <Box
                sx={{ height: 240 }}
                role="img"
                aria-label={`Donut chart: ${result.risk_score_pct}% phishing risk and ${result.trust_score_pct}% trust`}
              >
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      dataKey="value"
                      nameKey="name"
                      innerRadius={55}
                      outerRadius={85}
                      data={[
                        { name: 'Phishing risk', value: result.risk_score_pct },
                        { name: 'Trust', value: result.trust_score_pct },
                      ]}
                    >
                      <Cell fill="#f44336" />
                      <Cell fill="#66bb6a" />
                    </Pie>
                    <Tooltip formatter={(v) => `${v}%`} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </Box>
            </Box>

            {/* Diagnostic Threat Risk Flags */}
            <Typography variant="h6" fontWeight="bold" sx={{ mb: 1.5 }}>
              Diagnostic Threat Flags ({result.risk_flags.length})
            </Typography>

            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ gap: 1 }}>
              {result.risk_flags.map((flag, index) => (
                <Chip
                  key={index}
                  label={flag}
                  color={result.is_phishing ? 'error' : 'default'}
                  variant={result.is_phishing ? 'filled' : 'outlined'}
                  icon={result.is_phishing ? <ReportProblemIcon /> : <InfoIcon />}
                />
              ))}
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Chart 2: how do the URLs checked this session compare? */}
      {history.length > 0 && (
        <Card elevation={3} sx={{ mt: 4, borderRadius: 2 }}>
          <CardContent>
            <Typography variant="h6" fontWeight="bold" gutterBottom>
              Session history: risk score per scan
            </Typography>
            <Box
              sx={{ height: 260 }}
              role="img"
              aria-label="Bar chart of the phishing risk percentage for each URL scanned in this session"
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={history}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#445" />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: '#ccd6f6' }}
                    label={{ value: 'Scan number', position: 'insideBottom', offset: -5, fill: '#ccd6f6' }}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: '#ccd6f6' }}
                    label={{ value: 'Risk %', angle: -90, position: 'insideLeft', fill: '#ccd6f6' }}
                  />
                  <Tooltip
                    formatter={(v) => `${v}%`}
                    labelFormatter={(l, p) => (p && p[0] && p[0].payload ? p[0].payload.url : l)}
                  />
                  <Bar dataKey="risk" name="Risk %" fill="#1976d2" />
                </BarChart>
              </ResponsiveContainer>
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default URLScanner;