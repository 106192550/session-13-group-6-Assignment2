import React from 'react';
import { ThemeProvider, createTheme, CssBaseline, Container, Box, Typography, Button } from '@mui/material';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import URLScanner from './Components/URLScanner';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#1976d2' },
    background: { default: '#0a192f', paper: '#112240' },
  },
});

function NotFound() {
  return (
    <Box sx={{ textAlign: 'center', py: 10 }}>
      <Typography variant="h2" component="h1" gutterBottom>404</Typography>
      <Typography variant="h6" gutterBottom>That page does not exist.</Typography>
      <Button component={Link} to="/" variant="contained">Back to scanner</Button>
    </Box>
  );
}

class ErrorBoundary extends React.Component {
  state = { hasError: false };
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error) { console.error(error); }
  render() {
    if (this.state.hasError) {
      return (
        <Box sx={{ textAlign: 'center', py: 10 }}>
          <Typography variant="h4" component="h1" gutterBottom>Something went wrong</Typography>
          <Typography gutterBottom>An unexpected error occurred. Please try again.</Typography>
          <Button variant="contained" onClick={() => window.location.assign('/')}>Reload</Button>
        </Box>
      );
    }
    return this.props.children;
  }
}

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <Container maxWidth="lg">
          <Box sx={{ py: { xs: 3, md: 6 } }}>
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<URLScanner />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </ErrorBoundary>
          </Box>
        </Container>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;