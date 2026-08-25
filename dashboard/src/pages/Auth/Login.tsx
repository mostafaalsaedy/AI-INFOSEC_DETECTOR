/**
 * Sign-in screen.
 *
 * On success the user is returned to whichever page sent them here, so a
 * bookmark or an expired session does not dump them on the dashboard root.
 */

import React, { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Link,
  TextField,
  Typography,
} from '@mui/material';
import { Security as SecurityIcon } from '@mui/icons-material';
import { Helmet } from 'react-helmet-async';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../../contexts/AuthContext';
import { ApiError } from '../../services/api';

interface LocationState {
  from?: { pathname: string };
}

const Login: React.FC = () => {
  const { login, isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const redirectTo = (location.state as LocationState)?.from?.pathname ?? '/dashboard';

  if (!isLoading && isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await login(email.trim(), password);
      navigate(redirectTo, { replace: true });
    } catch (caught) {
      // Deliberately vague on 401: confirming which half was wrong would let an
      // attacker enumerate valid accounts.
      setError(
        caught instanceof ApiError && caught.status !== 401
          ? caught.message
          : 'Those credentials were not accepted.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <Helmet>
        <title>Sign in · InfoSec AI Monitor</title>
      </Helmet>

      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          width: '100%',
          p: 2,
        }}
      >
        <Card sx={{ width: '100%', maxWidth: 420 }}>
          <CardContent sx={{ p: 4 }}>
            <Box sx={{ textAlign: 'center', mb: 3 }}>
              <SecurityIcon color="primary" sx={{ fontSize: 44, mb: 1 }} />
              <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
                InfoSec AI Monitor
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Sign in to the security dashboard
              </Typography>
            </Box>

            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <Box component="form" onSubmit={handleSubmit} noValidate>
              <TextField
                fullWidth
                required
                autoFocus
                type="email"
                label="Email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                disabled={submitting}
                sx={{ mb: 2 }}
              />

              <TextField
                fullWidth
                required
                type="password"
                label="Password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                disabled={submitting}
                sx={{ mb: 3 }}
              />

              <Button
                fullWidth
                type="submit"
                variant="contained"
                size="large"
                disabled={submitting || !email || !password}
                startIcon={submitting ? <CircularProgress size={18} color="inherit" /> : null}
              >
                {submitting ? 'Signing in…' : 'Sign in'}
              </Button>
            </Box>

            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ display: 'block', mt: 3, textAlign: 'center' }}
            >
              Access is logged and audited. Contact your administrator if you need
              an account or a password reset.{' '}
              <Link href="/privacy-policy" underline="hover">
                Privacy policy
              </Link>
            </Typography>
          </CardContent>
        </Card>
      </Box>
    </>
  );
};

export default Login;
