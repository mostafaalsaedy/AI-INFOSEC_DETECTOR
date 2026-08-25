/**
 * Gate that only renders its children for an authenticated user.
 *
 * While the stored token is still being validated it shows a spinner rather
 * than redirecting, so a page refresh does not bounce the user to /login and
 * lose where they were.
 */

import React from 'react';
import { Box, CircularProgress, Typography } from '@mui/material';
import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from '../../contexts/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  /** Optional permission the user must hold, e.g. `admin`. */
  requires?: string;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, requires }) => {
  const { isAuthenticated, isLoading, can } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 2,
          minHeight: '100vh',
          width: '100%',
        }}
      >
        <CircularProgress />
        <Typography variant="body2" color="text.secondary">
          Restoring your session…
        </Typography>
      </Box>
    );
  }

  if (!isAuthenticated) {
    // `state.from` lets the login page send the user back where they meant to go.
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (requires && !can(requires)) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1,
          minHeight: '60vh',
          width: '100%',
          p: 3,
          textAlign: 'center',
        }}
      >
        <Typography variant="h5">Not authorised</Typography>
        <Typography variant="body2" color="text.secondary">
          Your account does not have the “{requires}” permission needed for this page.
        </Typography>
      </Box>
    );
  }

  return <>{children}</>;
};

export default ProtectedRoute;
