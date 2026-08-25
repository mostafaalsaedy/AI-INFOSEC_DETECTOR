/**
 * Authentication state for the dashboard.
 *
 * Holds the signed-in user and exposes `login`/`logout`. The token itself
 * lives in `services/api`, which attaches it to every request; this context
 * only tracks who the token belongs to and what they may do.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import toast from 'react-hot-toast';

import {
  AUTH_EXPIRED_EVENT,
  ApiError,
  apiGet,
  apiPost,
  tokenStorage,
} from '../services/api';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: 'viewer' | 'analyst' | 'admin';
  permissions: Record<string, boolean>;
}

interface LoginResponse {
  access_token: string;
  user: AuthUser;
}

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  /** True while the stored token is being validated on first load. */
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  /** Check a single named permission, e.g. `can('export_data')`. */
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const clearSession = useCallback(() => {
    tokenStorage.clear();
    setUser(null);
  }, []);

  // Restore the session from a stored token. The token is verified against the
  // API rather than trusted locally, so a revoked token does not appear valid.
  useEffect(() => {
    let cancelled = false;

    const restore = async () => {
      if (!tokenStorage.get()) {
        setIsLoading(false);
        return;
      }

      try {
        const profile = await apiGet<AuthUser>('/api/v1/auth/me');
        if (!cancelled) {
          setUser(profile);
        }
      } catch {
        // A 401 already cleared the token in the axios interceptor; anything
        // else means the API is unreachable, so start signed out either way.
        if (!cancelled) {
          clearSession();
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    void restore();

    return () => {
      cancelled = true;
    };
  }, [clearSession]);

  // The API layer fires this when a request comes back 401 mid-session.
  useEffect(() => {
    const handleExpiry = () => {
      setUser((current) => {
        if (current) {
          toast.error('Your session expired. Please sign in again.');
        }
        return null;
      });
    };

    window.addEventListener(AUTH_EXPIRED_EVENT, handleExpiry);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleExpiry);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const response = await apiPost<LoginResponse>('/api/v1/auth/login', {
      email,
      password,
    });

    if (!response.access_token) {
      throw new ApiError('The server did not return an access token', 500);
    }

    tokenStorage.set(response.access_token);
    setUser(response.user);
  }, []);

  const logout = useCallback(() => {
    // Best effort: revoke server-side, but sign out locally regardless so a
    // failed request can never trap the user in a session they wanted to end.
    void apiPost('/api/v1/auth/logout').catch(() => undefined);
    clearSession();
    toast.success('Signed out');
  }, [clearSession]);

  const can = useCallback(
    (permission: string) => Boolean(user?.permissions?.[permission]),
    [user]
  );

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      isAuthenticated: user !== null,
      isLoading,
      login,
      logout,
      can,
    }),
    [user, isLoading, login, logout, can]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
