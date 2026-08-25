/**
 * HTTP client for the InfoSec AI Monitor API.
 *
 * A single axios instance owns the base URL, attaches the bearer token, and
 * turns non-2xx responses into a consistent `ApiError`. Everything in the app
 * goes through here so authentication and error handling stay in one place.
 */

import axios, {
  AxiosError,
  AxiosInstance,
  AxiosRequestConfig,
  InternalAxiosRequestConfig,
} from 'axios';

/** Where the access token lives between page loads. */
const TOKEN_STORAGE_KEY = 'infosec.access_token';

/** Broadcast when the API rejects the stored token, so AuthContext can log out. */
export const AUTH_EXPIRED_EVENT = 'infosec:auth-expired';

/** Normalised error shape every caller can rely on. */
export class ApiError extends Error {
  readonly status: number;
  readonly details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }

  /** True when retrying the same request could plausibly succeed. */
  get isRetryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }
}

/* -------------------------------------------------------------------------
 * Token storage
 * ---------------------------------------------------------------------- */

export const tokenStorage = {
  get(): string | null {
    try {
      return localStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      // Private browsing or blocked site data - fall back to no session.
      return null;
    }
  },

  set(token: string): void {
    try {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } catch {
      // Non-fatal: the session simply will not survive a reload.
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      /* nothing to clear */
    }
  },
};

/* -------------------------------------------------------------------------
 * Axios instance
 * ---------------------------------------------------------------------- */

export const apiClient: AxiosInstance = axios.create({
  // Empty in development: the Vite proxy forwards /api to the backend, which
  // keeps requests same-origin and avoids CORS entirely.
  baseURL: import.meta.env.VITE_API_URL ?? '',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStorage.get();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ error?: string; detail?: unknown }>) => {
    // No response at all: DNS failure, offline, CORS block or timeout.
    if (!error.response) {
      return Promise.reject(
        new ApiError(
          error.code === 'ECONNABORTED'
            ? 'The request timed out'
            : 'Could not reach the API',
          0
        )
      );
    }

    const { status, data } = error.response;

    if (status === 401) {
      // The token is gone or expired. Clear it and let AuthContext react,
      // rather than leaving the UI in a half-authenticated state.
      tokenStorage.clear();
      window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
    }

    const message =
      data?.error ??
      (typeof data?.detail === 'string' ? data.detail : undefined) ??
      defaultMessageForStatus(status);

    return Promise.reject(new ApiError(message, status, data?.detail));
  }
);

function defaultMessageForStatus(status: number): string {
  switch (status) {
    case 400:
      return 'The request was rejected as invalid';
    case 401:
      return 'Your session has expired, please sign in again';
    case 403:
      return 'You do not have permission to do that';
    case 404:
      return 'Not found';
    case 422:
      return 'Some of the values sent were not valid';
    case 429:
      return 'Too many requests, please slow down';
    default:
      return status >= 500 ? 'The server ran into a problem' : 'Request failed';
  }
}

/* -------------------------------------------------------------------------
 * Typed helpers
 * ---------------------------------------------------------------------- */

export async function apiGet<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const { data } = await apiClient.get<T>(url, config);
  return data;
}

export async function apiPost<T>(
  url: string,
  body?: unknown,
  config?: AxiosRequestConfig
): Promise<T> {
  const { data } = await apiClient.post<T>(url, body, config);
  return data;
}

export async function apiPatch<T>(
  url: string,
  body?: unknown,
  config?: AxiosRequestConfig
): Promise<T> {
  const { data } = await apiClient.patch<T>(url, body, config);
  return data;
}

export async function apiDelete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const { data } = await apiClient.delete<T>(url, config);
  return data;
}

/**
 * Download a file the API generates on demand.
 *
 * The response is a blob rather than JSON, so it bypasses the typed helpers
 * and drives an object-URL download directly.
 */
export async function apiDownload(
  url: string,
  filename: string,
  config?: AxiosRequestConfig
): Promise<void> {
  const response = await apiClient.get(url, { ...config, responseType: 'blob' });

  const objectUrl = URL.createObjectURL(response.data as Blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  // Revoking immediately can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
}

/** Build a query string, dropping empty values so the URL stays readable. */
export function toQueryString(params: Record<string, unknown>): string {
  const search = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;

    if (Array.isArray(value)) {
      value.forEach((entry) => search.append(key, String(entry)));
    } else if (value instanceof Date) {
      search.append(key, value.toISOString());
    } else {
      search.append(key, String(value));
    }
  });

  return search.toString();
}
