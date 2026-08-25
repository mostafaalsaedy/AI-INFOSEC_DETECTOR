/**
 * Thin wrappers over React Query, so components describe *what* they need
 * rather than how fetching, caching and retrying work.
 */

import {
  UseMutationOptions,
  UseQueryOptions,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';

import { ApiError, apiDelete, apiGet, apiPatch, apiPost } from '../services/api';

type QueryOptions<T> = Omit<UseQueryOptions<T, ApiError>, 'queryKey' | 'queryFn'>;

/**
 * GET a URL and keep it fresh.
 *
 * `url` doubles as the cache key, so two components asking for the same
 * endpoint share one request.
 */
export function useApiQuery<T>(url: string, options?: QueryOptions<T>) {
  return useQuery<T, ApiError>({
    queryKey: [url],
    queryFn: () => apiGet<T>(url),
    // Authentication and permission failures will not resolve on retry;
    // anything else gets two more attempts.
    retry: (failureCount, error) =>
      error.isRetryable && error.status !== 429 && failureCount < 2,
    staleTime: 30_000,
    ...options,
  });
}

/** GET with query parameters, keyed on both the path and the parameters. */
export function useApiQueryWithParams<T>(
  url: string,
  params: Record<string, unknown>,
  options?: QueryOptions<T>
) {
  return useQuery<T, ApiError>({
    queryKey: [url, params],
    queryFn: () => apiGet<T>(url, { params }),
    retry: (failureCount, error) =>
      error.isRetryable && error.status !== 429 && failureCount < 2,
    staleTime: 30_000,
    ...options,
  });
}

type MutationOptions<TData, TVariables> = Omit<
  UseMutationOptions<TData, ApiError, TVariables>,
  'mutationFn'
> & {
  /** Query keys to refetch once the mutation succeeds. */
  invalidates?: string[];
};

function useApiMutationBase<TData, TVariables>(
  request: (variables: TVariables) => Promise<TData>,
  options?: MutationOptions<TData, TVariables>
) {
  const queryClient = useQueryClient();
  const { invalidates, onSuccess, ...rest } = options ?? {};

  return useMutation<TData, ApiError, TVariables>({
    mutationFn: request,
    // React Query v5 passes (data, variables, onMutateResult, context); the
    // extra arguments are forwarded untouched so callers keep the full signature.
    onSuccess: (...args) => {
      invalidates?.forEach((key) => {
        void queryClient.invalidateQueries({ queryKey: [key] });
      });
      onSuccess?.(...args);
    },
    ...rest,
  });
}

export function useApiPost<TData, TVariables = unknown>(
  url: string,
  options?: MutationOptions<TData, TVariables>
) {
  return useApiMutationBase<TData, TVariables>(
    (variables) => apiPost<TData>(url, variables),
    options
  );
}

export function useApiPatch<TData, TVariables = unknown>(
  buildUrl: (variables: TVariables) => string,
  options?: MutationOptions<TData, TVariables>
) {
  return useApiMutationBase<TData, TVariables>(
    (variables) => apiPatch<TData>(buildUrl(variables), variables),
    options
  );
}

export function useApiDelete<TData, TVariables = unknown>(
  buildUrl: (variables: TVariables) => string,
  options?: MutationOptions<TData, TVariables>
) {
  return useApiMutationBase<TData, TVariables>(
    (variables) => apiDelete<TData>(buildUrl(variables)),
    options
  );
}
