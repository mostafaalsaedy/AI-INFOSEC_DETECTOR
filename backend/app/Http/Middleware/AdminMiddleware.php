<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Restricts a route to administrators.
 *
 * Every rejection is logged: an unauthorised attempt to reach an admin route
 * is itself a security signal worth keeping in the audit trail.
 */
class AdminMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user) {
            return response()->json([
                'error' => 'Authentication required',
            ], Response::HTTP_UNAUTHORIZED);
        }

        if (! $this->isAdmin($user)) {
            Log::warning('Unauthorised admin route access attempt', [
                'user_id' => $user->id,
                'email' => $user->email,
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return response()->json([
                'error' => 'Administrator privileges required',
            ], Response::HTTP_FORBIDDEN);
        }

        return $next($request);
    }

    /**
     * Determine whether the authenticated user holds an administrator role.
     */
    protected function isAdmin(mixed $user): bool
    {
        if (method_exists($user, 'isAdmin')) {
            return (bool) $user->isAdmin();
        }

        return in_array($user->role ?? null, ['admin', 'super_admin'], true);
    }
}
