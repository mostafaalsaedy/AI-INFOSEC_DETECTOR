<?php

use App\Http\Middleware\AdminMiddleware;
use App\Http\Middleware\DataProtectionMiddleware;
use App\Http\Middleware\GdprComplianceMiddleware;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // The data-protection and GDPR guards apply to the extension-facing
        // collection routes only - they authenticate the extension itself, so
        // putting them on every route would lock out the dashboard and the
        // public health check. routes/api.php attaches them by alias.
        $middleware->alias([
            'admin' => AdminMiddleware::class,
            'data.protection' => DataProtectionMiddleware::class,
            'gdpr' => GdprComplianceMiddleware::class,
        ]);

        // The extension talks to the API statelessly with a signed payload, so
        // CSRF cookies do not apply to those routes.
        $middleware->validateCsrfTokens(except: [
            'api/*',
        ]);

        // This is an API-only application with no `login` route, so guests must
        // get a 401 rather than a redirect to a route that does not exist.
        $middleware->redirectGuestsTo(
            fn (Request $request) => $request->is('api/*') ? null : '/login'
        );

        $middleware->trustProxies(at: '*');
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // API clients always get JSON, never an HTML error page.
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson()
        );

        $exceptions->render(function (AuthenticationException $e, Request $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'error' => 'Unauthenticated',
                    'message' => 'A valid API token is required',
                ], Response::HTTP_UNAUTHORIZED);
            }

            return null;
        });

        $exceptions->render(function (ValidationException $e, Request $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'error' => 'Validation failed',
                    'details' => $e->errors(),
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            return null;
        });
    })->create();
