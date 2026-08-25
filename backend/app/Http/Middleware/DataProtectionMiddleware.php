<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class DataProtectionMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // Validate extension authenticity
        if (! $this->validateExtensionRequest($request)) {
            Log::warning('Invalid extension request blocked', [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'headers' => $request->headers->all(),
            ]);

            return response()->json([
                'error' => 'Unauthorized',
                'message' => 'Invalid extension authentication',
            ], 401);
        }

        // Check rate limiting
        if (! $this->checkRateLimit($request)) {
            Log::warning('Rate limit exceeded for extension request', [
                'ip' => $request->ip(),
                'session_id' => $request->input('sessionId'),
            ]);

            return response()->json([
                'error' => 'Rate limit exceeded',
                'retry_after' => 60,
            ], 429);
        }

        // Validate data payload
        if (! $this->validateDataPayload($request)) {
            Log::warning('Invalid data payload rejected', [
                'ip' => $request->ip(),
                'payload_size' => strlen(json_encode($request->all())),
            ]);

            return response()->json([
                'error' => 'Invalid payload',
                'message' => 'Data validation failed',
            ], 400);
        }

        // Add security headers to response
        $response = $next($request);
        $this->addSecurityHeaders($response);

        // Log the request for audit purposes
        $this->auditLog($request, $response);

        return $response;
    }

    private function validateExtensionRequest(Request $request): bool
    {
        // Check for required headers
        $requiredHeaders = [
            'X-Extension-Version',
            'User-Agent',
        ];

        foreach ($requiredHeaders as $header) {
            if (! $request->hasHeader($header)) {
                return false;
            }
        }

        // Validate extension version
        $extensionVersion = $request->header('X-Extension-Version');
        if (! $this->isValidExtensionVersion($extensionVersion)) {
            return false;
        }

        // Validate User-Agent contains extension signature
        $userAgent = $request->userAgent();
        if (! str_contains($userAgent, 'InfoSecAIMonitor') &&
            ! str_contains($userAgent, 'Chrome-Extension')) {
            // Allow legitimate browsers for development
            if (! $this->isDevelopmentEnvironment()) {
                return false;
            }
        }

        // Optional: Validate request signature if implemented
        if ($request->hasHeader('X-Request-Signature')) {
            return $this->validateRequestSignature($request);
        }

        return true;
    }

    private function checkRateLimit(Request $request): bool
    {
        $key = 'extension:'.$request->ip();
        $maxAttempts = 100; // requests per minute
        $decayMinutes = 1;

        return RateLimiter::attempt($key, $maxAttempts, function () {}, $decayMinutes * 60);
    }

    private function validateDataPayload(Request $request): bool
    {
        // Check payload size
        $maxSize = 1024 * 1024; // 1MB
        $payloadSize = strlen(json_encode($request->all()));

        if ($payloadSize > $maxSize) {
            return false;
        }

        // Check for malicious patterns in the payload
        $payload = json_encode($request->all());

        $maliciousPatterns = [
            '/<script[^>]*>.*?<\/script>/i',
            '/javascript:/i',
            '/data:text\/html/i',
            '/vbscript:/i',
            '/<iframe[^>]*>.*?<\/iframe>/i',
            '/on\w+\s*=/i', // Event handlers like onclick=
            '/expression\s*\(/i', // CSS expressions
        ];

        foreach ($maliciousPatterns as $pattern) {
            if (preg_match($pattern, $payload)) {
                Log::alert('Malicious payload detected', [
                    'pattern' => $pattern,
                    'ip' => $request->ip(),
                    'payload_sample' => substr($payload, 0, 500),
                ]);

                return false;
            }
        }

        return true;
    }

    private function addSecurityHeaders(Response $response): void
    {
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Cache-Control', 'no-cache, no-store, must-revalidate');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Expires', '0');
    }

    private function auditLog(Request $request, Response $response): void
    {
        $logData = [
            'timestamp' => now()->toISOString(),
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'status_code' => $response->getStatusCode(),
            'extension_version' => $request->header('X-Extension-Version'),
            'session_id' => $request->input('sessionId'),
            'payload_size' => strlen(json_encode($request->all())),
        ];

        // Only log successful requests at info level
        if ($response->isSuccessful()) {
            Log::info('Extension API request', $logData);
        } else {
            Log::warning('Extension API request failed', array_merge($logData, [
                'response_body' => $response->getContent(),
            ]));
        }
    }

    private function isValidExtensionVersion(string $version): bool
    {
        // Allow semantic versioning pattern
        return preg_match('/^\d+\.\d+\.\d+$/', $version);
    }

    private function validateRequestSignature(Request $request): bool
    {
        $signature = $request->header('X-Request-Signature');
        $payload = json_encode($request->all());
        $secret = config('app.extension_secret');

        if (! $secret) {
            return true; // Skip validation if no secret configured
        }

        $expectedSignature = hash_hmac('sha256', $payload, $secret);

        return hash_equals($expectedSignature, $signature);
    }

    private function isDevelopmentEnvironment(): bool
    {
        return app()->environment(['local', 'development', 'testing']);
    }
}
