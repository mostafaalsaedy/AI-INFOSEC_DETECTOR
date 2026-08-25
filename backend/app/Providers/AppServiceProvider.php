<?php

namespace App\Providers;

use App\Services\RiskAnalysisService;
use App\Services\SecurityAlertService;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Both services are stateless and hold compiled regex caches, so a
        // single shared instance per request cycle is cheaper than rebuilding
        // them for every injection point.
        $this->app->singleton(RiskAnalysisService::class);
        $this->app->singleton(SecurityAlertService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->configureRateLimiting();

        // The extension refuses to talk to a plaintext endpoint, so links
        // generated in production must match.
        if ($this->app->environment('production')) {
            URL::forceScheme('https');
        }
    }

    /**
     * Register the named rate limiters referenced by routes/api.php.
     */
    protected function configureRateLimiting(): void
    {
        // Bulk telemetry from the extension: generous, but per session so one
        // noisy browser cannot drown out the rest of the fleet.
        RateLimiter::for('extension', function (Request $request) {
            $key = $request->input('sessionId')
                ?? $request->header('X-Extension-Id')
                ?? $request->ip();

            return Limit::perMinute((int) config('infosec.rate_limits.extension', 120))
                ->by($key)
                ->response(fn () => response()->json([
                    'error' => 'Too many requests',
                    'retry_after_seconds' => 60,
                ], 429));
        });

        // Alerts are low volume by design; a burst usually means a
        // misbehaving client rather than a genuine incident storm.
        RateLimiter::for('alerts', function (Request $request) {
            $key = $request->input('sessionId')
                ?? $request->header('X-Extension-Id')
                ?? $request->ip();

            return Limit::perMinute((int) config('infosec.rate_limits.alerts', 30))->by($key);
        });

        // Authenticated dashboard traffic, keyed to the user where possible.
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute((int) config('infosec.rate_limits.api', 300))
                ->by($request->user()?->id ?: $request->ip());
        });

        // Exports are expensive; keep them deliberately scarce.
        RateLimiter::for('exports', function (Request $request) {
            return Limit::perHour((int) config('infosec.rate_limits.exports', 20))
                ->by($request->user()?->id ?: $request->ip());
        });
    }
}
