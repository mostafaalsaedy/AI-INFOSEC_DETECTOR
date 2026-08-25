<?php

use App\Http\Controllers\AnalyticsController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\DataCollectionController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Extension data collection. These routes authenticate the extension itself
// via a signed payload, and enforce the consent and retention rules.
Route::prefix('v1')->middleware(['data.protection', 'gdpr'])->group(function () {
    Route::post('/collect', [DataCollectionController::class, 'collect'])
        ->middleware(['throttle:extension']);

    Route::post('/alert', [DataCollectionController::class, 'alert'])
        ->middleware(['throttle:alerts']);

    Route::post('/consent', [DataCollectionController::class, 'consent'])
        ->middleware(['throttle:extension']);
});

// Unauthenticated health check, used by load balancers and container probes.
Route::prefix('v1')->group(function () {
    Route::get('/health', function () {
        return response()->json([
            'status' => 'healthy',
            'timestamp' => now()->toISOString(),
            'version' => config('infosec.version', '1.0.0'),
        ]);
    });
});

// Protected routes for dashboard and analytics
Route::middleware(['auth:sanctum'])->prefix('v1')->group(function () {

    // Dashboard endpoints
    Route::get('/dashboard/overview', [DashboardController::class, 'overview']);
    Route::get('/dashboard/alerts', [DashboardController::class, 'alerts']);
    Route::get('/dashboard/sessions', [DashboardController::class, 'sessions']);
    Route::get('/dashboard/interactions', [DashboardController::class, 'interactions']);

    // Analytics endpoints
    Route::get('/analytics/risk-trends', [AnalyticsController::class, 'riskTrends']);
    Route::get('/analytics/platform-usage', [AnalyticsController::class, 'platformUsage']);
    Route::get('/analytics/user-behavior', [AnalyticsController::class, 'userBehavior']);
    Route::get('/analytics/alert-patterns', [AnalyticsController::class, 'alertPatterns']);

    // Alert management
    Route::patch('/alerts/{alert}/assign', [DashboardController::class, 'assignAlert']);
    Route::patch('/alerts/{alert}/resolve', [DashboardController::class, 'resolveAlert']);
    Route::patch('/alerts/{alert}/false-positive', [DashboardController::class, 'markFalsePositive']);

    // Session management
    Route::get('/sessions/{sessionId}/details', [DashboardController::class, 'sessionDetails']);
    Route::delete('/sessions/{sessionId}', [DashboardController::class, 'deleteSession']);

    // Data export
    Route::post('/export/interactions', [AnalyticsController::class, 'exportInteractions']);
    Route::post('/export/alerts', [AnalyticsController::class, 'exportAlerts']);
    Route::post('/export/sessions', [AnalyticsController::class, 'exportSessions']);

    // User management
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});

// WebSocket routes for real-time monitoring
Route::middleware(['auth:sanctum'])->prefix('v1/ws')->group(function () {
    Route::get('/connect', function () {
        return response()->json([
            'websocket_url' => config('broadcasting.connections.pusher.host'),
            'key' => config('broadcasting.connections.pusher.key'),
            'cluster' => config('broadcasting.connections.pusher.options.cluster'),
        ]);
    });
});

// Admin routes
Route::middleware(['auth:sanctum', 'admin'])->prefix('v1/admin')->group(function () {
    // System configuration
    Route::get('/config', [DashboardController::class, 'getConfig']);
    Route::post('/config', [DashboardController::class, 'updateConfig']);

    // User management
    Route::get('/users', [DashboardController::class, 'getUsers']);
    Route::post('/users', [DashboardController::class, 'createUser']);
    Route::patch('/users/{user}', [DashboardController::class, 'updateUser']);
    Route::delete('/users/{user}', [DashboardController::class, 'deleteUser']);

    // System statistics
    Route::get('/system/stats', [AnalyticsController::class, 'systemStats']);
    Route::get('/system/health', [AnalyticsController::class, 'systemHealth']);

    // Data retention and cleanup
    Route::post('/cleanup/old-data', [DashboardController::class, 'cleanupOldData']);
    Route::post('/anonymize/user-data', [DashboardController::class, 'anonymizeUserData']);
});
