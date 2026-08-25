<?php

namespace App\Http\Controllers;

use App\Models\AiInteraction;
use App\Models\SecurityAlert;
use App\Models\UserSession;
use App\Services\RiskAnalysisService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rule;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Aggregate reporting over interactions, alerts and sessions.
 *
 * Time bucketing happens in PHP rather than with driver-specific SQL date
 * functions, so the same queries work on MySQL, PostgreSQL and SQLite.
 */
class AnalyticsController extends Controller
{
    public function __construct(
        private RiskAnalysisService $riskAnalysis
    ) {}

    /**
     * Risk score and volume over time.
     */
    public function riskTrends(Request $request): JsonResponse
    {
        [$start, $end, $granularity] = $this->resolveWindow($request);

        $rows = AiInteraction::whereBetween('created_at', [$start, $end])
            ->get(['created_at', 'risk_score', 'risk_level']);

        $buckets = [];
        foreach ($rows as $row) {
            $key = $this->bucketKey($row->created_at, $granularity);

            $buckets[$key] ??= [
                'period' => $key,
                'interactions' => 0,
                'risk_total' => 0.0,
                'high_risk' => 0,
            ];
            $buckets[$key]['interactions']++;
            $buckets[$key]['risk_total'] += (float) $row->risk_score;

            if (in_array($row->risk_level, ['high', 'critical'], true)) {
                $buckets[$key]['high_risk']++;
            }
        }

        ksort($buckets);

        return response()->json([
            'period' => ['start' => $start->toISOString(), 'end' => $end->toISOString()],
            'granularity' => $granularity,
            'series' => array_values(array_map(fn ($bucket) => [
                'period' => $bucket['period'],
                'interactions' => $bucket['interactions'],
                'mean_risk_score' => round($bucket['risk_total'] / max($bucket['interactions'], 1), 2),
                'high_risk_count' => $bucket['high_risk'],
            ], $buckets)),
            'totals' => [
                'interactions' => $rows->count(),
                'mean_risk_score' => round((float) $rows->avg('risk_score'), 2),
                'peak_risk_score' => round((float) $rows->max('risk_score'), 2),
            ],
        ]);
    }

    /**
     * Usage volume and risk profile per AI platform.
     */
    public function platformUsage(Request $request): JsonResponse
    {
        [$start, $end] = $this->resolveWindow($request);

        $usage = AiInteraction::whereBetween('created_at', [$start, $end])
            ->select(
                'platform',
                DB::raw('count(*) as interactions'),
                DB::raw('avg(risk_score) as mean_risk_score'),
                DB::raw('max(risk_score) as peak_risk_score'),
                DB::raw('count(distinct session_id) as sessions')
            )
            ->groupBy('platform')
            ->orderByDesc('interactions')
            ->get()
            ->map(fn ($row) => [
                'platform' => $row->platform,
                'display_name' => config("infosec.platforms.{$row->platform}", $row->platform),
                'interactions' => (int) $row->interactions,
                'sessions' => (int) $row->sessions,
                'mean_risk_score' => round((float) $row->mean_risk_score, 2),
                'peak_risk_score' => round((float) $row->peak_risk_score, 2),
            ]);

        return response()->json([
            'period' => ['start' => $start->toISOString(), 'end' => $end->toISOString()],
            'platforms' => $usage,
            'monitored_platform_count' => count(config('infosec.platforms', [])),
        ]);
    }

    /**
     * Behavioural analysis across sessions, including anomaly detection.
     */
    public function userBehavior(Request $request): JsonResponse
    {
        [$start, $end] = $this->resolveWindow($request);

        $sessions = UserSession::whereBetween('last_activity_at', [$start, $end])
            ->get()
            ->map(fn (UserSession $session) => [
                'session_id' => $session->session_id,
                'user_id' => $session->user_id,
                'total_interactions' => $session->total_interactions,
                'total_alerts' => $session->total_alerts,
                'duration_minutes' => $session->duration_minutes,
                'platforms_used' => $session->platforms_used ?? [],
                'risk_score' => $session->risk_score,
            ])
            ->all();

        return response()->json([
            'period' => ['start' => $start->toISOString(), 'end' => $end->toISOString()],
            'session_count' => count($sessions),
            'analysis' => $this->riskAnalysis->analyzeUserBehavior($sessions),
        ]);
    }

    /**
     * Alert volume, type distribution and resolution performance.
     */
    public function alertPatterns(Request $request): JsonResponse
    {
        [$start, $end, $granularity] = $this->resolveWindow($request);

        $alerts = SecurityAlert::whereBetween('created_at', [$start, $end])->get();

        $buckets = [];
        foreach ($alerts as $alert) {
            $key = $this->bucketKey($alert->created_at, $granularity);
            $buckets[$key] ??= ['period' => $key, 'count' => 0];
            $buckets[$key]['count']++;
        }
        ksort($buckets);

        $resolved = $alerts->whereNotNull('resolved_at');
        $resolutionHours = $resolved
            ->map(fn ($alert) => $alert->created_at->diffInMinutes($alert->resolved_at) / 60)
            ->values();

        return response()->json([
            'period' => ['start' => $start->toISOString(), 'end' => $end->toISOString()],
            'total_alerts' => $alerts->count(),
            'by_severity' => $alerts->groupBy('severity')->map->count(),
            'by_status' => $alerts->groupBy('status')->map->count(),
            'by_type' => $alerts->groupBy('alert_type')->map->count()->sortDesc()->take(10),
            'trend' => array_values($buckets),
            'resolution' => [
                'resolved_count' => $resolved->count(),
                'mean_hours' => round((float) $resolutionHours->avg(), 2),
                'slowest_hours' => round((float) ($resolutionHours->max() ?? 0), 2),
                'resolution_rate' => $alerts->count() > 0
                    ? round($resolved->count() / $alerts->count() * 100, 2)
                    : 0.0,
            ],
            'false_positive_rate' => $alerts->count() > 0
                ? round($alerts->where('status', 'false_positive')->count() / $alerts->count() * 100, 2)
                : 0.0,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Exports
    |--------------------------------------------------------------------------
    */

    public function exportInteractions(Request $request): StreamedResponse
    {
        [$start, $end] = $this->resolveWindow($request);

        $columns = [
            'id', 'session_id', 'platform', 'interaction_type', 'risk_level',
            'risk_score', 'content_length', 'content_hash', 'created_at',
        ];

        return $this->streamCsv(
            'interactions',
            $columns,
            AiInteraction::whereBetween('created_at', [$start, $end])->orderBy('id'),
            $request
        );
    }

    public function exportAlerts(Request $request): StreamedResponse
    {
        [$start, $end] = $this->resolveWindow($request);

        $columns = [
            'id', 'interaction_id', 'alert_type', 'severity', 'status', 'title',
            'confidence_score', 'assigned_to', 'resolved_at', 'created_at',
        ];

        return $this->streamCsv(
            'alerts',
            $columns,
            SecurityAlert::whereBetween('created_at', [$start, $end])->orderBy('id'),
            $request
        );
    }

    public function exportSessions(Request $request): StreamedResponse
    {
        [$start, $end] = $this->resolveWindow($request);

        $columns = [
            'id', 'session_id', 'browser_name', 'operating_system',
            'total_interactions', 'total_alerts', 'duration_minutes',
            'session_started_at', 'last_activity_at',
        ];

        return $this->streamCsv(
            'sessions',
            $columns,
            UserSession::whereBetween('last_activity_at', [$start, $end])->orderBy('id'),
            $request
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Admin diagnostics
    |--------------------------------------------------------------------------
    */

    public function systemStats(Request $request): JsonResponse
    {
        return response()->json([
            'records' => [
                'interactions' => AiInteraction::count(),
                'alerts' => SecurityAlert::count(),
                'sessions' => UserSession::count(),
            ],
            'oldest_interaction' => AiInteraction::min('created_at'),
            'newest_interaction' => AiInteraction::max('created_at'),
            'risk_patterns' => $this->riskAnalysis->getPatternStats(),
            'retention_days' => config('infosec.data_retention_days'),
            'generated_at' => now()->toISOString(),
        ]);
    }

    public function systemHealth(Request $request): JsonResponse
    {
        $checks = [];

        try {
            DB::connection()->getPdo();
            $checks['database'] = 'healthy';
        } catch (\Throwable $e) {
            Log::error('Database health check failed', ['error' => $e->getMessage()]);
            $checks['database'] = 'unhealthy';
        }

        try {
            cache()->put('health:probe', 1, 10);
            $checks['cache'] = cache()->get('health:probe') === 1 ? 'healthy' : 'degraded';
        } catch (\Throwable $e) {
            Log::error('Cache health check failed', ['error' => $e->getMessage()]);
            $checks['cache'] = 'unhealthy';
        }

        $checks['queue'] = config('queue.default');

        $healthy = ! in_array('unhealthy', $checks, true);

        return response()->json([
            'status' => $healthy ? 'healthy' : 'unhealthy',
            'checks' => $checks,
            'version' => config('infosec.version'),
            'timestamp' => now()->toISOString(),
        ], $healthy ? 200 : 503);
    }

    /*
    |--------------------------------------------------------------------------
    | Helpers
    |--------------------------------------------------------------------------
    */

    /**
     * Resolve the requested reporting window and a sensible bucket size.
     *
     * @return array{0: Carbon, 1: Carbon, 2: string}
     */
    private function resolveWindow(Request $request): array
    {
        $validated = $request->validate([
            'days' => ['nullable', 'integer', 'min:1', 'max:365'],
            'granularity' => ['nullable', Rule::in(['hour', 'day', 'week', 'month'])],
        ]);

        $days = $validated['days'] ?? 30;
        $end = now();
        $start = $end->copy()->subDays($days);

        $granularity = $validated['granularity'] ?? match (true) {
            $days <= 2 => 'hour',
            $days <= 60 => 'day',
            $days <= 365 => 'week',
            default => 'month',
        };

        return [$start, $end, $granularity];
    }

    private function bucketKey(Carbon $moment, string $granularity): string
    {
        return match ($granularity) {
            'hour' => $moment->format('Y-m-d\TH:00'),
            'week' => $moment->format('o-\WW'),
            'month' => $moment->format('Y-m'),
            default => $moment->format('Y-m-d'),
        };
    }

    /**
     * Stream a query to CSV in chunks so a large export never loads the whole
     * result set into memory.
     */
    private function streamCsv(
        string $name,
        array $columns,
        $query,
        Request $request
    ): StreamedResponse {
        $filename = sprintf('%s-%s.csv', $name, now()->format('Ymd-His'));

        Log::notice('Data export streamed', [
            'export' => $name,
            'by' => $request->user()?->id,
        ]);

        return response()->streamDownload(function () use ($columns, $query) {
            $handle = fopen('php://output', 'wb');
            fputcsv($handle, $columns);

            $query->chunk(1000, function ($rows) use ($handle, $columns) {
                foreach ($rows as $row) {
                    fputcsv($handle, array_map(
                        fn ($column) => is_array($row->$column)
                            ? json_encode($row->$column)
                            : $row->$column,
                        $columns
                    ));
                }
            });

            fclose($handle);
        }, $filename, [
            'Content-Type' => 'text/csv',
            'Cache-Control' => 'no-store',
        ]);
    }
}
