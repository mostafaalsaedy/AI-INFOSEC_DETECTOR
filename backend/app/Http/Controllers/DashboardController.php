<?php

namespace App\Http\Controllers;

use App\Models\AiInteraction;
use App\Models\SecurityAlert;
use App\Models\User;
use App\Models\UserSession;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rule;

/**
 * Read and triage endpoints backing the operations dashboard.
 *
 * Nothing here ever returns prompt or response content - only hashes, scores
 * and metadata - so the dashboard cannot become a way to read what users typed.
 */
class DashboardController extends Controller
{
    /**
     * Headline metrics for the dashboard landing page.
     */
    public function overview(Request $request): JsonResponse
    {
        $since24h = now()->subDay();
        $since7d = now()->subWeek();

        return response()->json([
            'kpis' => [
                'interactions_last_24h' => AiInteraction::where('created_at', '>=', $since24h)->count(),
                'interactions_last_7d' => AiInteraction::where('created_at', '>=', $since7d)->count(),
                'open_alerts' => SecurityAlert::open()->count(),
                'critical_open_alerts' => SecurityAlert::open()->critical()->count(),
                'active_sessions' => UserSession::active()->count(),
                'mean_risk_score_7d' => round(
                    (float) AiInteraction::where('created_at', '>=', $since7d)->avg('risk_score'),
                    2
                ),
            ],
            'risk_distribution' => AiInteraction::where('created_at', '>=', $since7d)
                ->select('risk_level', DB::raw('count(*) as total'))
                ->groupBy('risk_level')
                ->pluck('total', 'risk_level'),
            'top_platforms' => AiInteraction::where('created_at', '>=', $since7d)
                ->select('platform', DB::raw('count(*) as total'))
                ->groupBy('platform')
                ->orderByDesc('total')
                ->limit(5)
                ->get(),
            'recent_alerts' => SecurityAlert::recentFirst()
                ->limit(5)
                ->get(['id', 'title', 'severity', 'status', 'created_at']),
            'generated_at' => now()->toISOString(),
        ]);
    }

    /**
     * Paginated alert feed with filtering.
     */
    public function alerts(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'status' => ['nullable', Rule::in(['open', 'investigating', 'resolved', 'false_positive'])],
            'severity' => ['nullable', Rule::in(['low', 'medium', 'high', 'critical'])],
            'assigned_to' => ['nullable', 'string', 'max:100'],
            'search' => ['nullable', 'string', 'max:200'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $query = SecurityAlert::query()->with('interaction:id,platform,risk_score');

        if (! empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        if (! empty($validated['severity'])) {
            $query->where('severity', $validated['severity']);
        }

        if (! empty($validated['assigned_to'])) {
            $query->assignedTo($validated['assigned_to']);
        }

        if (! empty($validated['search'])) {
            $term = '%'.$validated['search'].'%';
            $query->where(function ($inner) use ($term) {
                $inner->where('title', 'like', $term)
                    ->orWhere('description', 'like', $term)
                    ->orWhere('alert_type', 'like', $term);
            });
        }

        return response()->json(
            $query->recentFirst()->paginate($validated['per_page'] ?? 20)
        );
    }

    /**
     * Paginated session list with derived risk scores.
     */
    public function sessions(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'active_only' => ['nullable', 'boolean'],
            'user_id' => ['nullable', 'string', 'max:100'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $query = UserSession::query();

        if (! empty($validated['active_only'])) {
            $query->active();
        }

        if (! empty($validated['user_id'])) {
            $query->byUser($validated['user_id']);
        }

        return response()->json(
            $query->recentFirst()->paginate($validated['per_page'] ?? 20)
        );
    }

    /**
     * Paginated interaction feed. Metadata only, never content.
     */
    public function interactions(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'platform' => ['nullable', 'string', 'max:50'],
            'risk_level' => ['nullable', Rule::in(['low', 'medium', 'high', 'critical'])],
            'session_id' => ['nullable', 'string', 'max:100'],
            'high_risk_only' => ['nullable', 'boolean'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $query = AiInteraction::query()->select([
            'id', 'session_id', 'platform', 'interaction_type', 'risk_level',
            'risk_score', 'risk_flags', 'content_length', 'created_at',
        ]);

        if (! empty($validated['platform'])) {
            $query->platform($validated['platform']);
        }

        if (! empty($validated['risk_level'])) {
            $query->where('risk_level', $validated['risk_level']);
        }

        if (! empty($validated['session_id'])) {
            $query->bySession($validated['session_id']);
        }

        if (! empty($validated['high_risk_only'])) {
            $query->highRisk();
        }

        return response()->json(
            $query->recentFirst()->paginate($validated['per_page'] ?? 25)
        );
    }

    /**
     * Assign an alert to an analyst.
     */
    public function assignAlert(Request $request, SecurityAlert $alert): JsonResponse
    {
        $validated = $request->validate([
            'assignee' => ['required', 'string', 'max:100'],
        ]);

        $alert->assign($validated['assignee']);

        Log::info('Alert assigned', [
            'alert_id' => $alert->id,
            'assignee' => $validated['assignee'],
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true, 'alert' => $alert->fresh()]);
    }

    /**
     * Close an alert with resolution notes.
     */
    public function resolveAlert(Request $request, SecurityAlert $alert): JsonResponse
    {
        $validated = $request->validate([
            'notes' => ['nullable', 'string', 'max:2000'],
        ]);

        $alert->resolve($validated['notes'] ?? null, $request->user()?->name);

        Log::info('Alert resolved', [
            'alert_id' => $alert->id,
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true, 'alert' => $alert->fresh()]);
    }

    /**
     * Mark an alert as a false positive so it stops skewing the metrics.
     */
    public function markFalsePositive(Request $request, SecurityAlert $alert): JsonResponse
    {
        $validated = $request->validate([
            'notes' => ['nullable', 'string', 'max:2000'],
        ]);

        $alert->markAsFalsePositive($validated['notes'] ?? null);

        Log::info('Alert marked false positive', [
            'alert_id' => $alert->id,
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true, 'alert' => $alert->fresh()]);
    }

    /**
     * Full detail for one session, including its interaction history.
     */
    public function sessionDetails(Request $request, string $sessionId): JsonResponse
    {
        $session = UserSession::where('session_id', $sessionId)->firstOrFail();

        return response()->json([
            'session' => $session,
            'risk_score' => $session->risk_score,
            'duration' => $session->session_duration_human,
            'browser' => $session->browser_info,
            'interactions' => $session->aiInteractions()
                ->recentFirst()
                ->limit(100)
                ->get([
                    'id', 'platform', 'interaction_type', 'risk_level',
                    'risk_score', 'risk_flags', 'created_at',
                ]),
            'alerts' => SecurityAlert::whereIn(
                'interaction_id',
                $session->aiInteractions()->select('id')
            )->recentFirst()->get(),
        ]);
    }

    /**
     * Erase a session and everything derived from it.
     *
     * This is the operator-facing half of the GDPR right to erasure; the
     * cascade on the interactions relationship removes the child records.
     */
    public function deleteSession(Request $request, string $sessionId): JsonResponse
    {
        $session = UserSession::where('session_id', $sessionId)->firstOrFail();

        $interactionCount = $session->aiInteractions()->count();

        DB::transaction(function () use ($session) {
            $session->aiInteractions()->forceDelete();
            $session->delete();
        });

        Log::warning('Session data erased', [
            'session_id' => $sessionId,
            'interactions_removed' => $interactionCount,
            'by' => $request->user()?->id,
        ]);

        return response()->json([
            'success' => true,
            'session_id' => $sessionId,
            'interactions_removed' => $interactionCount,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Admin
    |--------------------------------------------------------------------------
    */

    /**
     * Non-secret runtime configuration, for the admin settings screen.
     */
    public function getConfig(Request $request): JsonResponse
    {
        return response()->json([
            'version' => config('infosec.version'),
            'data_retention_days' => config('infosec.data_retention_days'),
            'consent_expiry_days' => config('infosec.consent_expiry_days'),
            'risk_thresholds' => config('infosec.risk_thresholds'),
            'rate_limits' => config('infosec.rate_limits'),
            'platforms' => config('infosec.platforms'),
            'alerts' => [
                'email_enabled' => config('alerts.email.enabled'),
                'slack_enabled' => config('alerts.slack.enabled'),
                'webhook_enabled' => config('alerts.webhook.enabled'),
                'business_hours' => config('alerts.business_hours'),
            ],
        ]);
    }

    /**
     * Persist runtime configuration overrides.
     *
     * Values are validated here but written to the cache rather than to .env:
     * mutating environment files from a web request is a code-injection risk,
     * and container deployments would lose the change on the next restart.
     */
    public function updateConfig(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'data_retention_days' => ['nullable', 'integer', 'min:1', 'max:3650'],
            'consent_expiry_days' => ['nullable', 'integer', 'min:1', 'max:3650'],
            'risk_thresholds.medium' => ['nullable', 'integer', 'min:0', 'max:100'],
            'risk_thresholds.high' => ['nullable', 'integer', 'min:0', 'max:100'],
            'risk_thresholds.critical' => ['nullable', 'integer', 'min:0', 'max:100'],
        ]);

        foreach (data_get($validated, 'risk_thresholds', []) as $band => $value) {
            config(["infosec.risk_thresholds.$band" => $value]);
            cache()->forever("infosec.risk_thresholds.$band", $value);
        }

        foreach (['data_retention_days', 'consent_expiry_days'] as $key) {
            if (isset($validated[$key])) {
                config(["infosec.$key" => $validated[$key]]);
                cache()->forever("infosec.$key", $validated[$key]);
            }
        }

        Log::notice('Runtime configuration updated', [
            'changes' => $validated,
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true, 'applied' => $validated]);
    }

    public function getUsers(Request $request): JsonResponse
    {
        return response()->json(
            User::query()
                ->select(['id', 'name', 'email', 'role', 'is_active', 'last_login_at', 'created_at'])
                ->orderBy('name')
                ->paginate(50)
        );
    }

    public function createUser(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:12'],
            'role' => ['required', Rule::in(User::ROLES)],
        ]);

        $user = User::create($validated);

        Log::notice('Dashboard user created', [
            'user_id' => $user->id,
            'role' => $user->role,
            'by' => $request->user()?->id,
        ]);

        return response()->json([
            'success' => true,
            'user' => $user->only(['id', 'name', 'email', 'role', 'is_active']),
        ], 201);
    }

    public function updateUser(Request $request, User $user): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => ['sometimes', 'email', 'max:255', Rule::unique('users', 'email')->ignore($user->id)],
            'password' => ['sometimes', 'string', 'min:12'],
            'role' => ['sometimes', Rule::in(User::ROLES)],
            'is_active' => ['sometimes', 'boolean'],
        ]);

        $user->update($validated);

        Log::notice('Dashboard user updated', [
            'user_id' => $user->id,
            'changes' => array_keys($validated),
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true, 'user' => $user->fresh()]);
    }

    public function deleteUser(Request $request, User $user): JsonResponse
    {
        if ($request->user()?->id === $user->id) {
            return response()->json([
                'error' => 'You cannot delete your own account',
            ], 422);
        }

        $user->tokens()->delete();
        $user->delete();

        Log::warning('Dashboard user deleted', [
            'user_id' => $user->id,
            'by' => $request->user()?->id,
        ]);

        return response()->json(['success' => true]);
    }

    /**
     * Run the retention purge on demand.
     */
    public function cleanupOldData(Request $request): JsonResponse
    {
        $cutoff = now()->subDays((int) config('infosec.data_retention_days', 365));

        $interactions = AiInteraction::where('created_at', '<', $cutoff)->delete();
        $sessions = UserSession::where('last_activity_at', '<', $cutoff)->delete();

        Log::notice('Manual retention cleanup executed', [
            'cutoff' => $cutoff->toISOString(),
            'interactions_removed' => $interactions,
            'sessions_removed' => $sessions,
            'by' => $request->user()?->id,
        ]);

        return response()->json([
            'success' => true,
            'cutoff' => $cutoff->toISOString(),
            'interactions_removed' => $interactions,
            'sessions_removed' => $sessions,
        ]);
    }

    /**
     * Irreversibly detach a user's records from their identity.
     */
    public function anonymizeUserData(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'user_id' => ['required', 'string', 'max:100'],
        ]);

        $userId = $validated['user_id'];
        $pseudonym = 'anon_'.substr(hash('sha256', $userId.config('app.key')), 0, 16);

        $interactions = AiInteraction::byUser($userId)->update([
            'user_id' => $pseudonym,
            'ip_address' => null,
            'user_agent' => null,
            'anonymized' => true,
        ]);

        $sessions = UserSession::byUser($userId)->update([
            'user_id' => $pseudonym,
            'user_agent' => null,
        ]);

        Log::warning('User data anonymised', [
            'original_user_id_hash' => hash('sha256', $userId),
            'interactions_updated' => $interactions,
            'sessions_updated' => $sessions,
            'by' => $request->user()?->id,
        ]);

        return response()->json([
            'success' => true,
            'pseudonym' => $pseudonym,
            'interactions_updated' => $interactions,
            'sessions_updated' => $sessions,
        ]);
    }
}
