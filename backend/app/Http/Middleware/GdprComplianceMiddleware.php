<?php

namespace App\Http\Middleware;

use App\Models\AiInteraction;
use App\Models\SecurityAlert;
use App\Models\UserSession;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class GdprComplianceMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // Check data retention policies
        $this->enforceDataRetention();

        // Validate consent for data collection
        if ($this->requiresConsent($request)) {
            $consentValid = $this->validateConsent($request);

            if (! $consentValid) {
                return response()->json([
                    'error' => 'Consent required',
                    'message' => 'Valid user consent is required for data collection',
                    'consent_url' => route('api.consent'),
                    'privacy_policy' => config('app.privacy_policy_url'),
                ], 403);
            }
        }

        $response = $next($request);

        // Add privacy-related headers
        $this->addPrivacyHeaders($response);

        return $response;
    }

    private function enforceDataRetention(): void
    {
        $retentionDays = config('app.data_retention_days', 365);
        $cutoffDate = now()->subDays($retentionDays);

        try {
            // Soft delete old interactions (can be recovered if needed)
            $deletedInteractions = AiInteraction::where('created_at', '<', $cutoffDate)
                ->whereNull('deleted_at')
                ->delete();

            // Hard delete very old soft-deleted records
            $hardDeleteCutoff = now()->subDays($retentionDays + 90);
            $hardDeletedInteractions = AiInteraction::onlyTrashed()
                ->where('deleted_at', '<', $hardDeleteCutoff)
                ->forceDelete();

            // Clean up old sessions
            $deletedSessions = UserSession::where('last_activity_at', '<', $cutoffDate)
                ->where('session_ended_at', '<', $cutoffDate)
                ->orWhere('created_at', '<', $cutoffDate)
                ->delete();

            if ($deletedInteractions > 0 || $hardDeletedInteractions > 0 || $deletedSessions > 0) {
                Log::info('Data retention cleanup completed', [
                    'soft_deleted_interactions' => $deletedInteractions,
                    'hard_deleted_interactions' => $hardDeletedInteractions,
                    'deleted_sessions' => $deletedSessions,
                    'retention_days' => $retentionDays,
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Data retention cleanup failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }
    }

    private function requiresConsent(Request $request): bool
    {
        // Data collection endpoints require consent
        $consentRequiredPaths = [
            'api/v1/collect',
            'api/v1/alert',
        ];

        return in_array($request->path(), $consentRequiredPaths);
    }

    private function validateConsent(Request $request): bool
    {
        $sessionId = $request->input('sessionId');

        if (! $sessionId) {
            return false;
        }

        $session = UserSession::where('session_id', $sessionId)->first();

        if (! $session) {
            // No session found, consent will be requested
            return false;
        }

        // Check if consent is valid and not expired
        if (! $session->data_collection_consent) {
            return false;
        }

        // Check if consent is not too old (refresh every 6 months)
        $consentExpiryDays = config('app.consent_expiry_days', 180);
        $consentExpired = $session->consent_updated_at &&
                         $session->consent_updated_at->lt(now()->subDays($consentExpiryDays));

        if ($consentExpired) {
            Log::info('User consent expired', [
                'session_id' => $sessionId,
                'consent_date' => $session->consent_updated_at,
                'expiry_days' => $consentExpiryDays,
            ]);

            return false;
        }

        return true;
    }

    private function addPrivacyHeaders(Response $response): void
    {
        // Add headers indicating data processing
        $response->headers->set('X-Data-Processing', 'security-monitoring');
        $response->headers->set('X-Data-Retention-Days', config('app.data_retention_days', 365));
        $response->headers->set('X-Privacy-Policy', config('app.privacy_policy_url', ''));
        $response->headers->set('X-GDPR-Compliant', 'true');

        // Add cookie policy headers if applicable
        if (config('app.uses_cookies', false)) {
            $response->headers->set('X-Cookies-Used', 'functional-only');
        }
    }

    public static function handleDataDeletionRequest(string $sessionId, ?string $userIdentifier = null): array
    {
        try {
            $deletionResults = [
                'interactions_deleted' => 0,
                'sessions_deleted' => 0,
                'alerts_affected' => 0,
                'success' => true,
                'message' => 'Data deletion completed successfully',
            ];

            // Find and delete user sessions
            $sessionsQuery = UserSession::where('session_id', $sessionId);
            if ($userIdentifier) {
                $sessionsQuery->orWhere('user_id', $userIdentifier);
            }

            $sessions = $sessionsQuery->get();
            $sessionIds = $sessions->pluck('session_id')->toArray();

            // Delete associated interactions
            $interactionsDeleted = AiInteraction::whereIn('session_id', $sessionIds)
                ->orWhere('user_id', $userIdentifier)
                ->forceDelete();

            // Update security alerts to remove personal data
            $alertsUpdated = SecurityAlert::whereHas('interaction', function ($query) use ($sessionIds, $userIdentifier) {
                $query->whereIn('session_id', $sessionIds)
                    ->orWhere('user_id', $userIdentifier);
            })->update([
                'evidence' => json_encode(['data_deleted' => true, 'deletion_date' => now()]),
                'description' => 'Personal data removed due to deletion request',
            ]);

            // Delete sessions
            $sessionsDeleted = UserSession::whereIn('id', $sessions->pluck('id'))->forceDelete();

            $deletionResults['interactions_deleted'] = $interactionsDeleted;
            $deletionResults['sessions_deleted'] = $sessionsDeleted;
            $deletionResults['alerts_affected'] = $alertsUpdated;

            Log::info('GDPR data deletion request processed', [
                'session_id' => $sessionId,
                'user_identifier' => $userIdentifier,
                'results' => $deletionResults,
            ]);

            return $deletionResults;

        } catch (\Exception $e) {
            Log::error('GDPR data deletion failed', [
                'session_id' => $sessionId,
                'user_identifier' => $userIdentifier,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return [
                'success' => false,
                'message' => 'Data deletion failed: '.$e->getMessage(),
                'interactions_deleted' => 0,
                'sessions_deleted' => 0,
                'alerts_affected' => 0,
            ];
        }
    }

    public static function generateDataExport(string $sessionId, ?string $userIdentifier = null): array
    {
        try {
            $exportData = [
                'export_date' => now()->toISOString(),
                'session_id' => $sessionId,
                'user_identifier' => $userIdentifier,
                'sessions' => [],
                'interactions' => [],
                'alerts' => [],
            ];

            // Export sessions
            $sessionsQuery = UserSession::where('session_id', $sessionId);
            if ($userIdentifier) {
                $sessionsQuery->orWhere('user_id', $userIdentifier);
            }

            $sessions = $sessionsQuery->get();
            $sessionIds = $sessions->pluck('session_id')->toArray();

            $exportData['sessions'] = $sessions->map(function ($session) {
                return [
                    'session_id' => $session->session_id,
                    'started_at' => $session->session_started_at,
                    'ended_at' => $session->session_ended_at,
                    'duration_minutes' => $session->duration_minutes,
                    'platforms_used' => $session->platforms_used,
                    'total_interactions' => $session->total_interactions,
                    'consent_status' => $session->data_collection_consent,
                    'consent_date' => $session->consent_updated_at,
                ];
            })->toArray();

            // Export interactions (without actual content, only metadata)
            $interactions = AiInteraction::whereIn('session_id', $sessionIds)
                ->orWhere('user_id', $userIdentifier)
                ->get();

            $exportData['interactions'] = $interactions->map(function ($interaction) {
                return [
                    'id' => $interaction->id,
                    'timestamp' => $interaction->created_at,
                    'platform' => $interaction->platform,
                    'type' => $interaction->type,
                    'content_length' => $interaction->content_length,
                    'risk_level' => $interaction->risk_level,
                    'risk_score' => $interaction->risk_score,
                    'risk_flags' => $interaction->risk_flags,
                    'user_consent' => $interaction->user_consent,
                ];
            })->toArray();

            // Export related alerts (anonymized)
            $alerts = SecurityAlert::whereHas('interaction', function ($query) use ($sessionIds, $userIdentifier) {
                $query->whereIn('session_id', $sessionIds)
                    ->orWhere('user_id', $userIdentifier);
            })->get();

            $exportData['alerts'] = $alerts->map(function ($alert) {
                return [
                    'id' => $alert->id,
                    'timestamp' => $alert->created_at,
                    'severity' => $alert->severity,
                    'alert_type' => $alert->alert_type,
                    'status' => $alert->status,
                    'confidence_score' => $alert->confidence_score,
                ];
            })->toArray();

            Log::info('GDPR data export generated', [
                'session_id' => $sessionId,
                'user_identifier' => $userIdentifier,
                'sessions_count' => count($exportData['sessions']),
                'interactions_count' => count($exportData['interactions']),
                'alerts_count' => count($exportData['alerts']),
            ]);

            return $exportData;

        } catch (\Exception $e) {
            Log::error('GDPR data export failed', [
                'session_id' => $sessionId,
                'user_identifier' => $userIdentifier,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }
}
