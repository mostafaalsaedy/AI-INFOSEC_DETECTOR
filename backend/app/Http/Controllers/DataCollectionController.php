<?php

namespace App\Http\Controllers;

use App\Models\AiInteraction;
use App\Models\SecurityAlert;
use App\Models\UserSession;
use App\Services\RiskAnalysisService;
use App\Services\SecurityAlertService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class DataCollectionController extends Controller
{
    public function __construct(
        private RiskAnalysisService $riskAnalysis,
        private SecurityAlertService $alertService
    ) {}

    public function collect(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'sessionId' => 'required|string|max:100',
                'type' => 'required|in:prompt,response',
                'platform' => 'required|string|max:50',
                'url' => 'required|url|max:500',
                'timestamp' => 'required|integer',
                'promptHash' => 'nullable|string|max:64',
                'responseHash' => 'nullable|string|max:64',
                'promptLength' => 'nullable|integer|min:0',
                'responseLength' => 'nullable|integer|min:0',
                'riskIndicators' => 'nullable|array',
                'metadata' => 'nullable|array',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'error' => 'Validation failed',
                    'details' => $validator->errors(),
                ], 422);
            }

            $data = $validator->validated();

            // Get or create session
            $session = $this->getOrCreateSession($data['sessionId'], $request);

            // Check consent
            if (! $session->hasConsent()) {
                return response()->json([
                    'error' => 'User consent required',
                    'consent_required' => true,
                ], 403);
            }

            // Create interaction record
            $interaction = $this->createInteraction($data, $session, $request);

            // Analyze risk and create alerts if needed
            $this->processRiskAnalysis($interaction);

            // Update session activity
            $session->updateActivity();
            $session->incrementInteractions();
            $session->addPlatform($data['platform']);

            return response()->json([
                'success' => true,
                'id' => $interaction->id,
                'risk_level' => $interaction->risk_level,
                'timestamp' => now()->toISOString(),
            ]);

        } catch (\Exception $e) {
            Log::error('Data collection error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'request_data' => $request->all(),
            ]);

            return response()->json([
                'error' => 'Internal server error',
                'message' => 'Failed to process data collection',
            ], 500);
        }
    }

    public function alert(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'type' => 'required|string|in:security_alert',
                'severity' => 'required|in:low,medium,high,critical',
                'data' => 'required|array',
                'timestamp' => 'required|integer',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'error' => 'Validation failed',
                    'details' => $validator->errors(),
                ], 422);
            }

            $alertData = $validator->validated();

            // Find the related interaction
            $interaction = null;
            if (isset($alertData['data']['sessionId'])) {
                $interaction = AiInteraction::where('session_id', $alertData['data']['sessionId'])
                    ->orderBy('created_at', 'desc')
                    ->first();
            }

            // Create security alert
            $alert = SecurityAlert::create([
                'interaction_id' => $interaction?->id,
                'severity' => $alertData['severity'],
                'alert_type' => 'real_time_detection',
                'title' => 'Real-time Security Alert',
                'description' => 'High-risk activity detected in real-time',
                'detection_rules' => ['real_time_analysis'],
                'evidence' => $this->sanitizeEvidence($alertData['data']),
                'confidence_score' => 90,
                'status' => 'open',
            ]);

            // Send notifications
            $this->alertService->sendNotification($alert);

            // Update session alert count
            if ($interaction && $interaction->session) {
                $interaction->session->incrementAlerts();
            }

            return response()->json([
                'success' => true,
                'alert_id' => $alert->id,
                'timestamp' => now()->toISOString(),
            ]);

        } catch (\Exception $e) {
            Log::error('Alert processing error', [
                'error' => $e->getMessage(),
                'request_data' => $request->all(),
            ]);

            return response()->json([
                'error' => 'Internal server error',
                'message' => 'Failed to process alert',
            ], 500);
        }
    }

    public function consent(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'sessionId' => 'required|string|max:100',
                'consent' => 'required|boolean',
                'consentDate' => 'required|integer',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'error' => 'Validation failed',
                    'details' => $validator->errors(),
                ], 422);
            }

            $data = $validator->validated();

            $session = UserSession::where('session_id', $data['sessionId'])->first();

            if (! $session) {
                // Create new session with consent
                $session = $this->getOrCreateSession($data['sessionId'], $request);
            }

            $session->update([
                'data_collection_consent' => $data['consent'],
                'consent_updated_at' => now(),
            ]);

            return response()->json([
                'success' => true,
                'consent_recorded' => $data['consent'],
                'timestamp' => now()->toISOString(),
            ]);

        } catch (\Exception $e) {
            Log::error('Consent processing error', [
                'error' => $e->getMessage(),
                'request_data' => $request->all(),
            ]);

            return response()->json([
                'error' => 'Internal server error',
                'message' => 'Failed to process consent',
            ], 500);
        }
    }

    private function getOrCreateSession(string $sessionId, Request $request): UserSession
    {
        return UserSession::firstOrCreate(
            ['session_id' => $sessionId],
            [
                'user_id' => $request->header('X-User-ID'),
                'extension_version' => $request->header('X-Extension-Version'),
                'browser' => $this->extractBrowserInfo($request->userAgent())['name'] ?? null,
                'browser_version' => $this->extractBrowserInfo($request->userAgent())['version'] ?? null,
                'os' => $this->extractOsInfo($request->userAgent()),
                'user_agent' => $request->userAgent(),
                'session_started_at' => now(),
                'last_activity_at' => now(),
                'monitoring_enabled' => true,
                'data_collection_consent' => false,
            ]
        );
    }

    private function createInteraction(array $data, UserSession $session, Request $request): AiInteraction
    {
        $contentHash = $data['promptHash'] ?? $data['responseHash'] ?? null;
        $contentLength = $data['promptLength'] ?? $data['responseLength'] ?? 0;

        // Perform initial risk analysis
        $riskAnalysis = $this->riskAnalysis->analyzeFromMetadata($data['riskIndicators'] ?? []);

        return AiInteraction::create([
            'session_id' => $data['sessionId'],
            'user_id' => $session->user_id,
            'platform' => $data['platform'],
            'url' => $data['url'],
            'page_title' => $data['metadata']['pageTitle'] ?? null,
            'type' => $data['type'],
            'content_hash' => $contentHash,
            'content_length' => $contentLength,
            'risk_level' => $riskAnalysis['riskLevel'],
            'risk_score' => $riskAnalysis['score'],
            'risk_flags' => $riskAnalysis['flags'],
            'metadata' => $data['metadata'] ?? [],
            'user_agent' => $request->userAgent(),
            'ip_address' => $request->ip(),
            'user_consent' => true,
            'consent_date' => now(),
            'data_processed' => false,
        ]);
    }

    private function processRiskAnalysis(AiInteraction $interaction): void
    {
        if ($interaction->isHighRisk()) {
            $alert = $this->alertService->createAlert([
                'interaction_id' => $interaction->id,
                'severity' => $interaction->risk_score >= 80 ? 'high' : 'medium',
                'alert_type' => 'risk_detection',
                'title' => 'High-Risk AI Interaction Detected',
                'description' => 'Automated analysis detected potential security risks',
                'detection_rules' => ['automated_risk_analysis'],
                'evidence' => [
                    'risk_level' => $interaction->risk_level,
                    'risk_score' => $interaction->risk_score,
                    'risk_flags' => $interaction->risk_flags,
                    'platform' => $interaction->platform,
                ],
                'confidence_score' => min(90, $interaction->risk_score),
            ]);

            if ($interaction->session) {
                $interaction->session->incrementAlerts();
            }
        }
    }

    private function sanitizeEvidence(array $data): array
    {
        // Remove sensitive data from evidence
        $sanitized = $data;
        unset($sanitized['prompt'], $sanitized['response'], $sanitized['content']);

        return [
            'platform' => $sanitized['platform'] ?? null,
            'risk_indicators' => $sanitized['riskIndicators'] ?? [],
            'timestamp' => $sanitized['timestamp'] ?? null,
            'content_length' => $sanitized['promptLength'] ?? $sanitized['responseLength'] ?? null,
        ];
    }

    private function extractBrowserInfo(string $userAgent): array
    {
        $browsers = [
            'Chrome' => '/Chrome\/([0-9.]+)/',
            'Firefox' => '/Firefox\/([0-9.]+)/',
            'Safari' => '/Safari\/([0-9.]+)/',
            'Edge' => '/Edge\/([0-9.]+)/',
            'Opera' => '/Opera\/([0-9.]+)/',
        ];

        foreach ($browsers as $browser => $pattern) {
            if (preg_match($pattern, $userAgent, $matches)) {
                return ['name' => $browser, 'version' => $matches[1] ?? null];
            }
        }

        return ['name' => 'Unknown', 'version' => null];
    }

    private function extractOsInfo(string $userAgent): ?string
    {
        $osList = [
            'Windows NT 10.0' => 'Windows 10',
            'Windows NT 6.3' => 'Windows 8.1',
            'Windows NT 6.2' => 'Windows 8',
            'Windows NT 6.1' => 'Windows 7',
            'Mac OS X' => 'macOS',
            'Linux' => 'Linux',
            'Android' => 'Android',
            'iOS' => 'iOS',
        ];

        foreach ($osList as $pattern => $os) {
            if (strpos($userAgent, $pattern) !== false) {
                return $os;
            }
        }

        return null;
    }
}
