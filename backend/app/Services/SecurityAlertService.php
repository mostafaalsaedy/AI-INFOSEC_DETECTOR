<?php

namespace App\Services;

use App\Models\SecurityAlert;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class SecurityAlertService
{
    private array $notificationChannels;

    private array $severityThresholds;

    public function __construct()
    {
        $this->notificationChannels = [
            'email' => config('alerts.email.enabled', true),
            'slack' => config('alerts.slack.enabled', false),
            'webhook' => config('alerts.webhook.enabled', false),
        ];

        $this->severityThresholds = [
            'critical' => ['email', 'slack', 'webhook'],
            'high' => ['email', 'slack'],
            'medium' => ['email'],
            'low' => [],
        ];
    }

    public function createAlert(array $alertData): SecurityAlert
    {
        $alert = SecurityAlert::create([
            'interaction_id' => $alertData['interaction_id'] ?? null,
            'severity' => $alertData['severity'] ?? 'medium',
            'alert_type' => $alertData['alert_type'] ?? 'security_detection',
            'title' => $alertData['title'] ?? 'Security Alert',
            'description' => $alertData['description'] ?? 'Security issue detected',
            'detection_rules' => $alertData['detection_rules'] ?? [],
            'evidence' => $alertData['evidence'] ?? [],
            'confidence_score' => $alertData['confidence_score'] ?? 50,
            'status' => 'open',
        ]);

        // Auto-assign based on severity and type
        $this->autoAssignAlert($alert);

        // Send notifications if appropriate
        if ($this->shouldNotify($alert)) {
            $this->sendNotification($alert);
        }

        Log::info('Security alert created', [
            'alert_id' => $alert->id,
            'severity' => $alert->severity,
            'type' => $alert->alert_type,
        ]);

        return $alert;
    }

    public function sendNotification(SecurityAlert $alert): void
    {
        $channels = $this->getNotificationChannels($alert->severity);
        $sentChannels = [];

        foreach ($channels as $channel) {
            if (! $this->notificationChannels[$channel]) {
                continue;
            }

            try {
                $success = match ($channel) {
                    'email' => $this->sendEmailNotification($alert),
                    'slack' => $this->sendSlackNotification($alert),
                    'webhook' => $this->sendWebhookNotification($alert),
                    default => false
                };

                if ($success) {
                    $sentChannels[] = $channel;
                }

            } catch (\Exception $e) {
                Log::error("Failed to send {$channel} notification", [
                    'alert_id' => $alert->id,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Update notification status
        if (! empty($sentChannels)) {
            $alert->update([
                'notification_sent' => true,
                'notification_sent_at' => now(),
                'notification_channels' => $sentChannels,
            ]);
        }
    }

    private function sendEmailNotification(SecurityAlert $alert): bool
    {
        $recipients = $this->getEmailRecipients($alert);

        if (empty($recipients)) {
            return false;
        }

        try {
            foreach ($recipients as $email) {
                Mail::send('emails.security-alert', [
                    'alert' => $alert,
                    'dashboard_url' => config('app.dashboard_url'),
                ], function ($message) use ($email, $alert) {
                    $message->to($email)
                        ->subject("[{$alert->severity}] Security Alert: {$alert->title}");
                });
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Email notification failed', [
                'alert_id' => $alert->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    private function sendSlackNotification(SecurityAlert $alert): bool
    {
        $webhookUrl = config('alerts.slack.webhook_url');

        if (empty($webhookUrl)) {
            return false;
        }

        $color = match ($alert->severity) {
            'critical' => '#ff0000',
            'high' => '#ff6600',
            'medium' => '#ffaa00',
            'low' => '#00aa00',
            default => '#cccccc'
        };

        $payload = [
            'text' => "Security Alert: {$alert->title}",
            'attachments' => [
                [
                    'color' => $color,
                    'fields' => [
                        [
                            'title' => 'Severity',
                            'value' => ucfirst($alert->severity),
                            'short' => true,
                        ],
                        [
                            'title' => 'Type',
                            'value' => str_replace('_', ' ', ucwords($alert->alert_type)),
                            'short' => true,
                        ],
                        [
                            'title' => 'Confidence',
                            'value' => "{$alert->confidence_score}%",
                            'short' => true,
                        ],
                        [
                            'title' => 'Status',
                            'value' => ucfirst($alert->status),
                            'short' => true,
                        ],
                        [
                            'title' => 'Description',
                            'value' => $alert->description,
                            'short' => false,
                        ],
                    ],
                    'footer' => 'InfoSec AI Monitor',
                    'ts' => $alert->created_at->timestamp,
                ],
            ],
        ];

        try {
            $response = Http::post($webhookUrl, $payload);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Slack notification failed', [
                'alert_id' => $alert->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    private function sendWebhookNotification(SecurityAlert $alert): bool
    {
        $webhookUrl = config('alerts.webhook.url');

        if (empty($webhookUrl)) {
            return false;
        }

        $payload = [
            'alert_id' => $alert->id,
            'severity' => $alert->severity,
            'alert_type' => $alert->alert_type,
            'title' => $alert->title,
            'description' => $alert->description,
            'confidence_score' => $alert->confidence_score,
            'status' => $alert->status,
            'created_at' => $alert->created_at->toISOString(),
            'evidence' => $alert->evidence,
            'interaction' => $alert->interaction ? [
                'platform' => $alert->interaction->platform,
                'risk_level' => $alert->interaction->risk_level,
                'session_id' => $alert->interaction->session_id,
            ] : null,
        ];

        try {
            $response = Http::timeout(30)
                ->withHeaders([
                    'X-Alert-Source' => 'infosec-ai-monitor',
                    'X-Alert-Signature' => $this->generateWebhookSignature($payload),
                ])
                ->post($webhookUrl, $payload);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Webhook notification failed', [
                'alert_id' => $alert->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    private function autoAssignAlert(SecurityAlert $alert): void
    {
        $assignee = match ($alert->alert_type) {
            'data_leakage' => config('alerts.assignees.data_protection'),
            'security_risk' => config('alerts.assignees.security_team'),
            'policy_violation' => config('alerts.assignees.compliance_team'),
            default => config('alerts.assignees.default')
        };

        if ($assignee) {
            $alert->assign($assignee);
        }
    }

    private function shouldNotify(SecurityAlert $alert): bool
    {
        // Don't notify for low confidence alerts
        if ($alert->confidence_score < 30) {
            return false;
        }

        // Always notify for critical and high severity
        if (in_array($alert->severity, ['critical', 'high'])) {
            return true;
        }

        // Check business hours for medium/low severity
        if ($alert->severity === 'medium') {
            return $this->isBusinessHours();
        }

        return false;
    }

    private function getNotificationChannels(string $severity): array
    {
        return $this->severityThresholds[$severity] ?? [];
    }

    private function getEmailRecipients(SecurityAlert $alert): array
    {
        $recipients = [];

        // Add default recipients
        $defaultRecipients = config('alerts.email.default_recipients', []);
        $recipients = array_merge($recipients, $defaultRecipients);

        // Add severity-specific recipients
        $severityRecipients = config("alerts.email.{$alert->severity}_recipients", []);
        $recipients = array_merge($recipients, $severityRecipients);

        // Add type-specific recipients
        $typeRecipients = config("alerts.email.{$alert->alert_type}_recipients", []);
        $recipients = array_merge($recipients, $typeRecipients);

        return array_unique($recipients);
    }

    private function generateWebhookSignature(array $payload): string
    {
        $secret = config('alerts.webhook.secret', '');

        return hash_hmac('sha256', json_encode($payload), $secret);
    }

    private function isBusinessHours(): bool
    {
        $timezone = config('app.timezone', 'UTC');
        $now = now($timezone);

        $businessStart = config('alerts.business_hours.start', 9);
        $businessEnd = config('alerts.business_hours.end', 17);
        $businessDays = config('alerts.business_hours.days', [1, 2, 3, 4, 5]); // Mon-Fri

        return in_array($now->dayOfWeek, $businessDays) &&
               $now->hour >= $businessStart &&
               $now->hour < $businessEnd;
    }

    public function getAlertStats(array $filters = []): array
    {
        $query = SecurityAlert::query();

        // Apply filters
        if (isset($filters['severity'])) {
            $query->where('severity', $filters['severity']);
        }

        if (isset($filters['status'])) {
            $query->where('status', $filters['status']);
        }

        if (isset($filters['from_date'])) {
            $query->where('created_at', '>=', $filters['from_date']);
        }

        if (isset($filters['to_date'])) {
            $query->where('created_at', '<=', $filters['to_date']);
        }

        $total = $query->count();
        $bySeverity = $query->selectRaw('severity, count(*) as count')
            ->groupBy('severity')
            ->pluck('count', 'severity')
            ->toArray();

        $byStatus = $query->selectRaw('status, count(*) as count')
            ->groupBy('status')
            ->pluck('count', 'status')
            ->toArray();

        $byType = $query->selectRaw('alert_type, count(*) as count')
            ->groupBy('alert_type')
            ->orderBy('count', 'desc')
            ->limit(10)
            ->pluck('count', 'alert_type')
            ->toArray();

        return [
            'total' => $total,
            'by_severity' => $bySeverity,
            'by_status' => $byStatus,
            'by_type' => $byType,
            'open_count' => $byStatus['open'] ?? 0,
            'critical_count' => $bySeverity['critical'] ?? 0,
        ];
    }
}
