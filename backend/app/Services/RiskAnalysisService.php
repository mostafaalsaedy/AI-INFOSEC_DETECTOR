<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class RiskAnalysisService
{
    private array $sensitivePatterns = [
        'credit_card' => [
            'pattern' => '/\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b/',
            'weight' => 10,
            'description' => 'Credit card number detected',
        ],
        'ssn' => [
            'pattern' => '/\b\d{3}-\d{2}-\d{4}\b/',
            'weight' => 10,
            'description' => 'Social Security Number detected',
        ],
        'password' => [
            'pattern' => '/\b(?:password|passwd|pwd)\s*[:=]\s*\S+/i',
            'weight' => 8,
            'description' => 'Password information detected',
        ],
        'api_key' => [
            'pattern' => '/\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|bearer\s+token)\s*[:=]\s*\S+/i',
            'weight' => 9,
            'description' => 'API key or token detected',
        ],
        'email' => [
            'pattern' => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/',
            'weight' => 3,
            'description' => 'Email address detected',
        ],
        'phone' => [
            'pattern' => '/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/',
            'weight' => 4,
            'description' => 'Phone number detected',
        ],
        'ip_address' => [
            'pattern' => '/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/',
            'weight' => 5,
            'description' => 'IP address detected',
        ],
        'confidential' => [
            'pattern' => '/\b(?:confidential|internal|proprietary|classified|restricted)\b/i',
            'weight' => 6,
            'description' => 'Confidential content indicator',
        ],
        'security_risk' => [
            'pattern' => '/\b(?:hack|exploit|bypass|vulnerability|penetration|malware|virus)\b/i',
            'weight' => 7,
            'description' => 'Security risk terminology',
        ],
        'financial' => [
            'pattern' => '/\b(?:bank\s+account|routing\s+number|iban|swift\s+code|account\s+number)\b/i',
            'weight' => 8,
            'description' => 'Financial information detected',
        ],
    ];

    private array $contextualRisks = [
        'code_injection' => [
            'patterns' => [
                '/\b(?:eval|exec|system|shell_exec)\s*\(/',
                '/\<\?php|\<script|\<\?/',
                '/SELECT\s+.*FROM\s+.*WHERE/i',
                '/INSERT\s+INTO\s+.*VALUES/i',
                '/DROP\s+TABLE/i',
            ],
            'weight' => 9,
            'description' => 'Potential code injection patterns',
        ],
        'social_engineering' => [
            'patterns' => [
                '/\b(?:urgent|immediate|expire|suspend|verify|confirm|click\s+here)\b/i',
                '/\b(?:act\s+now|limited\s+time|don\'t\s+delay)\b/i',
            ],
            'weight' => 5,
            'description' => 'Social engineering indicators',
        ],
    ];

    public function analyzeContent(string $content): array
    {
        $riskAnalysis = [
            'riskLevel' => 'low',
            'score' => 0,
            'flags' => [],
            'details' => [],
        ];

        // Analyze sensitive patterns
        foreach ($this->sensitivePatterns as $type => $config) {
            if (preg_match($config['pattern'], $content, $matches)) {
                $riskAnalysis['score'] += $config['weight'];
                $riskAnalysis['flags'][] = $type;
                $riskAnalysis['details'][] = [
                    'type' => $type,
                    'description' => $config['description'],
                    'weight' => $config['weight'],
                    'matches' => count($matches),
                ];
            }
        }

        // Analyze contextual risks
        foreach ($this->contextualRisks as $type => $config) {
            $matchCount = 0;
            foreach ($config['patterns'] as $pattern) {
                if (preg_match($pattern, $content)) {
                    $matchCount++;
                }
            }

            if ($matchCount > 0) {
                $weight = $config['weight'] * min($matchCount, 3); // Cap multiplier
                $riskAnalysis['score'] += $weight;
                $riskAnalysis['flags'][] = $type;
                $riskAnalysis['details'][] = [
                    'type' => $type,
                    'description' => $config['description'],
                    'weight' => $weight,
                    'matches' => $matchCount,
                ];
            }
        }

        // Determine risk level
        $riskAnalysis['riskLevel'] = $this->calculateRiskLevel($riskAnalysis['score']);

        // Log high-risk detections
        if ($riskAnalysis['riskLevel'] === 'high') {
            Log::warning('High-risk content detected', [
                'score' => $riskAnalysis['score'],
                'flags' => $riskAnalysis['flags'],
                'content_length' => strlen($content),
            ]);
        }

        return $riskAnalysis;
    }

    public function analyzeFromMetadata(array $riskIndicators): array
    {
        $riskAnalysis = [
            'riskLevel' => 'low',
            'score' => 0,
            'flags' => [],
        ];

        if (empty($riskIndicators)) {
            return $riskAnalysis;
        }

        // Extract risk data from client-side analysis
        if (isset($riskIndicators['flags']) && is_array($riskIndicators['flags'])) {
            $riskAnalysis['flags'] = $riskIndicators['flags'];

            // Calculate score based on flags
            foreach ($riskIndicators['flags'] as $flag) {
                if (isset($this->sensitivePatterns[$flag])) {
                    $riskAnalysis['score'] += $this->sensitivePatterns[$flag]['weight'];
                }
            }
        }

        if (isset($riskIndicators['score'])) {
            $riskAnalysis['score'] = max($riskAnalysis['score'], (int) $riskIndicators['score']);
        }

        if (isset($riskIndicators['riskLevel'])) {
            $clientRiskLevel = $riskIndicators['riskLevel'];
            $calculatedRiskLevel = $this->calculateRiskLevel($riskAnalysis['score']);

            // Use the higher of the two risk levels
            $riskAnalysis['riskLevel'] = $this->getHigherRiskLevel($clientRiskLevel, $calculatedRiskLevel);
        } else {
            $riskAnalysis['riskLevel'] = $this->calculateRiskLevel($riskAnalysis['score']);
        }

        return $riskAnalysis;
    }

    public function analyzeBulk(array $interactions): array
    {
        $results = [];

        foreach ($interactions as $interaction) {
            $content = $interaction['content'] ?? '';
            $results[] = [
                'id' => $interaction['id'] ?? null,
                'analysis' => $this->analyzeContent($content),
            ];
        }

        return $results;
    }

    public function getPatternStats(): array
    {
        $stats = [];

        foreach ($this->sensitivePatterns as $type => $config) {
            $stats[$type] = [
                'weight' => $config['weight'],
                'description' => $config['description'],
            ];
        }

        return $stats;
    }

    private function calculateRiskLevel(int $score): string
    {
        return match (true) {
            $score >= 15 => 'high',
            $score >= 8 => 'medium',
            default => 'low'
        };
    }

    private function getHigherRiskLevel(string $level1, string $level2): string
    {
        $levels = ['low' => 1, 'medium' => 2, 'high' => 3];

        $score1 = $levels[$level1] ?? 1;
        $score2 = $levels[$level2] ?? 1;

        $result = max($score1, $score2);

        return array_search($result, $levels) ?: 'low';
    }

    public function analyzeUserBehavior(array $sessions): array
    {
        $behaviorAnalysis = [
            'total_sessions' => count($sessions),
            'avg_session_duration' => 0,
            'high_risk_ratio' => 0,
            'platform_diversity' => 0,
            'anomalies' => [],
        ];

        if (empty($sessions)) {
            return $behaviorAnalysis;
        }

        $totalDuration = 0;
        $highRiskCount = 0;
        $allPlatforms = [];

        foreach ($sessions as $session) {
            $totalDuration += $session['duration_minutes'] ?? 0;

            if (($session['total_alerts'] ?? 0) > 0) {
                $highRiskCount++;
            }

            $platforms = $session['platforms_used'] ?? [];
            $allPlatforms = array_merge($allPlatforms, $platforms);
        }

        $behaviorAnalysis['avg_session_duration'] = $totalDuration / count($sessions);
        $behaviorAnalysis['high_risk_ratio'] = $highRiskCount / count($sessions);
        $behaviorAnalysis['platform_diversity'] = count(array_unique($allPlatforms));

        // Detect anomalies
        $this->detectBehaviorAnomalies($sessions, $behaviorAnalysis);

        return $behaviorAnalysis;
    }

    private function detectBehaviorAnomalies(array $sessions, array &$behaviorAnalysis): void
    {
        // Detect unusually long sessions
        $avgDuration = $behaviorAnalysis['avg_session_duration'];

        foreach ($sessions as $session) {
            $duration = $session['duration_minutes'] ?? 0;

            if ($duration > $avgDuration * 3) {
                $behaviorAnalysis['anomalies'][] = [
                    'type' => 'unusual_session_length',
                    'session_id' => $session['session_id'] ?? null,
                    'duration' => $duration,
                    'severity' => 'medium',
                ];
            }
        }

        // Detect unusual platform patterns
        if ($behaviorAnalysis['platform_diversity'] > 5) {
            $behaviorAnalysis['anomalies'][] = [
                'type' => 'high_platform_diversity',
                'platform_count' => $behaviorAnalysis['platform_diversity'],
                'severity' => 'low',
            ];
        }

        // Detect high alert frequency
        if ($behaviorAnalysis['high_risk_ratio'] > 0.3) {
            $behaviorAnalysis['anomalies'][] = [
                'type' => 'high_alert_frequency',
                'alert_ratio' => $behaviorAnalysis['high_risk_ratio'],
                'severity' => 'high',
            ];
        }
    }
}
