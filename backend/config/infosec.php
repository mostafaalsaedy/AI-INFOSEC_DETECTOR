<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Application Metadata
    |--------------------------------------------------------------------------
    |
    | Surfaced by /api/v1/health and used by the extension to decide whether it
    | needs to prompt the user to update.
    |
    */

    'version' => env('APP_VERSION', '1.0.0'),

    'minimum_extension_version' => env('MINIMUM_EXTENSION_VERSION', '1.0.0'),

    /*
    |--------------------------------------------------------------------------
    | Extension Authentication
    |--------------------------------------------------------------------------
    |
    | Shared secret used to sign payloads coming from the browser extension.
    | Requests are rejected when the HMAC signature does not match, so this
    | value must be identical in the extension build and on the server.
    |
    */

    'extension_secret' => env('EXTENSION_SECRET'),

    'signature_tolerance_seconds' => (int) env('SIGNATURE_TOLERANCE_SECONDS', 300),

    /*
    |--------------------------------------------------------------------------
    | Privacy & Retention
    |--------------------------------------------------------------------------
    |
    | Retention drives the automatic purge of interaction records. Consent
    | expiry forces users to re-affirm monitoring consent periodically, which
    | is what GDPR Article 7 expects for ongoing processing.
    |
    */

    'data_retention_days' => (int) env('DATA_RETENTION_DAYS', 365),

    'consent_expiry_days' => (int) env('CONSENT_EXPIRY_DAYS', 180),

    'privacy_policy_url' => env('PRIVACY_POLICY_URL', '/privacy-policy'),

    'dashboard_url' => env('DASHBOARD_URL', 'http://localhost:3000'),

    'uses_cookies' => (bool) env('USES_COOKIES', false),

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | Requests per minute, except `exports` which is per hour. Referenced by
    | the named limiters registered in AppServiceProvider.
    |
    */

    'rate_limits' => [
        'extension' => (int) env('EXTENSION_RATE_LIMIT', 120),
        'alerts' => (int) env('ALERTS_RATE_LIMIT', 30),
        'api' => (int) env('API_THROTTLE_ATTEMPTS', 300),
        'exports' => (int) env('EXPORTS_RATE_LIMIT', 20),
    ],

    /*
    |--------------------------------------------------------------------------
    | Risk Scoring
    |--------------------------------------------------------------------------
    |
    | Score thresholds that map a numeric risk score onto a severity band, and
    | the minimum severity that will actually raise an alert.
    |
    */

    'risk_thresholds' => [
        'medium' => (int) env('RISK_THRESHOLD_MEDIUM', 30),
        'high' => (int) env('RISK_THRESHOLD_HIGH', 60),
        'critical' => (int) env('RISK_THRESHOLD_CRITICAL', 85),
    ],

    'alert_minimum_severity' => env('ALERT_MINIMUM_SEVERITY', 'medium'),

    /*
    |--------------------------------------------------------------------------
    | Monitored Platforms
    |--------------------------------------------------------------------------
    |
    | Hostname to display-name mapping. Adding an entry here and to the
    | extension manifest is all that is needed to monitor a new platform.
    |
    */

    'platforms' => [
        'openai.com' => 'ChatGPT',
        'chatgpt.com' => 'ChatGPT',
        'claude.ai' => 'Claude',
        'anthropic.com' => 'Claude',
        'deepseek.com' => 'DeepSeek',
        'perplexity.ai' => 'Perplexity',
        'cohere.ai' => 'Cohere',
        'replicate.com' => 'Replicate',
        'huggingface.co' => 'Hugging Face',
        'together.ai' => 'Together AI',
        'mistral.ai' => 'Mistral AI',
    ],

];
