<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Email Notifications
    |--------------------------------------------------------------------------
    |
    | Recipient lists escalate with severity: a critical alert reaches the
    | default list plus the high-severity list plus the critical list.
    |
    */

    'email' => [
        'enabled' => (bool) env('ALERTS_EMAIL_ENABLED', true),

        'default_recipients' => array_filter(
            explode(',', (string) env('ALERTS_DEFAULT_RECIPIENTS', ''))
        ),

        'high_recipients' => array_filter(
            explode(',', (string) env('ALERTS_HIGH_RECIPIENTS', ''))
        ),

        'critical_recipients' => array_filter(
            explode(',', (string) env('ALERTS_CRITICAL_RECIPIENTS', ''))
        ),
    ],

    /*
    |--------------------------------------------------------------------------
    | Slack Notifications
    |--------------------------------------------------------------------------
    */

    'slack' => [
        'enabled' => (bool) env('ALERTS_SLACK_ENABLED', false),
        'webhook_url' => env('ALERTS_SLACK_WEBHOOK_URL'),
        'channel' => env('ALERTS_SLACK_CHANNEL', '#security-alerts'),
        'username' => env('ALERTS_SLACK_USERNAME', 'InfoSec AI Monitor'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Webhook / SIEM Integration
    |--------------------------------------------------------------------------
    |
    | Outbound alerts are signed with `secret` using HMAC-SHA256 and sent in an
    | `X-Signature` header so the receiver can verify they originated here.
    |
    */

    'webhook' => [
        'enabled' => (bool) env('ALERTS_WEBHOOK_ENABLED', false),
        'url' => env('ALERTS_WEBHOOK_URL'),
        'secret' => env('ALERTS_WEBHOOK_SECRET', ''),
        'timeout' => (int) env('ALERTS_WEBHOOK_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Business Hours
    |--------------------------------------------------------------------------
    |
    | Non-critical alerts are held outside business hours to avoid paging the
    | on-call rotation for low-signal findings. Critical alerts always send.
    | Days use ISO-8601 numbering (1 = Monday ... 7 = Sunday).
    |
    */

    'business_hours' => [
        'start' => (int) env('ALERTS_BUSINESS_HOURS_START', 9),
        'end' => (int) env('ALERTS_BUSINESS_HOURS_END', 17),
        'days' => array_map(
            'intval',
            array_filter(explode(',', (string) env('ALERTS_BUSINESS_DAYS', '1,2,3,4,5')))
        ),
        'timezone' => env('ALERTS_TIMEZONE', env('APP_TIMEZONE', 'UTC')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Automatic Assignment
    |--------------------------------------------------------------------------
    |
    | New alerts are routed to a queue based on the risk category that
    | triggered them, so the right team sees them first.
    |
    */

    'assignees' => [
        'default' => env('ALERTS_ASSIGNEE_DEFAULT', 'security-team'),
        'security_team' => env('ALERTS_ASSIGNEE_SECURITY_TEAM', 'security-team'),
        'compliance_team' => env('ALERTS_ASSIGNEE_COMPLIANCE', 'compliance-team'),
        'data_protection' => env('ALERTS_ASSIGNEE_DATA_PROTECTION', 'data-protection-officer'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Deduplication
    |--------------------------------------------------------------------------
    |
    | Suppress repeat alerts of the same type for the same session inside this
    | window, so a user pasting the same secret ten times raises one alert.
    |
    */

    'deduplication_window_minutes' => (int) env('ALERT_DEDUP_WINDOW_MINUTES', 15),

];
