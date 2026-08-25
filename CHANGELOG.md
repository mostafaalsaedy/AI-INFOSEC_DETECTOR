# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-25

First public release.

### Added

**Browser extension (Manifest V3)**
- Monitoring for ChatGPT, Claude, DeepSeek, Perplexity, Cohere, Replicate,
  Hugging Face, Together AI and Mistral AI.
- Client-side SHA-256 hashing — prompt and response text never leaves the
  browser.
- Client-side risk pattern matching for credentials, financial data, personal
  data, classification markers and security terminology.
- HMAC-SHA256 request signing with a five-minute replay window.
- Consent management with an expiry, and local queueing when the API is
  unreachable.

**FastAPI backend** (`backend-python/`)
- REST API for collection, alert triage and analytics, with OpenAPI docs.
- Native WebSocket endpoint at `/ws/monitor` for live dashboard updates.
- JWT authentication with `viewer`, `analyst` and `admin` roles.
- Risk analysis pipeline: deterministic pattern rules, plus optional
  transformer classification, isolation-forest anomaly detection and spaCy
  entity extraction.
- Alert routing to email, Slack and signed SIEM webhooks, with business-hours
  suppression for non-critical findings.
- GDPR/CCPA support: consent records, subject data export, erasure,
  pseudonymisation and automatic retention purge.
- Celery workers for ML retraining and notification fan-out.
- Prometheus metrics, structured JSON logging, Kubernetes manifests.
- 180 tests running against in-memory SQLite with no external services.

**Laravel backend** (`backend/`)
- Equivalent REST API on Laravel 12 with Sanctum authentication.
- Data-protection and GDPR-compliance middleware applied to every API route.
- Dashboard and analytics controllers with streamed CSV exports.
- Named rate limiters for extension, alert, API and export traffic.

**Dashboard** (`dashboard/`)
- React 18 + TypeScript + Vite, dark Material UI theme.
- Live security dashboard, alert triage, session explorer, analytics and
  settings.
- Colour-vision-safe chart palette, validated for contrast and CVD separation.
- Reconnecting WebSocket client with subscription replay and backoff.

**Repository**
- MIT license, contribution guide, security policy.
- GitHub Actions CI covering all three components.
- Issue and pull-request templates, Dependabot configuration.

[Unreleased]: https://github.com/mostafaalsaedy/AI-INFOSEC_DETECTOR/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mostafaalsaedy/AI-INFOSEC_DETECTOR/releases/tag/v1.0.0
