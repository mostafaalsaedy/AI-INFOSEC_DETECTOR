# Contributing

Thanks for taking an interest. This document covers how to get set up, what the
code is expected to look like, and how changes get reviewed.

## Ground rules

This project handles data about what people type into AI tools. Two rules
override everything else:

1. **Never widen what is collected.** The extension sends hashes and metadata.
   A change that transmits prompt or response content — even "just for
   debugging", even behind a flag — will not be merged.
2. **Never log a secret.** Webhook URLs carry tokens in their path, so log the
   host only. Consent records, tokens and salts never appear in log output.

## Getting set up

Pick the backend you intend to work on; you do not need both.

```bash
git clone https://github.com/mostafaalsaedy/AI-INFOSEC_DETECTOR.git
cd AI-INFOSEC_DETECTOR
```

**Python backend**

```bash
cd backend-python
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
ENVIRONMENT=testing pytest
```

The test suite runs against in-memory SQLite. No PostgreSQL, Redis or Celery
broker is needed, and the whole suite finishes in a few seconds.

**Dashboard**

```bash
cd dashboard
npm install
npm run type-check
npm run dev
```

**Laravel backend**

```bash
cd backend
composer install
cp .env.example .env
php artisan key:generate
php artisan test
```

## Before you open a pull request

```bash
# Python
cd backend-python
ruff check app tests
black --check app tests
ENVIRONMENT=testing pytest

# Dashboard
cd dashboard
npm run lint
npm run type-check
npm run build

# Laravel
cd backend
./vendor/bin/pint --test
php artisan test
```

CI runs exactly these, so a green local run means a green pipeline.

## Code standards

**Python** — Black formatting, 90-character lines, type hints on public
functions. Docstrings explain *why*, not *what*: the signature already says
what. Use `app.core.timeutils.utcnow()` rather than `datetime.utcnow()`, which
is deprecated.

**TypeScript** — `strict` is on and stays on. No `any` in new code without a
comment justifying it. Components are function components with typed props.
Data fetching goes through `hooks/useApi`, not bare `fetch`.

**PHP** — PSR-12 via Laravel Pint. Controllers stay thin; business logic lives
in `app/Services`. Validate every request.

**Charts** — the dashboard uses a colour-vision-safe palette defined in
`dashboard/src/theme/vizPalette.ts`. Assign series colours by position, never
cycle them, and never reuse a status colour as a series colour. Dual-axis charts
are not accepted — use two charts.

## Tests

New behaviour needs a test. Aim tests at observable behaviour rather than
implementation details, and give them names that state the expectation:

```python
async def test_viewer_may_only_update_their_own_alerts(...):
```

is more useful than `test_permissions_2`.

Security-relevant paths — authentication, signing, permission checks, PII
stripping — need a test for the failure case, not only the success case.

## Commits and pull requests

Write commit subjects in the imperative mood: `Add consent expiry check`, not
`Added...`. Keep the subject under 72 characters and explain the reasoning in
the body when it is not obvious.

A good pull request:

- Does one thing.
- Says what problem it solves and how you verified the fix.
- Notes anything that affects privacy, retention or authentication explicitly.
- Updates the relevant `.env.example` when it adds configuration.

## Adding a monitored platform

Four files, in this order:

1. `extension/manifest.json` — add the host to `host_permissions` **and** to the
   `content_scripts` matches.
2. `extension/content-scripts/ai-monitor.js` — add the hostname and its DOM
   selectors.
3. `backend-python/app/core/config.py` — add it to `AI_PLATFORMS`.
4. `backend/config/infosec.php` — add it to `platforms`.

## Reporting bugs

Open an issue with reproduction steps, what you expected, and what happened.
Include versions (browser, Python/PHP, backend) and any relevant log output —
with secrets redacted.

For anything with security impact, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## License

Contributions are accepted under the [MIT License](LICENSE).
