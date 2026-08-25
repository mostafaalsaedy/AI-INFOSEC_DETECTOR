# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through
[GitHub Security Advisories](https://github.com/mostafaalsaedy/AI-INFOSEC_DETECTOR/security/advisories/new),
which creates a channel visible only to the maintainers.

A useful report includes:

- What the issue is and which component it affects.
- Steps to reproduce, or a proof of concept.
- What an attacker could achieve with it.
- Any suggested fix, if you have one.

You can expect an acknowledgement within 72 hours and an assessment within a
week. Fixes for confirmed issues are released as quickly as the severity
warrants, and you will be credited in the advisory unless you would rather not
be.

Please give us a reasonable window to ship a fix before disclosing publicly.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |
| < 1.0 | ❌ |

## Security model

### What this system is trusted with

It handles metadata about what people type into AI tools. It never handles the
text itself — the extension hashes content client-side and discards it. A
compromise of the server therefore exposes hashes, risk scores and timing, not
conversations.

### Trust boundaries

| Boundary | Control |
|---|---|
| Extension → API | HMAC-SHA256 over `timestamp.body`, five-minute replay window |
| Dashboard → API | Short-lived JWT, three roles (`viewer`, `analyst`, `admin`) |
| API → database | Parameterised queries throughout; no string-built SQL |
| API → SIEM webhook | Outbound payloads signed with `X-Signature` |
| Model directory | Unpickling executes code — `ML_MODEL_PATH` must not be user-writable |

### Deploying safely

- Set `SECRET_KEY`, `EXTENSION_SECRET` and `ANONYMIZATION_SALT` to distinct
  random values of at least 32 characters. The production settings profile
  refuses to start on the development placeholders.
- Terminate TLS in front of the API. The extension will not send to plaintext
  endpoints in production.
- Keep `DEBUG=false` in production; it also disables the `/docs` and `/redoc`
  endpoints.
- Restrict `ALLOWED_HOSTS` and `ALLOWED_ORIGINS` to hosts you control.
  Production origins must be HTTPS.
- Put the database and Redis on a private network. Neither should be reachable
  from the internet.
- Rotating `ANONYMIZATION_SALT` permanently breaks the link to previously
  pseudonymised records. Treat it as write-once.
- Run the retention purge. Data you no longer hold cannot leak.

### Known limitations

- The default rate limiter is **in-process**. With multiple API replicas each
  enforces its own budget, so the effective limit is the configured value times
  the replica count. Swap in a Redis-backed limiter for multi-replica
  deployments — the dependency signature is unchanged.
- Persisted ML models are loaded with `pickle`, which executes arbitrary code.
  `ML_MODEL_PATH` is a trust boundary; never point it at shared or
  user-writable storage.
- Client-side risk patterns are regexes. They will produce false positives and
  will miss obfuscated secrets. They are a signal, not a guarantee.
- Content hashes are unsalted SHA-256. For short, low-entropy inputs a
  determined attacker with database access could confirm a guess by brute force.
  Do not treat a hash as equivalent to deletion.

## Legal notice

Workplace monitoring is regulated, and the rules differ substantially by
jurisdiction. Before deploying:

- Consult legal counsel and, where applicable, your works council.
- Inform the people being monitored and obtain the consent your jurisdiction
  requires.
- Publish a privacy notice covering what is collected and how long it is kept.
- Confirm your retention period is defensible.

The authors provide this software as-is and are not responsible for deployments
that do not meet local legal requirements.
