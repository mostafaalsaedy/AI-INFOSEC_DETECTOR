# InfoSec AI Monitor - Browser Extension

Chrome/Edge Manifest V3 extension that observes AI-platform usage and reports
**metadata only** to the monitoring API.

## What it collects, and what it does not

| Collected | Never collected |
|---|---|
| Platform hostname and page title | Prompt text |
| SHA-256 hash of the content | Response text |
| Content length and detected language | Attachments or files |
| Client-side risk flags (e.g. `api_key` matched) | The matched value itself |
| Session ID, extension version, browser name | Browsing history outside monitored platforms |

Hashes are one-way: the server can tell that the same text was sent twice, but
cannot recover the text.

## Install for development

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this `extension/` directory.
4. Open the extension's popup and grant consent.

## Configuration

The extension reads its settings from `chrome.storage.sync`:

| Key | Meaning |
|---|---|
| `apiEndpoint` | API base URL, e.g. `https://monitor.example.com/api/v1` |
| `extensionSecret` | Shared HMAC secret; must equal `EXTENSION_SECRET` on the server |
| `extensionId` | Optional identifier reported to the server (defaults to the runtime ID) |
| `monitorEnabled` | Master on/off switch |
| `userConsent` | Whether the user has agreed to monitoring |

Set them from the extension's service-worker console:

```js
chrome.storage.sync.set({
  apiEndpoint: 'https://monitor.example.com/api/v1',
  extensionSecret: 'the-same-value-as-EXTENSION_SECRET',
});
```

For a managed fleet, push the same keys through an enterprise policy instead, so
the secret never ships inside the packaged extension.

## Request signing

Every request carries three headers the API verifies before accepting anything:

```
X-Extension-Id:         <extension identifier>
X-Extension-Timestamp:  <unix seconds>
X-Extension-Signature:  hex(HMAC-SHA256(secret, "<timestamp>.<body>"))
```

Because the timestamp is part of the signed message and the server rejects
anything older than five minutes, a captured request cannot be replayed. If no
secret is configured the extension queues data locally rather than sending
requests that are certain to be refused.

See `background/request-signing.js` for the implementation.

## Layout

```
extension/
├── manifest.json              Manifest V3 declaration
├── background/
│   ├── service-worker.js      Event handling, batching, transport
│   └── request-signing.js     HMAC signing helpers
├── content-scripts/
│   ├── ai-monitor.js          Per-platform DOM observation
│   └── monitor-styles.css     Injected indicator styling
├── popup/                     Toolbar UI: status, consent, controls
└── icons/                     Toolbar and store icons
```

## Adding a platform

1. Add the host pattern to `host_permissions` **and** to the `content_scripts`
   matches in `manifest.json`.
2. Add the hostname to the platform map in `content-scripts/ai-monitor.js` and
   `background/service-worker.js`.
3. Add the matching entry to the server's platform list
   (`backend/config/infosec.php` and `backend-python/app/core/config.py`).

## Packaging

```bash
cd extension
zip -r ../infosec-ai-monitor-extension.zip . -x "*.map" "key.pem"
```

Upload the archive to the Chrome Web Store dashboard, or distribute it through
enterprise policy for internal deployment.
