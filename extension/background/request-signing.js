/**
 * HMAC request signing for extension -> API calls.
 *
 * The backend rejects any collection request that is not signed, so a stolen
 * endpoint URL alone cannot be used to inject fabricated telemetry. The
 * signature covers the exact request body plus a timestamp, which also bounds
 * replay: the server rejects anything outside a five-minute window.
 *
 * The shared secret must match `EXTENSION_SECRET` on the server. It is read
 * from `chrome.storage.sync`, so an administrator can provision it via managed
 * policy instead of baking it into the published build.
 */

const encoder = new TextEncoder();

/** Cached CryptoKey, so the secret is imported once rather than per request. */
let cachedKey = null;
let cachedSecret = null;

/** Read the configured shared secret, or null when the extension is unconfigured. */
export async function getExtensionSecret() {
  const stored = await chrome.storage.sync.get(['extensionSecret']);
  return stored.extensionSecret || null;
}

/** Read the configured extension identifier, falling back to the runtime ID. */
export async function getExtensionId() {
  const stored = await chrome.storage.sync.get(['extensionId']);
  return stored.extensionId || chrome.runtime.id;
}

async function getKey(secret) {
  if (cachedKey && cachedSecret === secret) {
    return cachedKey;
  }

  cachedKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  cachedSecret = secret;
  return cachedKey;
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Produce the hex HMAC-SHA256 of `${timestamp}.${body}`.
 *
 * Binding the timestamp into the signed message means an attacker cannot
 * replay a captured body under a fresh timestamp.
 */
export async function signPayload(body, timestamp, secret) {
  const key = await getKey(secret);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${timestamp}.${body}`)
  );
  return toHex(signature);
}

/**
 * Build the headers the API requires for an authenticated extension request.
 *
 * Returns null when no secret is configured, so callers can queue the payload
 * locally instead of firing a request that is certain to be rejected.
 */
export async function buildSignedHeaders(body, version = '1.0.0') {
  const secret = await getExtensionSecret();
  if (!secret) {
    return null;
  }

  const timestamp = Math.floor(Date.now() / 1000).toString();

  return {
    'Content-Type': 'application/json',
    'X-Extension-Id': await getExtensionId(),
    'X-Extension-Version': version,
    'X-Extension-Timestamp': timestamp,
    'X-Extension-Signature': await signPayload(body, timestamp, secret),
  };
}

/** Clear the cached key, e.g. after the administrator rotates the secret. */
export function resetSigningKey() {
  cachedKey = null;
  cachedSecret = null;
}
