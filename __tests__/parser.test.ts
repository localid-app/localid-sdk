/**
 * Tests for parseCallback — the SDK-side parser for localid callback URLs.
 *
 * Each test builds a valid callback URL the same way localid's callbackDispatch.ts
 * does (ECDH encrypt with response keypair → HMAC sign), then passes it through
 * parseCallback() to verify the full round-trip.
 */
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac';
import { gcm } from '@noble/ciphers/aes';
import { hexToBytes, bytesToHex, utf8ToBytes, randomBytes, concatBytes } from '@noble/hashes/utils';
import { parseCallback, PendingEntry } from '../src/deeplink/parser';
import { generateEphemeralKeyPair } from '../src/crypto/keyPair';
import { clearNonces } from '../src/session/nonceStore';

const DEV_SIGNING_KEY = '1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a';
const RETURN_SCHEME = 'driveiq';

// ── Helpers ───────────────────────────────────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

interface CallbackOpts {
  status?: 'success' | 'denied' | 'error';
  data?: Record<string, unknown>;
  message?: string;
  requestId?: string;
  tsOverride?: number;
  nonceOverride?: string;
  tamperCiphertext?: boolean;
  tamperSignature?: boolean;
}

/**
 * Build a valid callback URL the way localid's callbackDispatch.ts does.
 * Returns the URL and the SDK ephemeral private key needed to decrypt it.
 */
function buildCallbackUrl(sdkEphPubKeyHex: string, opts: CallbackOpts = {}): string {
  const requestId = opts.requestId ?? 'req-' + bytesToHex(randomBytes(8));
  const nonce = opts.nonceOverride ?? bytesToHex(randomBytes(32));
  const ts = opts.tsOverride ?? Math.floor(Date.now() / 1000);

  const response = JSON.stringify({
    v: 1,
    type: 'response',
    requestId,
    nonce,
    ts,
    status: opts.status ?? 'success',
    data: opts.data,
    message: opts.message,
  });

  // LocalID generates an ephemeral keypair for the response
  const localidEphPriv = x25519.utils.randomPrivateKey();
  const localidEphPub = x25519.getPublicKey(localidEphPriv);

  // ECDH(localidEphPriv, sdkEphPub) → HKDF("localid-response-v1") → AES key
  const sharedSecret = x25519.getSharedSecret(localidEphPriv, hexToBytes(sdkEphPubKeyHex));
  const encKey = hkdf(sha256, sharedSecret, new Uint8Array(0), utf8ToBytes('localid-response-v1'), 32);

  // AES-256-GCM encrypt
  const gcmNonce = randomBytes(12);
  const stream = gcm(encKey, gcmNonce);
  let ciphertext = stream.encrypt(utf8ToBytes(response));

  if (opts.tamperCiphertext) {
    // Flip a byte in the middle of the auth tag region
    const arr = new Uint8Array(ciphertext);
    const idx = arr.length - 8;
    arr[idx] = (arr[idx]! ^ 0xff);
    ciphertext = arr;
  }

  const c = toBase64Url(concatBytes(gcmNonce, ciphertext));
  const pk = bytesToHex(localidEphPub);
  const unsigned = `${RETURN_SCHEME}://localid-callback?pk=${pk}&c=${c}`;

  // HMAC-SHA256 sign
  const sigKey = hexToBytes(DEV_SIGNING_KEY);
  const sig = opts.tamperSignature
    ? 'a'.repeat(64)
    : bytesToHex(hmac(sha256, sigKey, utf8ToBytes(unsigned)));

  return `${unsigned}&s=${sig}`;
}

/** Build a PendingEntry with a generous (1-hour) TTL for test purposes. */
function pendingEntry(privateKeyHex: string): PendingEntry {
  return { privateKeyHex, expiresAt: Date.now() + 60 * 60 * 1000 };
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => clearNonces());

// ── Happy path ────────────────────────────────────────────────────────────────

describe('parseCallback — happy path', () => {
  it('returns ok: true with correct response for a success callback', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([[`req-001`, pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, {
      requestId: 'req-001',
      status: 'success',
      data: { firstName: 'Alice', age_over_18: true },
    });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.response.status).toBe('success');
    expect(result.response.requestId).toBe('req-001');
    expect(result.response.data?.firstName).toBe('Alice');
    expect(result.response.data?.age_over_18).toBe(true);
    expect(typeof result.response.ts).toBe('number');
  });

  it('returns ok: true for a denied response', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([[`req-002`, pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, { requestId: 'req-002', status: 'denied' });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.response.status).toBe('denied');
  });

  it('removes the matched request from the pending map after parsing', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([[`req-003`, pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, { requestId: 'req-003' });

    parseCallback(url, pending);

    expect(pending.has('req-003')).toBe(false);
  });

  it('works when multiple pending requests exist — matches the correct one', () => {
    const sdkKP1 = generateEphemeralKeyPair();
    const sdkKP2 = generateEphemeralKeyPair();
    const pending = new Map([
      ['req-a', pendingEntry(sdkKP1.privateKeyHex)],
      ['req-b', pendingEntry(sdkKP2.privateKeyHex)],
    ]);
    const url = buildCallbackUrl(sdkKP2.publicKeyHex, { requestId: 'req-b', status: 'success' });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.response.requestId).toBe('req-b');
    // req-a should still be pending
    expect(pending.has('req-a')).toBe(true);
  });
});

// ── Signature validation ──────────────────────────────────────────────────────

describe('parseCallback — signature validation', () => {
  it('rejects a callback with a tampered signature', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([['req-sig', pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, {
      requestId: 'req-sig',
      tamperSignature: true,
    });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects a callback where the URL has been modified after signing', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([['req-mod', pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, { requestId: 'req-mod' });

    // Tamper: replace the scheme to simulate URL modification
    const tampered = url.replace('driveiq://', 'attacker://');
    const result = parseCallback(tampered, pending);

    expect(result.ok).toBe(false);
  });
});

// ── Ciphertext integrity ──────────────────────────────────────────────────────

describe('parseCallback — ciphertext integrity', () => {
  it('rejects a callback with a tampered ciphertext (AES-GCM auth tag fails)', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([['req-ct', pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, {
      requestId: 'req-ct',
      tamperCiphertext: true,
    });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(false);
  });
});

// ── Replay prevention ─────────────────────────────────────────────────────────

describe('parseCallback — replay prevention', () => {
  it('rejects the same callback URL on second parse (duplicate nonce)', () => {
    const sdkKP = generateEphemeralKeyPair();
    const url = buildCallbackUrl(sdkKP.publicKeyHex, { requestId: 'req-replay', nonceOverride: 'fixed-nonce-aabbcc' });

    const pending1 = new Map([['req-replay', pendingEntry(sdkKP.privateKeyHex)]]);
    const first = parseCallback(url, pending1);
    expect(first.ok).toBe(true);

    // Re-add to pending (simulating replay attack)
    const pending2 = new Map([['req-replay', pendingEntry(sdkKP.privateKeyHex)]]);
    const second = parseCallback(url, pending2);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.error.code).toBe('REPLAY_DETECTED');
  });
});

// ── Timestamp expiry ──────────────────────────────────────────────────────────

describe('parseCallback — timestamp checks', () => {
  it('rejects a callback with an expired timestamp (> 5 min old)', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([['req-old', pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, {
      requestId: 'req-old',
      tsOverride: Math.floor(Date.now() / 1000) - 400,
    });

    const result = parseCallback(url, pending);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('EXPIRED');
  });

  it('accepts a callback with a timestamp within the 5-min window', () => {
    const sdkKP = generateEphemeralKeyPair();
    const pending = new Map([['req-recent', pendingEntry(sdkKP.privateKeyHex)]]);
    const url = buildCallbackUrl(sdkKP.publicKeyHex, {
      requestId: 'req-recent',
      tsOverride: Math.floor(Date.now() / 1000) - 60,
    });

    const result = parseCallback(url, pending);
    expect(result.ok).toBe(true);
  });
});

// ── Non-localid URLs ──────────────────────────────────────────────────────────

describe('parseCallback — non-localid URLs', () => {
  it('returns ok: false for a URL that is not a callback URL', () => {
    const result = parseCallback('driveiq://some-other-route?foo=bar', new Map());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNKNOWN');
  });

  it('returns ok: false for a callback URL with no query params', () => {
    const result = parseCallback('driveiq://localid-callback', new Map());
    expect(result.ok).toBe(false);
  });

  it('returns ok: false when pending map is empty (no key to decrypt with)', () => {
    const sdkKP = generateEphemeralKeyPair();
    const url = buildCallbackUrl(sdkKP.publicKeyHex, { requestId: 'req-nomatch' });
    const result = parseCallback(url, new Map()); // empty pending
    expect(result.ok).toBe(false);
  });
});
