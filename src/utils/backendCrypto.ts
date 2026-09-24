import { x25519 } from '@noble/curves/ed25519';
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function fromBase64Url(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  return new Uint8Array(Buffer.from(padded + '='.repeat(pad), 'base64'));
}

/**
 * Encrypt a request body for the backend.
 * Returns the encrypted envelope and the SDK ephemeral private key
 * needed to decrypt the backend's response.
 */
export function encryptHttpRequest(
  body: unknown,
  backendPubKeyHex: string,
): { encryptedBody: { pk: string; c: string }; sdkEphPrivKeyHex: string } {
  const sdkPriv = randomBytes(32);
  const sdkPub = x25519.getPublicKey(sdkPriv);
  const shared = x25519.getSharedSecret(sdkPriv, hexToBytes(backendPubKeyHex));
  const key = hkdf(sha256, shared, new Uint8Array(0), utf8ToBytes('localid-http-request-v1'), 32);
  const nonce = randomBytes(12);
  const pt = utf8ToBytes(JSON.stringify(body));
  const ct = gcm(key, nonce).encrypt(pt);
  return {
    encryptedBody: { pk: bytesToHex(sdkPub), c: toBase64Url(concatBytes(nonce, ct)) },
    sdkEphPrivKeyHex: bytesToHex(sdkPriv),
  };
}

/**
 * Decrypt a response envelope from the backend.
 * Uses the SDK ephemeral private key retained from the matching request.
 */
export function decryptHttpResponse(
  response: { pk: string; c: string },
  sdkEphPrivKeyHex: string,
): unknown {
  const shared = x25519.getSharedSecret(hexToBytes(sdkEphPrivKeyHex), hexToBytes(response.pk));
  const key = hkdf(sha256, shared, new Uint8Array(0), utf8ToBytes('localid-http-response-v1'), 32);
  const data = fromBase64Url(response.c);
  const nonce = data.slice(0, 12);
  const ct = data.slice(12);
  const pt = gcm(key, nonce).decrypt(ct);
  return JSON.parse(new TextDecoder().decode(pt));
}
