import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';
import { computeSharedSecret } from './keyPair';
import { LOCALID_DEV_PUBLIC_KEY } from './devKeys';

const AES_KEY_LEN = 32;
const GCM_NONCE_LEN = 12;

/**
 * Derive a 256-bit AES key from an X25519 shared secret using HKDF-SHA256.
 * salt distinguishes request vs. response direction.
 */
function deriveKey(sharedSecret: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, sharedSecret, new Uint8Array(0), utf8ToBytes(info), AES_KEY_LEN);
}

/**
 * AES-256-GCM encrypt. Returns `nonce || ciphertext` concatenated as Uint8Array.
 * The 12-byte nonce is prepended so the decryptor can extract it without side-channel.
 */
function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(GCM_NONCE_LEN);
  const stream = gcm(key, nonce);
  const ciphertext = stream.encrypt(plaintext);
  return concatBytes(nonce, ciphertext);
}

/**
 * AES-256-GCM decrypt. Expects `nonce || ciphertext` as produced by aesGcmEncrypt.
 * Throws if authentication tag check fails (tampered ciphertext).
 */
function aesGcmDecrypt(key: Uint8Array, data: Uint8Array): Uint8Array {
  const nonce = data.slice(0, GCM_NONCE_LEN);
  const ciphertext = data.slice(GCM_NONCE_LEN);
  const stream = gcm(key, nonce);
  return stream.decrypt(ciphertext);
}

/** base64url encode without padding */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** base64url decode */
export function fromBase64Url(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  return new Uint8Array(Buffer.from(padded + '='.repeat(padLength), 'base64'));
}

// ── SDK-side (encrypt request, decrypt response) ──────────────────────────────

/**
 * Encrypt a request payload for LocalID.
 * Uses the SDK's ephemeral private key + LocalID's public key for ECDH.
 *
 * @param plaintext  JSON-serialized request object
 * @param sdkEphPrivKeyHex  SDK's ephemeral private key (hex)
 * @param localidPublicKeyHex  LocalID's public key (hex). Omit to use the DEV_ONLY key.
 * @returns base64url-encoded `nonce || ciphertext`
 */
export function encryptRequest(
  plaintext: string,
  sdkEphPrivKeyHex: string,
  localidPublicKeyHex?: string,
): string {
  const pubKey = localidPublicKeyHex ?? LOCALID_DEV_PUBLIC_KEY;
  const sharedSecret = computeSharedSecret(sdkEphPrivKeyHex, pubKey);
  const key = deriveKey(sharedSecret, 'localid-request-v1');
  const encrypted = aesGcmEncrypt(key, utf8ToBytes(plaintext));
  return toBase64Url(encrypted);
}

/**
 * Decrypt a response payload from LocalID.
 * Uses the SDK's stored ephemeral private key + LocalID's response ephemeral public key.
 *
 * @param ciphertextB64  base64url-encoded `nonce || ciphertext` from callback c= param
 * @param localidEphPubKeyHex  LocalID's response ephemeral public key from callback pk= param
 * @param sdkEphPrivKeyHex  SDK's ephemeral private key stored from the original request
 */
export function decryptResponse(
  ciphertextB64: string,
  localidEphPubKeyHex: string,
  sdkEphPrivKeyHex: string,
): string {
  const sharedSecret = computeSharedSecret(sdkEphPrivKeyHex, localidEphPubKeyHex);
  const key = deriveKey(sharedSecret, 'localid-response-v1');
  const data = fromBase64Url(ciphertextB64);
  const plaintext = aesGcmDecrypt(key, data);
  return new TextDecoder().decode(plaintext);
}

// ── LocalID-side helpers (re-exported for use in localid app) ────────────────
// These are duplicated in localid/src/crypto/encrypt.ts to keep repos independent.

export {
  deriveKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
};
