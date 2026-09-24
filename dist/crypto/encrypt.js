"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBase64Url = toBase64Url;
exports.fromBase64Url = fromBase64Url;
exports.encryptRequest = encryptRequest;
exports.decryptResponse = decryptResponse;
exports.deriveKey = deriveKey;
exports.aesGcmEncrypt = aesGcmEncrypt;
exports.aesGcmDecrypt = aesGcmDecrypt;
const aes_1 = require("@noble/ciphers/aes");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
const keyPair_1 = require("./keyPair");
const devKeys_1 = require("./devKeys");
const AES_KEY_LEN = 32;
const GCM_NONCE_LEN = 12;
/**
 * Derive a 256-bit AES key from an X25519 shared secret using HKDF-SHA256.
 * salt distinguishes request vs. response direction.
 */
function deriveKey(sharedSecret, info) {
    return (0, hkdf_1.hkdf)(sha2_1.sha256, sharedSecret, new Uint8Array(0), (0, utils_1.utf8ToBytes)(info), AES_KEY_LEN);
}
/**
 * AES-256-GCM encrypt. Returns `nonce || ciphertext` concatenated as Uint8Array.
 * The 12-byte nonce is prepended so the decryptor can extract it without side-channel.
 */
function aesGcmEncrypt(key, plaintext) {
    const nonce = (0, utils_1.randomBytes)(GCM_NONCE_LEN);
    const stream = (0, aes_1.gcm)(key, nonce);
    const ciphertext = stream.encrypt(plaintext);
    return (0, utils_1.concatBytes)(nonce, ciphertext);
}
/**
 * AES-256-GCM decrypt. Expects `nonce || ciphertext` as produced by aesGcmEncrypt.
 * Throws if authentication tag check fails (tampered ciphertext).
 */
function aesGcmDecrypt(key, data) {
    const nonce = data.slice(0, GCM_NONCE_LEN);
    const ciphertext = data.slice(GCM_NONCE_LEN);
    const stream = (0, aes_1.gcm)(key, nonce);
    return stream.decrypt(ciphertext);
}
/** base64url encode without padding */
function toBase64Url(bytes) {
    return Buffer.from(bytes)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
/** base64url decode */
function fromBase64Url(str) {
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
function encryptRequest(plaintext, sdkEphPrivKeyHex, localidPublicKeyHex) {
    const pubKey = localidPublicKeyHex ?? devKeys_1.LOCALID_DEV_PUBLIC_KEY;
    const sharedSecret = (0, keyPair_1.computeSharedSecret)(sdkEphPrivKeyHex, pubKey);
    const key = deriveKey(sharedSecret, 'localid-request-v1');
    const encrypted = aesGcmEncrypt(key, (0, utils_1.utf8ToBytes)(plaintext));
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
function decryptResponse(ciphertextB64, localidEphPubKeyHex, sdkEphPrivKeyHex) {
    const sharedSecret = (0, keyPair_1.computeSharedSecret)(sdkEphPrivKeyHex, localidEphPubKeyHex);
    const key = deriveKey(sharedSecret, 'localid-response-v1');
    const data = fromBase64Url(ciphertextB64);
    const plaintext = aesGcmDecrypt(key, data);
    return new TextDecoder().decode(plaintext);
}
//# sourceMappingURL=encrypt.js.map