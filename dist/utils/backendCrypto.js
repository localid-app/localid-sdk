"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptHttpRequest = encryptHttpRequest;
exports.decryptHttpResponse = decryptHttpResponse;
const ed25519_1 = require("@noble/curves/ed25519");
const aes_1 = require("@noble/ciphers/aes");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
function toBase64Url(bytes) {
    return Buffer.from(bytes)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
function fromBase64Url(str) {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (padded.length % 4)) % 4;
    return new Uint8Array(Buffer.from(padded + '='.repeat(pad), 'base64'));
}
/**
 * Encrypt a request body for the backend.
 * Returns the encrypted envelope and the SDK ephemeral private key
 * needed to decrypt the backend's response.
 */
function encryptHttpRequest(body, backendPubKeyHex) {
    const sdkPriv = (0, utils_1.randomBytes)(32);
    const sdkPub = ed25519_1.x25519.getPublicKey(sdkPriv);
    const shared = ed25519_1.x25519.getSharedSecret(sdkPriv, (0, utils_1.hexToBytes)(backendPubKeyHex));
    const key = (0, hkdf_1.hkdf)(sha2_1.sha256, shared, new Uint8Array(0), (0, utils_1.utf8ToBytes)('localid-http-request-v1'), 32);
    const nonce = (0, utils_1.randomBytes)(12);
    const pt = (0, utils_1.utf8ToBytes)(JSON.stringify(body));
    const ct = (0, aes_1.gcm)(key, nonce).encrypt(pt);
    return {
        encryptedBody: { pk: (0, utils_1.bytesToHex)(sdkPub), c: toBase64Url((0, utils_1.concatBytes)(nonce, ct)) },
        sdkEphPrivKeyHex: (0, utils_1.bytesToHex)(sdkPriv),
    };
}
/**
 * Decrypt a response envelope from the backend.
 * Uses the SDK ephemeral private key retained from the matching request.
 */
function decryptHttpResponse(response, sdkEphPrivKeyHex) {
    const shared = ed25519_1.x25519.getSharedSecret((0, utils_1.hexToBytes)(sdkEphPrivKeyHex), (0, utils_1.hexToBytes)(response.pk));
    const key = (0, hkdf_1.hkdf)(sha2_1.sha256, shared, new Uint8Array(0), (0, utils_1.utf8ToBytes)('localid-http-response-v1'), 32);
    const data = fromBase64Url(response.c);
    const nonce = data.slice(0, 12);
    const ct = data.slice(12);
    const pt = (0, aes_1.gcm)(key, nonce).decrypt(ct);
    return JSON.parse(new TextDecoder().decode(pt));
}
//# sourceMappingURL=backendCrypto.js.map