"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAuthUrl = buildAuthUrl;
exports.buildShareUrl = buildShareUrl;
exports.buildAgentAuthUrl = buildAgentAuthUrl;
exports.buildDelegationUrl = buildDelegationUrl;
exports.buildAgeAssertionUrl = buildAgeAssertionUrl;
const keyPair_1 = require("../crypto/keyPair");
const encrypt_1 = require("../crypto/encrypt");
const signing_1 = require("../crypto/signing");
const nonceStore_1 = require("../session/nonceStore");
function generateRequestId() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
/**
 * Build a signed, encrypted localid://auth/v1 deep link.
 * URL format: localid://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 *
 * @param localidPublicKey  Per-app LocalID public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
function buildAuthUrl(appId, returnScheme, userIdentifier, localidPublicKey, signingKey, dynamicFaceAuth) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1,
        type: 'auth',
        appId,
        requestId,
        nonce: (0, nonceStore_1.generateNonce)(),
        ts: Math.floor(Date.now() / 1000),
        returnScheme,
        ...(userIdentifier ? { userIdentifier } : {}),
        ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
    const unsigned = `localid://auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned, signingKey);
    return {
        url: `${unsigned}&s=${sig}`,
        requestId,
        keyPair,
    };
}
/**
 * Build a signed, encrypted localid://share/v1 deep link.
 * URL format: localid://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param localidPublicKey  Per-app LocalID public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
function buildShareUrl(appId, returnScheme, fields, localidPublicKey, signingKey, dynamicFaceAuth) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1,
        type: 'identity',
        appId,
        requestId,
        nonce: (0, nonceStore_1.generateNonce)(),
        ts: Math.floor(Date.now() / 1000),
        returnScheme,
        fields,
        ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
    const unsigned = `localid://share/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned, signingKey);
    return {
        url: `${unsigned}&s=${sig}`,
        requestId,
        keyPair,
    };
}
/** UC1: Build a signed, encrypted localid://agent-auth/v1 deep link. */
function buildAgentAuthUrl(appId, returnScheme, agent, localidPublicKey, signingKey, dynamicFaceAuth) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1, type: 'agent-auth', appId, requestId,
        nonce: (0, nonceStore_1.generateNonce)(), ts: Math.floor(Date.now() / 1000),
        returnScheme, agent,
        ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
    const unsigned = `localid://agent-auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned, signingKey);
    return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}
/** UC2: Build a signed, encrypted localid://delegate/v1 deep link. */
function buildDelegationUrl(appId, returnScheme, delegation, localidPublicKey, signingKey, dynamicFaceAuth) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1, type: 'delegate', appId, requestId,
        nonce: (0, nonceStore_1.generateNonce)(), ts: Math.floor(Date.now() / 1000),
        returnScheme, delegation,
        ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
    const unsigned = `localid://delegate/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned, signingKey);
    return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}
/** UC4: Build a signed, encrypted localid://age-assert/v1 deep link. */
function buildAgeAssertionUrl(appId, returnScheme, minAge, validForSeconds, localidPublicKey, signingKey, dynamicFaceAuth) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1, type: 'age-assert', appId, requestId,
        nonce: (0, nonceStore_1.generateNonce)(), ts: Math.floor(Date.now() / 1000),
        returnScheme, minAge,
        validForSeconds: Math.min(validForSeconds, 86400),
        ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
    const unsigned = `localid://age-assert/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned, signingKey);
    return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}
//# sourceMappingURL=builder.js.map