"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ed25519_1 = require("@noble/curves/ed25519");
const aes_1 = require("@noble/ciphers/aes");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
const backendCrypto_1 = require("../utils/backendCrypto");
// Simulate backend decryption (mirrors serverCrypto.decryptHttpRequest)
function backendDecrypt(envelope, backendPrivHex) {
    const shared = ed25519_1.x25519.getSharedSecret((0, utils_1.hexToBytes)(backendPrivHex), (0, utils_1.hexToBytes)(envelope.pk));
    const key = (0, hkdf_1.hkdf)(sha2_1.sha256, shared, undefined, (0, utils_1.utf8ToBytes)('localid-http-request-v1'), 32);
    const padded = envelope.c.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - padded.length % 4) % 4;
    const data = new Uint8Array(Buffer.from(padded + '='.repeat(pad), 'base64'));
    const nonce = data.slice(0, 12);
    const ct = data.slice(12);
    const pt = (0, aes_1.gcm)(key, nonce).decrypt(ct);
    return JSON.parse(new TextDecoder().decode(pt));
}
// Simulate backend encryption (mirrors serverCrypto.encryptHttpResponse)
function backendEncrypt(data, sdkEphPubHex) {
    const respPriv = (0, utils_1.randomBytes)(32);
    const respPub = ed25519_1.x25519.getPublicKey(respPriv);
    const shared = ed25519_1.x25519.getSharedSecret(respPriv, (0, utils_1.hexToBytes)(sdkEphPubHex));
    const key = (0, hkdf_1.hkdf)(sha2_1.sha256, shared, undefined, (0, utils_1.utf8ToBytes)('localid-http-response-v1'), 32);
    const nonce = (0, utils_1.randomBytes)(12);
    const pt = (0, utils_1.utf8ToBytes)(JSON.stringify(data));
    const ct = (0, aes_1.gcm)(key, nonce).encrypt(pt);
    const c = Buffer.from((0, utils_1.concatBytes)(nonce, ct)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return { pk: (0, utils_1.bytesToHex)(respPub), c };
}
const BACKEND_PRIV = '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3';
const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';
describe('encryptHttpRequest', () => {
    it('returns { encryptedBody: { pk, c }, sdkEphPrivKeyHex }', () => {
        const body = { request_id: 'abc', requested_fields: [] };
        const result = (0, backendCrypto_1.encryptHttpRequest)(body, BACKEND_PUB);
        expect(result.encryptedBody.pk).toHaveLength(64);
        expect(typeof result.encryptedBody.c).toBe('string');
        expect(result.sdkEphPrivKeyHex).toHaveLength(64);
    });
    it('produces ciphertext the backend can decrypt', () => {
        const body = { request_id: 'test-123', requested_fields: ['name'] };
        const { encryptedBody } = (0, backendCrypto_1.encryptHttpRequest)(body, BACKEND_PUB);
        const decrypted = backendDecrypt(encryptedBody, BACKEND_PRIV);
        expect(decrypted).toEqual(body);
    });
    it('generates different sdkEphPrivKeyHex on each call', () => {
        const r1 = (0, backendCrypto_1.encryptHttpRequest)({ x: 1 }, BACKEND_PUB);
        const r2 = (0, backendCrypto_1.encryptHttpRequest)({ x: 1 }, BACKEND_PUB);
        expect(r1.sdkEphPrivKeyHex).not.toBe(r2.sdkEphPrivKeyHex);
        expect(r1.encryptedBody.pk).not.toBe(r2.encryptedBody.pk);
    });
});
describe('decryptHttpResponse', () => {
    it('decrypts backend-encrypted response', () => {
        const body = { x: 1 };
        const { encryptedBody, sdkEphPrivKeyHex } = (0, backendCrypto_1.encryptHttpRequest)(body, BACKEND_PUB);
        const responseEnv = backendEncrypt({ result: 'ok' }, encryptedBody.pk);
        const decrypted = (0, backendCrypto_1.decryptHttpResponse)(responseEnv, sdkEphPrivKeyHex);
        expect(decrypted).toEqual({ result: 'ok' });
    });
    it('throws on wrong sdkEphPrivKeyHex', () => {
        const { encryptedBody } = (0, backendCrypto_1.encryptHttpRequest)({ x: 1 }, BACKEND_PUB);
        const responseEnv = backendEncrypt({ result: 'ok' }, encryptedBody.pk);
        const wrongPriv = (0, utils_1.bytesToHex)((0, utils_1.randomBytes)(32));
        expect(() => (0, backendCrypto_1.decryptHttpResponse)(responseEnv, wrongPriv)).toThrow();
    });
});
//# sourceMappingURL=backendCrypto.test.js.map