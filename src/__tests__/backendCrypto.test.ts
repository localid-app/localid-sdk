import { x25519 } from '@noble/curves/ed25519';
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';
import { encryptHttpRequest, decryptHttpResponse } from '../utils/backendCrypto';

// Simulate backend decryption (mirrors serverCrypto.decryptHttpRequest)
function backendDecrypt(envelope: { pk: string; c: string }, backendPrivHex: string): unknown {
  const shared = x25519.getSharedSecret(hexToBytes(backendPrivHex), hexToBytes(envelope.pk));
  const key = hkdf(sha256, shared, undefined, utf8ToBytes('localid-http-request-v1'), 32);
  const padded = envelope.c.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - padded.length % 4) % 4;
  const data = new Uint8Array(Buffer.from(padded + '='.repeat(pad), 'base64'));
  const nonce = data.slice(0, 12);
  const ct = data.slice(12);
  const pt = gcm(key, nonce).decrypt(ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// Simulate backend encryption (mirrors serverCrypto.encryptHttpResponse)
function backendEncrypt(data: unknown, sdkEphPubHex: string): { pk: string; c: string } {
  const respPriv = randomBytes(32);
  const respPub = x25519.getPublicKey(respPriv);
  const shared = x25519.getSharedSecret(respPriv, hexToBytes(sdkEphPubHex));
  const key = hkdf(sha256, shared, undefined, utf8ToBytes('localid-http-response-v1'), 32);
  const nonce = randomBytes(12);
  const pt = utf8ToBytes(JSON.stringify(data));
  const ct = gcm(key, nonce).encrypt(pt);
  const c = Buffer.from(concatBytes(nonce, ct)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return { pk: bytesToHex(respPub), c };
}

const BACKEND_PRIV = '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3';
const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';

describe('encryptHttpRequest', () => {
  it('returns { encryptedBody: { pk, c }, sdkEphPrivKeyHex }', () => {
    const body = { request_id: 'abc', requested_fields: [] };
    const result = encryptHttpRequest(body, BACKEND_PUB);

    expect(result.encryptedBody.pk).toHaveLength(64);
    expect(typeof result.encryptedBody.c).toBe('string');
    expect(result.sdkEphPrivKeyHex).toHaveLength(64);
  });

  it('produces ciphertext the backend can decrypt', () => {
    const body = { request_id: 'test-123', requested_fields: ['name'] };
    const { encryptedBody } = encryptHttpRequest(body, BACKEND_PUB);

    const decrypted = backendDecrypt(encryptedBody, BACKEND_PRIV);
    expect(decrypted).toEqual(body);
  });

  it('generates different sdkEphPrivKeyHex on each call', () => {
    const r1 = encryptHttpRequest({ x: 1 }, BACKEND_PUB);
    const r2 = encryptHttpRequest({ x: 1 }, BACKEND_PUB);
    expect(r1.sdkEphPrivKeyHex).not.toBe(r2.sdkEphPrivKeyHex);
    expect(r1.encryptedBody.pk).not.toBe(r2.encryptedBody.pk);
  });
});

describe('decryptHttpResponse', () => {
  it('decrypts backend-encrypted response', () => {
    const body = { x: 1 };
    const { encryptedBody, sdkEphPrivKeyHex } = encryptHttpRequest(body, BACKEND_PUB);
    const responseEnv = backendEncrypt({ result: 'ok' }, encryptedBody.pk);

    const decrypted = decryptHttpResponse(responseEnv, sdkEphPrivKeyHex);
    expect(decrypted).toEqual({ result: 'ok' });
  });

  it('throws on wrong sdkEphPrivKeyHex', () => {
    const { encryptedBody } = encryptHttpRequest({ x: 1 }, BACKEND_PUB);
    const responseEnv = backendEncrypt({ result: 'ok' }, encryptedBody.pk);
    const wrongPriv = bytesToHex(randomBytes(32));
    expect(() => decryptHttpResponse(responseEnv, wrongPriv)).toThrow();
  });
});
