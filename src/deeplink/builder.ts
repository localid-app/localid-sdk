import { generateEphemeralKeyPair, EphemeralKeyPair } from '../crypto/keyPair';
import { encryptRequest, toBase64Url } from '../crypto/encrypt';
import { sign } from '../crypto/signing';
import { generateNonce } from '../session/nonceStore';
import { SdkAuthRequest, SdkIdentityRequest, SdkAgentAuthRequest, SdkDelegationRequest, SdkAgeAssertionRequest, IdentityField, AgentScope, DelegationScope } from '../types';

function generateRequestId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6]! & 0x0f) | 0x40; // version 4
  b[8] = (b[8]! & 0x3f) | 0x80; // variant
  const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface BuiltRequest {
  url: string;
  requestId: string;
  keyPair: EphemeralKeyPair; // store privately; needed to decrypt the response
}

/**
 * Build a signed, encrypted localid://auth/v1 deep link.
 * URL format: localid://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 *
 * @param localidPublicKey  Per-app LocalID public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export function buildAuthUrl(
  appId: string,
  returnScheme: string,
  userIdentifier?: string,
  localidPublicKey?: string,
  signingKey?: string,
  dynamicFaceAuth?: boolean,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();

  const request: SdkAuthRequest = {
    v: 1,
    type: 'auth',
    appId,
    requestId,
    nonce: generateNonce(),
    ts: Math.floor(Date.now() / 1000),
    returnScheme,
    ...(userIdentifier ? { userIdentifier } : {}),
    ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
  };

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
  const unsigned = `localid://auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);

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
export function buildShareUrl(
  appId: string,
  returnScheme: string,
  fields: IdentityField[],
  localidPublicKey?: string,
  signingKey?: string,
  dynamicFaceAuth?: boolean,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();

  const request: SdkIdentityRequest = {
    v: 1,
    type: 'identity',
    appId,
    requestId,
    nonce: generateNonce(),
    ts: Math.floor(Date.now() / 1000),
    returnScheme,
    fields,
    ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
  };

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
  const unsigned = `localid://share/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);

  return {
    url: `${unsigned}&s=${sig}`,
    requestId,
    keyPair,
  };
}

/** UC1: Build a signed, encrypted localid://agent-auth/v1 deep link. */
export function buildAgentAuthUrl(
  appId: string,
  returnScheme: string,
  agent: SdkAgentAuthRequest['agent'],
  localidPublicKey?: string,
  signingKey?: string,
  dynamicFaceAuth?: boolean,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();
  const request: SdkAgentAuthRequest = {
    v: 1, type: 'agent-auth', appId, requestId,
    nonce: generateNonce(), ts: Math.floor(Date.now() / 1000),
    returnScheme, agent,
    ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
  };
  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
  const unsigned = `localid://agent-auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);
  return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}

/** UC2: Build a signed, encrypted localid://delegate/v1 deep link. */
export function buildDelegationUrl(
  appId: string,
  returnScheme: string,
  delegation: SdkDelegationRequest['delegation'],
  localidPublicKey?: string,
  signingKey?: string,
  dynamicFaceAuth?: boolean,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();
  const request: SdkDelegationRequest = {
    v: 1, type: 'delegate', appId, requestId,
    nonce: generateNonce(), ts: Math.floor(Date.now() / 1000),
    returnScheme, delegation,
    ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
  };
  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
  const unsigned = `localid://delegate/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);
  return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}

/** UC4: Build a signed, encrypted localid://age-assert/v1 deep link. */
export function buildAgeAssertionUrl(
  appId: string,
  returnScheme: string,
  minAge: number,
  validForSeconds: number,
  localidPublicKey?: string,
  signingKey?: string,
  dynamicFaceAuth?: boolean,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();
  const request: SdkAgeAssertionRequest = {
    v: 1, type: 'age-assert', appId, requestId,
    nonce: generateNonce(), ts: Math.floor(Date.now() / 1000),
    returnScheme, minAge,
    validForSeconds: Math.min(validForSeconds, 86400),
    ...(dynamicFaceAuth ? { dynamicFaceAuth: true } : {}),
  };
  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, localidPublicKey);
  const unsigned = `localid://age-assert/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);
  return { url: `${unsigned}&s=${sig}`, requestId, keyPair };
}
