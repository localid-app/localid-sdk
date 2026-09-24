export { LocalIDClient } from './LocalIDClient';
export type {
  LocalIDConfig,
  BackendConfig,
  LocalIDResponse,
  LocalIDError,
  IdentityField,
  AgentScope,
  DelegationScope,
  DelegationDecision,
  DelegationDenyReason,
  SdkAuthRequest,
  SdkIdentityRequest,
  SdkAgentAuthRequest,
  SdkDelegationRequest,
  SdkAgeAssertionRequest,
  SdkRequest,
  SdkResponse,
} from './types';

// Crypto utilities needed by the LocalID host app (re-exported for reuse)
export { generateEphemeralKeyPair, computeSharedSecret } from './crypto/keyPair';
export { toBase64Url, fromBase64Url } from './crypto/encrypt';
export { sign, verify } from './crypto/signing';
export { generateNonce, addNonce, hasNonce } from './session/nonceStore';

// Deep link helpers (for testing/advanced use)
export { buildAuthUrl, buildShareUrl, buildAgentAuthUrl, buildDelegationUrl, buildAgeAssertionUrl } from './deeplink/builder';
export { parseCallback } from './deeplink/parser';
export type { PendingEntry } from './deeplink/parser';
