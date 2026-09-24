export { LocalIDClient } from './LocalIDClient';
export type { LocalIDConfig, BackendConfig, LocalIDResponse, LocalIDError, IdentityField, AgentScope, DelegationScope, SdkAuthRequest, SdkIdentityRequest, SdkAgentAuthRequest, SdkDelegationRequest, SdkAgeAssertionRequest, SdkRequest, SdkResponse, } from './types';
export { generateEphemeralKeyPair, computeSharedSecret } from './crypto/keyPair';
export { toBase64Url, fromBase64Url } from './crypto/encrypt';
export { sign, verify } from './crypto/signing';
export { generateNonce, addNonce, hasNonce } from './session/nonceStore';
export { buildAuthUrl, buildShareUrl, buildAgentAuthUrl, buildDelegationUrl, buildAgeAssertionUrl } from './deeplink/builder';
export { parseCallback } from './deeplink/parser';
export type { PendingEntry } from './deeplink/parser';
//# sourceMappingURL=index.d.ts.map