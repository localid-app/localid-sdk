import { EphemeralKeyPair } from '../crypto/keyPair';
import { SdkAgentAuthRequest, SdkDelegationRequest, IdentityField } from '../types';
export interface BuiltRequest {
    url: string;
    requestId: string;
    keyPair: EphemeralKeyPair;
}
/**
 * Build a signed, encrypted localid://auth/v1 deep link.
 * URL format: localid://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 *
 * @param localidPublicKey  Per-app LocalID public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export declare function buildAuthUrl(appId: string, returnScheme: string, userIdentifier?: string, localidPublicKey?: string, signingKey?: string, dynamicFaceAuth?: boolean): BuiltRequest;
/**
 * Build a signed, encrypted localid://share/v1 deep link.
 * URL format: localid://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param localidPublicKey  Per-app LocalID public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export declare function buildShareUrl(appId: string, returnScheme: string, fields: IdentityField[], localidPublicKey?: string, signingKey?: string, dynamicFaceAuth?: boolean): BuiltRequest;
/** UC1: Build a signed, encrypted localid://agent-auth/v1 deep link. */
export declare function buildAgentAuthUrl(appId: string, returnScheme: string, agent: SdkAgentAuthRequest['agent'], localidPublicKey?: string, signingKey?: string, dynamicFaceAuth?: boolean): BuiltRequest;
/** UC2: Build a signed, encrypted localid://delegate/v1 deep link. */
export declare function buildDelegationUrl(appId: string, returnScheme: string, delegation: SdkDelegationRequest['delegation'], localidPublicKey?: string, signingKey?: string, dynamicFaceAuth?: boolean): BuiltRequest;
/** UC4: Build a signed, encrypted localid://age-assert/v1 deep link. */
export declare function buildAgeAssertionUrl(appId: string, returnScheme: string, minAge: number, validForSeconds: number, localidPublicKey?: string, signingKey?: string, dynamicFaceAuth?: boolean): BuiltRequest;
//# sourceMappingURL=builder.d.ts.map