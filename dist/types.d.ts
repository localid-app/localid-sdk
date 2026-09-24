/** Scopes for a one-time agent action authorization (UC1). */
export type AgentScope = 'purchase' | 'signup' | 'data-access' | 'contract' | 'custom';
/** Capabilities an AI agent can be delegated (UC2). */
export type DelegationScope = 'purchase' | 'signup' | 'age-verify' | 'identity-share' | 'authorize';
/** Supported identity fields that can be requested via requestIdentity(). */
export type IdentityField = 'full_name' | 'firstName' | 'lastName' | 'dob' | 'age_over_18' | 'document_number' | 'selfie_photo' | 'email' | 'phone' | 'street' | 'city' | 'state' | 'zipCode';
export interface SdkAuthRequest {
    v: 1;
    type: 'auth';
    appId: string;
    requestId: string;
    nonce: string;
    ts: number;
    returnScheme: string;
    userIdentifier?: string;
    /** When true, LocalID captures a live selfie and matches it against the enrolled face before approving. */
    dynamicFaceAuth?: boolean;
}
export interface SdkIdentityRequest {
    v: 1;
    type: 'identity';
    appId: string;
    requestId: string;
    nonce: string;
    ts: number;
    returnScheme: string;
    fields: IdentityField[];
    /** When true, LocalID captures a live selfie and matches it against the enrolled face before sharing. */
    dynamicFaceAuth?: boolean;
    /** UC3: agent context — shown in the consent UI so the user understands why the agent needs these attributes. */
    agent?: {
        name: string;
        purpose: string;
    };
}
/** UC1: Request one-time human approval for a specific AI agent action. */
export interface SdkAgentAuthRequest {
    v: 1;
    type: 'agent-auth';
    appId: string;
    requestId: string;
    nonce: string;
    ts: number;
    returnScheme: string;
    agent: {
        name: string;
        action: string;
        scope: AgentScope;
        metadata?: Record<string, string>;
    };
    dynamicFaceAuth?: boolean;
}
/** UC2: Request standing delegation for a class of actions with a time limit. */
export interface SdkDelegationRequest {
    v: 1;
    type: 'delegate';
    appId: string;
    requestId: string;
    nonce: string;
    ts: number;
    returnScheme: string;
    delegation: {
        agentName: string;
        scopes: DelegationScope[];
        maxAmountPerAction?: number;
        expiresInSeconds: number;
        description: string;
    };
    dynamicFaceAuth?: boolean;
}
/** UC4: Request a self-contained, signed age assertion (DOB is NOT shared — only yes/no). */
export interface SdkAgeAssertionRequest {
    v: 1;
    type: 'age-assert';
    appId: string;
    requestId: string;
    nonce: string;
    ts: number;
    returnScheme: string;
    minAge: number;
    validForSeconds: number;
    dynamicFaceAuth?: boolean;
}
export type SdkRequest = SdkAuthRequest | SdkIdentityRequest | SdkAgentAuthRequest | SdkDelegationRequest | SdkAgeAssertionRequest;
export interface SdkResponse {
    v: 1;
    type: 'response';
    requestId: string;
    nonce: string;
    ts: number;
    status: 'success' | 'denied' | 'error';
    data?: Record<string, unknown>;
    message?: string;
    /** Set by LocalID at the top level when dynamic face auth ran. */
    dynamicFaceAuthVerified?: boolean;
}
export interface LocalIDResponse {
    status: 'success' | 'denied';
    data?: Record<string, unknown>;
    requestId: string;
    ts: number;
    /** Present when dynamicFaceAuth was requested. True = live face matched enrolled embedding. */
    dynamicFaceAuthVerified?: boolean;
    agentActionApproved?: boolean;
    approvedAction?: string;
    approvedScope?: string;
    approvalExpiresAt?: number;
    delegationGranted?: boolean;
    delegationId?: string;
    grantedScopes?: DelegationScope[];
    delegationExpiresAt?: number;
    ageAssertionGranted?: boolean;
    isAboveThreshold?: boolean;
    ageThreshold?: number;
    assertionExpiresAt?: number;
}
/** Why the backend refused an action under a delegation. */
export type DelegationDenyReason = 'not_found' | 'revoked' | 'expired' | 'scope_not_granted' | 'amount_required' | 'amount_exceeds_cap';
/** Result of checkDelegation(). Act only when `allowed` is true. */
export type DelegationDecision = {
    allowed: true;
    expiresAt: number;
} | {
    allowed: false;
    reason: DelegationDenyReason;
};
export interface LocalIDError {
    code: 'INVALID_SIGNATURE' | 'DECRYPTION_FAILED' | 'REPLAY_DETECTED' | 'EXPIRED' | 'REQUEST_ID_MISMATCH' | 'CANCELLED' | 'TIMEOUT' | 'FACE_NOT_ENROLLED' | 'FACE_VERIFICATION_FAILED' | 'AGENT_ACTION_DENIED' | 'DELEGATION_DENIED' | 'AGE_REQUIREMENT_NOT_MET' | 'DELEGATION_UNAVAILABLE' | 'UNKNOWN';
    message: string;
}
export interface LocalIDConfig {
    appId: string;
    returnScheme: string;
    backend?: BackendConfig;
}
/**
 * Configuration for the localid-backend control plane.
 * appId and appSecret come from POST /apps/register.
 * Note: BackendConfig.appId is the UUID from the control plane,
 * distinct from LocalIDConfig.appId (the mobile app identifier).
 */
export interface BackendConfig {
    url: string;
    appId: string;
    appSecret: string;
}
//# sourceMappingURL=types.d.ts.map