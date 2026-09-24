/** Scopes for a one-time agent action authorization (UC1). */
export type AgentScope = 'purchase' | 'signup' | 'data-access' | 'contract' | 'custom';

/** Capabilities an AI agent can be delegated (UC2). */
export type DelegationScope =
  | 'purchase'        // make purchases up to maxAmountPerAction
  | 'signup'          // sign up for services using the user's identity
  | 'age-verify'      // prove the user meets age requirements
  | 'identity-share'  // share specific identity attributes
  | 'authorize';      // trigger per-action HITL approvals from the user

/** Supported identity fields that can be requested via requestIdentity(). */
export type IdentityField =
  | 'full_name'
  | 'firstName'
  | 'lastName'
  | 'dob'
  | 'age_over_18'
  | 'document_number'
  | 'selfie_photo'
  | 'email'
  | 'phone'
  | 'street'
  | 'city'
  | 'state'
  | 'zipCode';

// ── Request schemas (encrypted inside the c= URL param) ──────────────────────

export interface SdkAuthRequest {
  v: 1;
  type: 'auth';
  appId: string;
  requestId: string;   // UUID v4 — correlates request to response
  nonce: string;       // 32-byte hex random — replay prevention
  ts: number;          // unix seconds
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
  agent?: { name: string; purpose: string };
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
    name: string;               // e.g. "Shopping AI"
    action: string;             // human-readable: "Purchase MacBook Pro for $2,499"
    scope: AgentScope;
    metadata?: Record<string, string>; // e.g. { amount: '2499', currency: '$', merchant: 'Apple' }
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
    maxAmountPerAction?: number;  // spending cap in USD
    expiresInSeconds: number;
    description: string;          // e.g. "Book rental cars on my behalf"
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
  minAge: number;          // e.g. 18 or 21
  validForSeconds: number; // assertion TTL; LocalID caps at 86400 (24h)
  dynamicFaceAuth?: boolean;
}

export type SdkRequest =
  | SdkAuthRequest
  | SdkIdentityRequest
  | SdkAgentAuthRequest
  | SdkDelegationRequest
  | SdkAgeAssertionRequest;

// ── Response schema (encrypted inside the c= callback param) ─────────────────

export interface SdkResponse {
  v: 1;
  type: 'response';
  requestId: string;   // must match the original request requestId
  nonce: string;
  ts: number;
  status: 'success' | 'denied' | 'error';
  data?: Record<string, unknown>;
  message?: string;
  /** Set by LocalID at the top level when dynamic face auth ran. */
  dynamicFaceAuthVerified?: boolean;
}

// ── SDK public types ──────────────────────────────────────────────────────────

export interface LocalIDResponse {
  status: 'success' | 'denied';
  data?: Record<string, unknown>;
  requestId: string;
  ts: number;
  /** Present when dynamicFaceAuth was requested. True = live face matched enrolled embedding. */
  dynamicFaceAuthVerified?: boolean;

  // UC1 — agent action authorization
  agentActionApproved?: boolean;
  approvedAction?: string;
  approvedScope?: string;
  approvalExpiresAt?: number;      // unix seconds

  // UC2 — delegation grant
  delegationGranted?: boolean;
  delegationId?: string;
  grantedScopes?: DelegationScope[];
  delegationExpiresAt?: number;    // unix seconds

  // UC4 — age assertion (DOB never shared; only yes/no above threshold)
  ageAssertionGranted?: boolean;
  isAboveThreshold?: boolean;
  ageThreshold?: number;
  assertionExpiresAt?: number;     // unix seconds
}

export interface LocalIDError {
  code:
    | 'INVALID_SIGNATURE'
    | 'DECRYPTION_FAILED'
    | 'REPLAY_DETECTED'
    | 'EXPIRED'
    | 'REQUEST_ID_MISMATCH'
    | 'CANCELLED'
    | 'TIMEOUT'
    | 'FACE_NOT_ENROLLED'
    | 'FACE_VERIFICATION_FAILED'
    | 'AGENT_ACTION_DENIED'        // UC1: user denied the agent action
    | 'DELEGATION_DENIED'          // UC2: user denied the delegation request
    | 'AGE_REQUIREMENT_NOT_MET'    // UC4: enrolled DOB does not meet minAge
    | 'UNKNOWN';
  message: string;
}

export interface LocalIDConfig {
  appId: string;
  returnScheme: string; // URL scheme your app handles, e.g. "driveiq"
  backend?: BackendConfig; // optional; if absent, SDK works as today (pure deep links)
}

// ── Backend control plane config ─────────────────────────────────────────────

/**
 * Configuration for the localid-backend control plane.
 * appId and appSecret come from POST /apps/register.
 * Note: BackendConfig.appId is the UUID from the control plane,
 * distinct from LocalIDConfig.appId (the mobile app identifier).
 */
export interface BackendConfig {
  url: string;       // e.g. "http://localhost:3000"
  appId: string;     // UUID from POST /apps/register
  appSecret: string; // hex secret — HMAC signing key
}
