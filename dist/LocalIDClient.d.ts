import { LocalIDConfig, LocalIDResponse, LocalIDError, IdentityField, SdkAgentAuthRequest, SdkDelegationRequest } from './types';
type SuccessCallback = (response: LocalIDResponse) => void;
type ErrorCallback = (error: LocalIDError) => void;
/** Function that opens a URL. Defaults to React Native's Linking.openURL but injectable for testing. */
export type OpenUrlFn = (url: string) => Promise<void>;
/**
 * LocalIDClient — main entry point for the LocalID SDK.
 *
 * Usage:
 *   import { Linking } from 'react-native';
 *   const sdk = new LocalIDClient({ appId: 'com.myapp', returnScheme: 'myapp' }, Linking.openURL.bind(Linking));
 *   sdk.onSuccess(r => console.log(r.data));
 *   sdk.onError(e => console.error(e.code));
 *   sdk.login({ userIdentifier: 'user@example.com' });
 *
 *   // In your app's deep link handler:
 *   sdk.handleCallback(url);
 */
export declare class LocalIDClient {
    private readonly config;
    private readonly openUrl;
    private readonly backendClient;
    private localidPublicKey;
    private signingKey;
    private initializePromise;
    private static readonly PENDING_TTL_MS;
    /**
     * Map of requestId → PendingEntry (ephemeral private key + expiry).
     * Held in memory for the lifetime of a pending request.
     * Used by parseCallback to decrypt the matched response.
     * Entries older than PENDING_TTL_MS are pruned on the next login/handleCallback call.
     */
    private readonly pendingRequests;
    private successCallbacks;
    private errorCallbacks;
    constructor(config: LocalIDConfig, openUrl: OpenUrlFn);
    /**
     * Fetch per-app cryptographic keys from the backend control plane and store them.
     * Must be called once after construction when a backend config is provided.
     * In dev/test (no backend config), resolves silently.
     * In production (NODE_ENV=production) without backend config, throws.
     */
    initialize(): Promise<void>;
    private _doInitialize;
    /** Initiate a login / authentication request against LocalID. */
    login(opts?: {
        userIdentifier?: string;
        dynamicFaceAuth?: boolean;
    }): void;
    /** UC1: Request one-time human approval for a specific AI agent action. */
    requestAgentAuth(agent: SdkAgentAuthRequest['agent'], opts?: {
        dynamicFaceAuth?: boolean;
    }): void;
    /** UC2: Request standing delegation for a class of actions with a time limit. */
    requestDelegation(delegation: SdkDelegationRequest['delegation'], opts?: {
        dynamicFaceAuth?: boolean;
    }): void;
    /** UC4: Request a self-contained signed age assertion. DOB is never shared — only yes/no above threshold. */
    requestAgeAssertion(minAge: number, validForSeconds?: number, opts?: {
        dynamicFaceAuth?: boolean;
    }): void;
    /** Initiate an identity attribute request against LocalID. */
    requestIdentity(fields: IdentityField[], opts?: {
        dynamicFaceAuth?: boolean;
    }): void;
    /**
     * Call this from your app's deep link handler whenever a URL arrives.
     * Returns true if the URL was an localid-callback handled by this SDK;
     * returns false if the URL is unrelated (let your app handle it normally).
     */
    handleCallback(url: string): boolean;
    /**
     * Register a success handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onSuccess(cb: SuccessCallback): () => void;
    /**
     * Register an error handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onError(cb: ErrorCallback): () => void;
    /**
     * Register this app with the LocalID control plane.
     * TODO(PHASE_2): pass apiKey; exchange for per-app signing credentials
     */
    registerApp(): void;
    /** Track a usage event for billing metering. No-op in Phase 1. */
    trackEvent(type: string, payload?: Record<string, unknown>): void;
    /**
     * Set the billing plan for this app.
     * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
     */
    setPlan(planId: string): void;
    private prunePendingRequests;
    private emitSuccess;
    private emitError;
}
export {};
//# sourceMappingURL=LocalIDClient.d.ts.map