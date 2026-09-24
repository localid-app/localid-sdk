import { buildAuthUrl, buildShareUrl, buildAgentAuthUrl, buildDelegationUrl, buildAgeAssertionUrl } from './deeplink/builder';
import { parseCallback, PendingEntry } from './deeplink/parser';
import { registerApp, trackEvent, setPlan } from './monetization/stubs';
import { BackendClient } from './utils/backendClient';
import { LocalIDConfig, LocalIDResponse, LocalIDError, IdentityField, SdkAgentAuthRequest, SdkDelegationRequest, DelegationScope, DelegationDecision } from './types';

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
export class LocalIDClient {
  private readonly config: LocalIDConfig;
  private readonly openUrl: OpenUrlFn;
  private readonly backendClient: BackendClient | null;
  private localidPublicKey: string | null = null;
  private signingKey: string | null = null;
  private initializePromise: Promise<void> | null = null;

  private static readonly PENDING_TTL_MS = 5 * 60 * 1000;

  /**
   * Map of requestId → PendingEntry (ephemeral private key + expiry).
   * Held in memory for the lifetime of a pending request.
   * Used by parseCallback to decrypt the matched response.
   * Entries older than PENDING_TTL_MS are pruned on the next login/handleCallback call.
   */
  private readonly pendingRequests = new Map<string, PendingEntry>();

  private successCallbacks: SuccessCallback[] = [];
  private errorCallbacks: ErrorCallback[] = [];

  constructor(config: LocalIDConfig, openUrl: OpenUrlFn) {
    this.config = config;
    this.openUrl = openUrl;
    this.backendClient = config.backend ? new BackendClient(config.backend) : null;
    // TODO(PHASE_2): call registerApp() here after exchanging apiKey for signing credentials
    registerApp(config.appId);
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Fetch per-app cryptographic keys from the backend control plane and store them.
   * Must be called once after construction when a backend config is provided.
   * In dev/test (no backend config), resolves silently.
   * In production (NODE_ENV=production) without backend config, throws.
   */
  async initialize(): Promise<void> {
    if (this.initializePromise) return this.initializePromise;
    this.initializePromise = this._doInitialize();
    return this.initializePromise;
  }

  private async _doInitialize(): Promise<void> {
    if (!this.backendClient) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('[localid-sdk] initialize() requires backend config in production');
      }
      return;
    }
    const { localidPublicKey, signingKey } = await this.backendClient.fetchInitKeys();
    this.localidPublicKey = localidPublicKey;
    this.signingKey = signingKey;
  }

  /** Initiate a login / authentication request against LocalID. */
  login(opts: { userIdentifier?: string; dynamicFaceAuth?: boolean } = {}): void {
    const built = buildAuthUrl(
      this.config.appId,
      this.config.returnScheme,
      opts.userIdentifier,
      this.localidPublicKey ?? undefined,
      this.signingKey ?? undefined,
      opts.dynamicFaceAuth,
    );
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
    });
    trackEvent('auth_request', { appId: this.config.appId });

    if (this.backendClient) {
      void this.backendClient.initiateRequest(built.requestId, []).catch((err: unknown) => {
        this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
      });
    }

    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
    });
  }

  /** UC1: Request one-time human approval for a specific AI agent action. */
  requestAgentAuth(
    agent: SdkAgentAuthRequest['agent'],
    opts: { dynamicFaceAuth?: boolean } = {},
  ): void {
    const built = buildAgentAuthUrl(
      this.config.appId, this.config.returnScheme, agent,
      this.localidPublicKey ?? undefined, this.signingKey ?? undefined,
      opts.dynamicFaceAuth,
    );
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
    });
    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
    });
  }

  /** UC2: Request standing delegation for a class of actions with a time limit. */
  requestDelegation(
    delegation: SdkDelegationRequest['delegation'],
    opts: { dynamicFaceAuth?: boolean } = {},
  ): void {
    const built = buildDelegationUrl(
      this.config.appId, this.config.returnScheme, delegation,
      this.localidPublicKey ?? undefined, this.signingKey ?? undefined,
      opts.dynamicFaceAuth,
    );
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
    });
    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
    });
  }

  /** UC4: Request a self-contained signed age assertion. DOB is never shared — only yes/no above threshold. */
  requestAgeAssertion(
    minAge: number,
    validForSeconds: number = 3600,
    opts: { dynamicFaceAuth?: boolean } = {},
  ): void {
    const built = buildAgeAssertionUrl(
      this.config.appId, this.config.returnScheme, minAge, validForSeconds,
      this.localidPublicKey ?? undefined, this.signingKey ?? undefined,
      opts.dynamicFaceAuth,
    );
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
    });
    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
    });
  }

  /**
   * UC2: Ask the LocalID backend whether the agent may act under a delegation.
   * Call this before EVERY action, including repeats: it is what makes a
   * revocation or expiry take effect immediately. Act only on `allowed: true`.
   * Rejects if no backend is configured or the backend could not be reached;
   * treat that as "not allowed".
   */
  async checkDelegation(
    delegationId: string,
    action: { scope: DelegationScope; amount?: number },
  ): Promise<DelegationDecision> {
    if (!this.backendClient) {
      throw new Error('[localid-sdk] checkDelegation requires the `backend` config option');
    }
    return this.backendClient.checkDelegation(delegationId, action);
  }

  /** Initiate an identity attribute request against LocalID. */
  requestIdentity(fields: IdentityField[], opts: { dynamicFaceAuth?: boolean } = {}): void {
    const built = buildShareUrl(
      this.config.appId,
      this.config.returnScheme,
      fields,
      this.localidPublicKey ?? undefined,
      this.signingKey ?? undefined,
      opts.dynamicFaceAuth,
    );
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
    });
    trackEvent('identity_request', { appId: this.config.appId, fields });

    if (this.backendClient) {
      void this.backendClient.initiateRequest(built.requestId, fields).catch((err: unknown) => {
        this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
      });
    }

    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
    });
  }

  /**
   * Call this from your app's deep link handler whenever a URL arrives.
   * Returns true if the URL was an localid-callback handled by this SDK;
   * returns false if the URL is unrelated (let your app handle it normally).
   */
  handleCallback(url: string): boolean {
    if (!url.includes('localid-callback')) return false;
    this.prunePendingRequests();
    const result = parseCallback(url, this.pendingRequests, this.signingKey ?? undefined);
    if (result.ok) {
      trackEvent('callback_success', { appId: this.config.appId, requestId: result.response.requestId });
      if (this.backendClient) {
        void this.backendClient.completeRequest(result.response.requestId, 'completed');
      }
      this.emitSuccess(result.response);
    } else {
      trackEvent('callback_error', { appId: this.config.appId, code: result.error.code });
      const requestId = (result as { requestId?: string }).requestId ?? '';
      if (this.backendClient && requestId) {
        void this.backendClient.completeRequest(requestId, 'failed');
      }
      this.emitError(result.error);
    }
    return true;
  }

  /**
   * Register a success handler. Returns an unsubscribe function.
   * Multiple handlers are supported.
   */
  onSuccess(cb: SuccessCallback): () => void {
    this.successCallbacks.push(cb);
    return () => {
      this.successCallbacks = this.successCallbacks.filter(fn => fn !== cb);
    };
  }

  /**
   * Register an error handler. Returns an unsubscribe function.
   * Multiple handlers are supported.
   */
  onError(cb: ErrorCallback): () => void {
    this.errorCallbacks.push(cb);
    return () => {
      this.errorCallbacks = this.errorCallbacks.filter(fn => fn !== cb);
    };
  }

  // ── Monetization stubs ──────────────────────────────────────────────────────

  /**
   * Register this app with the LocalID control plane.
   * TODO(PHASE_2): pass apiKey; exchange for per-app signing credentials
   */
  registerApp(): void {
    registerApp(this.config.appId);
  }

  /** Track a usage event for billing metering. No-op in Phase 1. */
  trackEvent(type: string, payload?: Record<string, unknown>): void {
    trackEvent(type, payload);
  }

  /**
   * Set the billing plan for this app.
   * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
   */
  setPlan(planId: string): void {
    setPlan(planId);
  }

  // ── Private ─────────────────────────────────────────────────────────────────

  private prunePendingRequests(): void {
    const now = Date.now();
    for (const [id, entry] of this.pendingRequests) {
      if (now > entry.expiresAt) this.pendingRequests.delete(id);
    }
  }

  private emitSuccess(response: LocalIDResponse): void {
    for (const cb of this.successCallbacks) cb(response);
  }

  private emitError(error: LocalIDError): void {
    for (const cb of this.errorCallbacks) cb(error);
  }
}
