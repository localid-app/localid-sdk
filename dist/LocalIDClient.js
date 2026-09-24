"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalIDClient = void 0;
const builder_1 = require("./deeplink/builder");
const parser_1 = require("./deeplink/parser");
const stubs_1 = require("./monetization/stubs");
const backendClient_1 = require("./utils/backendClient");
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
class LocalIDClient {
    constructor(config, openUrl) {
        this.localidPublicKey = null;
        this.signingKey = null;
        this.initializePromise = null;
        /**
         * Map of requestId → PendingEntry (ephemeral private key + expiry).
         * Held in memory for the lifetime of a pending request.
         * Used by parseCallback to decrypt the matched response.
         * Entries older than PENDING_TTL_MS are pruned on the next login/handleCallback call.
         */
        this.pendingRequests = new Map();
        this.successCallbacks = [];
        this.errorCallbacks = [];
        this.config = config;
        this.openUrl = openUrl;
        this.backendClient = config.backend ? new backendClient_1.BackendClient(config.backend) : null;
        // TODO(PHASE_2): call registerApp() here after exchanging apiKey for signing credentials
        (0, stubs_1.registerApp)(config.appId);
    }
    // ── Public API ──────────────────────────────────────────────────────────────
    /**
     * Fetch per-app cryptographic keys from the backend control plane and store them.
     * Must be called once after construction when a backend config is provided.
     * In dev/test (no backend config), resolves silently.
     * In production (NODE_ENV=production) without backend config, throws.
     */
    async initialize() {
        if (this.initializePromise)
            return this.initializePromise;
        this.initializePromise = this._doInitialize();
        return this.initializePromise;
    }
    async _doInitialize() {
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
    login(opts = {}) {
        const built = (0, builder_1.buildAuthUrl)(this.config.appId, this.config.returnScheme, opts.userIdentifier, this.localidPublicKey ?? undefined, this.signingKey ?? undefined, opts.dynamicFaceAuth);
        this.prunePendingRequests();
        this.pendingRequests.set(built.requestId, {
            privateKeyHex: built.keyPair.privateKeyHex,
            expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
        });
        (0, stubs_1.trackEvent)('auth_request', { appId: this.config.appId });
        if (this.backendClient) {
            void this.backendClient.initiateRequest(built.requestId, []).catch((err) => {
                this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
            });
        }
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
        });
    }
    /** UC1: Request one-time human approval for a specific AI agent action. */
    requestAgentAuth(agent, opts = {}) {
        const built = (0, builder_1.buildAgentAuthUrl)(this.config.appId, this.config.returnScheme, agent, this.localidPublicKey ?? undefined, this.signingKey ?? undefined, opts.dynamicFaceAuth);
        this.prunePendingRequests();
        this.pendingRequests.set(built.requestId, {
            privateKeyHex: built.keyPair.privateKeyHex,
            expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
        });
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
        });
    }
    /** UC2: Request standing delegation for a class of actions with a time limit. */
    requestDelegation(delegation, opts = {}) {
        const built = (0, builder_1.buildDelegationUrl)(this.config.appId, this.config.returnScheme, delegation, this.localidPublicKey ?? undefined, this.signingKey ?? undefined, opts.dynamicFaceAuth);
        this.prunePendingRequests();
        this.pendingRequests.set(built.requestId, {
            privateKeyHex: built.keyPair.privateKeyHex,
            expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
        });
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
        });
    }
    /** UC4: Request a self-contained signed age assertion. DOB is never shared — only yes/no above threshold. */
    requestAgeAssertion(minAge, validForSeconds = 3600, opts = {}) {
        const built = (0, builder_1.buildAgeAssertionUrl)(this.config.appId, this.config.returnScheme, minAge, validForSeconds, this.localidPublicKey ?? undefined, this.signingKey ?? undefined, opts.dynamicFaceAuth);
        this.prunePendingRequests();
        this.pendingRequests.set(built.requestId, {
            privateKeyHex: built.keyPair.privateKeyHex,
            expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
        });
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
        });
    }
    /** Initiate an identity attribute request against LocalID. */
    requestIdentity(fields, opts = {}) {
        const built = (0, builder_1.buildShareUrl)(this.config.appId, this.config.returnScheme, fields, this.localidPublicKey ?? undefined, this.signingKey ?? undefined, opts.dynamicFaceAuth);
        this.prunePendingRequests();
        this.pendingRequests.set(built.requestId, {
            privateKeyHex: built.keyPair.privateKeyHex,
            expiresAt: Date.now() + LocalIDClient.PENDING_TTL_MS,
        });
        (0, stubs_1.trackEvent)('identity_request', { appId: this.config.appId, fields });
        if (this.backendClient) {
            void this.backendClient.initiateRequest(built.requestId, fields).catch((err) => {
                this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
            });
        }
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open LocalID: ${String(err)}` });
        });
    }
    /**
     * Call this from your app's deep link handler whenever a URL arrives.
     * Returns true if the URL was an localid-callback handled by this SDK;
     * returns false if the URL is unrelated (let your app handle it normally).
     */
    handleCallback(url) {
        if (!url.includes('localid-callback'))
            return false;
        this.prunePendingRequests();
        const result = (0, parser_1.parseCallback)(url, this.pendingRequests, this.signingKey ?? undefined);
        if (result.ok) {
            (0, stubs_1.trackEvent)('callback_success', { appId: this.config.appId, requestId: result.response.requestId });
            if (this.backendClient) {
                void this.backendClient.completeRequest(result.response.requestId, 'completed');
            }
            this.emitSuccess(result.response);
        }
        else {
            (0, stubs_1.trackEvent)('callback_error', { appId: this.config.appId, code: result.error.code });
            const requestId = result.requestId ?? '';
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
    onSuccess(cb) {
        this.successCallbacks.push(cb);
        return () => {
            this.successCallbacks = this.successCallbacks.filter(fn => fn !== cb);
        };
    }
    /**
     * Register an error handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onError(cb) {
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
    registerApp() {
        (0, stubs_1.registerApp)(this.config.appId);
    }
    /** Track a usage event for billing metering. No-op in Phase 1. */
    trackEvent(type, payload) {
        (0, stubs_1.trackEvent)(type, payload);
    }
    /**
     * Set the billing plan for this app.
     * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
     */
    setPlan(planId) {
        (0, stubs_1.setPlan)(planId);
    }
    // ── Private ─────────────────────────────────────────────────────────────────
    prunePendingRequests() {
        const now = Date.now();
        for (const [id, entry] of this.pendingRequests) {
            if (now > entry.expiresAt)
                this.pendingRequests.delete(id);
        }
    }
    emitSuccess(response) {
        for (const cb of this.successCallbacks)
            cb(response);
    }
    emitError(error) {
        for (const cb of this.errorCallbacks)
            cb(error);
    }
}
exports.LocalIDClient = LocalIDClient;
LocalIDClient.PENDING_TTL_MS = 5 * 60 * 1000;
//# sourceMappingURL=LocalIDClient.js.map