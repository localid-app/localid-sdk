/**
 * Monetization stubs — Phase 1 no-ops.
 *
 * TODO(PHASE_2): Implement registerApp to POST to the LocalID control plane:
 *   POST /v1/apps/register { appId, apiKey } → returns { planId, signingKey, localidPublicKey }
 *   The returned localidPublicKey replaces LOCALID_DEV_PUBLIC_KEY in devKeys.ts.
 *
 * TODO(PHASE_2): Implement trackEvent to POST usage events for billing metering:
 *   POST /v1/events { appId, type, payload, ts }
 *
 * TODO(PHASE_2): Implement setPlan to upgrade/downgrade the app's billing plan:
 *   POST /v1/apps/{appId}/plan { planId }
 */
export declare function registerApp(_appId?: string): void;
export declare function trackEvent(_type: string, _payload?: Record<string, unknown>): void;
export declare function setPlan(_planId: string): void;
//# sourceMappingURL=stubs.d.ts.map