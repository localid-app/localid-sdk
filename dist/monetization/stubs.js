"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerApp = registerApp;
exports.trackEvent = trackEvent;
exports.setPlan = setPlan;
function registerApp(_appId) {
    // TODO(PHASE_2): call control plane to register app and exchange API key for signing key
}
function trackEvent(_type, _payload) {
    // TODO(PHASE_2): send usage event to billing backend
}
function setPlan(_planId) {
    // TODO(PHASE_2): call control plane to set billing plan
}
//# sourceMappingURL=stubs.js.map