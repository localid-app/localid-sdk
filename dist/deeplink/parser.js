"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCallback = parseCallback;
const signing_1 = require("../crypto/signing");
const encrypt_1 = require("../crypto/encrypt");
const nonceStore_1 = require("../session/nonceStore");
const MAX_AGE_SECONDS = 300; // 5 minutes
/**
 * Parse and validate an incoming localid-callback deep link URL.
 * Expected format: {scheme}://localid-callback?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param url  The raw deep link URL received by the caller app
 * @param pendingRequests  Map of requestId → sdkEphemeralPrivKeyHex (held by LocalIDClient)
 * @param signingKey  Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
function parseCallback(url, pendingRequests, signingKey) {
    try {
        if (!url.includes('localid-callback')) {
            return { ok: false, error: { code: 'UNKNOWN', message: 'Not an localid callback URL' } };
        }
        const queryStart = url.indexOf('?');
        if (queryStart === -1) {
            return { ok: false, error: { code: 'UNKNOWN', message: 'Missing query params' } };
        }
        const params = parseParams(url.slice(queryStart + 1));
        // Error callback format: ?error=...&s=... (no pk/c — sent by LocalID for rate-limit etc.)
        if (params['error'] && !params['pk']) {
            const unsigned = url.slice(0, url.lastIndexOf('&s='));
            const s = params['s'] ?? '';
            if (!(0, signing_1.verify)(unsigned, s, signingKey)) {
                return { ok: false, error: { code: 'INVALID_SIGNATURE', message: 'HMAC verification failed on error callback' } };
            }
            return { ok: false, error: { code: 'UNKNOWN', message: params['error'] } };
        }
        const pk = params['pk'];
        const c = params['c'];
        const s = params['s'];
        if (!pk || !c || !s) {
            return { ok: false, error: { code: 'UNKNOWN', message: 'Missing pk, c, or s param' } };
        }
        // 1. Verify HMAC signature — signs the full URL up to (not including) &s=
        if (!(0, signing_1.verify)(url.slice(0, url.lastIndexOf('&s=')), s, signingKey)) {
            return { ok: false, error: { code: 'INVALID_SIGNATURE', message: 'HMAC verification failed' } };
        }
        // 2. Find a pending request to determine which ephemeral key to use for decryption.
        //    We try each pending request; the matching one will decrypt successfully.
        let decrypted = null;
        let matchedRequestId = null;
        for (const [requestId, entry] of pendingRequests.entries()) {
            try {
                const plaintext = (0, encrypt_1.decryptResponse)(c, pk, entry.privateKeyHex);
                const parsed = JSON.parse(plaintext);
                if (parsed.requestId === requestId) {
                    decrypted = parsed;
                    matchedRequestId = requestId;
                    break;
                }
            }
            catch {
                // Decryption with this key failed — try next
            }
        }
        if (!decrypted || !matchedRequestId) {
            return { ok: false, error: { code: 'DECRYPTION_FAILED', message: 'Could not decrypt response' } };
        }
        // 3. Version check
        if (decrypted.v !== 1) {
            return { ok: false, error: { code: 'UNKNOWN', message: `Unsupported response version: ${decrypted.v}` } };
        }
        // 4. Timestamp check
        const nowSeconds = Math.floor(Date.now() / 1000);
        if (Math.abs(nowSeconds - decrypted.ts) > MAX_AGE_SECONDS) {
            return { ok: false, error: { code: 'EXPIRED', message: 'Response timestamp out of range' } };
        }
        // 5. Replay prevention
        if (!(0, nonceStore_1.addNonce)(decrypted.nonce)) {
            return { ok: false, error: { code: 'REPLAY_DETECTED', message: 'Duplicate nonce detected' } };
        }
        // 6. Remove from pending
        pendingRequests.delete(matchedRequestId);
        if (decrypted.status === 'error') {
            return {
                ok: false,
                error: { code: 'UNKNOWN', message: decrypted.message ?? 'LocalID returned an error' },
            };
        }
        const d = decrypted.data ?? {};
        const bool = (k) => typeof d[k] === 'boolean' ? d[k] : undefined;
        const num = (k) => typeof d[k] === 'number' ? d[k] : undefined;
        const str = (k) => typeof d[k] === 'string' ? d[k] : undefined;
        return {
            ok: true,
            response: {
                status: decrypted.status,
                data: decrypted.data,
                requestId: decrypted.requestId,
                ts: decrypted.ts,
                dynamicFaceAuthVerified: bool('dynamicFaceAuthVerified'),
                // UC1
                agentActionApproved: bool('agentActionApproved'),
                approvedAction: str('approvedAction'),
                approvedScope: str('approvedScope'),
                approvalExpiresAt: num('approvalExpiresAt'),
                // UC2
                delegationGranted: bool('delegationGranted'),
                delegationId: str('delegationId'),
                grantedScopes: Array.isArray(d['grantedScopes']) ? d['grantedScopes'] : undefined,
                delegationExpiresAt: num('delegationExpiresAt'),
                // UC4
                ageAssertionGranted: bool('ageAssertionGranted'),
                isAboveThreshold: bool('isAboveThreshold'),
                ageThreshold: num('ageThreshold'),
                assertionExpiresAt: num('assertionExpiresAt'),
            },
        };
    }
    catch (err) {
        return {
            ok: false,
            error: { code: 'UNKNOWN', message: err instanceof Error ? err.message : 'Unknown parse error' },
        };
    }
}
function parseParams(query) {
    const params = {};
    for (const pair of query.split('&')) {
        const eq = pair.indexOf('=');
        if (eq < 1)
            continue;
        params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
    }
    return params;
}
//# sourceMappingURL=parser.js.map