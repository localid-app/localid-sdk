"use strict";
/**
 * DEV_ONLY: Hardcoded X25519 public key for LocalID and shared HMAC signing key.
 *
 * These keys are used in Phase 1 for local development and testing.
 *
 * TODO(PHASE_2): Replace LOCALID_DEV_PUBLIC_KEY with a per-app public key fetched
 *   from the LocalID control plane at SDK.initialize(apiKey) time. The backend
 *   will issue and rotate keypairs, invalidating these hardcoded constants.
 *
 * TODO(PHASE_2): Replace DEV_SIGNING_KEY with a per-app HMAC key issued by the
 *   control plane. The SDK will exchange its API key for a session signing key
 *   on first initialize(), eliminating the need for a bundled secret.
 *
 * SECURITY NOTE: These keys provide tamper detection and replay prevention but
 *   NOT true confidentiality since both are statically bundled in the SDK binary.
 *   Real key distribution requires the Phase 2 backend.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEV_SIGNING_KEY = exports.LOCALID_DEV_PUBLIC_KEY = void 0;
/** X25519 public key of LocalID (hex-encoded, 32 bytes). SDK uses this to encrypt requests. */
exports.LOCALID_DEV_PUBLIC_KEY = '142de0d823bff7485f00d58d34290eaf1a1ee214d5f1e7ed643caef869a6f74b';
/** Shared HMAC-SHA256 signing key (hex-encoded, 32 bytes). Prevents URL parameter tampering. */
exports.DEV_SIGNING_KEY = '1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a';
//# sourceMappingURL=devKeys.js.map