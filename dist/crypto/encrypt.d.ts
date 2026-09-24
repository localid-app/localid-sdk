/**
 * Derive a 256-bit AES key from an X25519 shared secret using HKDF-SHA256.
 * salt distinguishes request vs. response direction.
 */
declare function deriveKey(sharedSecret: Uint8Array, info: string): Uint8Array;
/**
 * AES-256-GCM encrypt. Returns `nonce || ciphertext` concatenated as Uint8Array.
 * The 12-byte nonce is prepended so the decryptor can extract it without side-channel.
 */
declare function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array;
/**
 * AES-256-GCM decrypt. Expects `nonce || ciphertext` as produced by aesGcmEncrypt.
 * Throws if authentication tag check fails (tampered ciphertext).
 */
declare function aesGcmDecrypt(key: Uint8Array, data: Uint8Array): Uint8Array;
/** base64url encode without padding */
export declare function toBase64Url(bytes: Uint8Array): string;
/** base64url decode */
export declare function fromBase64Url(str: string): Uint8Array;
/**
 * Encrypt a request payload for LocalID.
 * Uses the SDK's ephemeral private key + LocalID's public key for ECDH.
 *
 * @param plaintext  JSON-serialized request object
 * @param sdkEphPrivKeyHex  SDK's ephemeral private key (hex)
 * @param localidPublicKeyHex  LocalID's public key (hex). Omit to use the DEV_ONLY key.
 * @returns base64url-encoded `nonce || ciphertext`
 */
export declare function encryptRequest(plaintext: string, sdkEphPrivKeyHex: string, localidPublicKeyHex?: string): string;
/**
 * Decrypt a response payload from LocalID.
 * Uses the SDK's stored ephemeral private key + LocalID's response ephemeral public key.
 *
 * @param ciphertextB64  base64url-encoded `nonce || ciphertext` from callback c= param
 * @param localidEphPubKeyHex  LocalID's response ephemeral public key from callback pk= param
 * @param sdkEphPrivKeyHex  SDK's ephemeral private key stored from the original request
 */
export declare function decryptResponse(ciphertextB64: string, localidEphPubKeyHex: string, sdkEphPrivKeyHex: string): string;
export { deriveKey, aesGcmEncrypt, aesGcmDecrypt, };
//# sourceMappingURL=encrypt.d.ts.map