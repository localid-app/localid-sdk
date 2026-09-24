import { BackendConfig } from '../types';
import { encryptHttpRequest } from './backendCrypto';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

function sha256Hex(str: string): string {
  return bytesToHex(sha256(utf8ToBytes(str)));
}

function hmacSign(data: string, secret: string): string {
  // Matches backend's createHmac('sha256', secret) — secret is UTF-8 encoded key
  return bytesToHex(hmac(sha256, utf8ToBytes(secret), utf8ToBytes(data)));
}

export class BackendClient {
  private readonly config: BackendConfig;
  private backendPubKey: string | null = null;

  constructor(config: BackendConfig) {
    this.config = config;
  }

  private async getBackendPublicKey(): Promise<string> {
    if (this.backendPubKey) return this.backendPubKey;
    const res = await fetch(`${this.config.url}/public-key`);
    if (!res.ok) throw new Error(`Failed to fetch public key: ${res.status}`);
    const body = await res.json() as { publicKey: string };
    this.backendPubKey = body.publicKey;
    return this.backendPubKey;
  }

  private async postEncrypted(
    path: string,
    body: object,
    timeoutMs = 30000,
  ): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const backendPubKey = await this.getBackendPublicKey();
      const { encryptedBody } = encryptHttpRequest(body, backendPubKey);
      const encryptedBodyStr = JSON.stringify(encryptedBody);
      const timestamp = Date.now().toString();
      const bodyHash = sha256Hex(encryptedBodyStr);
      const signature = hmacSign(
        `${this.config.appId}:${timestamp}:${bodyHash}`,
        this.config.appSecret,
      );

      const res = await fetch(`${this.config.url}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-LocalID-App-Id': this.config.appId,
          'X-LocalID-Timestamp': timestamp,
          'X-LocalID-Signature': signature,
        },
        body: encryptedBodyStr,
        signal: controller.signal,
      });

      if (!res.ok) {
        console.warn(`[localid-sdk] ${path} failed: ${res.status}`);
      }
    } catch (err) {
      console.warn(`[localid-sdk] ${path} error: ${String(err)}`);
    } finally {
      clearTimeout(timer);
    }
  }

  async initiateRequest(requestId: string, requestedFields: string[]): Promise<void> {
    await this.postEncrypted('/requests/initiate', {
      request_id: requestId,
      requested_fields: requestedFields,
    });
  }

  async completeRequest(requestId: string, status: 'completed' | 'failed'): Promise<void> {
    await this.postEncrypted('/requests/complete', {
      request_id: requestId,
      status,
    });
  }

  private async getWithHmac<T>(path: string, timeoutMs = 10000): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const timestamp = Date.now().toString();
      const bodyHash = sha256Hex('{}');
      const signature = hmacSign(
        `${this.config.appId}:${timestamp}:${bodyHash}`,
        this.config.appSecret,
      );
      const res = await fetch(`${this.config.url}${path}`, {
        method: 'GET',
        headers: {
          'X-LocalID-App-Id': this.config.appId,
          'X-LocalID-Timestamp': timestamp,
          'X-LocalID-Signature': signature,
        },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
      try {
        return await res.json() as T;
      } catch {
        throw new Error(`${path} returned non-JSON body (status ${res.status})`);
      }
    } finally {
      clearTimeout(timer);
    }
  }

  async fetchInitKeys(): Promise<{ localidPublicKey: string; signingKey: string }> {
    const result = await this.getWithHmac<{ localidPublicKey: string; signingKey: string }>('/apps/init');
    if (!result.localidPublicKey || !result.signingKey) {
      throw new Error('[localid-sdk] /apps/init response missing localidPublicKey or signingKey');
    }
    return result;
  }
}
