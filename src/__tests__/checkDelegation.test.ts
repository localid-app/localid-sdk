import { createHash, createHmac } from 'crypto';
import { BackendClient } from '../utils/backendClient';
import { LocalIDClient } from '../LocalIDClient';

const config = {
  url: 'http://localhost:9999',
  appId: '123e4567-e89b-12d3-a456-426614174000',
  appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
};
const ID = `dlg_${'b'.repeat(32)}`;

describe('checkDelegation', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; });

  const mockFetch = (status: number, body: unknown) => {
    const fn = jest.fn().mockResolvedValue({ status, ok: status < 300, json: () => Promise.resolve(body) });
    global.fetch = fn as unknown as typeof fetch;
    return fn;
  };

  it('signs the request exactly as the backend verifies it', async () => {
    const fn = mockFetch(200, { allowed: true, expiresAt: 2_000_000_000 });
    const decision = await new BackendClient(config).checkDelegation(ID, { scope: 'purchase', amount: 150 });
    expect(decision).toEqual({ allowed: true, expiresAt: 2_000_000_000 });

    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${config.url}/delegations/${ID}/check`);
    const headers = init.headers as Record<string, string>;
    const bodyHash = createHash('sha256').update(init.body as string).digest('hex');
    const expected = createHmac('sha256', config.appSecret)
      .update(`${config.appId}:${headers['X-LocalID-Timestamp']}:${bodyHash}`).digest('hex');
    expect(headers['X-LocalID-Signature']).toBe(expected);
    expect(JSON.parse(init.body as string)).toEqual({ scope: 'purchase', amount: 150 });
  });

  it('returns a denial with its reason', async () => {
    mockFetch(200, { allowed: false, reason: 'revoked' });
    await expect(new BackendClient(config).checkDelegation(ID, { scope: 'purchase' }))
      .resolves.toEqual({ allowed: false, reason: 'revoked' });
  });

  it('rejects when the backend errors, so an outage is never "allowed"', async () => {
    mockFetch(503, { error: 'Service unavailable' });
    await expect(new BackendClient(config).checkDelegation(ID, { scope: 'purchase' })).rejects.toThrow();
  });

  it('rejects on a malformed response', async () => {
    mockFetch(200, { ok: true });
    await expect(new BackendClient(config).checkDelegation(ID, { scope: 'purchase' })).rejects.toThrow();
  });

  it('LocalIDClient requires a backend config', async () => {
    const client = new LocalIDClient({ appId: 'com.example', returnScheme: 'example' }, async () => undefined);
    await expect(client.checkDelegation(ID, { scope: 'purchase' })).rejects.toThrow(/backend/);
  });
});
