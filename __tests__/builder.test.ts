import { buildAuthUrl, buildShareUrl } from '../src/deeplink/builder';

describe('Builder: buildAuthUrl', () => {
  it('produces a valid localid://auth/v1 URL with pk, c, and s params', () => {
    const result = buildAuthUrl('com.test', 'testapp', 'user@example.com');
    expect(result.url).toMatch(/^localid:\/\/auth\/v1\?pk=[^&]+&c=[^&]+&s=[a-f0-9]{64}$/);
    expect(result.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.keyPair.privateKeyHex).toHaveLength(64);
    expect(result.keyPair.publicKeyHex).toHaveLength(64);
  });

  it('pk param matches the keypair public key', () => {
    const result = buildAuthUrl('com.test', 'testapp');
    const pkMatch = result.url.match(/pk=([^&]+)/);
    expect(pkMatch?.[1]).toEqual(result.keyPair.publicKeyHex);
  });

  it('generates different requestIds on each call', () => {
    const r1 = buildAuthUrl('com.test', 'testapp');
    const r2 = buildAuthUrl('com.test', 'testapp');
    expect(r1.requestId).not.toEqual(r2.requestId);
  });

  it('generates different URLs on each call (random nonce + ephemeral key)', () => {
    const r1 = buildAuthUrl('com.test', 'testapp', 'user@example.com');
    const r2 = buildAuthUrl('com.test', 'testapp', 'user@example.com');
    expect(r1.url).not.toEqual(r2.url);
  });
});

describe('Builder: buildShareUrl', () => {
  it('produces a valid localid://share/v1 URL', () => {
    const result = buildShareUrl('com.test', 'testapp', ['full_name', 'dob']);
    expect(result.url).toMatch(/^localid:\/\/share\/v1\?pk=[^&]+&c=[^&]+&s=[a-f0-9]{64}$/);
  });

  it('does not include fields in plain URL params (fields are encrypted)', () => {
    const result = buildShareUrl('com.test', 'testapp', ['full_name', 'dob']);
    expect(result.url).not.toContain('full_name');
    expect(result.url).not.toContain('dob');
  });
});
