import { sign, verify } from '../src/crypto/signing';

describe('Signing: HMAC-SHA256', () => {
  it('sign returns a non-empty hex string', () => {
    const sig = sign('hello world');
    expect(typeof sig).toBe('string');
    expect(sig).toHaveLength(64); // 32-byte hex
  });

  it('verify accepts a valid signature', () => {
    const msg = 'localid://auth/v1?pk=abc123&c=def456';
    const sig = sign(msg);
    expect(verify(msg, sig)).toBe(true);
  });

  it('verify rejects a tampered message', () => {
    const msg = 'localid://auth/v1?pk=abc123&c=def456';
    const sig = sign(msg);
    expect(verify('localid://auth/v1?pk=abc123&c=TAMPERED', sig)).toBe(false);
  });

  it('verify rejects a forged signature', () => {
    const msg = 'localid://auth/v1?pk=abc123&c=def456';
    const fakeSig = 'a'.repeat(64);
    expect(verify(msg, fakeSig)).toBe(false);
  });

  it('verify rejects an invalid hex signature', () => {
    const msg = 'some message';
    expect(verify(msg, 'not-hex')).toBe(false);
  });

  it('two different messages produce different signatures', () => {
    expect(sign('msg1')).not.toEqual(sign('msg2'));
  });

  it('same message always produces same signature (deterministic)', () => {
    const msg = 'deterministic test';
    expect(sign(msg)).toEqual(sign(msg));
  });
});
