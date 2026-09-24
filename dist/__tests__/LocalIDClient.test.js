"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const LocalIDClient_1 = require("../../src/LocalIDClient");
const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';
describe('LocalIDClient with backend config', () => {
    const backendConfig = {
        url: 'http://localhost:9999',
        appId: '123e4567-e89b-12d3-a456-426614174000',
        appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
    };
    let mockOpenUrl;
    let client;
    let originalFetch;
    beforeEach(() => {
        originalFetch = global.fetch;
        mockOpenUrl = jest.fn().mockResolvedValue(undefined);
        client = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test', backend: backendConfig }, mockOpenUrl);
    });
    afterEach(() => {
        global.fetch = originalFetch;
    });
    it('login() calls backendClient.initiateRequest (non-blocking)', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ publicKey: BACKEND_PUB }) })
            .mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ pk: 'a', c: 'b' }) });
        client.login();
        // openUrl called synchronously
        expect(mockOpenUrl).toHaveBeenCalled();
        // Allow fetch promises to settle
        await new Promise(r => setTimeout(r, 50));
        expect(global.fetch).toHaveBeenCalledTimes(2); // /public-key + /requests/initiate
    });
    it('login() does not throw if backend call fails', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('network'));
        const errors = [];
        client.onError(e => errors.push(e));
        client.login();
        await new Promise(r => setTimeout(r, 50));
        // openUrl still called
        expect(mockOpenUrl).toHaveBeenCalled();
    });
    it('without backend config, no fetch calls are made', async () => {
        const clientNoBe = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test' }, mockOpenUrl);
        global.fetch = jest.fn();
        clientNoBe.login();
        await new Promise(r => setTimeout(r, 10));
        expect(global.fetch).not.toHaveBeenCalled();
    });
});
describe('pendingRequests TTL', () => {
    let mockOpenUrl;
    let client;
    beforeEach(() => {
        mockOpenUrl = jest.fn().mockResolvedValue(undefined);
        client = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test' }, mockOpenUrl);
    });
    afterEach(() => {
        jest.restoreAllMocks();
    });
    it('entries within TTL survive pruning', () => {
        client.login();
        const map = client.pendingRequests;
        expect(map.size).toBe(1);
        // Second login triggers prune — fresh entry survives
        client.login();
        expect(map.size).toBe(2);
    });
    it('entries older than 5 minutes are pruned on next login()', () => {
        const realNow = Date.now();
        jest.spyOn(Date, 'now').mockReturnValue(realNow - 6 * 60 * 1000);
        client.login();
        jest.spyOn(Date, 'now').mockReturnValue(realNow);
        const map = client.pendingRequests;
        expect(map.size).toBe(1);
        client.login(); // triggers prune
        expect(map.size).toBe(1); // stale pruned, new one added
    });
    it('stale entries are pruned on handleCallback()', () => {
        const realNow = Date.now();
        jest.spyOn(Date, 'now').mockReturnValue(realNow - 6 * 60 * 1000);
        client.login();
        jest.spyOn(Date, 'now').mockReturnValue(realNow);
        const map = client.pendingRequests;
        expect(map.size).toBe(1);
        client.handleCallback('myapp://localid-callback?pk=x&c=y&s=z');
        expect(map.size).toBe(0); // pruned by handleCallback
    });
});
describe('LocalIDClient.initialize()', () => {
    const backendConfig = {
        url: 'http://localhost:9999',
        appId: '123e4567-e89b-12d3-a456-426614174000',
        appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
    };
    let mockOpenUrl;
    let originalFetch;
    beforeEach(() => {
        originalFetch = global.fetch;
        mockOpenUrl = jest.fn().mockResolvedValue(undefined);
    });
    afterEach(() => { global.fetch = originalFetch; });
    it('fetches and stores localidPublicKey and signingKey', async () => {
        const client = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test', backend: backendConfig }, mockOpenUrl);
        global.fetch = jest.fn().mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                localidPublicKey: '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f',
                signingKey: '1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a',
            }),
        });
        await client.initialize();
        const priv = client;
        expect(priv.localidPublicKey).toBe('026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f');
        expect(priv.signingKey).toBe('1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a');
        expect(() => client.login()).not.toThrow();
        // Verify the URL passed to openUrl was signed with the fetched signingKey, not DEV key
        expect(mockOpenUrl).toHaveBeenCalledTimes(1);
        const url = mockOpenUrl.mock.calls[0][0];
        expect(url).toMatch(/^localid:\/\/auth\/v1\?pk=[0-9a-f]+&c=.+&s=[0-9a-f]{64}$/);
    });
    it('resolves silently in dev mode without backend config', async () => {
        const client = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test' }, mockOpenUrl);
        await expect(client.initialize()).resolves.toBeUndefined();
    });
    it('throws in production without backend config', async () => {
        const orig = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';
        const client = new LocalIDClient_1.LocalIDClient({ appId: 'com.test', returnScheme: 'test' }, mockOpenUrl);
        await expect(client.initialize()).rejects.toThrow('requires backend config');
        process.env.NODE_ENV = orig;
    });
});
//# sourceMappingURL=LocalIDClient.test.js.map