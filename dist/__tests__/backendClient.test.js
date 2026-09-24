"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const backendClient_1 = require("../utils/backendClient");
const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';
const testConfig = {
    url: 'http://localhost:9999', // unused server — we mock fetch
    appId: '123e4567-e89b-12d3-a456-426614174000',
    appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
};
describe('BackendClient', () => {
    let originalFetch;
    beforeEach(() => {
        originalFetch = global.fetch;
    });
    afterEach(() => {
        global.fetch = originalFetch;
    });
    describe('getBackendPublicKey (via initiateRequest)', () => {
        it('fetches public key then sends encrypted initiate request', async () => {
            const pubKeyRes = { publicKey: BACKEND_PUB };
            const initiateRes = { pk: BACKEND_PUB, c: 'AAAA' }; // encrypted response
            let callCount = 0;
            global.fetch = jest.fn().mockImplementation((url) => {
                callCount++;
                if (callCount === 1) {
                    // GET /public-key
                    expect(url).toContain('/public-key');
                    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(pubKeyRes) });
                }
                // POST /requests/initiate
                expect(url).toContain('/requests/initiate');
                return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve(initiateRes) });
            });
            const client = new backendClient_1.BackendClient(testConfig);
            await client.initiateRequest('abc-123', []);
            expect(callCount).toBe(2);
        });
        it('caches public key — only fetches once across multiple calls', async () => {
            let fetchCallCount = 0;
            global.fetch = jest.fn().mockImplementation((url) => {
                fetchCallCount++;
                if (url.includes('/public-key')) {
                    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ publicKey: BACKEND_PUB }) });
                }
                return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve({ pk: 'a', c: 'b' }) });
            });
            const client = new backendClient_1.BackendClient(testConfig);
            await client.initiateRequest('req1', []);
            await client.completeRequest('req1', 'completed');
            // /public-key fetched only once; /requests/initiate and /requests/complete each once
            const pubKeyCalls = global.fetch.mock.calls.filter(([url]) => url.includes('/public-key'));
            expect(pubKeyCalls.length).toBe(1);
        });
    });
    describe('initiateRequest', () => {
        it('does not throw on network error (fire-and-forget)', async () => {
            global.fetch = jest.fn().mockRejectedValue(new Error('network error'));
            const client = new backendClient_1.BackendClient(testConfig);
            // Should not throw
            await expect(client.initiateRequest('req-id', [])).resolves.toBeUndefined();
        });
        it('sends encrypted envelope with HMAC headers', async () => {
            let capturedRequest = null;
            global.fetch = jest.fn().mockImplementation((url, options) => {
                if (url.includes('/public-key')) {
                    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ publicKey: BACKEND_PUB }) });
                }
                capturedRequest = { url, options };
                return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve({ pk: 'a', c: 'b' }) });
            });
            const client = new backendClient_1.BackendClient(testConfig);
            await client.initiateRequest('test-req-id', ['name']);
            expect(capturedRequest).not.toBeNull();
            const headers = capturedRequest.options.headers;
            expect(headers['X-LocalID-App-Id']).toBe(testConfig.appId);
            expect(headers['X-LocalID-Timestamp']).toBeDefined();
            expect(headers['X-LocalID-Signature']).toBeDefined();
            const body = JSON.parse(capturedRequest.options.body);
            expect(typeof body.pk).toBe('string');
            expect(typeof body.c).toBe('string');
        });
    });
    describe('completeRequest', () => {
        it('does not throw on non-2xx response', async () => {
            global.fetch = jest.fn().mockImplementation((url) => {
                if (url.includes('/public-key')) {
                    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ publicKey: BACKEND_PUB }) });
                }
                return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({ error: 'not found' }) });
            });
            const client = new backendClient_1.BackendClient(testConfig);
            await expect(client.completeRequest('req-id', 'failed')).resolves.toBeUndefined();
        });
    });
});
//# sourceMappingURL=backendClient.test.js.map