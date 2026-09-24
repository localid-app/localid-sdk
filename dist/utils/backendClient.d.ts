import { BackendConfig } from '../types';
export declare class BackendClient {
    private readonly config;
    private backendPubKey;
    constructor(config: BackendConfig);
    private getBackendPublicKey;
    private postEncrypted;
    initiateRequest(requestId: string, requestedFields: string[]): Promise<void>;
    completeRequest(requestId: string, status: 'completed' | 'failed'): Promise<void>;
    private getWithHmac;
    fetchInitKeys(): Promise<{
        localidPublicKey: string;
        signingKey: string;
    }>;
}
//# sourceMappingURL=backendClient.d.ts.map