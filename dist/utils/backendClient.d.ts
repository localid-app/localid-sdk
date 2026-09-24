import { BackendConfig, DelegationDecision, DelegationScope } from '../types';
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
    /**
     * Ask the backend whether an action is allowed under a delegation. Sent as
     * plain signed JSON: the scope and amount are not personal data.
     * Throws when no decision could be obtained, so an outage is never read as "allowed".
     */
    checkDelegation(delegationId: string, action: {
        scope: DelegationScope;
        amount?: number;
    }, timeoutMs?: number): Promise<DelegationDecision>;
}
//# sourceMappingURL=backendClient.d.ts.map