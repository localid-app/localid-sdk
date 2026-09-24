# AI agent integration guide

An AI agent acting for a person needs two things it should never hold itself: proof of who it acts for, and that person's permission. With `@localid/sdk`, the agent asks LocalID; the person approves on their phone with Face ID; the agent gets back a signed, scoped answer. The identity data behind that answer stays on the phone.

This guide covers the four agent requests. For installation, `initialize()` and callback wiring, see the [README](README.md).

| You want to… | Call | The agent receives |
|---|---|---|
| Get approval for one specific action | `requestAgentAuth` | A one-time approval, valid for 5 minutes |
| Act repeatedly within limits | `requestDelegation` | Scopes, a per-action cap and an expiry |
| Fill a form with verified details | `requestIdentity` | Only the fields the person approved |
| Prove the person meets an age limit | `requestAgeAssertion` | Yes, the age tested and an expiry — never a date of birth |

## Setup

Register the callback handlers once, then make requests from anywhere in your app:

```ts
import { LocalIDClient } from '@localid/sdk';

const localid = new LocalIDClient({
  appId: 'com.example.agent',     // must match your registered bundle id
  returnScheme: 'exampleagent',   // the URL scheme your app handles
  backend: { url, appId: appUuid, appSecret },
});
await localid.initialize();

localid.onSuccess(response => { /* see "Handling results" */ });
localid.onError(error => { /* see "Errors" */ });

// In your deep-link handler:
localid.handleCallback(url);
```

Every request below opens LocalID, shows the person a consent screen, and returns to your `returnScheme`. Each accepts `{ dynamicFaceAuth: true }` to also require a live face match against the enrolled ID before the answer is sent.

## 1. Approve a single action

Use this when the agent is about to do something the person should explicitly confirm: a purchase, a sign-up, signing a contract.

```ts
localid.requestAgentAuth({
  name: 'Travel Assistant',
  action: 'Upgrade rental to Porsche 911 for +$180/day',
  scope: 'purchase',              // 'purchase' | 'signup' | 'data-access' | 'contract' | 'custom'
  metadata: { amount: '180', currency: '$', merchant: 'DriveIQ' },
});
```

The person sees the agent's name, the action and the metadata. On approval:

```ts
response.agentActionApproved  // true
response.approvedAction       // the action string you sent
response.approvedScope        // the scope you sent
response.approvalExpiresAt    // unix seconds, 5 minutes after approval
```

Act before `approvalExpiresAt`. An approval covers exactly the action shown; request a new one for anything else.

## 2. Delegate standing authority

Use this when asking for every action would be tedious, and the person is comfortable granting a bounded mandate.

```ts
localid.requestDelegation({
  agentName: 'Travel Assistant',
  description: 'Book rental cars on my behalf',
  scopes: ['purchase'],           // 'purchase' | 'signup' | 'age-verify' | 'identity-share' | 'authorize'
  maxAmountPerAction: 200,        // USD, optional
  expiresInSeconds: 7 * 24 * 3600,
});
```

On approval:

```ts
response.delegationGranted    // true
response.delegationId         // identifies this grant
response.grantedScopes        // the scopes approved
response.delegationExpiresAt  // unix seconds
```

**Check with LocalID before every action.** The grant is recorded on the LocalID backend, which decides each action against the scopes, the per-action cap and the expiry. Ask it every time, including for repeats:

```ts
const decision = await localid.checkDelegation(response.delegationId, { scope: 'purchase', amount: 189.5 });

if (decision.allowed) {
  // go ahead
} else {
  // decision.reason: 'revoked' | 'expired' | 'scope_not_granted'
  //                | 'amount_exceeds_cap' | 'amount_required' | 'not_found'
}
```

- Pass `amount` whenever the grant has a cap; without it the check returns `amount_required`.
- `checkDelegation` rejects if the backend cannot be reached. Treat that as a denial and do not act.
- It needs the `backend` option from Setup, because the request is signed with your app secret. A grant can only be checked by the app it was granted to.

The person can revoke a grant at any time from LocalID's Identities screen. The backend refuses the next check with `revoked`, so the revocation takes effect immediately. Your app is not told when it happens, which is why you check before each action. For anything a grant does not cover, fall back to `requestAgentAuth`.

## 3. Share verified details

When the agent needs real details to complete a form, request exactly those fields:

```ts
localid.requestIdentity(['firstName', 'lastName', 'email', 'street', 'city', 'state', 'zipCode']);
```

The person approves field by field. `response.data` contains only the approved fields, each taken from their verified government ID. Request the minimum: every extra field is one more reason to decline.

## 4. Prove age without a birth date

```ts
localid.requestAgeAssertion(25, 3600);   // minimum age, validity in seconds
```

LocalID checks the date of birth on the phone. On success:

```ts
response.ageAssertionGranted  // true
response.isAboveThreshold     // true
response.ageThreshold         // 25
response.assertionExpiresAt   // unix seconds; LocalID caps validity at 24 hours
```

The date of birth is never included. If the person is under the threshold you receive the `AGE_REQUIREMENT_NOT_MET` error, and nothing else about their age.

## Handling results

Approvals and denials both arrive in `onSuccess`. Check `status` first:

```ts
localid.onSuccess(response => {
  if (response.status === 'denied') {
    // The person tapped Deny. Stop, and do not retry automatically.
    return;
  }
  if (response.agentActionApproved) { /* 1 */ }
  if (response.delegationGranted)   { /* 2 */ }
  if (response.ageAssertionGranted) { /* 4 */ }
  if (response.data)                { /* 3: approved fields */ }
});
```

If you passed `dynamicFaceAuth: true`, `response.dynamicFaceAuthVerified` is `true` when the live face matched.

## Errors

Failures that stop a request arrive in `onError`:

| `error.code` | Meaning |
|---|---|
| `AGE_REQUIREMENT_NOT_MET` | The person is under the requested age |
| `FACE_VERIFICATION_FAILED` | Dynamic face auth did not match |
| `FACE_NOT_ENROLLED` | Dynamic face auth was requested but no face is enrolled |
| `DELEGATION_UNAVAILABLE` | The person approved a delegation, but LocalID could not record it. Nothing was granted; try again |
| `INVALID_SIGNATURE` | The callback was not signed by LocalID; discard it |
| `REPLAY_DETECTED` | The callback was already used; discard it |
| `EXPIRED` | The callback's timestamp is outside the 5-minute window; discard it |
| `UNKNOWN` | Anything else; `error.message` has the reason |

## Security properties

- **End-to-end encrypted.** Each request carries a fresh key; only your app can decrypt the answer.
- **Signed.** Callbacks are signed with your app's key. `handleCallback` rejects anything that fails verification.
- **Single use.** Each callback carries a nonce and is rejected if seen again.
- **Expiring.** Approvals, grants and age assertions all carry an expiry. Honour it.
- **Revocable.** Delegations are enforced by the LocalID backend on every `checkDelegation`, so a revoked or expired grant stops working at once.
- **Person-approved.** Nothing is returned without the person approving on their phone, with Face ID or their passcode.
