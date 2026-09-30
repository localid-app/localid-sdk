# @localid/sdk

**The official SDK for integrating [LocalID](https://localid.ai) identity verification into your React Native app.**

LocalID is a privacy-first mobile identity wallet. Users enroll once by scanning a government-issued ID and completing face verification. Your app can then request authentication or specific identity attributes — the user sees a consent screen on their phone and approves exactly what to share. No data ever leaves the user's device or passes through a server.

---

## Status

> **Early Access — Phase 1**
>
> The LocalID app is not yet publicly available. To request access to the LocalID app for testing and integration, contact **hello@localid.ai**.

---

## How it works

```
Your App                              LocalID (on user's phone)
─────────────────────────────────────────────────────────────────
sdk.login({ userIdentifier })
  → encrypted deep link ──────────────▶  shows consent screen
                                          user authenticates
                                          user approves
  ◀── encrypted callback ──────────────  dispatches response

sdk.onSuccess(response => {
  // response.data contains approved fields
})
```

All payloads are **end-to-end encrypted** (X25519 ECDH + AES-256-GCM) and **signed** (HMAC-SHA256). Nothing is readable in transit. LocalID never sends data to a server — the callback goes directly from the LocalID app to your app via deep link.

---

## Installation

The SDK is distributed as a tarball on the [Releases](https://github.com/localid-app/localid-sdk/releases/latest) page (it is not yet on the npm registry). Download `localid-sdk-{version}.tgz`, then:

```bash
npm install ./localid-sdk-0.1.1.tgz
# or
yarn add ./localid-sdk-0.1.1.tgz
```

The package installs as `@localid/sdk`.

> **Developer preview.** 0.1.x is for evaluation; the request and response formats may change before 1.0.

### Peer requirements

- React Native ≥ 0.70
- iOS 15+ / Android API 26+

### iOS — register your callback URL scheme

In `ios/<YourApp>/Info.plist`, add your scheme to `CFBundleURLTypes`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>yourapp</string>
    </array>
  </dict>
</array>
```

### Android — register your callback URL scheme

In `android/app/src/main/AndroidManifest.xml`, add an intent filter to your main activity:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="yourapp" />
</intent-filter>
```

---

## Quick Start

### 1. Create the SDK client (once, at app startup)

```typescript
// sdk.ts
import { Linking } from 'react-native';
import { LocalIDClient } from '@localid/sdk';

export const localid = new LocalIDClient(
  {
    appId: 'com.yourcompany.yourapp',
    returnScheme: 'yourapp',       // must match your registered URL scheme
    backend: {
      url: 'https://localid-be.onrender.com',
      appId: 'YOUR_APP_UUID',      // from POST /apps/register
      appSecret: 'YOUR_APP_SECRET',
    },
  },
  Linking.openURL.bind(Linking),   // injected so the SDK has no RN dependency
);

// Fetch per-app cryptographic keys before making requests.
// Call this once, as early as possible (e.g. in your root component's useEffect).
await localid.initialize();
```

### 2. Register callbacks (in your root component)

```typescript
import { localid } from './sdk';

useEffect(() => {
  const unsubSuccess = localid.onSuccess(response => {
    console.log('Status:', response.status);   // 'success' | 'denied'
    console.log('Data:', response.data);        // approved identity fields
  });

  const unsubError = localid.onError(error => {
    console.error(`[${error.code}] ${error.message}`);
  });

  // Route incoming deep links through the SDK
  const listener = Linking.addEventListener('url', ({ url }) => {
    localid.handleCallback(url);
  });

  // Handle cold-start deep links
  Linking.getInitialURL().then(url => {
    if (url) localid.handleCallback(url);
  });

  return () => {
    unsubSuccess();
    unsubError();
    listener.remove();
  };
}, []);
```

### 3. Make requests

```typescript
// Authentication — verify the user is who they say they are
localid.login({ userIdentifier: 'user@example.com' });

// Identity attributes — request specific fields
localid.requestIdentity(['firstName', 'lastName', 'dob']);

// Age verification only
localid.requestIdentity(['age_over_18']);

// Multiple fields — user can toggle each one individually
localid.requestIdentity(['firstName', 'lastName', 'email', 'phone', 'dob']);
```

---

## API Reference

### `new LocalIDClient(config, openUrl)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `config.appId` | `string` | Your app's bundle identifier (e.g. `com.yourcompany.yourapp`) |
| `config.returnScheme` | `string` | Your registered deep link scheme (e.g. `yourapp`) |
| `config.backend` | `BackendConfig` (optional) | Backend control plane config. Required in production. |
| `openUrl` | `(url: string) => Promise<void>` | URL opener — pass `Linking.openURL.bind(Linking)` |

```typescript
interface BackendConfig {
  url: string;       // LocalID backend base URL
  appId: string;     // UUID assigned at app registration
  appSecret: string; // Hex secret from registration — authenticates backend requests
}
```

---

### `client.initialize()`

Fetches per-app cryptographic keys from the backend and stores them for use in all subsequent requests and response verification. **Call this once, before `login()` or `requestIdentity()`.**

- Idempotent — concurrent calls share the same in-flight Promise.
- No-op when `backend` config is omitted (development/test mode).
- Throws in `NODE_ENV=production` when `backend` config is absent.

```typescript
await localid.initialize();
```

---

### `client.login(opts?)`

Requests authentication. LocalID verifies the user's enrolled identity matches the provided identifier.

```typescript
localid.login({ userIdentifier: 'user@example.com' });
localid.login({ userIdentifier: '+14155552671' });
localid.login(); // no identifier — LocalID prompts user to confirm their identity
```

Every request method accepts `{ dynamicFaceAuth: true }` (see [Dynamic face auth](#dynamic-face-auth)).

---

### `client.requestIdentity(fields, opts?)`

Requests specific identity attributes. The user sees per-field consent toggles and can approve or deny each field individually.

```typescript
localid.requestIdentity(fields: IdentityField[], opts?: { dynamicFaceAuth?: boolean })
```

**Available fields:**

| Field | Type | Description |
|-------|------|-------------|
| `firstName` | `string` | First name from enrolled ID |
| `lastName` | `string` | Last name from enrolled ID |
| `email` | `string` | Email address |
| `phone` | `string` | Phone number |
| `dob` | `string` | Date of birth (ISO 8601) |
| `age_over_18` | `boolean` | `true` / `false` — DOB is never exposed |
| `document_number` | `string` | Government ID document number |
| `selfie_photo` | `string` | Enrollment selfie (base64 JPEG) |

---

### Dynamic face auth

Face ID or a passcode proves that someone can unlock the phone. For high-stakes
moments, pass `{ dynamicFaceAuth: true }` to any request: after Face ID, LocalID
matches the person's live face against the photo on the government ID they
enrolled with, on the phone. No face image leaves the device.

- Match: the signed response carries `dynamicFaceAuthVerified: true`.
- No match after three tries: nothing is shared and `onError` receives `FACE_VERIFICATION_FAILED`.
- No face enrolled: `onError` receives `FACE_NOT_ENROLLED`.

```typescript
localid.login({ dynamicFaceAuth: true });
localid.onSuccess(r => { if (r.dynamicFaceAuthVerified) { /* proceed */ } });
```

---

### AI agent requests

`requestAgentAuth`, `requestDelegation`, `requestAgeAssertion` and
`checkDelegation` are documented in the [agent integration guide](./agent.md).
Delegations are enforced by the LocalID backend: call `checkDelegation` before
every action taken under a grant.

---

### `client.handleCallback(url)`

Call this from your deep link handler. Returns `true` if the URL was an LocalID callback (handled); `false` if unrelated.

```typescript
const handled = localid.handleCallback(url);
if (!handled) {
  // your own deep link routing
}
```

---

### `client.onSuccess(callback)` / `client.onError(callback)`

Register response handlers. Both return an unsubscribe function.

```typescript
const unsub = localid.onSuccess((response: LocalIDResponse) => {
  // response.status   — 'success' | 'denied'
  // response.data     — Record<string, unknown> — approved fields
  // response.requestId — correlates to the originating request
  // response.ts       — Unix timestamp
  // response.dynamicFaceAuthVerified — true when a requested face match passed
});

const unsubErr = localid.onError((error: LocalIDError) => {
  // error.code — callback integrity: 'INVALID_SIGNATURE' | 'DECRYPTION_FAILED' | 'EXPIRED'
  //               | 'REPLAY_DETECTED' | 'REQUEST_ID_MISMATCH'
  //             — the person or LocalID declined: 'CANCELLED' | 'TIMEOUT'
  //               | 'FACE_NOT_ENROLLED' | 'FACE_VERIFICATION_FAILED'
  //               | 'AGENT_ACTION_DENIED' | 'DELEGATION_DENIED' | 'DELEGATION_UNAVAILABLE'
  //               | 'AGE_REQUIREMENT_NOT_MET'
  //             — anything else: 'UNKNOWN'
  // error.message  — human-readable description
});

// Clean up
unsub();
unsubErr();
```

---

## Security

### Encryption

Every request and response is end-to-end encrypted using a fresh ephemeral keypair:

```
Request:  ECDH(sdkEphPriv, localidPub) → HKDF-SHA256("localid-request-v1")  → AES-256-GCM
Response: ECDH(localidEphPriv, sdkPub) → HKDF-SHA256("localid-response-v1") → AES-256-GCM
```

Every URL is HMAC-SHA256 signed. Tampered or replayed URLs are rejected.

### Replay prevention

Each payload includes a 32-byte random nonce and a Unix timestamp. LocalID rejects:
- Requests older than 5 minutes
- Any nonce seen more than once

### Per-app signing keys (live)

Each registered app has a unique HMAC signing key. `initialize()` fetches this key at startup so:
- Every callback URL carries a signature that only your app can verify
- LocalID rejects requests signed with a different app's key
- Error callbacks (rate limits, unknown app ID, etc.) are also signed

The X25519 encryption keypair is still shared across all Phase 1 apps (the dev keypair in `src/crypto/devKeys.ts` is used as fallback when `initialize()` is not called or backend config is absent). Per-app encryption keys require Phase 2.

### What goes to the LocalID backend

Identity data never touches a server: it travels between your app and the
person's LocalID app in end-to-end encrypted deep links. When the `backend`
option is configured, the SDK talks to the LocalID backend only for:

- `initialize()` — fetch your app's signing key and LocalID's public key.
- Request bookkeeping — each request's id and the *names* of the fields asked
  for (never their values), encrypted to the backend, and whether it completed.
- `checkDelegation()` — ask whether an agent action is allowed under a grant.

No analytics or tracking.

---

## Full Integration Example

```typescript
import React, { useEffect, useState } from 'react';
import { View, Text, Button, Linking } from 'react-native';
import { LocalIDClient, LocalIDResponse } from '@localid/sdk';

const localid = new LocalIDClient(
  {
    appId: 'com.example.myapp',
    returnScheme: 'myapp',
    backend: {
      url: 'https://localid-be.onrender.com',
      appId: 'YOUR_APP_UUID',
      appSecret: 'YOUR_APP_SECRET',
    },
  },
  Linking.openURL.bind(Linking),
);

export default function App() {
  const [result, setResult] = useState<LocalIDResponse | null>(null);

  useEffect(() => {
    // Fetch per-app keys before registering handlers or making requests
    localid.initialize().catch(console.error);

    const unsubOk  = localid.onSuccess(r => setResult(r));
    const unsubErr = localid.onError(e => console.error(e));
    const listener = Linking.addEventListener('url', ({ url }) => localid.handleCallback(url));
    Linking.getInitialURL().then(url => { if (url) localid.handleCallback(url); });

    return () => { unsubOk(); unsubErr(); listener.remove(); };
  }, []);

  return (
    <View>
      <Button title="Verify Age (18+)"    onPress={() => localid.requestIdentity(['age_over_18'])} />
      <Button title="Get Name + Email"    onPress={() => localid.requestIdentity(['firstName', 'lastName', 'email'])} />
      <Button title="Authenticate User"   onPress={() => localid.login({ userIdentifier: 'user@example.com' })} />
      {result && <Text>{JSON.stringify(result.data, null, 2)}</Text>}
    </View>
  );
}
```

---

## Releases

Pre-built SDK packages are available on the [Releases](https://github.com/localid-app/localid-sdk/releases) page.

Each release includes:
- `localid-sdk-{version}.tgz` — installable npm tarball (`npm install ./localid-sdk-{version}.tgz`)
- TypeScript type declarations (`.d.ts`)
- Compiled CommonJS + ESM bundles

---

## Requirements

| Requirement | Version |
|-------------|---------|
| React Native | ≥ 0.70 |
| iOS | 15+ |
| Android API | 26+ |
| TypeScript | ≥ 5.0 (optional but recommended) |
| Node.js (build) | ≥ 18 |

---

## Early Access

**The LocalID app is currently in private early access.**

To request access for your app:

📧 **hello@localid.ai**

Include:
- Your app name and bundle ID
- Platform (iOS / Android / both)
- Estimated user count
- Your use case (age verification, authentication, identity attributes, etc.)

We'll get back to you within 48 hours.

---

## License

MIT © 2026 LocalID

---

*Built with privacy first. No servers. No tracking. User consent always required.*
