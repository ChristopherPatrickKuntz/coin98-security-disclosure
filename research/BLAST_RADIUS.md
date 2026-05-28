# Coin98 Blast Radius Analysis

## Executive Summary

This document maps every discovered secret, vulnerability, and misconfiguration to its **exact compromise capability** — what an attacker can read, write, impersonate, or drain. Each finding is tagged with scope status (in-scope vs out-of-scope per HackenProof), PoC status, and evidence strength.

**Scope**: `*.coin98.com`, Chrome Extension, Android/iOS apps
**Out of scope**: `search.coin98.com`, `blog.coin98.com`, `campaign.coin98.com`

---

## 1. CRITICAL — Full Wallet Drain (Loss of Funds)

### 1.1 `sync_wallet` + `aes_decrypt_coin98` via Whitelisted Origin XSS

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Extract ALL private keys and mnemonics for ALL 164 chains |
| **Scope** | ✅ Chrome Extension (in-scope) |
| **Prerequisite** | XSS on any of 16 COIN98_SYSTEM whitelisted origins |
| **User Interaction** | NONE — zero popups, zero clicks, works even when wallet is LOCKED |
| **PoC Status** | ✅ BUILT — `poc/c98staging-drain/index.html` (full exploit chain with key verification) |
| **Evidence** | Code-level proof: `isConnected = (A, t) => true`, `request_unlock` always returns `{isUnlocked: true}` |

**Kill Chain**:
1. Attacker achieves XSS on whitelisted origin (dagora.xyz, baryon.network, saros.finance, etc.)
2. XSS calls `connect_coin98` → gets `deviceId` (silent, no popup)
3. XSS calls `sync_wallet` → extension **decrypts ALL mnemonics** and returns wallet data
4. XSS calls `aes_decrypt_coin98` with encrypted privateKeys → extension returns plaintext keys
5. Attacker derives addresses from keys, signs proof message, sweeps all funds

**Blast Radius**:
- Every wallet in the extension (all chains: EVM, Solana, Cosmos, Bitcoin, TON, NEAR, Aptos, Sui, etc.)
- Every token balance on every chain
- NFTs, staked assets, LP positions
- Cloud backup data (if encrypted with same master key)
- **Impact**: Total loss of all user funds across 164 supported blockchains

**Whitelisted Origins Attack Surface** (all 16):

| Origin | CSP | XSS Feasibility | In Scope? |
|--------|-----|-----------------|-----------|
| **dagora.xyz** | `script-src * unsafe-inline unsafe-eval` + CORS:* | **HIGHEST** — effectively no CSP | ✅ Related product |
| **baryon.network** | NONE (CF WAF only) | **HIGH** — WAF bypass needed | ✅ Related product |
| **saros.finance** → dex.saros.xyz | `unsafe-eval unsafe-inline` | **HIGH** | ✅ Related product |
| **connect.coin98.com** | NONE (S3 SPA, zero headers) | MEDIUM — no reflection found | ✅ In scope |
| **apps.coin98.com** | NONE, CORS:* | MEDIUM | ✅ In scope |
| **airdrop.coin98.com** | NONE | LOW — minimal JS | ✅ In scope |
| **leaderboard.coin98.com** | NONE | LOW — minimal JS | ✅ In scope |
| **coin98.com** | Behind CF WAF (403) | LOW — WAF + 403 | ✅ In scope |
| **kyc.oneid.xyz** | `unsafe-inline` | MEDIUM | ⚠️ 3rd party |
| **c98staging.dev** | NONE | **HIGH** — staging, less scrutiny | ⚠️ Staging |
| **coin98.dev** | NONE | HIGH — dev domain | ⚠️ Dev |
| **localhost** | N/A | **TRIVIAL** — any local process | ✅ Extension scope |
| **127.0.0.1** | N/A | **TRIVIAL** | ✅ Extension scope |
| **10.10.1.220** | N/A | Internal only | ❌ Internal |
| **campaign.coin98.com** | NONE | LOW | ❌ Out of scope |
| **2025.coin98.com** | NONE | LOW | ⚠️ Unclear |

---

### 1.2 localhost/127.0.0.1 Whitelisted — Local App Wallet Drain

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Same as 1.1 but from local machine |
| **Scope** | ✅ Chrome Extension |
| **Prerequisite** | Any process running HTTP server on localhost or 127.0.0.1 |
| **User Interaction** | NONE — no browser interaction, no popup |
| **PoC Status** | ✅ BUILT — `poc/localhost-test/index.html` |
| **Evidence** | Hardcoded in whitelist array in background worker |

**Kill Chain**:
1. Malicious app/npm package/VS Code extension/Discord bot starts local HTTP server
2. Opens `http://localhost:PORT` in Chrome (or hidden tab)
3. Page passes COIN98_SYSTEM origin check → calls `sync_wallet` → ALL keys extracted
4. No phishing, no external website, no domain takeover needed

**Blast Radius**: Identical to 1.1 — total wallet drain across all chains.

---

### 1.3 Google OAuth Client Secret → Drive Backup → Offline Key Recovery

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Recover all wallet keys from cloud backup |
| **Scope** | ✅ Chrome Extension |
| **Prerequisite** | User has enabled Google Drive cloud backup |
| **User Interaction** | Victim must authorize crafted OAuth URL (social engineering) |
| **PoC Status** | ❌ NOT BUILT — needs PoC |
| **Evidence** | `GOCSPX-████████████████████████████` in 3 JS files |

**Kill Chain**:
1. Attacker crafts OAuth URL with known `client_id=663197326394-████████████████████████████████`
2. Victim authorizes (looks legitimate — Coin98's own Google project)
3. Attacker intercepts auth code via redirect manipulation
4. Exchanges code using exposed `client_secret` → Drive access token
5. Lists `.C98` files from victim's Google Drive
6. Offline brute-force: password min 6 chars, known HMAC key `"coin98_token"`, weak MD5-based KDF
7. All wallet mnemonics/keys recovered

**Blast Radius**: All wallets backed up to Google Drive. Same total drain as 1.1 for cloud-synced wallets.

---

### 1.4 CodePush OTA Bundle Replacement (iOS)

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Push malicious JS bundle to ALL iOS users |
| **Scope** | ✅ iOS App |
| **Prerequisite** | Compromise of CodePush/App Center account |
| **User Interaction** | NONE — OTA update is automatic |
| **PoC Status** | ❌ NOT BUILT — requires account compromise |
| **Evidence** | Key `3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` in Info.plist |

**Blast Radius**: Every iOS user who receives the OTA update — complete wallet compromise at scale.

---

## 2. HIGH — Data Theft / Credential Exposure / Impersonation

### 2.1 Password Stored Encrypted (Not Hashed) — Fully Reversible

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Recover plaintext password → decrypt all wallet data |
| **Scope** | ✅ All platforms (Extension, Android, iOS) |
| **Prerequisite** | Read access to `chrome.storage.local` / AsyncStorage |
| **PoC Status** | ❌ Code-level proof only |

**Blast Radius**: `AES.decrypt(password, token)` → plaintext password. Both `password` (encrypted) and `token` (plaintext master key) stored in same `persist:root` object. Any read access to storage = full wallet compromise.

---

### 2.2 Unauthenticated MongoDB Write (history-records)

| Attribute | Value |
|-----------|-------|
| **Capability** | **WRITE** — Create arbitrary transaction records in production DB |
| **Scope** | ✅ `superwallet-history-records.coin98.tech` (*.coin98.com backend) |
| **Prerequisite** | None — no auth, no WAF |
| **User Interaction** | None |
| **PoC Status** | ✅ CONFIRMED — 4 test writes via api-monitor |
| **Evidence** | `POST /record/log` and `POST /record/log/dapps` accept arbitrary JSON |

**Kill Chain**:
1. `POST /record/log` with crafted transaction data
2. Fake tx history appears in user's wallet app
3. Social engineering: fake "deposit received" notifications → user sends real funds

**Blast Radius**:
- Data poisoning of ALL users' transaction history
- Social engineering attacks at scale
- Fake airdrop/deposit notifications
- No rate limiting observed

---

### 2.3 Supabase RLS Bypass — User Financial Data Exposed

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Wallet addresses + trading volumes of competition participants |
| **Scope** | ⚠️ `campaign.coin98.com` is listed as out-of-scope, but the Supabase instance serves in-scope data |
| **Prerequisite** | None — anon read with extracted anon key |
| **PoC Status** | ✅ CONFIRMED |
| **Evidence** | `jdxkhxqpoqafflwspzte.supabase.co` — `lc_campaigns.wallet_and_volume` |

**Blast Radius**:
- `lc_campaigns` — wallet addresses + trading volumes (user financial data)
- `campaigns`, `creator_campaigns`, `perp_campaigns` — campaign metadata
- `profiles`, `user_roles` — user data (currently empty)

---

### 2.4 Supabase Open Signup — Admin PII Schema

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ/WRITE** — Register account, potentially access RLS-gated admin data |
| **Scope** | ⚠️ `2025.coin98.com` scope unclear |
| **Prerequisite** | None — `disable_signup: false` |
| **PoC Status** | ❌ NOT PROBED — signup → check table access |
| **Evidence** | `wxgwpabjnpylabpktlvr.supabase.co` — PostgREST 13.0.5 |

**Blast Radius**:
- `admin_activity_logs` — `user_email`, `ip_address`, `action_type`, `details` (admin PII)
- `wallet_addresses` — `user_id` → `wallet_address` mapping (user PII)
- `page_views` — `wallet_address`, `user_agent`, `referrer` (tracking data)

---

### 2.5 BOBA Leaderboard — 31,309 Wallet Addresses Exposed

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Wallet deanonymization + balance data |
| **Scope** | ✅ `superwallet-xpoint.coin98.tech` (behind CF) |
| **Prerequisite** | None — no auth |
| **PoC Status** | ✅ CONFIRMED |
| **Evidence** | `/api/v1/boba/leaderboard` returns 3MB JSON |

**Blast Radius**:
- 31,309 wallet addresses with BOBA balances (23.1M BOBA total)
- Per-address transaction history via `/api/v1/boba/history?address=`
- Cross-reference with on-chain data → user deanonymization

---

### 2.6 Ramper Shamir Share Recovery — Social Wallet Drain

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Recover social wallet mnemonics via Shamir shares |
| **Scope** | ✅ Extension + Mobile apps |
| **Prerequisite** | Firebase UID + Ramper `/fragment` API access |
| **PoC Status** | ❌ NOT PROBED — fragment endpoint accessibility unknown |

**Kill Chain**:
1. Obtain Firebase UID (enumeration, data leak)
2. Access Ramper `/fragment` endpoint → get Share 3 (encrypted with `CryptoJS.AES.encrypt(share, UID)`)
3. Decrypt Share 3 with known UID (short, predictable)
4. If Firebase compromised → Share 2 available (KMS-encrypted)
5. 2 of 3 shares → `recoverMnemonic()` → full mnemonic → all funds
6. Share 1 in local AsyncStorage is **not encrypted at all**

---

### 2.7 postMessage Wildcard Origin

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ/IMPERSONATE** — Intercept wallet messages cross-origin |
| **Scope** | ✅ Chrome Extension |
| **Prerequisite** | Iframe a page where Coin98 is active |
| **PoC Status** | ❌ NOT BUILT |

**Blast Radius**: Intercept account addresses, signed transaction data, provider responses. 6+ files use `postMessage(e, "*")`.

---

### 2.8 Cloud Backup HMAC Key Hardcoded

| Attribute | Value |
|-----------|-------|
| **Capability** | **DRAIN** — Offline brute-force cloud backup passwords |
| **Scope** | ✅ Chrome Extension |
| **Prerequisite** | Obtain `.C98` file from Google Drive |
| **PoC Status** | ❌ NOT BUILT |

**Blast Radius**: `HmacSHA256(password, "coin98_token")` → AES key. Min password 6 chars. MD5-based KDF (1 iteration). Feasible brute-force on modern GPU.

---

### 2.9 Socket.IO CORS Wildcard — WalletConnect Session Hijack

| Attribute | Value |
|-----------|-------|
| **Capability** | **IMPERSONATE** — Hijack WalletConnect sessions |
| **Scope** | ✅ `connect.coin98.com` + `socket.coin98.services` |
| **Prerequisite** | Intercept or replay `connect` token |
| **PoC Status** | ❌ NOT PROBED — socket.coin98.services is NXDOMAIN now |

---

### 2.10 Android Root Detection Removed + Zero SSL Pinning

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Full traffic interception + local data theft on rooted device |
| **Scope** | ✅ Android App |
| **Prerequisite** | Rooted device or MITM position |
| **PoC Status** | ❌ NOT BUILT |

**Blast Radius**:
- `libtoolChecker.so` removed in v16.9.0
- Zero SSL pinning, zero Frida/Magisk detection, zero Play Integrity
- `usesCleartextTraffic=true` — HTTP allowed globally
- AsyncStorage (×23 refs) in plaintext SQLite
- MITM → intercept all API traffic, steal session tokens, modify transactions

---

## 3. MEDIUM — Information Disclosure / Service Abuse

### 3.1 33 Hardcoded Secrets Across 3 Platforms

| # | Secret Type | Value (truncated) | Capability | Platform |
|---|------------|-------------------|------------|----------|
| 1 | **Google OAuth CLIENT SECRET** | `GOCSPX-l8st6...` | **DRAIN** (see 1.3) | Extension |
| 2 | Google API Key | `AIzaSyBqw7YK...` | READ — Drive API calls | All |
| 3 | Google API Key (iOS) | `AIzaSyAxVjv2...` | READ — Firebase API calls | iOS |
| 4-8 | 5× Google OAuth Client IDs | `663197326394-*` | IMPERSONATE — craft OAuth flows | All |
| 9 | GA4 API Secret | `UMuzrYVDSJ--z...` | WRITE — analytics poisoning | Extension |
| 10-11 | 2× Infura Project IDs | `92d53cee...`, `9aa3d95b...` | ABUSE — RPC quota exhaustion | All |
| 12-14 | 3× NodeReal BSC Keys | `955ab7c0...` etc | ABUSE — RPC quota exhaustion | All |
| 15-24 | 10× GetBlock RPC Keys | Various | ABUSE — paid RPC exhaustion | Mobile |
| 25 | BlockVision API Key | `2q6L43iKBg...` | ABUSE — Sui RPC exhaustion | Extension |
| 26 | TokenView API Key | `qVHq2o6jpa...` | ABUSE — ETH/BSC RPC exhaustion | Extension |
| 27 | Static HMAC Signature | `c0435caf93...` | IMPERSONATE — forge API requests | Extension |
| 28 | JWT #2 (HS512, no expiry) | `eyJhbGciOi...` | READ — permanent backend access (rejected by endpoints tested) | Extension |
| 29 | TON API Bearer | `AFPJTKEBPO...` | READ — TON blockchain queries | Extension |
| 30 | Basescan API Key | `RTDZPUZ83P...` | ABUSE — rate limit exhaustion | Extension |
| 31 | Lineascan API Key | `WE24ED6XW2...` | ABUSE — rate limit exhaustion | Extension |
| 32 | Scrollscan API Key | `MZBHEUFG4S...` | ABUSE — rate limit exhaustion | Extension |
| 33 | OKLink API Key (×3 chains) | `6ff621a9-40...` | ABUSE — rate limit exhaustion | Extension |
| 34 | CodePush Key | `3upL_dngkKK...` | **DRAIN** (see 1.4) | iOS |
| 35 | Facebook Client Token | `4f227919be...` | READ — Graph API calls | iOS |
| 36 | Airbridge SDK Secret | `cb5bb86fc0...` | IMPERSONATE — forge attribution | Mobile |
| 37 | Cloud Backup HMAC | `"coin98_token"` | **DRAIN** (see 2.8) | Extension |

---

### 3.2 Swagger/OpenAPI Spec Exposure

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Full API schema, auth schemes, staging URLs |
| **Scope** | ✅ `superwallet-misc.coin98.tech` |
| **Evidence** | `/swagger.json` → OpenAPI 3.0.0, 7 endpoints, `bearerAuth` + `adminAuth` schemes |

**Blast Radius**: Reveals internal API structure, auth mechanisms, staging server URLs. Aids in discovering admin escalation paths.

---

### 3.3 21 Staging Endpoints in Production Bundle

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ/WRITE** — Staging servers with weaker auth |
| **Scope** | ✅ Android + iOS apps |
| **Confirmed Reachable** | `ramper-v2-api-test.coin98.dev`, `superwallet-chat-api-stg.coin98.tech`, `zencard-visa-api-stg.coin98.tech` |

**Blast Radius**: Staging servers with debug endpoints, verbose errors, weaker auth. `zencard-visa-api-stg` is financial infrastructure. `internal.c98staging.dev` and `api-dagora-dev.c98staging.dev` are NEW in v16.9.0.

---

### 3.4 Zencard API — CORS Wildcard on Financial API

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Cross-origin access to card issuance API |
| **Scope** | ⚠️ `api-server.zencard.io` (related product) |
| **Evidence** | CORS:*, `/health` returns `true`, `/api-docs` serves Swagger UI |

---

### 3.5 GA4 Analytics Poisoning

| Attribute | Value |
|-----------|-------|
| **Capability** | **WRITE** — Send fake analytics events to Coin98's GA4 |
| **Scope** | ✅ Extension |
| **Evidence** | `G-CCPPHL1RJT` + `████████████████████████` |

**Blast Radius**: Pollute business metrics, create false conversion data, trigger internal alerts.

---

### 3.6 Extension Fingerprinting via Web Accessible Resources

| Attribute | Value |
|-----------|-------|
| **Capability** | **READ** — Detect Coin98 installation from any website |
| **Scope** | ✅ Extension |
| **Evidence** | `inpage.*.js`, `cosmos.*.js`, `public/**` exposed to `<all_urls>` |

**Blast Radius**: Any website can detect Coin98 → serve targeted phishing or exploit pages.

---

### 3.7 CryptoJS AES-CBC Without Authenticated Encryption

| Attribute | Value |
|-----------|-------|
| **Capability** | **WRITE** — Bit-flip encrypted wallet data without detection |
| **Scope** | ✅ All platforms |
| **Evidence** | `encryptService` uses CBC mode, PKCS7, no HMAC/GCM |

---

## 4. Gap Analysis — Assets Found But Not Fully Probed

| # | Asset | Status | What's Missing | Priority |
|---|-------|--------|---------------|----------|
| 1 | **dagora.xyz stored XSS via NFT metadata** | NOT TESTED | Mint NFT with HTML payload on Viction chain, check if rendered unsafely | 🔴 CRITICAL — this is the #1 XSS vector for wallet drain |
| 2 | **baryon.network DOM XSS** | NOT TESTED | Deep analysis of 28 JS bundles, localStorage reads, WAF bypass techniques | 🔴 HIGH |
| 3 | **saros.finance DOM XSS** | NOT TESTED | `/info/wallet/[address]` has 6 reflections (URL-encoded). Need deeper DOM analysis | 🔴 HIGH |
| 4 | **2025 Supabase signup path** | NOT PROBED | Register → check if `admin_activity_logs` or `wallet_addresses` become readable | HIGH |
| 5 | **Ramper `/fragment` API** | NOT PROBED | Is endpoint accessible externally? Can fragments be enumerated by UID? Rate limiting? | HIGH |
| 6 | **Google OAuth client secret PoC** | NOT BUILT | Full chain: craft URL → intercept code → exchange → Drive access → .C98 download → decrypt | HIGH |
| 7 | **postMessage wildcard PoC** | NOT BUILT | Iframe page with Coin98 active → intercept wallet messages | HIGH |
| 8 | **Firebase RTDB rules** | TESTED (locked) | `coin98-b7f98.firebaseio.com` returns 401. Retest with auth token | MEDIUM |
| 9 | **connect.coin98.com deep link abuse** | NOT TESTED | `coin98://` protocol auto-click → test mobile deep link handler | MEDIUM |
| 10 | **Infura/GetBlock key rate limits** | NOT TESTED | Are keys origin-restricted? Can we exhaust quotas? | MEDIUM |
| 11 | **superwallet-misc admin auth** | NOT TESTED | Can JWT #2 (HS512, no expiry) auth to `/events` or admin endpoints? | MEDIUM |
| 12 | **Zencard API endpoints** | NOT PROBED | Swagger UI at `/api-docs` has empty spec. Fuzz for hidden routes | MEDIUM |
| 13 | **Android deep link intent injection** | NOT TESTED | `coin98://TokenMarketDetails?chain=PAYLOAD` — chain param validation | MEDIUM |
| 14 | **3 reachable staging endpoints** | NOT PROBED | `ramper-v2-api-test`, `superwallet-chat-api-stg`, `zencard-visa-api-stg` — debug endpoints? | MEDIUM |
| 15 | **internal.c98staging.dev** | NOT PROBED | New in v16.9.0, 3 refs in prod bundle | MEDIUM |
| 16 | **Ordinals APIs (GCP)** | DNS resolves but unreachable | May be decommissioned | LOW |
| 17 | **frontierdao.org / interlock.news** | NOT PROBED | Shared AWS IPs, no CF, nginx + Next.js | LOW |

---

## 5. PoC Inventory — What's Built vs What's Needed

### Built and Ready

| PoC | Location | Demonstrates | Evidence Strength |
|-----|----------|-------------|-------------------|
| **Whitelist Private Key Extraction** | `poc/c98staging-drain/index.html` | Full chain: detect → connect → sync_wallet → decrypt → verify key ownership + sign message | **UNDENIABLE** — derives address + signs proof |
| **Localhost Vector** | `poc/localhost-test/index.html` | Same chain from localhost (no external website needed) | **UNDENIABLE** |
| **API Monitor** | `poc/api-monitor/` | Probes all backend APIs via proxy, tests secrets | **STRONG** — live probe results |
| **Exchange Monitor** | `poc/exchange-monitor/` | Traffic interception + logging | **STRONG** |

### Needs Building

| PoC | Priority | What It Proves |
|-----|----------|---------------|
| **dagora.xyz NFT stored XSS** | 🔴 CRITICAL | XSS on whitelisted origin → real-world wallet drain vector |
| **Google OAuth → Drive → .C98 → brute-force** | HIGH | Full backup compromise chain |
| **postMessage interception** | HIGH | Cross-origin wallet message theft |
| **Supabase signup → RLS escalation** | HIGH | Admin PII access after registration |
| **MongoDB write → fake tx history** | HIGH | Data poisoning (already confirmed, needs pretty PoC) |
| **GA4 analytics poisoning** | MEDIUM | Business metrics manipulation |
| **Infura/GetBlock rate limit exhaustion** | MEDIUM | DoS on blockchain connectivity |

---

## 6. Bounty Submission Strategy

### Tier 1: Critical (Wallet Drain) — Maximum Bounty

**Finding**: COIN98_SYSTEM Whitelist Design Flaw — 9 Internal Methods Bypass All User Approval

**Impact**: Any XSS on 16 whitelisted origins OR any local process silently extracts ALL private keys and mnemonics across 164 blockchains. Zero user interaction. Works when wallet is locked.

**Evidence Package**:
- PoC: `c98staging-drain/index.html` — full exploit chain with cryptographic proof of key ownership
- PoC: `localhost-test/index.html` — localhost vector (no phishing needed)
- Code analysis: `isConnected = (A, t) => true` (broken guard), `request_unlock` always true
- Whitelist scan: 8/16 origins have ZERO CSP, remaining allow `unsafe-inline`/`unsafe-eval`

**Scope Proof**:
- Chrome Extension ID `aeachknmefphepccionboohckonoeemg` is explicitly in scope
- Whitelisted origins include `*.coin98.com` subdomains (in scope)
- localhost/127.0.0.1 — extension-level vulnerability, no external domain needed

### Tier 2: High (Credential/Data Theft)

| Finding | Impact | Scope Proof |
|---------|--------|-------------|
| Google OAuth Client Secret Exposed | Cloud backup key recovery chain | Extension in scope |
| Unauthenticated MongoDB Write | Transaction history poisoning for all users | `superwallet-history-records.coin98.tech` (*.coin98.com) |
| Password stored encrypted not hashed | Full key recovery if storage read | Extension + mobile apps in scope |
| 33 hardcoded secrets (zero rotation) | Rate limit abuse, impersonation, free RPC | All platforms in scope |
| Root detection removed (Android v16.9.0) | Full local data theft on rooted device | Android app in scope |
| Zero SSL pinning (all platforms) | Full traffic interception | All platforms in scope |

### Tier 3: Medium (Information Disclosure)

| Finding | Impact | Scope Proof |
|---------|--------|-------------|
| Supabase RLS bypass — wallet addresses exposed | User financial data leak | Campaign Supabase serves in-scope user data |
| BOBA leaderboard — 31K wallets exposed | User deanonymization | `superwallet-xpoint.coin98.tech` |
| Swagger spec exposure | API schema + admin auth leak | `superwallet-misc.coin98.tech` |
| 21 staging endpoints in prod bundle | Expanded attack surface | Android + iOS apps |
| Supabase open signup with admin PII schema | Potential admin data access | `2025.coin98.com` backend |

---

## 7. Risk Scoring Matrix

| Finding | Likelihood | Impact | CVSS-ish | Bounty Priority |
|---------|-----------|--------|----------|-----------------|
| sync_wallet drain (XSS vector) | HIGH (8 origins with zero CSP) | CRITICAL (total fund loss) | 9.8 | **#1** |
| sync_wallet drain (localhost) | HIGH (any local process) | CRITICAL (total fund loss) | 9.6 | **#1** (same finding) |
| OAuth secret → Drive backup drain | MEDIUM (needs social engineering) | CRITICAL (total fund loss) | 8.5 | **#2** |
| CodePush OTA compromise (iOS) | LOW (needs account compromise) | CRITICAL (all iOS users) | 8.0 | **#3** |
| Unauth MongoDB write | HIGH (no auth, no WAF) | HIGH (data poisoning) | 8.1 | **#4** |
| Password not hashed | MEDIUM (needs storage read) | CRITICAL (full key recovery) | 7.5 | **#5** |
| Supabase RLS bypass | HIGH (anon access) | MEDIUM (user financial data) | 6.5 | **#6** |
| 33 hardcoded secrets | HIGH (public JS) | MEDIUM (varied per secret) | 6.0 | **#7** |
| Zero SSL pinning + root detection removed | MEDIUM (rooted device) | HIGH (full interception) | 7.0 | **#8** |
| BOBA leaderboard exposure | HIGH (no auth) | MEDIUM (deanonymization) | 5.5 | **#9** |
| Staging endpoints in prod | MEDIUM (3 reachable) | MEDIUM (debug access) | 5.0 | **#10** |

---

## 8. Defense-in-Depth Assessment

### What's Protecting Users Right Now

| Defense | Status | Effectiveness |
|---------|--------|--------------|
| Cloudflare WAF | ✅ On main domain + some subs | **Partial** — 4 ALBs have NO WAF, S3 SPAs bypass |
| URL encoding on reflections | ✅ All whitelisted origins | **Good** — blocks reflected XSS |
| Firebase security rules | ✅ Locked (401 on RTDB) | **Good** — but rules could change |
| Password requirement (6-30 chars) | ✅ Enforced | **Weak** — too short minimum, weak KDF |
| Extension CSP | ✅ `script-src 'self' 'wasm-unsafe-eval'` | **Good** — for extension pages only |
| Cloudflare WAF on baryon.network | ✅ Blocks `<script>` | **Partial** — WAF bypass possible |

### What's NOT Protecting Users

| Missing Defense | Impact |
|----------------|--------|
| ❌ Session validation (`isConnected = () => true`) | Whitelist origin exploit |
| ❌ CSP on 8/16 whitelisted origins | XSS → wallet drain |
| ❌ SSL certificate pinning (all platforms) | MITM → credential theft |
| ❌ Root/jailbreak detection (removed in v16.9.0) | Local data theft |
| ❌ Device attestation (Play Integrity / App Attest) | Emulator/tampered device access |
| ❌ Password hashing (bcrypt/scrypt/argon2) | Reversible password storage |
| ❌ Authenticated encryption (AES-GCM vs AES-CBC) | Bit-flipping attacks |
| ❌ API authentication on history-records | Unauthenticated writes |
| ❌ Supabase RLS on campaign tables | Anon data access |
| ❌ Secret rotation (zero observed) | Permanent credential exposure |

---

*Generated: 2026-03-03*
*Source: ASSET_INTELLIGENCE.md (2559 lines), WHITELIST_CONNECTION_MAP.md (438 lines), 4 PoC directories*
