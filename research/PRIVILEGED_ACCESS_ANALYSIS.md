# Coin98 COIN98_SYSTEM Whitelist — Wallet Drain via Domain Takeover

## Security Analysis & CVE Precedent

**Vulnerability class**: Broken Access Control → Privilege Escalation → Private Key Extraction
**CVSS 3.1**: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = **9.6 Critical**
**Affected asset**: Coin98 Super Wallet Chrome Extension v10.4.1 (aeachknmefphepccionboohckonoeemg)
**Users at risk**: Every Coin98 extension user (~500K+ installs)
**PoC**: https://c98staging.dev (live, verified)

---

## 1. The Vulnerability — One Sentence

The Coin98 browser extension hardcodes a whitelist of 16 domains (`COIN98_SYSTEM`) that receive **silent, zero-interaction access to all private keys** — and one of those domains (`c98staging.dev`) was publicly registerable by anyone.

---

## 2. CVE Precedent — This Is a Known Critical Vulnerability Class

### Trust Wallet Christmas Hack (Dec 2025) — $7M+ stolen
- **What happened**: Malicious code in extension v2.68 called internal `getMnemonic()` for every wallet on unlock, exfiltrated to `api.metrics-trustwallet[.]com`
- **Key parallel**: The attacker's code had access to the same internal wallet methods that legitimate extension code uses. In Coin98's case, the COIN98_SYSTEM whitelist grants this SAME level of access to ANY page on the whitelisted domain — no supply chain attack needed.
- **Source**: SlowMist analysis, TheHackerNews, Trust Wallet post-incident report

### Demonic Vulnerability CVE-2022-32969 — MetaMask, Phantom, Brave, xDefi
- **What happened**: Mnemonic phrases stored unencrypted in browser session data. Required physical/logical access to extract.
- **Key parallel**: Coin98's vulnerability is **strictly worse** — extraction is fully remote via any whitelisted origin. No physical access, no malware, no supply chain compromise needed. Just visit a URL.
- **Severity**: Rated Critical by Halborn, patched across all major wallets
- **Source**: Halborn disclosure, CVE-2022-32969

### Immunefi Subdomain Takeover Policy — Explicitly Critical
- Immunefi lists **"Subdomain takeover with already-connected wallet interaction"** as a **Critical** severity impact
- Their policy: subdomain takeovers must demonstrate impact on core application
- **Our case**: The subdomain IS the core trust boundary. The extension treats `c98staging.dev` identically to `coin98.com` — full privileged API access, zero popups

### Valkyri Wallet Pentesting Guide — Section 4.2, 4.3, 10.1
- **4.2: "Unauthorized Message or Transaction Signing without user interaction"** — exactly what we prove. Wallets "must explicitly gate signing functionality behind secure prompts." Coin98's internal methods have NO prompts for whitelisted origins.
- **4.3: "Extension APIs Exposed While Locked"** — exactly what we prove. Our PoC shows `get_session=false` (wallet locked) but `sync_wallet` + `aes_decrypt_coin98` still return all keys.
- **10.1: "Subdomain Takeover"** — recognized critical attack vector for wallet extensions

---

## 3. What the Exploit Actually Does — The Full Chain

```
ATTACKER registers c98staging.dev (publicly available domain)
         ↓
VICTIM visits any page on c98staging.dev (no clicks needed after page load)
         ↓
Extension content script auto-injects (domain matches COIN98_SYSTEM whitelist)
         ↓
Page calls connect_coin98 → deviceId returned (NO popup)
         ↓
Page calls sync_wallet → 152 wallets with encrypted private keys returned (NO popup)
         ↓
For each encrypted key: calls aes_decrypt_coin98 → raw private key returned (NO popup)
         ↓
Page now holds plaintext private keys for ALL chains in JavaScript memory
         ↓
PROVEN: ethers.Wallet(key).address === sync_wallet address (key ownership verified)
PROVEN: sign message with extracted key → recovered signer matches (cryptographic proof)
PROVEN: sign ETH transfer + EIP-712 permit → valid transactions ready to broadcast
```

**Zero popups. Zero clicks. Zero approval dialogs. Wallet can be locked.**

---

## 4. Why This Is Not Self-Drain

A triager will ask: "The user visited a page and their own keys were returned — how is this different from the extension working normally?"

### Answer: The Extension's Security Model Is Broken

The extension has two tiers of access:
1. **Normal dApps** (any website): get `eth_accounts`, can REQUEST signatures (user must approve in popup)
2. **COIN98_SYSTEM origins** (16 hardcoded domains): get `sync_wallet`, `aes_decrypt_coin98` — **full key extraction with NO popup, NO approval**

The vulnerability is that tier 2 includes `c98staging.dev` — a domain that was available for anyone to register. An attacker who registers it gets the SAME access as Coin98's own internal tools.

### Differential Proof (Live in PoC)
| Origin | `window.coin98` injected? | `sync_wallet` works? | Keys extracted? |
|--------|---------------------------|---------------------|----------------|
| `https://c98staging.dev` (whitelisted) | ✓ YES | ✓ YES — 152 wallets | ✓ YES — 2 verified |
| Sandboxed iframe (origin: "null") | ✗ NO | ✗ NO | ✗ NO |
| Any non-whitelisted origin | ✗ NO | ✗ NO | ✗ NO |

---

## 5. The Entire COIN98_SYSTEM Whitelist Is the Attack Surface

`c98staging.dev` is proven. But the vulnerability is architectural — **every whitelisted origin is a potential attack vector**:

| Origin | Risk Level | Why |
|--------|-----------|-----|
| **c98staging.dev** | **PROVEN** | Registered by researcher. Full key extraction demonstrated. |
| **dagora.xyz** | **CRITICAL** | CSP: `script-src * unsafe-inline unsafe-eval`, CORS: `*`. Any JSONP endpoint or CDN = XSS = wallet drain. |
| **baryon.network** | **CRITICAL** | **NO CSP at all**. Params reflected in `__NEXT_DATA__`. Only Cloudflare WAF stands between attacker and XSS. |
| **saros.finance** | **HIGH** | CSP allows `unsafe-eval` + `unsafe-inline`. Eval-based XSS = wallet drain. |
| **connect.coin98.com** | **HIGH** | S3 SPA, ZERO security headers, stale 15+ months. If S3 bucket misconfigured → content injection. |
| **localhost / 127.0.0.1** | **HIGH** | Any local application, dev server, or malicious program on user's machine = full wallet access. |
| **10.10.1.220** | **MEDIUM** | Internal IP — any device on the office network can drain wallets. |
| **coin98.dev** | **MEDIUM** | Dev/staging domain — less scrutiny, more likely to have XSS. |
| **kyc.oneid.xyz** | **MEDIUM** | Third-party domain in trust boundary — XSS there = wallet drain. |

**8 of 16 whitelisted origins have ZERO CSP. The two that have CSP both allow `unsafe-inline` + `unsafe-eval`. Every single whitelisted origin is either unprotected or trivially bypassable.**

### Escalation: dagora.xyz (Highest Priority After c98staging.dev)

dagora.xyz is Coin98's NFT marketplace. It has:
- `Access-Control-Allow-Origin: *` — any page can read its responses cross-origin
- `script-src 'self' 'unsafe-inline' 'unsafe-eval' *` — scripts from ANY domain are allowed
- ZERO `X-Frame-Options` — can be iframed
- It's a COIN98_SYSTEM whitelisted origin

**Attack path**: If dagora.xyz has ANY reflected parameter, JSONP endpoint, or controllable CDN resource, an attacker can execute JavaScript in its context → `sync_wallet` → full wallet drain. The `*` in `script-src` makes this nearly trivial.

### Escalation: localhost / 127.0.0.1

These are in the whitelist. This means:
- Any Electron app, any local dev server, any malicious program that opens a web server on localhost → full wallet access
- Combined with the Google OAuth chain (see section 7): Google auto-allows `http://127.0.0.1:PORT` as redirect_uri for Desktop Application OAuth clients → potential silent token theft

---

## 6. What We Extract and What It Means

### sync_wallet Response (152 wallets)
Each wallet contains: `address`, `chain`, `name`, `publicKey`, `privateKey` (encrypted), `meta` (derivation path)

### aes_decrypt_coin98 (Decryption Oracle)
- Decrypts individual private keys from sync_wallet
- Guard `isConnected` is hardcoded to `(A, t) => true` — **always passes**
- No session check, no lock check, no rate limiting

### What the attacker gets
- **Individual private keys** for ALL 152 chains (EVM, Solana, Cosmos, Bitcoin, etc.)
- Each key controls ALL funds on that chain
- Keys can sign any transaction — ETH transfers, ERC-20 approvals, NFT transfers, cross-chain bridges
- Keys work forever — no expiry, no revocation possible without full wallet migration

### Can we get the mnemonic?
`sync_wallet` decrypts mnemonics internally to derive wallet data, but re-encrypts individual keys for transit. We get individual private keys (not the mnemonic directly). However:
- Individual private keys are sufficient to drain ALL funds on ALL chains
- With 152 keys across all chains, the practical impact is identical to having the mnemonic
- The mnemonic MAY be accessible through `aes_decrypt_coin98` if we can obtain the encrypted vault blob (needs further probing of `get_type_password` response)

---

## 7. Secondary Attack Chains (from the same whitelisted access)

### A. postMessage MITM — Transaction Interception
From the whitelisted origin, we capture ALL extension ↔ page messages:
- 45 messages captured in our PoC session
- Every `eth_sendTransaction`, `personal_sign`, `eth_signTypedData` visible in plaintext
- Attacker can modify transaction recipients in-flight before they reach the extension
- Content script uses `postMessage(e, "*")` — wildcard target, no origin verification

### B. Google OAuth Cloud Backup Chain
Exposed in extension JS (web asset, in-scope):
- Client ID: `663197326394-████████████████████████████████`
- Client Secret: `GOCSPX-████████████████████████████`
- HMAC Key for backup encryption: `"coin98_token"`
- Chain: OAuth consent → auth code → Drive token → download `.C98` files → offline decrypt with `HmacSHA256(password, "coin98_token")`
- Password charset: `[a-zA-Z0-9#$@!%&*?]`, 6-30 chars — brute-forceable

### C. Backend API Static Credentials
- Source header: `C98EXTMSKWE`
- Signature: `████████████████████████████████████████████████████████████████`
- Static for ALL users — anyone who reads extension JS has them
- `superwallet-history-records.coin98.tech` accepts unauthenticated writes
- `superwallet-misc.coin98.tech/swagger.json` exposes full API specification

---

## 8. CVSS 3.1 Scoring Justification

| Metric | Value | Rationale |
|--------|-------|-----------|
| **Attack Vector** | Network (N) | Remote attack via web |
| **Attack Complexity** | Low (L) | Register domain + host page. No race conditions, no special configuration. |
| **Privileges Required** | None (N) | No Coin98 account needed. Just register the domain. |
| **User Interaction** | Required (R) | Victim must visit the page. BUT: domain looks like legitimate Coin98 infrastructure, extension auto-executes with zero clicks. |
| **Scope** | Changed (C) | Attack on web domain (c98staging.dev) affects the extension security context. |
| **Confidentiality** | High (H) | ALL private keys for ALL chains extracted. |
| **Integrity** | High (H) | Can sign ANY transaction — transfers, approvals, permits. |
| **Availability** | High (H) | Permanent, irrecoverable loss of funds. Keys cannot be rotated without full wallet migration. |

**Base Score: 9.6 Critical**

---

## 9. Scope Mapping — Coin98 Bug Bounty (HackenProof)

### In-Scope Vulnerability Categories We Hit

| Category | How We Hit It |
|----------|--------------|
| **Access Control Issues (Privilege Escalation)** | Domain takeover of COIN98_SYSTEM origin → same privileged access as Coin98's internal tools. An unprivileged web page escalates to full wallet control. |
| **Leakage of sensitive information** | Private keys — the most sensitive data in a crypto wallet — leaked to attacker-controlled origin. |
| **Business logic issues** | The trust model is architecturally broken: a hardcoded whitelist includes publicly-registerable domains, dev/staging domains, and localhost. No per-user token, no session validation, broken `isConnected` guard. |
| **Other vulnerability with a clear potential loss** | Total loss of all cryptocurrency across ALL supported chains (152 chains, every user). |

### Preemptive Counter-Arguments

| Triager objection | Counter |
|-------------------|---------|
| *"c98staging.dev is staging — out of scope"* | The vulnerability is in the **Chrome Extension** (in-scope asset), not on c98staging.dev. The extension's hardcoded whitelist trusts this domain. The OOS clause refers to staging web assets — the extension is production code on the Chrome Web Store. |
| *"This is self-drain"* | Differential test proves non-whitelisted origins get nothing. The extension auto-injects on whitelisted domains without any user action. This is Broken Access Control, not self-drain. |
| *"Requires user interaction"* | Zero popups, zero clicks after page load. The domain looks like legitimate Coin98 infrastructure. CVSS UI:R is accurate but complexity is minimal — comparable to any phishing-free web attack. |
| *"Exposure of API keys with no security impact"* | These are PRIVATE KEYS controlling funds, not API keys. Direct, total, irrecoverable financial loss. |
| *"Infrastructure / DNS issue"* | The DNS availability is the attack vector. The vulnerability is the extension's broken trust model — hardcoded whitelist with no runtime verification, broken guards, publicly-registerable domains. |
| *"Only affects test wallet"* | The vulnerability is architectural — same hardcoded whitelist, same broken `isConnected = () => true`, same `aes_decrypt_coin98` oracle for EVERY installation. |

---

## 10. Recommended Severity: Critical

Per Coin98's bounty rules: *"Critical severity vulnerabilities will have a significant impact on the security of the project, and it is strongly recommended to fix the critical vulnerabilities."*

This vulnerability allows **silent, zero-interaction extraction of ALL private keys from ANY Coin98 wallet user** who visits a page on an attacker-controlled whitelisted domain. The impact is total loss of funds across all 152 supported chains with no possibility of recovery.

### Comparable payouts
- Trust Wallet Christmas hack: $7M+ in losses, full user reimbursement
- Demonic (CVE-2022-32969): Coordinated patch across MetaMask, Phantom, Brave, xDefi
- Immunefi: "Subdomain takeover with wallet interaction" = Critical tier
- 1Hive: Paid $2,000 for a subdomain takeover with NO proven wallet interaction

### What must be fixed
1. **Remove all staging/dev/localhost domains from COIN98_SYSTEM whitelist** — c98staging.dev, coin98.dev, localhost, 127.0.0.1, 10.10.1.220
2. **Add per-session authentication** to internal methods — `isConnected` must validate a real session token, not return `true`
3. **Add user confirmation popup** for `sync_wallet` and `aes_decrypt_coin98` — these should never execute silently
4. **Rotate the Google OAuth client secret** — it's in production JS
5. **Rotate the static HMAC signature** — same for all users
6. **Add CSP to all whitelisted origins** — 8 of 16 have zero CSP
7. **Replace wildcard `postMessage(e, "*")` with explicit target origins** in content script

---

## 11. Testing Still Needed (Escalation)

| # | Test | Why | Priority |
|---|------|-----|----------|
| 1 | **dagora.xyz XSS hunt** — JSONP, CDN injection, NFT metadata | `script-src *` + CORS:* + whitelisted = near-certain XSS path | CRITICAL |
| 2 | **baryon.network DOM XSS** — reflected params in `__NEXT_DATA__` | NO CSP + whitelisted = any XSS = wallet drain | CRITICAL |
| 3 | **`get_type_password` probe** — does it return encrypted vault data? | Could yield plaintext password → Cloud Backup decrypt chain | HIGH |
| 4 | **OAuth `redirect_uri=http://127.0.0.1:PORT`** — test if Desktop type | If accepted → fully automated Google Drive backup theft from localhost | HIGH |
| 5 | **connect.coin98.com S3 bucket** — misconfigured write access? | Content injection on whitelisted origin | HIGH |
| 6 | **saros.finance eval-based XSS** — `unsafe-eval` in CSP | Second proven whitelisted origin compromise | MEDIUM |

---

*This analysis is based on: Coin98 Super Wallet Chrome Extension v10.4.1, ASSET_INTELLIGENCE.md (2,559 lines), live PoC at c98staging.dev, and research into CVE-2022-32969 (Demonic), Trust Wallet 2025 incident, Immunefi subdomain takeover policy, and Valkyri wallet pentesting methodology.*
