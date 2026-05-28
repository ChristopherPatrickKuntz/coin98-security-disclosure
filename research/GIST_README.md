![SEVERITY](https://img.shields.io/badge/SEVERITY-CRITICAL-red) ![CVSS](https://img.shields.io/badge/CVSS_3.1-9.6-red) ![AUTH REQUIRED](https://img.shields.io/badge/AUTH_REQUIRED-NONE-orange) ![POC](https://img.shields.io/badge/POC-CONFIRMED-brightgreen) ![WALLETS](https://img.shields.io/badge/WALLETS_EXTRACTED-152-blue) ![KEYS](https://img.shields.io/badge/KEYS_DECRYPTED-2-blue)

# Coin98 Super Wallet — Critical Wallet Drain Vulnerability

## Silent Private Key Extraction via Hardcoded localhost Whitelist in Chrome Extension

| | |
|---|---|
| **Target** | Coin98 Chrome Extension v10.4.1 → Android v16.9.0 → iOS v16.9.0 |
| **Platform** | [HackenProof](https://hackenproof.com/programs/coin98) |
| **Severity** | Critical |
| **Authentication** | None required |
| **Date** | March 5, 2026 |
| **Author** | Christopher Patrick Kuntz |

---

## Summary

The Coin98 Chrome Extension (500,000+ users) hardcodes `127.0.0.1` and `localhost` in a privileged origin whitelist that grants **silent, popup-free access** to internal methods capable of decrypting and returning **every private key and mnemonic** across all 164 supported blockchains. The session validation function is hardcoded to `return true`.

A 30-line Node.js server on localhost extracts all wallet keys. Zero dependencies. Zero infrastructure. One "Connect" click (identical to any dApp connection).

**PoC confirmed**: 152 wallets returned, 2 unique private keys decrypted, across ~80 blockchain networks.

---

## Findings

### Finding 1: Broken Access Control in Chrome Extension Privilege Model
**CVSS 9.6 Critical** — The extension's `COIN98_SYSTEM` whitelist includes `127.0.0.1` and `localhost`. Any local HTTP server gains silent access to `sync_wallet` (decrypts all mnemonics) and `aes_decrypt_coin98` (decrypts all private keys). The `isConnected` guard is `(A, t) => true` — always passes. Standard dApp methods require popup approval; these internal methods execute silently with access to ALL wallets.

**Asset**: Chrome Extension (in-scope) — vulnerability is in the production service worker code distributed via Chrome Web Store.

### Finding 2: Production Mobile Apps Hardcode Attacker-Controlled Endpoint
**CVSS 7.4 High** — Both Android and iOS production apps hardcode `internal.c98staging.dev` as a backend endpoint. The domain was unregistered and has been registered by the researcher. 27 API requests captured including 10 JWT session tokens from real production users. Tokens are HS512-signed; escalation to account takeover requires the signing key.

**Asset**: Android + iOS apps (in-scope) — hardcoded endpoints are in the production app binaries.

---

## Evidence

**5 PoC screenshots** documenting the full attack chain from wallet unlock → connect popup → 152 wallets extracted → 2 private keys decrypted are available in the private repository:

> **[ChristopherPatrickKuntz/coin98-security-disclosure](https://github.com/ChristopherPatrickKuntz/coin98-security-disclosure)** → `poc/localhost-drain/evidence/`

| # | File | Description |
|---|------|-------------|
| 1 | `01-wallet-unlock.png` | Standard Coin98 wallet unlock |
| 2 | `02-connect-popup.png` | Connect popup from `http://127.0.0.1` — identical to any dApp |
| 3 | `03-first-attempt-timeout.png` | First connect requires one approval; then fully silent |
| 4 | `04-full-extraction-152-wallets.png` | **152 wallets** across ~80 chains, keys being decrypted |
| 5 | `05-result-2-keys-extracted.png` | **2 private keys decrypted** — "trust model broken BY DESIGN" |

---

## Vulnerable Code

```javascript
// Session validation — ALWAYS returns true (background/index_10.4.1.js)
this.isConnected = (A, t) => true;

// 16 origins with silent access to ALL wallet data
const COIN98_SYSTEM = [
  "coin98.com", "dagora.xyz", "saros.finance", "baryon.network",
  "c98staging.dev", "localhost", "127.0.0.1", "10.10.1.220",
  /* ... 8 more origins, 8/16 have zero CSP */
];
```

## Attack Chain

```
Any local process (npm pkg, Electron app, VS Code ext, etc.)
    │
    ▼
Starts HTTP server on 127.0.0.1
    │
    ▼
connect_coin98()  →  one "Connect" popup (then silent forever)
    │
    ▼
sync_wallet()     →  ALL 152 wallets with encrypted keys (silent)
    │
    ▼
aes_decrypt_coin98({data, deviceId: "any", uuid: "any"})
    │               isConnected = (A, t) => true  ← BROKEN
    ▼
PLAINTEXT PRIVATE KEYS — every wallet, every chain
```

---

## Repository

Full audit report, PoC code, evidence screenshots, and methodology documentation:

> **[ChristopherPatrickKuntz/coin98-security-disclosure](https://github.com/ChristopherPatrickKuntz/coin98-security-disclosure)** (public disclosure)

### Contents
- `README.md` — Overview with inline evidence screenshots
- `HACKENPROOF_SUBMISSION.md` — Scope-focused bounty submission (2 findings)
- `SECURITY_DISCLOSURE_REPORT.md` — Full Trail of Bits-style report (10 findings, 3 critical / 5 high / 2 medium)
- `poc/localhost-drain/server.js` — Zero-dependency localhost PoC
- `poc/localhost-drain/evidence/` — 5 PoC screenshots
- `poc/c98staging-drain/` — Subdomain takeover PoC (secondary proof)
- `ESCALATION_AUDIT.md` — CVE cross-reference and infrastructure assessment
- `ASSET_INTELLIGENCE.md` — Full static analysis (2,600 lines across 3 platforms)
- `APP_FLOW_ANALYSIS.md` — Extension architecture and message flow
- `WHITELIST_CONNECTION_MAP.md` — All 16 whitelisted origins mapped

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-03-02 | Static analysis of Chrome Extension, Android APK, iOS IPA |
| 2026-03-03 | Whitelist vulnerability identified, attack chains mapped |
| 2026-03-03 | `c98staging.dev` registered by researcher (domain was unregistered) |
| 2026-03-04 | Mobile credential capture began — 27 requests, 10 JWTs collected |
| 2026-03-05 | Localhost PoC confirmed — 152 wallets, 2 keys extracted |
| 2026-03-05 | Report submitted to HackenProof |
| 2026-06-05 | 90-day disclosure deadline |

---

## Precedent

| Incident | Impact | Comparison |
|----------|--------|------------|
| **Trust Wallet Christmas Hack (Dec 2025)** | $7M+ stolen via internal method abuse | Same vulnerability class — silent privileged method access |
| **Demonic CVE-2022-32969** | MetaMask/Phantom mnemonic extraction | Less severe — required physical device access |
| **Coinspect Coin98 Audit (2023)** | Silent wallet drain via privileged methods | Same target, same finding class — paid $1,000 |

---

*All findings based on static analysis of publicly distributed software. No unauthorized access was performed. Evidence preserved for coordinated disclosure.*
