# Broken Access Control in COIN98_SYSTEM Whitelist: Silent Extraction of All Private Keys Across 164 Chains (Extension) + Production Credential Exfiltration via Hardcoded Attacker-Controlled Endpoints (Mobile)

**Date**: 2026-03-05
**Researcher**: CPK Solutions
**Scope**: HackenProof — *.coin98.com, Chrome Extension, Android/iOS apps

---

## Executive Summary

The Coin98 Chrome Extension (production, Chrome Web Store) contains a broken access control vulnerability in its privilege model. The extension hardcodes 16 origins as `COIN98_SYSTEM` trusted domains and grants them **silent, approval-free access to decrypt and return all wallet mnemonics and private keys** via internal methods (`sync_wallet`, `aes_decrypt_coin98`). The `isConnected` guard that should gate these methods is hardcoded to `(A, t) => true` — it always passes.

Separately, the Coin98 mobile apps (production, App Store and Play Store) ship with hardcoded API endpoints pointing to infrastructure the developer does not control. Real user credentials — 27 authenticated requests containing Bearer JWTs with wallet IDs and device UUIDs from 3 iOS devices — were captured without any interception, proxy, or network modification. The app sent them to attacker-controlled infrastructure on its own.

**These are not staging environment issues.** The vulnerabilities exist in production code distributed through official app stores right now. The domain registration was the proof method; the findings are the extension's broken trust model and the mobile app's hardcoded attacker-controlled endpoints.

---

## Finding 1: Broken Access Control in Extension Privilege Model (Critical)

### Vulnerability

The Coin98 Chrome Extension defines a `COIN98_SYSTEM` whitelist of 16 origins. Any JavaScript executing on these origins can call internal wallet methods without any user interaction, popup, or approval:

- `sync_wallet` — returns all wallets with encrypted key material
- `aes_decrypt_coin98` — decrypts any encrypted key to plaintext
- `connect_coin98` — returns device ID silently
- `get_session` — returns lock state (works even when locked)

The `isConnected` check that should verify whether the user has explicitly connected a site is implemented as `(A, t) => true` — a hardcoded bypass. Every whitelisted origin is treated as permanently connected with full permissions.

### Proof of Exploitation

```
Attacker registers expired whitelisted domain (c98staging.dev)
  → Extension content script auto-injects on page load
  → JavaScript calls: postMessage({isCoin98: true, target: "sync_wallet"})
  → Extension returns 152 wallets with encrypted keys (NO popup, NO approval)
  → JavaScript calls: aes_decrypt_coin98 for each key
  → Extension decrypts to plaintext private keys
  → 2 private keys verified: address derivation + ECDSA signature match
  → All material persisted to Supabase evidence store
```

**Evidence**: `drain_captures` table in Supabase — 152 wallets, 2 verified plaintext private keys.

### Root Cause

This is not a domain takeover finding. The domain registration proved exploitability. The vulnerability is three things working together in the production extension binary:

1. **A hardcoded whitelist** that includes publicly registerable domains (`c98staging.dev`, `coin98.dev` which is currently NXDOMAIN)
2. **An `isConnected` guard** that always returns `true` — broken access control
3. **Internal methods** (`sync_wallet`, `aes_decrypt_coin98`) that decrypt all wallet material without user approval for any origin the extension considers trusted

### Whitelisted Origin Attack Surface

The whitelist includes 16 origins. Of 9 reachable production origins, **7 are critically insecure** — meaning the broken trust model is exploitable not just via expired domains but via XSS on most of the whitelisted origins:

| Origin | CSP | Frameable | Arb JS Possible | Notes |
|--------|-----|-----------|-----------------|-------|
| **dagora.xyz** | `script-src * unsafe-inline unsafe-eval` | No¹ | **YES** | Any external script loads. `CORS: *` + permissive CSP makes XSS highly feasible |
| **baryon.network** | **NONE** | No² | **YES** | **Already flagged malicious** in Phantom Wallet phishing DB. `dangerouslySetInnerHTML` in source |
| **connect.coin98.com** | **NONE** | **YES** | **YES** | S3-hosted SPA, zero headers, 5.6MB bundle with wallet signing methods |
| **campaign.coin98.com** | **NONE** | **YES** | **YES** | AI-generated (Lovable.app), shared Supabase with known RLS bypass |
| **2025.coin98.com** | **NONE** | **YES** | **YES** | No security controls |
| **airdrop.coin98.com** | **NONE** | **YES** | **YES** | AI-generated (Lovable.app), 11MB bundle with WalletConnect |
| **leaderboard.coin98.com** | **NONE** | **YES** | **YES** | AI-generated (Lovable.app) |
| **coin98.dev** | NXDOMAIN | — | — | **Available for registration** → instant whitelisted origin |
| coin98.com | CF 403 | — | — | Behind Cloudflare |

¹ `frame-ancestors 'self'` in CSP  ² `X-Frame-Options: SAMEORIGIN`

### CVSS 3.1

**Vector**: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H — **9.6 Critical**

- **Attack Complexity**: Low — register an available domain or achieve XSS on any of 7 critically insecure whitelisted origins
- **User Interaction**: Required — user visits any page on a whitelisted origin
- **Scope**: Changed — extension compromise affects all wallet funds across 164 chains
- **Confidentiality/Integrity/Availability**: High — all private keys extracted, attacker can sign any transaction, complete fund loss

---

## Finding 2: Hardcoded Attacker-Controlled Endpoints in Production Mobile Binary (High/Critical)

### Vulnerability

The Coin98 mobile apps (v16.9.0, production builds on App Store and Play Store) contain hardcoded API endpoints pointing to `internal.c98staging.dev` and `api-dagora-dev.c98staging.dev`. These domains are not owned by Coin98. The production app binary sends authenticated requests — including Bearer JWT tokens, wallet identifiers, and device UUIDs — directly to attacker-controlled infrastructure without any interception, proxy, or network modification required.

This is a **supply chain integrity failure**. The app did this to itself.

### Proof of Exploitation

```
Production iOS app (Coin98 v16.9.0) on 3 real user devices
  → App resolves internal.c98staging.dev → attacker's Netlify function
  → POST /adapters/wallet/zen/acertify with:
      - Bearer JWT (HS256, contains device ID + wallet binding)
      - Body: {"id": "<wallet-id>", "device": "<device-UUID>"}
  → 27 authenticated requests captured from 3 unique iOS devices
  → JWT payload: {id, source: "C98WLFININS", isOnChain: true, iat, exp}
  → All captured without any MITM proxy, certificate pinning bypass, or network interception
```

**Evidence**: `captures` table in Supabase — 27 POST requests, 10 unique JWT tokens, 3 device UUIDs.

### Captured Request Detail

| Field | Value |
|-------|-------|
| Endpoint | `POST /adapters/wallet/zen/acertify`, `POST /adapters/wallet/zen/ucertify` |
| Content-Type | `application/json` |
| Authorization | `Bearer eyJhbGciOiJIUzI1NiI...` (HS256 JWT) |
| Body | `{"id": "<16-char wallet ID>", "device": "<iOS device UUID>"}` |
| Source IPs | Vietnamese ISPs (118.69.x.x, 171.247.x.x) — real residential users |
| User-Agent | Coin98 iOS production app |

### Root Cause

The production mobile binary contains backend URL selection logic that includes development/internal endpoints alongside production ones. When the app selects `internal.c98staging.dev` as its backend for wallet certification endpoints, it sends authenticated requests to a domain that expired and was registered by an external party. The backend hosts found in the production Android bundle include:

- `internal.c98staging.dev` — **attacker-controlled** (wallet certification)
- `api-dagora-dev.c98staging.dev` — **attacker-controlled** (auth refresh)
- `encrypted.coin98.com` — production (behind Cloudflare)
- `encrypted.coin98.tech` — production
- `api.coin98.com` — production (behind Cloudflare)
- `main-server.dagora.xyz` — production

### Impact

An attacker controlling these domains:
1. **Captures** wallet IDs, device UUIDs, and session tokens from real users passively
2. **Controls the response** to wallet certification requests — can manipulate the app's understanding of wallet-device binding state
3. Receives credentials **continuously** as long as the domain is registered — no active attack required after initial setup

---

## Supporting Context: Systemic Security Neglect

The following findings are not submitted as independent vulnerabilities but demonstrate a pattern of systemic neglect that amplifies the severity of Findings 1 and 2.

### baryon.network — Whitelisted Origin Already Flagged Malicious

`baryon.network` is one of the 16 `COIN98_SYSTEM` whitelisted origins. It is flagged as malicious in Phantom Wallet's community phishing database. This means a known-malicious domain already has the same silent key extraction privileges described in Finding 1. Coin98 has not removed it from the whitelist.

### coin98.dev — Whitelisted Origin Available for Registration

`coin98.dev` is in the whitelist but resolves to NXDOMAIN. Any attacker can register it and immediately gain the same privileged access demonstrated in Finding 1.

### WalletConnect Relay (socket.coin98.services) — Any Origin Can Establish Sessions

`socket.coin98.services` issues Socket.IO session IDs to any origin, allowing any website to establish itself as a WalletConnect "dApp" on Coin98's relay. Combined with the `coin98://wc?uri=` deep link, an attacker can propose transaction signing sessions to Coin98 mobile users. Transaction approval still requires user interaction in the wallet UI, but the attacker appears as a legitimate dApp session.

### Extension Cryptographic Weaknesses

- Wallet passwords are **encrypted, not hashed** — `aes_decrypt_coin98` can reverse them
- Key derivation uses EvpKDF (weak, not PBKDF2/scrypt/argon2)
- The `isConnected` bypass means these weaknesses are directly exploitable from any whitelisted origin

### Mobile App Security Gaps

- **Zero SSL pinning** on all platforms
- **Root/jailbreak detection removed** in Android v16.9.0 (present in v16.7.0)
- **33 hardcoded secrets** across all platforms with zero rotation between versions
- **`usesCleartextTraffic=true`** in Android manifest

---

## Evidence Summary

| Metric | Value |
|--------|-------|
| **Wallets extracted (extension)** | 152 |
| **Private keys decrypted** | 2 (plaintext, verified via address derivation + signature) |
| **Mobile requests captured** | 27 (Bearer JWT authenticated) |
| **Unique mobile devices** | 3 (real iOS users, Vietnam) |
| **JWT tokens captured** | 10 unique |
| **Device UUIDs captured** | 3 unique |
| **Wallet IDs captured** | 4 unique |
| **Time range** | 2026-03-04 23:55 → 2026-03-05 17:12 UTC |
| **Evidence store** | Supabase (`captures` + `drain_captures` tables) |

---

## Recommendations

### Immediate (Finding 1 — Extension)

1. **Remove all non-Coin98-controlled domains from `COIN98_SYSTEM` whitelist** — no external domains, no expired domains, no registerable TLDs
2. **Fix the `isConnected` bypass** — implement actual connection state verification with explicit user approval
3. **Gate `sync_wallet` and `aes_decrypt_coin98` behind user approval** — popup confirmation for ANY key material access
4. **Implement per-origin permissions** — each origin must be explicitly approved by the user
5. **Remove `coin98.dev` and `c98staging.dev` from whitelist immediately**

### Immediate (Finding 2 — Mobile)

1. **Remove all non-production endpoints from production builds** — no staging/dev URLs in release binaries
2. **Implement build-time environment separation** — development endpoints must never reach production builds
3. **Implement SSL certificate pinning** for all API endpoints
4. **Rotate all JWT signing secrets** — attacker has captured tokens signed with current secret
5. **Audit which users' wallet certifications may have been affected** by requests to the attacker-controlled endpoint

### Architectural

1. **Replace password encryption with proper hashing** (bcrypt/argon2)
2. **Replace EvpKDF with a modern KDF** (PBKDF2/scrypt/argon2)
3. **Implement device attestation** (SafetyNet/Play Integrity for Android, DeviceCheck for iOS)
4. **Restore root/jailbreak detection** that was removed in v16.9.0
5. **Rotate all 33 hardcoded secrets** found across platforms
6. **Remove `baryon.network` from whitelist** — it's flagged as malicious
