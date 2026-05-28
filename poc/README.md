# Coin98 Proof of Concept — Reproduction Guide

## Overview

These PoCs demonstrate critical vulnerabilities in the Coin98 Chrome Extension (v10.4.1) that allow **silent extraction of all private keys** from any user who has the extension installed.

The root cause is a hardcoded `COIN98_SYSTEM` whitelist of 16 origins that receive full privileged access to internal methods (`sync_wallet`, `aes_decrypt_coin98`) — bypassing all user approval popups. The whitelist includes attacker-controllable entries: `localhost`, `127.0.0.1`, and staging domains.

---

## PoC-1: Localhost Drain (`localhost-drain/`)

**What it proves**: The trust model is fundamentally broken *by design*. `127.0.0.1` is hardcoded in the `COIN98_SYSTEM` whitelist — no domain registration, no XSS, no external infrastructure needed.

**Requirements**:
- Node.js (any version, zero dependencies)
- Chrome browser with Coin98 Extension installed
- At least one wallet configured in the extension

**Steps to reproduce**:
```bash
cd poc/localhost-drain
node server.js
# Open http://127.0.0.1:1337 in Chrome
# Approve the one-time "Connect" popup
# Watch as ALL private keys are extracted silently
```

**Expected output**: The page will display each wallet's chain, address, and decrypted private key prefix. The Node server console logs the full evidence payload.

**Attack scenario**: Any malicious desktop application, browser extension, or local development tool can spawn an HTTP server on 127.0.0.1 and silently drain all Coin98 wallets. The user sees only a benign-looking "Connect to Coin98" popup on first connection — identical to any legitimate dApp connection request.

---

## PoC-2: Subdomain Takeover Drain (`c98staging-drain/`)

**What it proves**: `c98staging.dev` — a `COIN98_SYSTEM` whitelisted origin — was registerable and is now attacker-controlled. The extension grants it identical privileges to `coin98.com`.

**Requirements**:
- The `c98staging-drain/index.html` deployed to `c98staging.dev` (currently live on Netlify)
- Chrome browser with Coin98 Extension installed

**Steps to reproduce**:
1. Visit `https://c98staging.dev` with Coin98 installed
2. Approve the one-time "Connect" popup
3. The page silently calls `connect_coin98` → `sync_wallet` → `aes_decrypt_coin98`
4. All private keys are extracted and logged

**Files**:
- `index.html` — The exploit page (looks like a legitimate staging status page)
- `netlify/functions/proxy.mjs` — Serverless proxy for backend testing from the whitelisted origin

---

## PoC-3: Mobile Credential Capture (`exchange-monitor/`)

**What it proves**: The mobile app (Android/iOS) hardcodes `internal.c98staging.dev` as a backend endpoint. Since `c98staging.dev` is attacker-controlled, all mobile API traffic to this endpoint is captured.

**Evidence**: 27 unique requests captured, 10 JWT tokens, wallet certification payloads.

---

## Attack Chain Summary

```
COIN98_SYSTEM whitelist (hardcoded in extension background.js)
    │
    ├─ localhost / 127.0.0.1  ─── PoC-1: Any local server
    ├─ c98staging.dev          ─── PoC-2: Subdomain takeover  
    ├─ baryon.network          ─── ALREADY COMPROMISED (Phantom blocklist)
    ├─ dagora.xyz              ─── CORS:*, script-src *, stored XSS vector
    └─ 12 other origins        ─── Various CSP weaknesses
         │
         ▼
    connect_coin98()  →  deviceId (one popup, then silent forever)
         │
         ▼
    sync_wallet()     →  ALL wallets with encrypted private keys (silent)
         │
         ▼
    aes_decrypt_coin98({data, deviceId: "any", uuid: "any"})
         │                    ↑
         │          isConnected = (A, t) => true  ← THE BUG
         ▼
    PLAINTEXT PRIVATE KEYS FOR EVERY WALLET
```

## Ethical Notes

- All captured credentials were logged to a researcher-controlled evidence store
- No private keys were used to sign transactions or access funds
- No user wallets were compromised during testing
- Evidence is preserved for coordinated disclosure

## CVSS 3.1

**Score: 9.6 Critical** — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

- **Network** attack vector (remote for PoC-2, local for PoC-1)
- **Low** complexity (no special conditions)
- **No** privileges required
- **Required** user interaction (one "Connect" click)
- **Changed** scope (extension compromise affects all connected chains)
- **High** confidentiality/integrity/availability impact
