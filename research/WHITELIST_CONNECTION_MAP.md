# Coin98 — Full Whitelist & Connection Map

## The Core Mechanism

The Coin98 Chrome Extension (v10.4.1) has **9 internal privileged methods** that bypass all user approval popups. These are gated by a single check: `checkAccess(origin)` — which verifies the calling page's origin is in the `COIN98_SYSTEM` whitelist.

**The two that matter:**
- `sync_wallet` → decrypts ALL mnemonics from ALL wallets, returns full key material
- `aes_decrypt_coin98` → decrypts ANY encrypted data using master key

**The guards are broken:**
- `isConnected = (A, t) => true` — always passes
- `request_unlock` → always returns `{isUnlocked: true}`
- `connect_coin98` → no popup for whitelisted origins

**Result: XSS on ANY whitelisted origin = silent, total wallet drain. No popup. No user interaction.**

---

## The 16 Whitelisted Origins

```
COIN98_SYSTEM = [
  "coin98.com",                    ← Main site (Cloudflare WAF)
  "dagora.xyz",                    ← NFT marketplace (CORS:*, script-src *)
  "saros.finance",                 ← DEX (unsafe-eval, unsafe-inline)
  "baryon.network",                ← DEX (NO CSP, Cloudflare WAF only)
  "apps.coin98.com",               ← App hub (NO CSP, redirects)
  "connect.coin98.com",            ← WalletConnect bridge (S3, NO CSP, stale)
  "campaign.coin98.com",           ← Lovable.app (OUT OF SCOPE, NO CSP)
  "2025.coin98.com",               ← Lovable.app (NO CSP)
  "airdrop.coin98.com",            ← Lovable.app (NO CSP)
  "leaderboard.coin98.com",        ← Lovable.app (NO CSP)
  "kyc.oneid.xyz",                 ← 3rd party KYC (unsafe-inline)
  "c98staging.dev",                ← Staging (NO CSP)
  "coin98.dev",                    ← Dev/staging domain (NO CSP)
  "localhost",                     ← Local dev
  "127.0.0.1",                     ← Local dev
  "10.10.1.220"                    ← Office/VPN internal IP
]
```

**Protection summary: 8/16 have ZERO CSP. The other 8 all have `unsafe-inline`/`unsafe-eval` or are behind Cloudflare WAF only.**

---

## Each Whitelisted Origin — What It Connects To

### 1. dagora.xyz (NFT Marketplace) — HIGHEST PRIORITY TARGET

```
dagora.xyz (Next.js 15, Turbopack, Cloudflare CDN)
│
│ CSP: script-src * unsafe-inline unsafe-eval
│ CORS: * (wildcard — any origin can read responses)
│ XFO: NONE
│
├── api.dagora.xyz ◄── NestJS/Express backend
│   │                   ⚠️ NO CLOUDFLARE
│   │                   ⚠️ NO WAF  
│   │                   CORS: *
│   │
│   ├── /api/v1/playgrounds?slug=          (collection data)
│   ├── /api/v1/playgrounds/{slug}/{id}    (ERC721 token metadata — NFT name/desc/image/attributes)
│   ├── /api/v1/launchpad-playgrounds      (launchpad listings)
│   ├── /api/v1/launchpad-playgrounds/item/{slug}  (launchpad detail — description, story, socials)
│   ├── /api/v1/launchpad-playgrounds/register     (register address for mint — needs address + roundId)
│   ├── /api/v1/launchpad-playgrounds/pendingToken (403 — auth required)
│   ├── /api/v1/playgrounds/collection/group-by-address  (all collections)
│   ├── /api/v1/playgrounds/top-minted     (top minters — wallet addresses exposed)
│   ├── /api/v1/playgrounds/lock-metadata  (POST 403 — auth required)
│   ├── /api/v1/playgrounds/update-share-link (needs playground ID)
│   ├── /api/v1/launchpad-playgrounds/launchpads/banners (banner images)
│   └── upload/user                         (profile image upload)
│
├── general-inventory.coin98.tech ◄── Express image service
│   │   ⚠️ NO CLOUDFLARE, NO WAF
│   │   Shared ALB: alb-shared-prd-1996992288
│   │   x-powered-by: Express (leaked)
│   └── /images/*  (NFT images, avatars, banners)
│
├── inventory.coin98.com ◄── Another image service (Cloudflare)
│   └── /images/*  (collection logos)
│
└── Viction blockchain (chainId: 88, "tomo")
    └── NFT contracts (e.g. 0x2BA295918a155D08BD9592313bCb75960aB2FD61)
```

**What we confirmed:**
- URL params reflected in RSC Flight `<script>` tags on ALL routes — but server URL-encodes all special chars
- NFT descriptions are plain text, rendered with React auto-escaping (no dangerouslySetInnerHTML)
- 11 JS chunks have XSS sinks (dangerouslySetInnerHTML, innerHTML, eval) but all are in libraries (React DOM, Swiper, Lottie), not application code on user data
- Lottie has `eval()` on animation expressions — exploitable IF we control animation JSON data
- No open redirect, no JSONP, no callback params found
- `/forward` route exists on frontend (not API) — takes `host` param but just reflects in RSC

---

### 2. baryon.network (DEX) — HIGH PRIORITY

```
baryon.network (Next.js, Cloudflare CDN + WAF)
│
│ CSP: NONE ◄── zero script protection
│ WAF: Cloudflare (blocks <script>, </script>, common XSS)
│ CORS: standard
│
├── Server-side: URL params reflected in __NEXT_DATA__ urlParts (URL-encoded)
├── dangerouslySetInnerHTML ×11 in React runtime (standard, not custom)
├── Routes: /swap, /farm, /liquidity, /info, /stake, /snapshot
│
└── Backend APIs: (not fully enumerated — behind Cloudflare)
    ├── Viction blockchain (swap, farm, liquidity operations)
    └── superwallet-*.coin98.tech (shared backend)
```

**Status:** NO CSP but Cloudflare WAF blocks classic XSS vectors. WAF bypass is the path here.

---

### 3. saros.finance → dex.saros.xyz (Solana DEX)

```
saros.finance ──301──→ dex.saros.xyz (Next.js, Cloudflare)
│
│ CSP: script-src 'self' 'unsafe-eval' 'unsafe-inline'; connect-src *; 
│      frame-ancestors 'self' https://dapps.coin98.com
│
├── /info/wallet/[address] — reflects path segment in HTML <div> (6 reflections)
│   └── BUT: URL-encoded by server (< → %3C)
├── Also reflected in RSC __next_f.push() payloads (URL-encoded)
├── Routes: /swap, /farm, /liquidity, /info, /stake, /leaderboard, /saros-garden
│
└── Solana blockchain (Solana RPC endpoints)
```

**Status:** `unsafe-eval` + `unsafe-inline` in CSP. Reflections exist but URL-encoded. DOM XSS or stored XSS via Solana token metadata would bypass.

---

### 4. connect.coin98.com (WalletConnect Bridge)

```
connect.coin98.com (S3 SPA via CloudFront)
│
│ CSP: NONE
│ CORS: NONE
│ Security headers: ZERO
│ Last updated: ~Nov 2024 (stale 15+ months)
│
├── 5.6MB JS bundle: /assets/index-CZTEbnu2.js
│
├── socket.coin98.services ◄── Socket.IO server
│   │   CORS: * (wildcard — any origin can connect)
│   │   Engine.IO v4, WebSocket upgrade
│   └── Events: coin98_connect {type: "verify_sdk", message: {token: <from URL>}}
│
├── verifySession(url):
│   │   Reads "connect" URL param
│   │   Sends token directly to socket — NO VALIDATION
│   └── connect.coin98.com?connect=<ATTACKER_TOKEN>
│
├── coin98:// protocol handler:
│   │   Creates <a href="coin98://..."> and auto-clicks
│   │   Input is encodeURIComponent'd (no direct XSS)
│   └── But: mobile deep link handler may be vulnerable
│
└── sessionStorage: "Coin98Connection" → {id, chain}
```

**Status:** Zero security headers, stale SPA, socket server with CORS:*. The `connect` URL param → socket relay is a session hijack vector.

---

### 5. apps.coin98.com (App Hub)

```
apps.coin98.com ──301──→ coin98.com/wallet (Cloudflare)
│
│ CSP: NONE
│ CORS: * (wildcard)
│ URL reflected in og:url meta tag (URL-encoded)
│
└── Deep links: coin98.com/wallet/* → mobile app (AASA + assetlinks.json)
    └── Android: get_login_creds delegation (credential sharing!)
```

---

### 6-9. Lovable.app Origins (campaign, 2025, airdrop, leaderboard)

```
campaign.coin98.com ──→ Lovable.app (185.158.133.1) ──→ Supabase (jdxkhxqpoqafflwspzte)
2025.coin98.com     ──→ Lovable.app (185.158.133.1) ──→ Supabase (wxgwpabjnpylabpktlvr)
airdrop.coin98.com  ──→ Lovable.app (185.158.133.1)
leaderboard.coin98.com → Lovable.app (185.158.133.1)
│
│ ALL: CSP NONE, Security headers NONE
│ ALL: React/Vite SPAs, minimal JS (2-3 files each)
│ ALL: No parameter reflection found
│ ALL: Have ~api/analytics endpoints
│
├── campaign Supabase (jdxkhxqpoqafflwspzte.supabase.co):
│   │   PostgREST 14.1
│   │   ⚠️ RLS BYPASS: lc_campaigns table exposes wallet addresses + trading volumes (anon read)
│   └── Tables: campaigns, creator_campaigns, perp_campaigns (all readable)
│
└── 2025 Supabase (wxgwpabjnpylabpktlvr.supabase.co):
    │   PostgREST 13.0.5
    │   ⚠️ OPEN SIGNUP (disable_signup: false)
    └── Schema: admin_activity_logs (email + IP columns), wallet_addresses (user→wallet mapping)
```

**Note:** campaign.coin98.com is explicitly OUT OF SCOPE per bounty rules.

---

### 10. kyc.oneid.xyz (3rd Party KYC)

```
kyc.oneid.xyz (3rd party — OneID)
│
│ CSP: unsafe-inline
│
└── api.oneid.xyz ◄── OneID domain resolution service
    └── Used by extension for identity resolution
```

---

### 11-12. Staging/Dev Domains

```
c98staging.dev ──→ NXDOMAIN (dead/expired)
coin98.dev     ──→ AWS Route53 (staging infrastructure)
│
├── vpn.coin98.dev ──→ Pritunl VPN (corporate VPN portal exposed!)
├── superwallet-misc-api-stg.coin98.dev ──→ Staging ALB (no WAF)
├── ramper-v2-fragment-stg.coin98.dev ──→ Staging ALB (no WAF)
└── superwallet-telegramwallet-stg.teleport.coin98.dev ──→ Staging ALB
```

---

### 13-15. localhost / 127.0.0.1 / 10.10.1.220

```
localhost     ──→ ANY local web server passes origin check
127.0.0.1     ──→ ANY local web server passes origin check
10.10.1.220   ──→ Office/VPN IP passes origin check
│
└── Attack: Malicious desktop app / browser extension / local dev server
    └── Runs HTTP on localhost → calls sync_wallet → drains ALL wallets
    └── No popup, no user interaction needed
```

---

## The Backend Web (What Extension Talks To)

```
Chrome Extension v10.4.1
│
├── CLOUDFLARE-PROTECTED (WAF blocks most probes):
│   ├── api.coin98.com               (main API)
│   ├── encrypted.coin98.com         (encrypted data service)
│   ├── fragment-api.coin98.com      (social recovery fragments)
│   ├── information.coin98.com       (legacy info API)
│   ├── rapid.coin98.com             (cached data — 404 currently)
│   ├── superwallet-xpoint.coin98.tech (BOBA points — 31K wallet addrs exposed!)
│   └── superwallet-information-api.coin98.tech (chain info)
│
├── AWS ALBs — NO CLOUDFLARE:
│   │
│   ├── [WAF ALB] superwallet-markets.coin98.tech
│   │   └── Express + Helmet.js
│   │   └── /api/tokens (8.1MB!), /api/token-prices (3.6MB, 18636 tokens)
│   │
│   ├── [NO WAF ALB] superwallet-prd-1429875593
│   │   ├── superwallet-misc.coin98.tech
│   │   │   └── Express, Swagger exposed (/swagger.json — OpenAPI 3.0.0)
│   │   │   └── 7 endpoints: staking-pools CRUD (GET=no auth, POST/PUT/DELETE=auth)
│   │   │
│   │   ├── superwallet-history-records.coin98.tech
│   │   │   └── Express
│   │   │   └── ⚠️ POST /record/log — UNAUTHENTICATED WRITE TO MONGODB
│   │   │   └── ⚠️ POST /record/log/dapps — UNAUTHENTICATED WRITE
│   │   │
│   │   └── superlink-server.coin98.tech
│   │       └── Express (deep links)
│   │
│   └── [NO WAF ALB] alb-shared-prd-1996992288
│       ├── general-inventory.coin98.tech
│       │   └── Express (x-powered-by leaked), /images/*
│       └── assets-api.coin98.tech
│           └── Express (404 on most paths)
│
├── FIREBASE (GCP):
│   ├── us-central1-coin98-b7f98.cloudfunctions.net (Cloud Functions)
│   ├── coin98-b7f98.firebaseio.com (RTDB — locked, 401)
│   └── Firestore (locked)
│
├── SUPABASE (2 instances):
│   ├── jdxkhxqpoqafflwspzte.supabase.co (campaign — RLS BYPASS)
│   └── wxgwpabjnpylabpktlvr.supabase.co (2025 — OPEN SIGNUP)
│
├── S3 + CloudFront:
│   ├── connect.coin98.com (WalletConnect SPA)
│   ├── livechat.coin98.com (React CRA, LiveChat #13023900)
│   ├── telegramwallet.coin98.com (Telegram Mini App)
│   └── coin98.s3.ap-southeast-1.amazonaws.com (static assets)
│
├── 3RD PARTY:
│   ├── api.oneid.xyz (identity resolution)
│   ├── api.unisat.io/wallet-v4 (Bitcoin Ordinals)
│   ├── tonapi.io (TON blockchain)
│   ├── nft.api.live.ledger.com (Ledger NFT data)
│   ├── cdn.live.ledger.com (Ledger crypto assets)
│   └── 1,074 HTTPS + 60 WSS RPC endpoints across 48+ chains
│
└── BARE EC2 (NO CLOUDFLARE, SHARED IPs):
    ├── frontierdao.org    ─┐
    ├── interlock.news     ─┼── 3.1.33.23, 13.228.191.38 (nginx + Next.js)
    └── finwallet.app      ─┘   Compromise one → lateral to all
```

---

## Auth Headers the Extension Sends

| Header | Value | Note |
|--------|-------|------|
| `Source` | `C98EXTMSKWE` | Identifies Chrome extension |
| `Signature` | `c043...9755` | **STATIC HMAC** — same for all users, hardcoded |
| `Authorization` | `Bearer <JWT>` | Dynamic session token |

---

## Hardcoded Secrets (33 total across platforms)

| Secret | Where | Impact |
|--------|-------|--------|
| Google OAuth Client Secret `GOCSPX-████████████████████████████` | Extension (3 JS files) | Exchange auth codes → Drive tokens → .C98 backups |
| GA4 API Secret `████████████████████████` | Extension | Analytics poisoning |
| HMAC key `"coin98_token"` | Extension | Cloud backup brute-force |
| Static Signature `c043...9755` | Extension | Impersonate extension to backends |
| 3 Infura Project IDs | Extension | RPC DoS |
| BlockVision API key | Extension | Sui RPC DoS |
| TokenView API key | Extension | ETH/BSC/ETC/KCS RPC DoS |
| 5 Block Explorer API keys | Extension | Tx history DoS |
| 2 JWTs (1 with NO EXPIRY) | Extension | Permanent backend access (rejected currently) |
| TON Bearer token | Extension | TON API access |
| Google API Key | Extension | Drive API calls |
| CodePush deployment key | iOS | Push malicious RN bundle |
| Firebase DB URL | iOS | Database access (locked) |
| Facebook Client Token | iOS | Auth flow abuse |
| 10 GetBlock RPC keys | Android | RPC DoS |
| 21 staging endpoints in prod | Android | Staging access |

---

## The Kill Chain (What Matters)

```
                    ┌─────────────────────────────────┐
                    │     FIND XSS ON ANY OF THESE:   │
                    │                                 │
                    │  dagora.xyz      (CORS:*, CSP:*)│
                    │  baryon.network  (NO CSP)       │
                    │  saros.finance   (unsafe-*)     │
                    │  connect.coin98.com (NO CSP)    │
                    │  localhost/127.0.0.1 (no CSP)   │
                    └────────────┬────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────────────┐
                    │  XSS payload executes on page   │
                    │  in whitelisted origin context   │
                    └────────────┬────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────────────┐
                    │  postMessage → content script    │
                    │  → background service worker     │
                    │                                 │
                    │  checkAccess(origin) ✓ PASSES   │
                    │  isConnected() → true (broken)  │
                    │  request_unlock → {isUnlocked}  │
                    └────────────┬────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────────────┐
                    │  connect_coin98 → get deviceId   │
                    │  sync_wallet → decrypt ALL       │
                    │    mnemonics from ALL wallets    │
                    │  aes_decrypt_coin98 → decrypt    │
                    │    any remaining encrypted data  │
                    └────────────┬────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────────────┐
                    │  Exfiltrate to attacker server   │
                    │  Attacker has ALL private keys   │
                    │  for ALL 164 supported chains    │
                    │                                 │
                    │  SILENT. NO POPUP. NO APPROVAL.  │
                    └─────────────────────────────────┘
```

---

## Current XSS Status Per Target

| Target | Reflection Found | Encoding | Breakout | Status |
|--------|-----------------|----------|----------|--------|
| **dagora.xyz** | URL in RSC Flight `<script>` tags (ALL routes) | URL-encoded (`<` → `%3C`, `"` → `%22`) | ❌ No breakout yet | Server encodes properly |
| **baryon.network** | URL in `__NEXT_DATA__` urlParts | URL-encoded | ❌ Cloudflare WAF blocks | WAF bypass needed |
| **saros.finance** | Path in HTML `<div>` + RSC (6× on /info/wallet/) | URL-encoded | ❌ Server encodes | DOM XSS or stored XSS needed |
| **connect.coin98.com** | None (S3 SPA) | N/A | N/A | Socket relay + protocol handler |
| **Lovable.app origins** | None | N/A | N/A | No reflection found |
| **localhost** | N/A | N/A | ✅ WORKS | Any local server = instant drain |

---

## What's Left To Try

1. **Stored XSS via NFT metadata on dagora.xyz** — Mint NFT on Viction with HTML in name/description. If rendered unsafely anywhere (collection page, search results, og:image, social share) → persistent XSS.

2. **DOM XSS on dagora.xyz** — Client-side JS reading hash fragments, localStorage, or postMessage data and rendering unsafely. Lottie `eval()` on animation expressions is a vector if we control animation data.

3. **Cloudflare WAF bypass on baryon.network** — No CSP means ANY script execution wins. WAF bypass techniques: chunked encoding, Unicode normalization, double encoding, mutation XSS.

4. **Stored XSS via Solana token metadata on saros.finance** — Solana NFT/token metadata is stored on-chain. If saros.finance renders token names/descriptions unsafely → stored XSS.

5. **Socket.IO session hijack on connect.coin98.com** — CORS:*, token relay from URL param. Forge `coin98_connect` events from any origin.

6. **localhost proof-of-concept** — Trivially provable: local HTTP server → sync_wallet → drain. This is already a critical finding on its own.
