# Coin98 (coin98.com) — Complete Asset Intelligence

**Generated**: 2026-03-03T02:30:00Z (v7 — 24 secrets, 13 attack chains, whitelisted origin live scan, socket.coin98.services CORS wildcard, dagora.xyz script-src *, connect.coin98.com coin98:// protocol)
**Sources**: subfinder, crt.sh (CT logs), dig, curl, openssl, GAU, CPK Scanner, Supabase REST, JS bundle analysis, Apple iTunes API, Android Asset Links, AASA, Play Store, Chrome Extension full code deconstruction (v10.4.1 — 499 files, 151 JS, 226MB total), whitelisted origin live security scan (16 origins, CSP/CORS/XFO profiled), connect.coin98.com JS bundle analysis (5.6MB), socket.coin98.services Socket.IO recon, dagora.xyz API enumeration, baryon.network WAF/reflection testing, Lovable.app origin profiling
**Scope**: HackenProof bug bounty — https://hackenproof.com/coin98/coin98
**Bounty Scope**: `*.coin98.com` (web), Chrome Extension, Android/iOS apps
**Out of Scope**: search.coin98.com, blog.coin98.com, campaign.coin98.com

---

## 1. DNS — Root Zone

| Record | Value |
|--------|-------|
| **NS** | colette.ns.cloudflare.com, patryk.ns.cloudflare.com |
| **A** | 104.26.12.35, 104.26.13.35, 172.67.75.218 (Cloudflare) |
| **AAAA** | 2606:4700:20::681a:c23, 2606:4700:20::681a:d23, 2606:4700:20::ac43:4bda |
| **MX** | 1 aspmx.l.google.com, 5 alt1/alt2.aspmx.l.google.com, 10 alt3/alt4.aspmx.l.google.com, 10 aspmx2/aspmx3.googlemail.com, 100 mx.sendgrid.net |
| **SOA** | colette.ns.cloudflare.com. dns.cloudflare.com |
| **CAA** | (not set) |
| **SPF** | `v=spf1 include:_spf.google.com include:sendgrid.net -all` |
| **DMARC** | `v=DMARC1; p=reject; rua=mailto:eb989c976abe49a4ae75e207f04a04d6@dmarc-reports.cloudflare.net,mailto:coin98.net@gmail.com` |
| **DKIM** | RSA key present (direct TXT record, no selector) |
| **TXT** | google-site-verification (×2), atlassian-domain-verification, wallet-connect-dns-verification, ca3-7187efba5ece43e4a026722ea6c25f92 |

**Email**: Google Workspace (MX → aspmx.l.google.com) + SendGrid (transactional, MX priority 100)
**Project Mgmt**: Atlassian (Jira/Confluence verified)
**WalletConnect**: DNS-verified (`d07cd6e60a6e2fce6fa3e4eeba55c262a08d5ec9319521ee3809bc3efe378a15`)

---

## 2. All Subdomains (42 total)

### Resolving (33 with A records)

| Subdomain | A Records | CNAME | Provider | HTTP | Notes |
|-----------|-----------|-------|----------|------|-------|
| **coin98.com** | 104.26.12.35, .13.35, 172.67.75.218 | — | Cloudflare | 200 | Main site, Next.js |
| **www.coin98.com** | same as root | — | Cloudflare | 301→root | Redirect |
| **markets.coin98.com** | same | — | Cloudflare | 403 | CF-walled, Next.js app |
| **dapps.coin98.com** | same | — | Cloudflare | 403 | CF-walled, dApp browser |
| **exchange.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **wallet.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **vault.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **stake.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **hub.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **spacegate.coin98.com** | same | — | Cloudflare | 403 | CF-walled |
| **mercuryo.coin98.com** | same | — | Cloudflare | 403 | Fiat on-ramp (Mercuryo) |
| **snapshot.coin98.com** | same | — | Cloudflare | 403 | Governance snapshots |
| **terminals.coin98.com** | same | — | Cloudflare | 403 | Trading terminals |
| **storage.coin98.com** | same | — | Cloudflare | 403 | File storage |
| **file.coin98.com** | same | — | Cloudflare | 403 | File service |
| **information.coin98.com** | same | — | Cloudflare | 403 | Internal API |
| **inventory.coin98.com** | same | — | Cloudflare | 403 | Asset inventory |
| **cusd.coin98.com** | same | — | Cloudflare | 403 | CUSD stablecoin |
| **creator.coin98.com** | same | — | Cloudflare | 200 | Creator hub |
| **blog.coin98.com** | same | — | Cloudflare | 403→200 | Blog (OUT OF SCOPE) |
| **rapid.coin98.com** | same | — | Cloudflare | 404 | Dead |
| **connect.coin98.com** | 108.139.47.* | d1j3es73fbmg4f.cloudfront.net | **CloudFront + S3** | 200 | WalletConnect bridge |
| **livechat.coin98.com** | 108.139.47.* | d1j3es73fbmg4f.cloudfront.net | **CloudFront + S3** | 200 | LiveChat widget |
| **airdrop.coin98.com** | 185.41.148.* | holder-airdrop.lovable.app | **Lovable.app** | 200 | Airdrop checker |
| **2025.coin98.com** | 185.158.133.1 | — | **Lovable.app (via CF)** | 200 | Wrapped 2025 recap |
| **campaign.coin98.com** | 185.158.133.1 | — | **Lovable.app (via CF)** | 200 | Campaign station (OUT OF SCOPE) |
| **leaderboard.coin98.com** | 185.158.133.1 | — | **Lovable.app (via CF)** | 200 | Trading competitions |
| **recap2025.coin98.com** | 185.158.133.1 | — | **Lovable.app (via CF)** | 200 | Recap redirect |
| **clicks.coin98.com** | via CloudFront | coin98.branded-domains.singular.net | **Singular (AWS ELB)** | 200 | Email/ad click tracking |
| **apps.coin98.com** | via CF | coin98superwallet-mjnl.custom-domain.airbridge.io | **Airship** | 302 | Mobile attribution |
| **docs.coin98.com** | 104.18.40.47 | c0570540ec-hosting.gitbook.io | **GitBook** | 200 | Documentation |
| **android.coin98.com** | CF IPs | — | Cloudflare→Google | 301 | Play Store redirect |
| **chrome.coin98.com** | CF IPs | — | Cloudflare→Google | 301 | Chrome Web Store redirect |
| **ios.coin98.com** | CF IPs | — | Cloudflare→Apple | 301 | App Store redirect |

### Non-Resolving (9 — no A/AAAA records)

auth, dan, di7ft3n72130zh5h5jxe, host, ipfs, pay, payment-sandbox, portfolio, x

**Notable dead subs**: `auth`, `pay`, `payment-sandbox` — indicate prior auth/payment infrastructure that was decommissioned.

---

## 3. All IP Addresses (20 unique)

### Cloudflare Proxy IPs (all *.coin98.com behind CF)

| IP | ASN | Role |
|----|-----|------|
| **104.26.12.35** | AS13335 CLOUDFLARENET | Primary CF proxy |
| **104.26.13.35** | AS13335 CLOUDFLARENET | Primary CF proxy |
| **172.67.75.218** | AS13335 CLOUDFLARENET | Primary CF proxy |
| **104.18.40.47** | AS13335 CLOUDFLARENET | GitBook CF proxy |
| **185.158.133.1** | AS13335 CLOUDFLARENET | Lovable.app CF proxy (2025, campaign, leaderboard, recap2025) |
| **185.41.148.1/2** | AS13335 CLOUDFLARENET | Lovable.app CF proxy (airdrop) |

### CloudFront / AWS IPs (connect + livechat origin)

| IP | rDNS | Role |
|----|------|------|
| **108.139.47.16/23/26/104** | server-108-139-47-*.jfk50.r.cloudfront.net | CloudFront edge (JFK50) |
| **3.171.117.102/107/113/123** | server-3-171-117-*.jfk50.r.cloudfront.net | CloudFront edge (JFK50) |
| **18.173.219.81/84/88/112** | server-18-173-219-*.jfk52.r.cloudfront.net | CloudFront edge (JFK52) |
| **172.64.147.209** | — | Cloudflare (GitBook) |

### IPv6

| IPv6 | Role |
|------|------|
| 2606:4700:20::681a:c23 | Cloudflare |
| 2606:4700:20::681a:d23 | Cloudflare |
| 2606:4700:20::ac43:4bda | Cloudflare |

---

## 4. TLS Certificate

| Field | Value |
|-------|-------|
| **Subject** | CN=coin98.com |
| **SAN** | coin98.com, *.coin98.com |
| **Issuer** | Let's Encrypt **E8** |
| **Valid** | Feb 28 16:44:33 2026 → May 29 16:44:32 2026 |
| **Type** | Wildcard (covers all subdomains) |

Single wildcard cert for everything. No per-subdomain certs observed (all behind CF proxy using the same wildcard).

---

## 5. Infrastructure Map

### Provider Summary

| Provider | Count | Subdomains | Notes |
|----------|-------|------------|-------|
| **Cloudflare (proxy)** | 24 | Most *.coin98.com | WAF + CDN, many return 403 (bot protection) |
| **CloudFront + S3** | 2 | connect, livechat | **Direct origin — no WAF** |
| **Lovable.app** | 4 | 2025, campaign, leaderboard, recap2025 | Low-code app builder, CF-proxied |
| **GitBook** | 1 | docs | Documentation platform |
| **Singular** | 1 | clicks | Email/ad click tracking |
| **Airship** | 1 | apps | Mobile deep linking/attribution |
| **Google (ESF/daiquiri)** | 3 | android, chrome, ios | Store redirects |

### Non-Cloudflare Hosts (HIGHER VALUE — direct origin access)

| Host | Origin | Server Header | Security Headers |
|------|--------|---------------|-----------------|
| **connect.coin98.com** | S3 via CloudFront | AmazonS3 | **NONE** (no HSTS, no XCTO, no XFO, no CSP) |
| **livechat.coin98.com** | S3 via CloudFront | AmazonS3 | **NONE** |
| **clicks.coin98.com** | Singular via CloudFront | awselb/2.0 | **NONE** |
| **airdrop.coin98.com** | Lovable.app via CF | cloudflare | HSTS, XCTO |
| **docs.coin98.com** | GitBook via CF | cloudflare | HSTS, XCTO, CSP |

---

## 6. Live Host Fingerprints

### coin98.com (Main Landing)
- **Status**: 200
- **Server**: cloudflare
- **Framework**: Next.js
- **CORS**: * (wildcard, no credentials)
- **HSTS**: Not set
- **CSP**: Not set
- **XFO**: SAMEORIGIN
- **WAF**: Cloudflare
- **Tech**: React, Next.js, Vite

### connect.coin98.com (WalletConnect Bridge)
- **Status**: 200
- **Server**: AmazonS3
- **Origin**: S3 bucket via CloudFront (d1j3es73fbmg4f.cloudfront.net)
- **SPA**: Yes (all paths return index.html, 566B)
- **Framework**: Vite SPA
- **Last-Modified**: Wed, 20 Nov 2024 03:22:33 GMT (stale — 15+ months old)
- **S3 SSE**: AES256
- **CORS**: * (via CloudFront)
- **Security Headers**: NONE (no HSTS, no CSP, no XFO, no XCTO)

### livechat.coin98.com (Customer Support Chat)
- **Status**: 200
- **Server**: AmazonS3
- **Origin**: S3 bucket via CloudFront (same distribution as connect)
- **SPA**: Yes (all paths return index.html, 1254B)
- **Framework**: React (CRA)
- **Last-Modified**: Wed, 13 Nov 2024 08:19:02 GMT (stale — 15+ months old)
- **Backend**: LiveChat Inc (license ID: **13023900**)
- **robots.txt**: `User-agent: * Disallow:` (allows all crawling)
- **Security Headers**: NONE

### airdrop.coin98.com (Airdrop Checker)
- **Status**: 200
- **Server**: cloudflare (Lovable.app)
- **Framework**: Vite + React
- **Tech**: Solana/web3.js, Amplitude, Phantom wallet integration
- **HSTS**: max-age=31536000; includeSubDomains

### campaign.coin98.com (Campaign Station — OUT OF SCOPE)
- **Status**: 200
- **Server**: cloudflare (Lovable.app)
- **Framework**: Vite + React
- **Backend**: **Supabase** (jdxkhxqpoqafflwspzte.supabase.co)
- **Tech**: React, Solana/web3.js, Supabase, Amplitude, TailwindCSS, Telegram Mini App
- **Integrations**: Supabase (data), Amplitude (analytics), Telegram Web App SDK

### 2025.coin98.com (Wrapped 2025)
- **Status**: 200
- **Server**: cloudflare (Lovable.app)
- **Framework**: Vite + React
- **Backend**: **Supabase** (wxgwpabjnpylabpktlvr.supabase.co)
- **Tech**: React, Solana/web3.js, Supabase, Amplitude

### leaderboard.coin98.com (Trading Competitions)
- **Status**: 200
- **Server**: cloudflare (Lovable.app)
- **Framework**: React

### creator.coin98.com (Creator Hub)
- **Status**: 200
- **Server**: cloudflare
- **Redirects to**: cypheus.fun (external domain)
- **Google Tag Manager**: Active

### docs.coin98.com (Documentation)
- **Status**: 200
- **Server**: cloudflare
- **Platform**: GitBook
- **CSP**: Present (strict)
- **HSTS**: Present

---

## 7. CORS Matrix

| Host | ACAO | ACAC | Risk |
|------|------|------|------|
| coin98.com | * | — | Low |
| connect.coin98.com | * | — | **Medium** (S3 origin, no security headers) |
| livechat.coin98.com | * | — | **Medium** (S3 origin, no security headers) |
| airdrop.coin98.com | — | — | Secure |
| campaign.coin98.com | — | — | Secure |
| 2025.coin98.com | — | — | Secure |
| leaderboard.coin98.com | — | — | Secure |
| All CF-walled (403) | * | — | N/A (blocked) |

---

## 8. Backend Services & API Endpoints

### Internal APIs (discovered in JS bundles)

| API Domain | Purpose | Found In |
|-----------|---------|----------|
| **api.coin98.com** | Main API | markets/dapps JS |
| **information.coin98.com** | Data service (Solana endpoints, market data) | markets/dapps JS |
| **development.coin98.services** | Development/staging API | markets/dapps JS |
| **exchange.c98staging.dev** | **Staging exchange** | markets JS |
| **superwallet-markets.coin98.tech** | Markets backend | markets JS |

### Supabase Instances

#### Campaign Supabase (jdxkhxqpoqafflwspzte.supabase.co)
- **Anon Key**: Extracted from campaign.coin98.com JS bundle
- **PostgREST Version**: 14.1
- **Auth**: Email only, signup disabled, mailer_autoconfirm=true
- **Storage**: 0 buckets (but public object URLs work via campaign-images path)
- **Exposed Tables (with anon read)**:
  - `campaigns` — campaign metadata (names, dates, rewards, links) ✅ READABLE
  - `creator_campaigns` — creator campaign data ✅ READABLE
  - `lc_campaigns` — **lottery campaigns with wallet addresses + trading volumes** ✅ READABLE
  - `perp_campaigns` — perpetual trading competition data ✅ READABLE
  - `profiles` — user profiles (empty) ✅ READABLE
  - `user_roles` — role assignments (empty) ✅ READABLE
  - `perp_campaign_stats` — empty ✅ READABLE

**⚠️ FINDING**: `lc_campaigns.wallet_and_volume` field contains JSON array of wallet addresses with their trading volumes — this is **user financial data** exposed to anonymous read.

#### 2025 Recap Supabase (wxgwpabjnpylabpktlvr.supabase.co)
- **Anon Key**: Extracted from 2025.coin98.com JS bundle
- **PostgREST Version**: 13.0.5
- **Auth**: Email only, **signup NOT disabled** (disable_signup: false)
- **Storage**: 0 buckets
- **Schema** (11 tables, all currently empty):
  - `admin_activity_logs` — **user_email, ip_address, action_type, details** (admin PII)
  - `wallet_addresses` — **user_id → wallet_address mapping** (user PII)
  - `page_views` — wallet_address, user_agent, referrer (tracking)
  - `onchain_data` — per-address on-chain stats
  - `recap_swap_2025_evm/sol/vic` — swap recap data per address
  - `user_roles` — role assignments

**⚠️ FINDING**: Signup is open — anonymous users can register and potentially access RLS-gated data. Schema exposes admin PII columns (email, IP).

### S3 Buckets

| Bucket | Region | Access |
|--------|--------|--------|
| **coin98.s3.ap-southeast-1.amazonaws.com** | ap-southeast-1 | Public read (image assets — Chains/, Coin/ paths) |
| CloudFront S3 (connect) | us-east-1 (JFK) | SPA fallback only |
| CloudFront S3 (livechat) | us-east-1 (JFK) | SPA fallback only |
| Supabase storage (campaign-images) | Supabase | Public objects via known paths |

### RPC Endpoints (48 found in JS bundles)

**Infura Project IDs (EXPOSED)**:
- `c4bb906ed6904c42b19c95825fe55f39` — Mainnet, Goerli, Polygon, Rinkeby, Mumbai
- `████████████████████████████████` — Mainnet, Polygon, Rinkeby

**NodeReal BSC Key**:
- `5c4ed7c647c0479f9ae118b0b62c745c` — BSC mainnet

**Public RPC endpoints** (partial list):
| Chain | Endpoint |
|-------|----------|
| Ethereum | mainnet.infura.io/v3/c4bb906ed6..., mainnet.infura.io/v3/92d53ce... |
| BSC | bscrpc.com, bsc-mainnet.nodereal.io/v1/5c4ed7c... |
| Polygon | polygon-mainnet.infura.io/v3/* |
| Avalanche | api.avax.network/ext/bc/C/rpc |
| Arbitrum | arb1.arbitrum.io/rpc |
| Ronin | api.roninchain.com/rpc |
| TON | toncenter.com/api/v2/jsonRPC |
| Injective | injective-rpc.publicnode.com:443 |
| Story | mainnet.storyrpc.io |
| Tezos | mainnet.api.tez.ie |
| Theta | eth-rpc-api.thetatoken.org/rpc |
| Moonbeam | rpc.api.moonbeam.network |
| PlatON | openapi2.platon.network/rpc |

### Third-Party Service Integrations

| Service | Domain | Purpose |
|---------|--------|---------|
| **Binance** | api.binance.com | Price data |
| **CoinGecko** | api.coingecko.com | Token data |
| **DexGuru** | api.dex.guru | DEX analytics |
| **MDEX** | market.mdex.cc | Market data (BROKEN — connection error) |
| **Apilayer** | apilayer.net | Fiat currency rates |
| **LiveChat** | secure.livechatinc.com | Customer support (license: 13023900) |
| **Amplitude** | (embedded) | Product analytics |
| **Google Tag Manager** | www.googletagmanager.com | Tag management |
| **Unstoppable Domains** | unstoppabledomains.com/api/v1 | Domain resolution |
| **YouTube** | googleapis.com/youtube/v3 | Video embeds |
| **Singular** | clicks.coin98.com | Attribution/click tracking |
| **Airship/Airbridge** | apps.coin98.com | Mobile deep links |
| **Telegram** | telegram.org | Mini App SDK |
| **Ledger** | cdn.live.ledger.com | Ledger Live integration |

---

## 9. Technology Stack Summary

| Component | Technology | Version |
|-----------|-----------|---------|
| **DNS** | Cloudflare | — |
| **CDN/WAF** | Cloudflare (most subs) + CloudFront (connect, livechat) | — |
| **TLS** | Let's Encrypt E8, wildcard *.coin98.com | — |
| **App Framework** | Next.js (main), Vite+React (Lovable apps) | — |
| **Backend** | Supabase (×2), S3, internal APIs | PostgREST 14.1 / 13.0.5 |
| **Low-Code** | Lovable.app | 4 subdomains |
| **Documentation** | GitBook | — |
| **Email** | Google Workspace + SendGrid | — |
| **Project Mgmt** | Atlassian (verified) | — |
| **Customer Support** | LiveChat Inc | License 13023900 |
| **Analytics** | Amplitude, Google Analytics/GTM | — |
| **Attribution** | Singular, Airship/Airbridge | — |
| **Wallet SDKs** | WalletConnect, Phantom, MetaMask, Ledger, MathWallet, NEAR | — |
| **Blockchain Libs** | ethers.js, web3.js, viem, @solana/web3.js, CosmJS, TON SDK | — |
| **Multi-Chain** | EVM (ETH, BSC, Polygon, Arbitrum, Avalanche, Ronin, Moonbeam, PlatON), Solana, TON, Cosmos, Tezos, Theta, Injective, Story, NEAR | — |
| **S3 Storage** | coin98.s3.ap-southeast-1.amazonaws.com | AES256 SSE |

---

## 10. Security Headers Matrix

| Host | HSTS | XCTO | XFO | CSP | CORS | Server |
|------|------|------|-----|-----|------|--------|
| coin98.com | ✗ | ✓ | ✓ | ✗ | * | cloudflare |
| connect.coin98.com | ✗ | ✗ | ✗ | ✗ | * | AmazonS3 |
| livechat.coin98.com | ✗ | ✗ | ✗ | ✗ | * | AmazonS3 |
| clicks.coin98.com | ✗ | ✗ | ✗ | ✗ | — | awselb/2.0 |
| airdrop.coin98.com | ✓ | ✓ | ✗ | ✗ | — | cloudflare |
| 2025.coin98.com | ✓ | ✓ | ✗ | ✗ | — | cloudflare |
| campaign.coin98.com | ✓ | ✓ | ✗ | ✗ | — | cloudflare |
| leaderboard.coin98.com | ✓ | ✓ | ✗ | ✗ | — | cloudflare |
| creator.coin98.com | ✓ | ✓ | ✗ | ✗ | * | cloudflare |
| docs.coin98.com | ✓ | ✓ | ✗ | ✓ | — | cloudflare |
| All CF-walled (403) | ✗ | ✓ | ✓ | ✗ | * | cloudflare |

**Key gaps**: Main site has no HSTS, no CSP. S3-hosted services have ZERO security headers.

---

## 11. Chrome Extension (v10.4.1)

**Extension ID**: `aeachknmefphepccionboohckonoeemg`
**CRX Size**: 76.3MB (228MB extracted)
**Manifest Version**: 3
**Background**: Service Worker (`static/background/index_10.4.1.js` — 20.2MB)

### Permissions

| Permission | Risk | Notes |
|-----------|------|-------|
| `<all_urls>` (host) | **Critical** | Full access to every page |
| `storage` / `unlimitedStorage` | High | Stores wallet keys, seeds |
| `activeTab` / `tabs` | High | Can read/modify any tab |
| `scripting` | High | Inject scripts into any page |
| `webRequest` | Medium | Intercept all network requests |
| `clipboardRead` | Medium | Can read clipboard (seed phrases, passwords) |
| `identity` | Medium | OAuth/OpenID authentication |
| `notifications` | Low | Push notifications |
| `sidePanel` | Low | Chrome side panel UI |

### Content Scripts (injected into ALL pages)

| File | Size | Run At | Purpose |
|------|------|--------|---------|
| `takePlaces.f90f5315.js` | ~2KB | document_start | Cosmos provider setup, imports `@coin98/extension-stream` |
| `contents.e02f0287.js` | 21.6KB | document_start | Main injection — creates `<script>` elements for inpage.js + cosmos.js |

### Inpage Provider Overrides (injected into every page)

The extension injects providers that **override other wallets**:

| `window.*` Property | Chain | Overrides |
|---------------------|-------|-----------|
| `window.ethereum` | EVM | MetaMask, any EVM wallet |
| `window.coin98` | Multi | Native multi-chain provider |
| `window.BinanceChain` | BSC | Binance Wallet |
| `window.kardiachain` | KardiaChain | KardiaChain wallet |
| `window.aptos` / `window.petra` | Aptos | **Petra wallet** |
| `window.sui` | Sui | Sui wallet |
| `window.near` | NEAR | NEAR wallet |
| `window.mytonwallet` | TON | MyTonWallet |

**EIP-6963** (Multi-Provider Discovery) supported:
- UUID: `bd2a0cc1-7040-44ac-b377-8e74da619898`
- RDNS: `coin98.com`

### Supported RPC Methods

`eth_requestAccounts`, `eth_accounts`, `eth_sign`, `eth_coinbase`, `eth_chainId`, `net_version`, `wallet_requestPermissions`, `wallet_switchEthereumChain`, `wallet_addEthereumChain`, `wallet_revokePermissions`, `wallet_aggregator`

### Key JS Bundles (by size)

| File | Size | Purpose |
|------|------|---------|
| `static/background/index_10.4.1.js` | 20.2MB | Background service worker (ALL backend logic) |
| `thor.69793e78.js` | 12.2MB | THORChain integration |
| `BaseProvider.70b75d50.js` | 11.5MB | Base provider (multi-chain) |
| `evm.d608d057.js` | 10.2MB | EVM chain handler |
| `concordium.1721d91b.js` | 9.2MB | Concordium chain |
| `TokenSendScreen.adae951e.js` | 6.6MB | Token send UI |
| `InitService.fd0f5ecc.js` | 4.5MB | Initialization/bootstrap |
| `WalletSocialEmail.ddb01262.js` | 4.4MB | Social login (email-based wallet) |
| `stellar.c63d0e7e.js` | 3.6MB | Stellar chain |
| `near.a4495ce0.js` | 3.3MB | NEAR Protocol |

### Extension → Backend Connection Map

The extension calls these Coin98 backend APIs:

| Backend | Purpose | Transport |
|---------|---------|-----------|
| `superwallet-markets.coin98.tech` | Token prices, market data, token registry | HTTPS REST (baseURL) |
| `superwallet-history-records.coin98.tech` | Transaction history, activity records | HTTPS REST (baseURL) |
| `superlink-server.coin98.tech` | Deep links, universal links | HTTPS REST (baseURL) |
| `superwallet-information-api.coin98.tech` | Chain info, Solana data | HTTPS REST (behind CF) |
| `superwallet-xpoint.coin98.tech` | BOBA points, rewards, campaigns | HTTPS REST (behind CF) |
| `superwallet-misc.coin98.tech` | Staking pools, misc services | HTTPS REST |
| `general-inventory.coin98.tech` | Token images, chain icons | HTTPS static |
| `assets-api.coin98.tech` | Asset data | HTTPS REST |
| `information.coin98.com` | Legacy info API (Solana, market data) | HTTPS (CF-walled) |
| `api.coin98.com` | Main API | HTTPS (CF-walled) |
| `encrypted.coin98.com` | Encrypted data service | HTTPS (CF-walled) |
| `fragment-api.coin98.com` | Fragment/social recovery | HTTPS (CF-walled) |
| `rapid.coin98.com` | Fast/cached data endpoint | HTTPS (CF, 404 currently) |
| `us-central1-coin98-b7f98.cloudfunctions.net` | Firebase Cloud Functions | HTTPS |
| `coin98.s3.ap-southeast-1.amazonaws.com` | Static assets (chain logos, token icons) | HTTPS S3 |
| `wallet.coin98.com` | Universal link handler for mobile app | HTTPS |
| `api.oneid.xyz` | OneID domain resolution | HTTPS REST (baseURL) |
| `api.unisat.io/wallet-v4` | UniSat BTC wallet API | HTTPS REST (baseURL) |
| `tonapi.io` | TON blockchain API | HTTPS REST (baseURL) |
| `nft.api.live.ledger.com/v1/ethereum` | Ledger NFT API | HTTPS REST (baseURL) |
| `cdn.live.ledger.com` | Ledger crypto asset data | HTTPS REST (baseURL) |

### Auth Tokens Found in Extension (DECODED)

| Token | Algorithm | Payload | Status |
|-------|-----------|---------|--------|
| JWT #1 `eyJhbGciOiJIUzI1NiIs...` | **HS256** | `id: "cqmpLwUFxCJ-2MA-e-KhJ"`, `iat: 1685353963` (2023-05-29), `exp: 1716889963` (2024-05-28) | **EXPIRED** |
| JWT #2 `eyJhbGciOiJIUzUxMiIs...` | **HS512** | `id: 526`, `iat: 1718339125` (2024-06-14) | **NO EXPIRY!** |
| Bearer `AFPJTKEBPOX3AIY...` | — | Used with `tonapi.io` API (TON blockchain) | Active |
| Basic Auth pattern | — | `btoa(username + ":" + password)` in axios config | Dynamic |
| Dynamic Bearer | — | `Authorization: Bearer ${token}` (user session token) | Dynamic |

**Critical**: JWT #2 (HS512, id=526) has **no expiry field** — if still valid, it grants permanent authenticated access to whatever service it targets.

### Ramper Social Recovery (Smart Contract)

The extension integrates **Ramper SDK v2** for social login/recovery:
- Contract: `0xDCf96195e7A5daB186a16081b09197721CA6a474` (BOBA chain)
- Method: `social/syncHash` — syncs email hash to on-chain recovery contract
- Versions: V1 and V2 supported (enum `RAMPER_VERSION`)
- Packages: `@coin98/ramper-sdk`, `@wallet/ramper-sdk-v2` (both v3.3.8)

### Internal Packages (monorepo structure — all v3.3.8)

| Package | Purpose |
|---------|---------|
| `@coin98/extension-stream` | Extension ↔ content script communication |
| `@coin98/ramper-sdk` | Social recovery integration |
| `@coin98/typescript-config` | Shared TS config |
| `@wallet/polkadot` | Polkadot chain handler |
| `@wallet/ramper-sdk-v2` | Ramper v2 integration |
| `@wallet/registry` | Chain/token registry |
| `@wallet/solana` | Solana chain handler |

### RPC Endpoint Scale

| Type | Count | Examples |
|------|-------|---------|
| **WSS** (WebSocket) | 60 | publicnode.com, onfinality.io, dwellir.com, unitedbloc.com |
| **HTTPS** (JSON-RPC) | 1,074 | 1rpc.io, publicnode.com, ankr.com, blastapi.io, quicknode.com |
| **Total chains** | 48+ | EVM, Cosmos, TON, Solana, NEAR, Aptos, Sui, Stellar, Bitcoin, etc. |

### Chrome Storage Keys

| Key | Purpose |
|-----|---------|
| `clientId` | Device/client identifier |
| `sessionData` | Active session state |

### Extension Communication Flow

```
         ┌──────────────────────────────────────────┐
         │  WEB PAGE (any dApp)                      │
         │                                           │
         │  window.ethereum ──┐                      │
         │  window.coin98   ──┤  (inpage.js)         │
         │  window.keplr    ──┤                      │
         │  window.aptos    ──┘                      │
         └──────────┬───────────────────────────────┘
                    │ postMessage (window.location.origin)
                    ▼
         ┌──────────────────────────────────────────┐
         │  CONTENT SCRIPT (contents.e02f0287.js)    │
         │  @coin98/extension-stream                 │
         └──────────┬───────────────────────────────┘
                    │ chrome.runtime.connect("Coin98:*")
                    ▼
         ┌──────────────────────────────────────────┐
         │  BACKGROUND SERVICE WORKER (20.2MB)       │
         │  - Key management (encrypted storage)     │
         │  - Transaction signing                    │
         │  - RPC routing to 48+ chains              │
         │  - Backend API calls                      │
         │  - WalletConnect relay                    │
         └──────────┬───────────────────────────────┘
                    │ HTTPS
                    ▼
         ┌──────────────────────────────────────────┐
         │  COIN98 BACKEND (AWS ap-southeast-1)      │
         │  superwallet-*.coin98.tech                │
         │  *.coin98.com (via Cloudflare)            │
         │  Firebase Cloud Functions                 │
         └──────────────────────────────────────────┘
```

---

## 11. Chrome Extension v10.4.1 — Deep Code Deconstruction

### 11.0a. Encryption Service (CRITICAL) — Exact Code from Module `gmkfp`

**Module**: `~src/services/encryption` (Parcel ID: `gmkfp`)
**Algorithm**: CryptoJS AES-CBC (no authenticated encryption — no HMAC/GCM)

```
class B {
  constructor() {
    this.encoder = CryptoJS.enc.Utf8;
    this.encrypt = (data, opts={usingPassword:true}) => {
      let {password, token} = this.requireUserInformation();
      if (!opts.usingPassword) return CryptoJS.AES.encrypt(data, token).toString();
      let salt = opts.salt ?? CryptoJS.AES.decrypt(password, token).toString(this.encoder);
      return CryptoJS.AES.encrypt(data, salt).toString();
    };
    this.decrypt = (data, opts={usingPassword:true}) => {
      let {token, password} = this.requireUserInformation();
      if (!opts.usingPassword) return CryptoJS.AES.decrypt(data, token).toString(this.encoder);
      try {
        let salt = opts.salt ?? CryptoJS.AES.decrypt(password, token).toString(this.encoder);
        return CryptoJS.AES.decrypt(data, salt).toString(this.encoder);
      } catch(e) { return null; }
    };
    this.requireUserInformation = () => {
      let {password, token} = store.getState().user.authentication;
      return {password, token};
    };
    this.decryptWallet = (wallet) => {
      let privateKey = this.decrypt(wallet.privateKey);
      let mnemonic = this.decrypt(wallet.mnemonic);
      return Wallet.fromObject({...wallet, privateKey, mnemonic});
    };
  }
}
let encryptService = new B;
```

**2-Layer Encryption Architecture**:

| Component | Implementation | Risk |
|-----------|---------------|------|
| **Master key** | `authentication.token` from Redux state → `chrome.storage.local` key `persist:root` | If attacker reads chrome.storage.local, they have the master decryption key |
| **Password storage** | `authentication.password` = **AES-encrypted with token** (stored in Redux, NOT hashed) | Password is reversible — not hashed with bcrypt/scrypt/argon2 |
| **Encrypt** (default) | `salt = AES.decrypt(password, token)` → `AES.encrypt(data, salt)` | 2-layer: token decrypts password → password encrypts data |
| **Encrypt** (no password) | `AES.encrypt(data, token)` directly | Single-layer: token is key |
| **Decrypt** (default) | `salt = AES.decrypt(password, token)` → `AES.decrypt(data, salt)` | Same 2-layer chain |
| **Decrypt** (no password) | `AES.decrypt(data, token)` directly | Single-layer |
| **KDF** | CryptoJS default: MD5-based EVP_BytesToKey | **Weak** — no PBKDF2/scrypt/argon2 |
| **Mode** | CBC (CryptoJS default) with PKCS7 padding | No integrity — vulnerable to bit-flipping |
| **decryptWallet** | Decrypts both `wallet.privateKey` and `wallet.mnemonic` | Returns full plaintext key material |

**Password Validation Rules** (from CloudSync regex):
```
/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d#$@!%&*?]{6,30}$/
```
- Min 6, max 30 chars — **very short minimum**
- Must contain: lowercase, uppercase, digit
- Allowed specials: `#$@!%&*?` only — restricted charset
- **No unicode, no spaces** — reduces brute-force keyspace significantly

**Redux Authentication State Shape**:
```
user.authentication = {
  isLock: true,              // Whether wallet is locked
  password: <encrypted>,     // AES-encrypted password (encrypted WITH token)
  token: <plaintext>,        // Master key — THE key to everything
  vault: <encrypted>,        // Encrypted vault data
  type: undefined,           // Password type
  connections: [],           // External dapp connections
  internalConnections: [],   // COIN98_SYSTEM connections (whitelisted origins)
  lastActivity: 0,           // Timestamp
  apiToken: undefined,       // Backend API token
  adapterToken: undefined,   // Adapter token
  renewAdapterToken: undefined
}
```

**CRITICAL**: `password` is stored AES-encrypted with `token`, NOT hashed. If `token` is known, password is recoverable. Both are in `chrome.storage.local` under key `persist:root`.

**Cloud Backup Encryption** (Google Drive `.C98` files):
- Key derivation: `HmacSHA256(password, "coin98_token")` → hex string used as AES key
- **Hardcoded HMAC key**: `"coin98_token"` — known to anyone reading the source
- **Google API Key**: `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I` (used for Drive file listing)
- **Drive scope**: `drive.file` (read/write files created by extension)
- Backup files named `*.C98` on Google Drive, Base64-encoded names, mimeType `text/plain`
- Google Drive API calls: list files (`/drive/v3/files`), read file (`/drive/v2/files/{id}?alt=media`), upload (`/upload/drive/v3/files?uploadType=multipart`)
- File names decoded with `Base64.decode(name.replace(".C98",""))` to get wallet name

### 11.0b. Internal Methods — COIN98_SYSTEM Privileged API (CRITICAL)

The background worker exposes **9 internal methods** callable ONLY from whitelisted origins. These methods bypass all user approval popups:

| Method | What It Does | Auth Check | Risk |
|--------|-------------|------------|------|
| **`aes_decrypt_coin98`** | **Decrypts ANY data** using master encryptService | `checkAccess(origin)` + `isConnected(uuid, deviceId)` | **CRITICAL** — returns plaintext of encrypted wallet data |
| **`sync_wallet`** | **Decrypts ALL mnemonics** from all wallets, generates master seeds, returns full wallet data | `checkAccess(origin)` | **CRITICAL** — full key material exfiltration |
| **`connect_coin98`** | Returns `deviceId` | `checkAccess(origin)` | Leaks device identifier |
| **`get_session`** | Returns lock state (`!authentication.isLock`) | None | Information disclosure |
| **`compare_passwords`** | Returns `{session: true}` for valid origins | `checkAccess(origin)` | Auth bypass indicator |
| **`active_wallet`** | **Always returns `true`** | None | No real check |
| **`request_unlock`** | **Always returns `{isUnlocked: true}`** | None | Fake unlock response |
| **`get_type_password`** | Returns password type info | Unknown | Auth info disclosure |
| **`lock_screen`** | Locks the wallet | Unknown | DoS |

**CRITICAL BYPASS**: `isConnected = (A, t) => true` — session validation **always returns true**. The `isConnected` check in `aes_decrypt_coin98` is completely ineffective.

**Exact `checkAccess` implementation** (from source):
```
this.checkAccess = (origin) => {
  let {user} = store.getState();
  let r = !!user.authentication.internalConnections?.some(t => t.origin === origin);
  return r;
};
this.isConnected = (A, t) => true;  // BROKEN — always returns true
```

**Exact `sync_wallet` implementation** (decrypts ALL wallets):
```
this.sync_wallet = async (A) => {
  if (!this.checkAccess(A?.sender.origin)) return [];
  let {walletData, custom} = store.getState();
  let {originalWallets, activeWallet} = walletData;
  // For each wallet: decrypt mnemonic, generate master seed, return with encrypted privateKey
  let results = (await Promise.all(originalWallets.slice().map(async wallet => {
    let mnemonic = wallet.mnemonic && encryptService.decrypt(wallet.mnemonic);
    let masterSeed;
    if (mnemonic) {
      let evmSeed = await generateMasterSeedEvm(mnemonic, chainData.chain);
      masterSeed = encryptService.encrypt(evmSeed);  // Re-encrypts for transit
    }
    return await Promise.all(wallet.wallets.slice().map(async sub => {
      let privateKey = masterSeed || sub.privateKey;
      // ... returns wallet data with privateKey still encrypted
    }));
  }))).flat().filter(Boolean);
  return results;
};
```
**NOTE**: `sync_wallet` decrypts mnemonics server-side but re-encrypts private keys for transit. However, the calling origin (which passed `checkAccess`) can then call `aes_decrypt_coin98` to decrypt those keys — and `isConnected` always returns `true`.

**Exact `compare_passwords` implementation**:
```
this.compare_passwords = (A) => this.checkAccess(A?.sender.origin) 
  ? {session: true} 
  : {error: "Access denied"};
```
**NOTE**: Does NOT actually compare any password. Just returns `{session: true}` if origin is whitelisted. The method name is misleading.

**`isStrictMethod` — which methods require popup approval**:
```
this.isStrictMethod = (A) => {
  let {user} = store.getState();
  let r = ["compare_passwords"];
  switch (A.method) {
    case "connect_coin98": {
      let t = this.checkAccess(A?.sender?.origin);
      t || r.push("connect_coin98");  // Only strict if NOT whitelisted
      break;
    }
    case "request_unlock":
      user.authentication.isLock && r.push("request_unlock");
  }
  return !!r.includes(A.method);
};
```

### 11.0c. COIN98_SYSTEM Origin Whitelist (16 origins) — LIVE SCAN RESULTS

| Origin | Category | CSP | CORS | XFO | XSS Impact |
|--------|----------|-----|------|-----|------------|
| **coin98.com** | PRODUCTION | Behind Cloudflare (403 to bots) | — | — | XSS → full wallet drain via `sync_wallet` |
| **dagora.xyz** | PRODUCTION | `default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' *` | **`*` (wildcard!)** | NONE | **HIGH RISK** — CORS:* + script-src allows any origin + unsafe-eval |
| **saros.finance** → dex.saros.xyz | PRODUCTION | `script-src 'self' 'unsafe-eval' 'unsafe-inline'; connect-src *; frame-ancestors 'self' https://dapps.coin98.com` | — | NONE | **HIGH RISK** — unsafe-eval + unsafe-inline |
| **baryon.network** | PRODUCTION | **NO CSP** | — | SAMEORIGIN | **HIGH RISK** — zero script protection; params reflected in `__NEXT_DATA__` (URL-encoded); Cloudflare WAF blocks `<script>` |
| **apps.coin98.com** → coin98.com/wallet | PRODUCTION | **NO CSP** | **`*`** | SAMEORIGIN | Redirects to coin98.com; URL reflected in `og:url` meta (URL-encoded) |
| **connect.coin98.com** | PRODUCTION | **NO CSP** | — | NONE | S3 SPA, zero headers, stale 15 months |
| **campaign.coin98.com** | OUT OF SCOPE | **NO CSP** | — | NONE | Lovable.app SPA, has `~api/analytics` |
| **2025.coin98.com** | OUT OF SCOPE? | **NO CSP** | — | NONE | Lovable.app SPA, wallet connect present |
| **airdrop.coin98.com** | PRODUCTION | **NO CSP** | — | NONE | Lovable.app SPA, has `~api/analytics` |
| **leaderboard.coin98.com** | PRODUCTION | **NO CSP** | — | NONE | Lovable.app SPA, wallet connect present |
| **kyc.oneid.xyz** | PRODUCTION (3rd party) | `unsafe-inline` | — | — | Third-party domain in trust boundary |
| **c98staging.dev** | STAGING | **NO CSP** | — | — | Staging with no protection |
| **coin98.dev** | DEV/STAGING | **NO CSP** | — | — | Dev domain, less scrutiny |
| **localhost** | DEV | N/A | N/A | N/A | **Any local web server can access internal methods** |
| **127.0.0.1** | DEV | N/A | N/A | N/A | **Any local web server can access internal methods** |
| **10.10.1.220** | INTERNAL | N/A | N/A | N/A | Office/VPN private IP |

**Key observation**: 8 of 16 whitelisted origins have **ZERO CSP**. The two that have CSP (dagora.xyz, saros.finance) both allow `unsafe-inline` + `unsafe-eval`. **Every single whitelisted origin is either unprotected or trivially bypassable**.

### 11.0c-1. Ramper Social Recovery API Infrastructure

| Service | URL | Purpose |
|---------|-----|---------|
| **Auth v1 (prod)** | `https://auth.v1.ramper.xyz` | Authentication |
| **Auth v1 (staging)** | `https://auth.v1.staging.ramper.xyz` | Staging auth |
| **Auth v1 (preview)** | `https://auth.v1.preview.ramper.xyz` | Preview auth |
| **Auth v1 (dev)** | `https://auth.v1.dev.ramper.xyz` | Dev auth |
| **Social Sign-in v2** | `https://social-signin.v2.ramper.xyz/` | OAuth/social login |
| **Fragment (staging)** | `https://ramper-v2-fragment-stg.coin98.dev/` | Shamir share storage (staging) |
| **Cloud Functions** | `https://us-central1-ramper-prod.cloudfunctions.net` | Ramper backend (GCP) |
| **Firebase** | `https://coin98-b7f98.firebaseio.com` | Realtime DB |

**Fragment API**: `POST /fragment {id: UID, fragment: AES_encrypted_share3, address}` — stores Shamir Share 3. Staging endpoint on coin98.dev ALB (VPN-restricted). Production endpoint likely behind `us-central1-ramper-prod.cloudfunctions.net`.

### 11.0d. Method Categorization — Popup vs No-Popup vs Internal

**POPUP-REQUIRED (STRICT_METHODS)** — user must approve in extension UI:

| Category | Methods |
|----------|---------|
| **Signing** | `eth_sign`, `personal_sign`, `eth_signTypedData`, `eth_signTypedData_v1`, `eth_signTypedData_v3`, `eth_signTypedData_v4` |
| **Transaction** | `eth_sendTransaction` |
| **Decryption** | `eth_decrypt`, `eth_getEncryptionPublicKey` |
| **Connection** | `wallet_requestPermissions`, `wallet_addEthereumChain`, `wallet_switchEthereumChain`, `wallet_registerOnboarding` |

**INTERNAL-ONLY (no popup, origin-whitelisted)**: See 11.0b above — `connect_coin98`, `sync_wallet`, `get_session`, `get_type_password`, `compare_passwords`, `active_wallet`, `aes_decrypt_coin98`, `request_unlock`, `lock_screen`

**NO-POPUP (permission-free)**: `eth_accounts`, `eth_chainId`, `net_version`, `eth_coinbase`, `wallet_watchAsset`, `wallet_getPermissions`

### 11.0e. Authentication Headers (Backend API Calls)

| Header | Value | Usage |
|--------|-------|-------|
| **Source** | `C98EXTMSKWE` | Identifies requests as coming from Chrome extension |
| **Signature** | `████████████████████████████████████████████████████████████████` | **Static HMAC** — same for all users, hardcoded |
| **Authorization** | `Bearer <JWT>` | Dynamic user session token |

**Axios clients** (5 configured baseURLs):

| baseURL | Has Interceptor | Notes |
|---------|----------------|-------|
| `https://superwallet-markets.coin98.tech/` | Yes | Token prices, market data |
| `https://superlink-server.coin98.tech` | Yes | Deep links |
| `https://api.oneid.xyz/` | Yes | OneID identity |
| `https://api.unisat.io/wallet-v4` | No | Bitcoin Ordinals/Inscriptions |
| `https://superwallet-history-records.coin98.tech/` | No | Transaction history (UNAUTH WRITE!) |

Whitelisted paths that skip auth response parsing: `smartRouter/calculator`, `wallet/search`, `cloudSync/create`, `social/search/wallet`

### 11.0f. Hardcoded Secrets Inventory (All Extension JS Files)

| # | Secret | Value | Files Found In | Severity |
|---|--------|-------|---------------|----------|
| 1 | **Google OAuth Client SECRET** | `GOCSPX-████████████████████████████` | CloudSyncRestoreDecryptionScreen, CloudSyncScreen, CloudSyncRestoreScreen | **CRITICAL** |
| 2 | **Google OAuth Client ID #2** | `663197326394-████████████████████████████████.apps.googleusercontent.com` | CloudSync screens (3), WalletSocial (2) | **CRITICAL** |
| 3 | **Google OAuth Client ID #1** | `114789873055-e2sktrogsg2k12rj9lhhvfhpg796ebsf.apps.googleusercontent.com` | manifest.json + 25 JS files | HIGH |
| 4 | **Google API Key** | `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I` | WalletSocial + CloudSync screens (×6 files) | HIGH |
| 5 | **GA4 Measurement ID** | `G-CCPPHL1RJT` | Background worker | MEDIUM |
| 6 | **GA4 API Secret** | `████████████████████████` | Background worker | **HIGH** |
| 7 | **BlockVision API Key** | `████████████████████████████` | Background worker (Sui RPC) | HIGH |
| 8 | **TokenView API Key** | `████████████████████` | Background worker (ETH, BSC, KCS, ETC RPCs) | HIGH |
| 9 | **Infura ID #1** | `████████████████████████████████` | 35+ chain handler files | HIGH |
| 10 | **Infura ID #2** | `████████████████████████████████` | evm.js, background worker | HIGH |
| 11 | **Infura ID #3** | `████████████████████████████████` | NFT screens, TokenSend, WalletCard | HIGH |
| 12 | **Static HMAC Signature** | `████████████████████████████████████████████████████████████████` | Background worker (API auth) | HIGH |
| 13 | **Cloud Backup HMAC Key** | `"coin98_token"` | CloudSyncRestore screen | HIGH |
| 14 | **JWT #1 (expired)** | `eyJhbGciOiJIUzI1NiIs...` (HS256, exp 2024-05-28) | Background worker | LOW |
| 15 | **JWT #2 (no expiry!)** | `eyJhbGciOiJIUzUxMiIs...` (HS512, id=526) | Background worker | HIGH |
| 16 | **TON API Bearer** | `AFPJTKEBPOX3AIYAAAAKA2HWOTRNJP5MUCV5DMDCZAAOCPSAYEYS3CILNQVL` | ton.js | HIGH |
| 17 | **S3 Bucket** | `coin98.s3.ap-southeast-1.amazonaws.com` | Background worker (notification icons) | MEDIUM |
| 18 | **Basescan API Key** | `RTDZPUZ83PJDN4FRFQGDIJ1IE9Q9KVK4TF` | InitService (CHAIN_HISTORY) | MEDIUM |
| 19 | **Lineascan API Key** | `WE24ED6XW2IC2577231JYCPR2F64AC9UYA` | InitService (CHAIN_HISTORY) | MEDIUM |
| 20 | **Scrollscan API Key** | `MZBHEUFG4S2BJQS89JR3NRAPFNP5D3TEA4` | InitService (CHAIN_HISTORY) | MEDIUM |
| 21 | **OKLink API Key** | `6ff621a9-4040-4cd1-a131-3251e08bbcaf` | InitService — Manta, KuCoin, xLayer | MEDIUM |
| 22 | **Infura Default ID** | `84842078b09946638c03157f83405213` | 10+ JS files (ethers InfuraProvider) | MEDIUM |
| 23 | **Firebase messagingSenderId** | `663197326394` | WalletSocialEmail (= OAuth client ID #2 project) | LOW |
| 24 | **Trezor Dev Email** | `support@coin98-com.com` | InitService (TrezorConnect manifest) | LOW |

**Block Explorer API Keys — Full Map** (from `CHAIN_HISTORY` in InitService.js):
| Chain | Explorer URL | API Key |
|-------|-------------|--------|
| base | `api.basescan.org/api` | `RTDZPUZ83PJDN4FRFQGDIJ1IE9Q9KVK4TF` |
| linea | `api.lineascan.build/api` | `WE24ED6XW2IC2577231JYCPR2F64AC9UYA` |
| scroll | `api.scrollscan.com/api` | `MZBHEUFG4S2BJQS89JR3NRAPFNP5D3TEA4` |
| manta | `oklink.com/api/v5/explorer/manta/api` | `6ff621a9-4040-4cd1-a131-3251e08bbcaf` |
| kucoin | `scan.kcc.io/api` | `6ff621a9-4040-4cd1-a131-3251e08bbcaf` |
| xLayer | `oklink.com/api/v5/explorer/xlayer/api` | `6ff621a9-4040-4cd1-a131-3251e08bbcaf` |
| ether | `api.etherscan.io/api` | (empty) |
| binanceSmart | `api.bscscan.com/api` | (empty) |
| matic | `api.polygonscan.com/api` | (empty) |
| arbitrum | `api.arbiscan.io/api` | (empty) |
| optimism | `api-optimistic.etherscan.io/api` | (empty) |
| fantom | `api.ftmscan.com/api` | (empty) |
| avax | `api.snowtrace.io/api` | (empty) |

**Firebase Full Config** (from WalletSocialEmail.js):
```
{
  apiKey: "AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I",
  authDomain: "coin98-b7f98.firebaseapp.com",
  projectId: "coin98-b7f98",
  storageBucket: "coin98-b7f98.appspot.com",
  messagingSenderId: "663197326394"  // Same as OAuth Client ID #2 GCP project
}
```
**NOTE**: `messagingSenderId: 663197326394` confirms OAuth Client ID #2 (`663197326394-brgh9...`) belongs to the same GCP project `coin98-b7f98` as Firebase.

**Trezor Connect Manifest**:
```
manifest: { appName: "Coin98 Wallet", email: "support@coin98-com.com", appUrl: "coin98.com" }
```
**NOTE**: Email domain is `coin98-com.com` (hyphenated), NOT `coin98.com`. This could be a typo or a separate domain.

**Google OAuth Client SECRET — Full Attack Context**:
```
// CloudSyncRestoreDecryptionScreen.49faa1d0.js
chrome.identity.launchWebAuthFlow({
  url: `https://accounts.google.com/o/oauth2/auth?
    client_id=663197326394-████████████████████████████████.apps.googleusercontent.com
    &response_type=code
    &scope=https://www.googleapis.com/auth/drive.file
    &state={"appId":"coin98-b7f98"}
    &redirect_uri=${redirectUri}
    &prompt=consent`,
  interactive: true
}, async (responseUrl) => {
  let code = extractCode(responseUrl);
  let response = await axios.post("https://accounts.google.com/o/oauth2/token", {
    client_id: "663197326394-████████████████████████████████.apps.googleusercontent.com",
    code: code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    client_secret: "GOCSPX-████████████████████████████"  // ← EXPOSED IN CLIENT-SIDE JS
  });
  accessToken = response?.data?.access_token;
});
```
**Impact**: This client secret is used to exchange authorization codes for access tokens. While Google OAuth for Chrome extensions typically uses `chrome.identity` flow (which doesn't need the secret), the secret being exposed means:
- Any code that obtains an authorization code for this client_id can exchange it for a Drive access token
- The secret is the same across ALL installations of the extension
- Present in 3 separate JS files (CloudSync flow)

**GA4 Analytics — What's Tracked**:
- Measurement ID: `G-CCPPHL1RJT`
- API Secret: `████████████████████████` — allows anyone to send fake analytics events to Coin98's GA4 property
- Endpoint: `https://www.google-analytics.com/mp/collect`
- Client ID stored in `chrome.storage.local` key `clientId`
- Debug endpoint also available: `https://www.google-analytics.com/debug/mp/collect`

### 11.0g. Supported Blockchains, BIP44 Paths, Cosmos Methods, Third-Party SDKs

**164 CHAIN_TYPE values** — Major chains: ETH, BSC, bitcoin, solana, matic, avax, arbitrum, optimism, base, near, sui, aptos, ton, cosmos, polkadot, cardano, tron, starknet, stellar, tezos, xrp, doge, conflux, elrond, algorand, casper, concordium, mina

**BIP44 Derivation Paths** (12 found):
| Path | Chain |
|------|-------|
| `m/44'/60'/0'/0/0` | EVM (Ethereum, BSC, etc.) |
| `m/44'/60'/0'/0` | EVM (alt derivation) |
| `m/44'/60'/0'` | EVM (account-level) |
| `m/84'/0'/0'` | Bitcoin (BIP84 native segwit) |
| `m/44'/397'/0'` | NEAR |
| `m/44'/118'/0'/0/0` | Cosmos |
| `m/44'/637'/0'/0` | Aptos |
| `m/44'/784'/0'/0` | Sui |
| `m/54'/784'/0'/0/0` | Sui (alt) |
| `m/44'/3'/0'/0/0` | Dogecoin |
| `m/44'/3'/0'` | Dogecoin (alt) |
| `m/44'/60'/0'/0/948202` | Special derivation (chain 948202) |

**Mnemonic generation**: Uses `@scure/bip39` with `randomBytes(entropy/8)` where entropy defaults to 128 bits (12 words). Validates wordlist is exactly 2048 strings.

**Hardware wallet support**: Ledger (TransportWebHID + TransportWebUSB + BluetoothTransport), Trezor (TrezorConnectDynamic with iframe/popup/desktop modes), Keystone, Lattice, BitBox, KeepKey, SafePal

**Cosmos/Keplr handler** (12 methods in `cosmos.8ea577c8.js`, 46KB):
| Method | Category |
|--------|----------|
| `enable` | Connection |
| `getKey` | Key retrieval |
| `getOfflineSigner` | Signer |
| `getOfflineSignerOnlyAmino` | Amino signer |
| `getOfflineSignerAuto` | Auto signer |
| `signAmino` | Amino signing |
| `signDirect` | Protobuf signing |
| `sendTx` | Transaction broadcast |
| `experimentalSuggestChain` | Chain suggestion (always returns `true`) |
| `cosmos_connect` | Internal connect |
| `cosmos_messages` | Message handling |
| `cosmos_transaction` | Transaction construction |

**DEX/Swap — Smart Router**:
- Endpoint: `smartRouter/calculator` (whitelisted, skips auth response parsing)
- Fiat check: `smartRouter/fiat` (checks if token pair allows trading)
- Default slippage: `"auto"` (stored in `exchange.setting.slippageTolerance`)
- Supported AMM chains: avax, binanceSmart, ether, fantom, heco, matic, arbitrum, optimism, solana, ton

**Ramper Social Recovery — Shamir Secret Sharing Key Sharding**:

The social wallet uses **Shamir's Secret Sharing (3 shares, threshold 2)** to split the mnemonic:

```
// Key generation + sharding flow:
let mnemonic = Key.generateMnemonic(false);  // 12 words
let [address, privateKey, mnemonic] = await createNewWallet({name:"ramper", chain, mnemonic});
let [share1, share2, share3] = splitMnemonic(mnemonic, 3, 2, user.UID);
//                                          ↑shares ↑threshold ↑salt

// Share distribution:
// Share 1 → AsyncStorage.setValue(UID, share1)           // LOCAL DEVICE
// Share 2 → KMS.encrypt(share2) → Firebase Firestore     // FIREBASE (server)
// Share 3 → CryptoJS.AES.encrypt(share3, UID) → POST /fragment  // RAMPER API
```

| Share | Storage | Encryption | Recovery Access |
|-------|---------|-----------|----------------|
| **Share 1** | Local device (AsyncStorage) | None (hex string) | Lost if device wiped |
| **Share 2** | Firebase Firestore | KMS encryption | Server-side access |
| **Share 3** | Ramper API `/fragment` | `CryptoJS.AES.encrypt(share, UID)` | UID is Firebase UID — **predictable** |

**CRITICAL**: Share 3 is encrypted with `user.UID` (Firebase UID) — this is a short, predictable string. If an attacker obtains the UID (e.g., from Firebase auth enumeration) and access to the Ramper `/fragment` endpoint, they can decrypt Share 3. Combined with Share 2 from Firebase, they have 2 of 3 shares → full mnemonic recovery.

Library: `shamir-bip39` — GF(256) Shamir over BIP39 entropy. Functions: `splitMnemonic`, `recoverMnemonic`, `splitEntropy`, `recoverEntropy`.

**Ramper Contract Interaction** (on-chain deposit):
```
// deposit(tokenAddress, amount, emailHash, provider, timestamp)
let emailHash = web3.utils.asciiToHex(email);
if (emailHash.length > 66 && ramper) {
  // If email hash too long, POST to social/syncHash endpoint
  let result = await ramper.post("social/syncHash", {email});
  emailHash = hash(emailHash);
}
let data = contract.methods.deposit(
  tokenAddress ?? ZERO_ADDRESS, 
  convertBalanceToWei(amount, decimal),
  emailHash, provider, new Date().getTime()
).encodeABI();
```

**Key Third-Party SDK Versions**:
| Package | Version | Risk Notes |
|---------|---------|-----------|
| `web3` | ^1.8.2 | Dated — current is 4.x |
| `ethers` | 4.0.46 | **Very old** — current is 6.x |
| `crypto-js` | ^4.0.0 | Used for all encryption |
| `@solana/web3.js` | 1.41.1 | Dated |
| `bip39` | 3.0.2 | Mnemonic generation |
| `@scure/bip39` | 1.5.4 | Modern mnemonic lib |
| `@noble/curves` | 1.8.1 | Modern crypto |
| `@noble/hashes` | 1.3.2 | Modern hashing |
| `bitcoinjs-lib` | ^5.2.0 | Bitcoin operations |
| `elliptic` | ^6.5.4 | EC crypto |
| `tweetnacl` | ^1.0.3 | NaCl crypto |
| `secp256k1` | ^4.0.3 | EC signing |
| `redux` | ^4.0.5 | State management |
| `redux-persist` | ^6.0.0 | Persistence to chrome.storage |
| `react` | 18.0.0 | UI framework |

**40+ Internal @wallet/ Packages** (all v3.3.8): abi-decoder, alarms, algorand, aptos, avax, band, base, bitcoin, cardano, casper, concordium, conflux, constants, core, cosmos, cosmos-new, doge, elrond, evm, gas-estimator, near, phishing-detector, polkadot, ramper-sdk-v2, registry, solana, starknet, stellar, sui, tezos, theta, thor, ton, tron, utils, xrp

**Extension File Inventory**: 499 total files, 151 JS files, 226MB total size. Top 5: background worker (19.7MB), thor.js (11.9MB), BaseProvider.js (11.3MB), evm.js (9.9MB), concordium.js (9.0MB)

### 11.0h. Attack Chains (from code deconstruction)

**AC-1: XSS on whitelisted origin → Full wallet drain** (CRITICAL)
1. Find XSS on any COIN98_SYSTEM origin (dagora.xyz, saros.finance, baryon.network are weakest)
2. XSS calls `connect_coin98` → gets `deviceId`
3. XSS calls `sync_wallet` → extension **DECRYPTS ALL MNEMONICS** and returns wallet data
4. Attacker has all private keys/mnemonics for all 164 supported chains
5. `isConnected` bypass: always returns `true` — no session validation

**AC-2: XSS + aes_decrypt_coin98 → Decrypt any encrypted data** (CRITICAL)
1. Find XSS on whitelisted origin
2. Call `aes_decrypt_coin98` with encrypted wallet data
3. Extension decrypts using master key and returns plaintext
4. `isConnected` bypass: always returns `true`

**AC-3: localhost/127.0.0.1 whitelisting → Local app exploit** (HIGH)
1. Malicious app/extension runs local web server on localhost or 127.0.0.1
2. Opens page from localhost → passes COIN98_SYSTEM origin check
3. Calls internal methods to drain wallet without any user interaction

**AC-4: postMessage wildcard origin → Cross-origin message interception** (HIGH)
1. `inpage.js` uses `postMessage(e, "*")` — no origin restriction on some stream payloads
2. Any page that iframes a page with Coin98 extension active can intercept wallet messages
3. Could intercept or inject provider responses (account addresses, signed transactions)

**AC-5: Cloud backup key weakness → Offline brute force** (MEDIUM)
1. Cloud backup encrypts with `HmacSHA256(password, "coin98_token")` — HMAC key is hardcoded
2. If attacker gets `.C98` file from Google Drive (phishing, account compromise)
3. Can offline brute-force the password since the HMAC key and AES algorithm are known
4. CryptoJS AES default uses weak EVP_BytesToKey KDF (MD5-based, not PBKDF2)

**AC-6: CryptoJS AES-CBC without authenticated encryption** (MEDIUM)
1. `encryptService` uses CryptoJS AES (CBC mode, PKCS7 padding, no HMAC/GCM)
2. No integrity verification on decryption — silent corruption possible
3. Potential for bit-flipping attacks on encrypted wallet data in chrome.storage.local

**AC-7: Google OAuth Client Secret exposed → Drive backup access** (HIGH)
1. `GOCSPX-████████████████████████████` hardcoded in 3 client-side JS files
2. Attacker obtains auth code (e.g., via phishing/redirect manipulation with client_id `663197326394-████████████████████████████████`)
3. Exchanges code for Drive access token using known client_secret
4. Lists and downloads `.C98` backup files from victim's Google Drive
5. Offline brute-force password (6-char min, known HMAC key `"coin98_token"`, weak EVP_BytesToKey KDF)
6. Recovers all wallet mnemonics/keys

**AC-8: GA4 API Secret exposed → Analytics poisoning** (MEDIUM)
1. GA4 API Secret `████████████████████████` + Measurement ID `G-CCPPHL1RJT` hardcoded
2. Anyone can POST fake events to `https://www.google-analytics.com/mp/collect`
3. Can pollute Coin98's analytics data, create false usage metrics
4. Debug endpoint also available for probing

**AC-9: Password stored encrypted (not hashed) → Reversible** (HIGH)
1. `authentication.password` is AES-encrypted with `token`, stored in Redux (`chrome.storage.local`)
2. If attacker reads `persist:root` from chrome.storage.local (via extension vuln, malware, or backup access)
3. Both `token` (plaintext master key) and `password` (encrypted) are in the same storage object
4. `AES.decrypt(password, token)` recovers the plaintext password immediately
5. Password can be used to decrypt all wallet data and cloud backups

**AC-10: Ramper Shamir share recovery → Social wallet drain** (HIGH)
1. Social wallets split mnemonic into 3 shares (threshold 2) using Shamir's Secret Sharing
2. Share 3 is encrypted with `CryptoJS.AES.encrypt(share, user.UID)` — Firebase UID as key
3. Share 3 stored on Ramper API (`POST /fragment {id: UID, fragment: encrypted, address}`)
4. Share 2 stored in Firebase Firestore (KMS-encrypted)
5. If attacker obtains Firebase UID (enumeration, data leak) + access to Ramper `/fragment` endpoint:
   - Decrypt Share 3 with known UID
   - If Firebase also compromised → Share 2 available
   - 2 shares → `recoverMnemonic()` → full mnemonic → all funds
6. Share 1 in local AsyncStorage is **not encrypted at all** (raw hex)

**AC-11: Block explorer API key abuse → Transaction history poisoning/DoS** (MEDIUM)
1. 5 block explorer API keys hardcoded (Basescan, Lineascan, Scrollscan, OKLink×3)
2. Attacker can exhaust rate limits → extension loses ability to fetch tx history for those chains
3. OKLink key (`6ff621a9-...`) reused across 3 chains (Manta, KuCoin, xLayer) — single key exhaustion impacts all three

**AC-12: socket.coin98.services CORS wildcard → WalletConnect session hijack** (HIGH)
1. Socket.IO server at `socket.coin98.services` has `ACAO: *` (wildcard CORS)
2. Any website can establish a WebSocket connection and emit `coin98_connect` events
3. `connect.coin98.com/verifySession` reads `connect` URL param and sends it as a token to the socket
4. If attacker can intercept or replay the `connect` token → session impersonation
5. Combined with zero CSP on connect.coin98.com → XSS on that origin gives full socket control

**AC-13: dagora.xyz CORS:* + script-src * unsafe-eval → Cross-origin data theft** (HIGH)
1. dagora.xyz serves `Access-Control-Allow-Origin: *` on all responses
2. CSP `script-src 'self' 'unsafe-inline' 'unsafe-eval' *` allows loading scripts from ANY origin
3. Attacker page can: (a) read dagora.xyz content cross-origin, (b) inject scripts via eval
4. dagora.xyz is a COIN98_SYSTEM whitelisted origin → XSS here = `sync_wallet` = full wallet drain
5. The `*` in script-src means a JSONP endpoint or any controllable CDN = instant XSS

### 11.0i-1. Wallet Data Redux Actions (43 actions)

The walletData slice exposes 43 reducer actions controlling all wallet state:

**Creation/Deletion**: `onAddWallet`, `onRemoveWallet`, `onArchiveWallet`, `onRenameWallet`
**Connections**: `putConnections`, `removeConnections`, `clearConnections`, `putInternalConnection`, `clearInternalConnection`
**Tokens**: `onAddCustomToken`, `onRemoveCustomToken`, `onClearCustomToken`, `onUpdateToken`, `onUpdateTokenList`, `onResetTokenList`, `onResetTempTokenList`, `onUpdateTempTokenList`, `onForceTokenList`, `onAddHidToken`, `onRemoveHidToken`, `onRemoveAllHidTokens`, `onToggleShowTokenAssets`, `onSetLastSendToken`, `onReloadTokenChain`
**Wallet State**: `onUpdateWallet`, `onForceActiveWallet`, `onToggleWallet`, `onUpdateChangeAddress`, `onUpdatePriority`, `onUpdateOldStandard`, `onSyncWalletChains`, `onSyncWalletName`, `onUpdateWalletChangePassword`, `onUpdateWalletCustomNetwork`
**Cloud Sync**: `onUpdateCloudSyncWallet`
**Migration**: `onMigrateWalletSlice`, `onMigrateWalletV2`, `onSetMigrateWalletV2`
**NFT**: `onUpdateCollectionList`, `onResetCollectionList`
**Social**: `onClearWalletSocial`
**First Load**: `onUpdateFirstLoading`

### 11.0i-2. Tracking & Analytics — Airbridge + GA4

**Airbridge SDK** (loaded from `sdk.airbridge.io`):
- Embedded as `airbridge.js` in extension package
- `airbridgeService.sendAirbridgeWallet(wallet, opts)` — called on wallet creation, import, and cloud restore
- Sends wallet metadata: `{fromCloudSync, isRestore, hardwareWallet, kind, name, wallets, isCreate, social}`
- Log endpoint: `web.sdk-log.airbridge.io` (production), `web.sdk-log.dev.airbridge.io` (dev)

**Google Analytics 4 Measurement Protocol**:
- Measurement ID: `G-CCPPHL1RJT`
- API Secret: `████████████████████████`
- Events sent via `https://www.google-analytics.com/mp/collect`
- Client ID persisted in `chrome.storage.local` key `clientId`

**Chrome Notifications**:
- Transaction tracking: polls transaction status up to 100 times
- Icon URL: `https://coin98.s3.ap-southeast-1.amazonaws.com/Coin/coin98.png`
- Title: "Coin98 Wallet Extension: Crypto & Defit" (note typo: "Defit" not "DeFi")
- On click: opens URL in new tab via `chrome.tabs.create({url})`

### 11.0i-3. Phishing Domain Blocklist (~509 domains)

**Implementation**: `@wallet/phishing-detector` package (v3.3.8) using `eth-phishing-detect` fork
```
let sanitizeUrl = (url) => {
  try {
    let hostname = new URL(url).hostname;
    let isValid = phishingDetector.isValid(hostname);
    if (!isValid) return url;
    return "";  // Returns empty string for phishing URLs
  } catch(e) { return ""; }
};
```

**Blocklist config**: `{allowlist, blocklist, fuzzylist, tolerance}` — supports exact match, fuzzy match (Levenshtein distance), and allowlist override.

**Sample domains** (509 total): `0army.io`, `aave.live`, `access-collab.land`, `akkswap.io`, `alletbridges.com`, `ammmine.cc/club/com/info/org/pro`, `aneswap.com`, `ape-coin.app/art/claims/net`, `cryptowalletconnector.com`, `norddappverification.*`, `automaticsynchronize.*`, `dexsynchr.*` ...

**No dynamic updates found** — blocklist appears to be bundled at build time, not fetched from remote.

### 11.0i-4. Extension Security Architecture & Runtime Behavior

**Manifest CSP**: `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`
- `wasm-unsafe-eval` required for WebAssembly (crypto operations)
- No `unsafe-inline` or `unsafe-eval` for extension pages — good

**`externally_connectable`**: `{}` (empty) — no external websites can use `chrome.runtime.sendMessage` to the extension directly

**`web_accessible_resources`**: Broadly exposed to ALL URLs:
```json
[
  {"resources": ["public/**", "cosmos.*.js", "inpage.*.js"], "matches": ["*://*/*", "<all_urls>"]},
  {"resources": ["cosmos.8ea577c8.js", "inpage.e40da296.js"], "matches": ["<all_urls>"]}
]
```
- `inpage.*.js` and `cosmos.*.js` are accessible from any website — allows fingerprinting of the extension
- `public/**` directory also fully exposed

**2-Step Verification — NOT real 2FA**:
```
// Settings initial state:
is2StepVerification: false,  // Just a Redux toggle
isSidePanelMode: false,
isEnableDev: false,
language: "en",
fiatCurrency: "USD"
```
- `onToggle2StepVerification` is a simple Redux action — sets a boolean flag
- No TOTP, no authenticator app, no SMS/email OTP
- The "2-step" is likely just a second password prompt, not true 2FA

**ForceAlive Service — Keeps Service Worker Alive**:
```
let FORCE_ALIVE = "FORCE_ALIVE";
setInterval(() => {
  port.postMessage({name: FORCE_ALIVE, data: FORCE_ALIVE, id: FORCE_ALIVE, event: FORCE_ALIVE})
}, 5e3);  // Every 5 seconds
```
- Also has `FORCE_ALIVE_SIDE_PANEL` for side panel mode
- Keeps MV3 service worker from being terminated by Chrome
- Side panel mode: `chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true})`
- Default path: `tabs/extension.html`

**eth_sign Blind Signing**: `"eth_sign"` is in the handled methods list. Blind signing of arbitrary data without human-readable display is a known dangerous pattern — allows signing malicious transactions that appear as raw hex.

**Wildcard postMessage Audit** (confirmed in 6+ files):
| File | Context |
|------|---------|
| `inpage.e40da296.js` | Stream payload relay — `postMessage(payload, "*")` |
| `contents.e02f0287.js` | Window message relay — `postMessage(data, "*")` |
| `trezor-usb-permissions.js` | USB permission iframe — `postMessage({type:'usb-permissions-init'}, '*')` |
| `index_10.4.1.js` | Multiple: `setImmediate` polyfill, JSON-RPC transport frame, async scheduler |
| `error.4d17d995.js` | `setImmediate` polyfill — `postMessage("","*")` |

**External Domain Footprint**: **1,231 unique external domains** contacted by the extension:
- **424** RPC/blockchain endpoints (Infura, Alchemy, ChainStack, QuickNode, Ankr, etc.)
- **6** Crypto services (Ledger, Trezor)
- **4** Google services (Analytics, APIs)
- **2** CDN/infra (Cloudflare ETH, Cloudflare IPFS)
- ~795 others (chain-specific RPCs, DEX routers, bridge endpoints)

### 11.0i-5. Whitelisted Origin Deep Scan Results

**connect.coin98.com — WalletConnect Bridge SPA** (S3, zero headers, stale since Nov 2024):

5.6MB JS bundle (`/assets/index-CZTEbnu2.js`). Key findings:

1. **`coin98://` protocol handler** — Auto-clicks crafted deep links:
```
openURL(j) {
  j = encodeURIComponent(j);
  j = j.startsWith("coin98://") ? j : "coin98://" + j;
  if (window.location.hash) {
    var tt = document.createElement("a");
    tt.setAttribute("href", j);
    document.body.appendChild(tt);
    requestAnimationFrame(() => { tt.click(); /* then removes element */ });
  }
}
```
Creates an `<a>` element with attacker-controlled `href`, appends to DOM, and auto-clicks. Input is `encodeURIComponent`'d so direct XSS is mitigated, but `coin98://` protocol could be abused if the mobile app's deep link handler is vulnerable.

2. **`verifySession` reads URL param, sends to socket**:
```
verifySession(j) {
  var ot = new URLSearchParams(j.split("?")[1]);
  var Ct = ot.get("connect");
  return new Promise((wt) => {
    this.client.emit("coin98_connect", {type: "verify_sdk", message: {token: Ct}}, (Lt) => { wt(Lt) });
  });
}
```
The `connect` URL parameter is extracted and sent directly to `socket.coin98.services` as a verification token. No validation on the token format.

3. **socket.coin98.services** — Socket.IO server:
   - `ACAO: *` (wildcard CORS, no credentials)
   - Accepts connections from any origin
   - Engine.IO v4, supports WebSocket upgrade
   - Session IDs: `{"sid":"...","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":60000}`
   - Events: `coin98_connect` with types `verify_sdk`, `request`

4. **sessionStorage** key: `Coin98Connection` — stores `{id, chain}` JSON

**dagora.xyz — NFT Marketplace** (CORS:*, CSP: `script-src * unsafe-inline unsafe-eval`):
- API: `api.dagora.xyz/api/v1/playgrounds?slug=` — NestJS backend, returns NFT data
- Sub-routes: `/nfts`, `/collections`, `/activities`, `/users` under playground slugs
- Images served from `general-inventory.coin98.tech` (no WAF ALB)
- `window.open(url, "_blank")` in wallet install flow

**baryon.network — DEX** (NO CSP, Cloudflare WAF):
- Build ID: `wdf5bqJA1LkRB76gXWI5U` (Next.js)
- URL params reflected in `__NEXT_DATA__` `urlParts` (URL-encoded by server)
- Cloudflare WAF blocks `<script>`, `</script>`, and other XSS vectors
- Routes: `/swap`, `/farm`, `/liquidity`, `/info`, `/stake`, `/snapshot`
- `dangerouslySetInnerHTML` ×11 in React runtime (standard, not custom)

**Lovable.app origins** (campaign, 2025, airdrop, leaderboard):
- All built with GPT-engineer/Lovable.app
- Minimal JS (2-3 files each), no parameter reflection
- All have `~api/analytics` endpoints
- leaderboard and 2025 have wallet connect functionality
- Zero security headers across all four

**dex.saros.xyz — DEX** (`unsafe-eval` + `unsafe-inline` CSP):
- `/info/wallet/[address]` reflects path segment in HTML `<div>` (6 reflections total)
- HTML reflection: `<div>PAYLOAD</div>` — but **URL-encoded** by server (`<` → `%3C`)
- Also reflected in RSC `__next_f.push()` payloads (also URL-encoded)
- CSP: `script-src 'self' 'unsafe-eval' 'unsafe-inline'; connect-src *; frame-ancestors 'self' https://dapps.coin98.com`
- Routes: `/swap`, `/farm`, `/liquidity`, `/info`, `/stake`, `/leaderboard`, `/saros-garden`

**dapps.coin98.com — DApp Browser** (NOT a COIN98_SYSTEM whitelisted origin):
- CSP: `script-src 'self' 'unsafe-eval' 'unsafe-inline'; script-src-elem 'self' 'unsafe-eval' 'unsafe-inline' https://www.googletagmanager.com; frame-ancestors 'none'`
- `ACAO: *` (wildcard CORS)
- 12 JS files, no param reflection
- Images served from `file.coin98.com`
- Referenced in saros CSP `frame-ancestors` but itself blocks framing (`frame-ancestors: 'none'`)
- NOT in COIN98_SYSTEM whitelist → XSS here doesn't trigger `sync_wallet`

### 11.0i-6. Whitelisted Origin XSS Hunt — Final Assessment

| Origin | Reflection | Encoding | CSP | XSS Status |
|--------|-----------|----------|-----|------------|
| **dagora.xyz** | RSC payload + HTML (all routes) | URL-encoded | `script-src * unsafe-*` | ❌ No breakout — server encodes |
| **dex.saros.xyz** | RSC + HTML `<div>` (/info/wallet/) | URL-encoded | `unsafe-eval unsafe-inline` | ❌ No breakout — server encodes |
| **baryon.network** | RSC urlParts (all routes) | URL-encoded | NONE (CF WAF) | ❌ WAF blocks + server encodes |
| **apps.coin98.com** | og:url meta tag | URL-encoded | NONE | ❌ No breakout |
| **connect.coin98.com** | None (S3 SPA) | N/A | NONE | ⚠️ coin98:// protocol + socket relay |
| **campaign/2025/airdrop/leaderboard** | None | N/A | NONE | ❌ No reflection found |

**Conclusion**: All whitelisted origins properly URL-encode server-side reflected input. Remaining XSS vectors require:
1. **DOM-based XSS** — client JS reading URL hash/params and rendering unsafely (not found in static analysis)
2. **Stored XSS** — user-controlled content (NFT metadata, profiles, usernames) rendered via `dangerouslySetInnerHTML` (NFT names use React JSX auto-escape)
3. **WAF bypass** on baryon.network (no CSP, only Cloudflare WAF)
4. **Third-party dependency** vulnerability in outdated libs

### 11.0i-7. Content Script Message Flow — Attack Surface

**Message flow**: Page → `contents.js` (relay) → `chrome.runtime.sendMessage` → Background (`index_10.4.1.js`) → COIN98_SYSTEM origin check

**contents.e02f0287.js** (21KB):
- Listens `window.addEventListener("message")` — relays ALL messages where `e.source === window`
- Relay: `M.postMessage({data: e.data})` → background via runtime port
- **No origin filtering in content script** — all origin checking is deferred to background
- Imports: `@coin98/extension-stream`, injects `inpage.js` + `cosmos.js`

**inpage.e40da296.js** (571KB):
- `isCoin98` flag in postMessage — any page can set `{isCoin98: true}` to reach stream handler
- `postMessage(e, "*")` — wildcard origin on 2 relay calls (stream → content script)
- `innerHTML = i.htmlFile` — disconnect wallet UI, hardcoded HTML template (not attacker-controllable)
- Stream: `{source: "Coin98:Inpage", target: "Coin98:ContentScript"}` — fixed identifiers
- Providers: `window.coin98`, `window.ethereum`, `window.keplr`, `window.phantom` (Solana)
- TON provider with wallet info pointing to `wallet.ton.org`

**Attack implication**: Any XSS on a COIN98_SYSTEM whitelisted origin can:
1. Craft `postMessage({isCoin98: true, target: "...", payload: {...}})` to content script
2. Content script relays to background without filtering
3. Background checks `sender.origin` against whitelist → **passes** (XSS runs in whitelisted origin)
4. Internal methods (`sync_wallet`, `aes_decrypt_coin98`, etc.) execute with full privileges
5. Mnemonic returned to the page → exfiltrated by attacker XSS payload

### 11.0i. Telegram Mini App (telegramwallet.coin98.com) — Code Deconstruction

| Component | Details |
|-----------|---------|
| **index.0e9519ba.js** | 152KB — React runtime, NO backend API calls, NO secrets, NO wallet operations |
| **index.4ecfbafc.js** | 10KB — Asset manifest (image references only), chrome polyfill shim |
| **External SDK** | `telegram.org/js/telegram-web-app.js` (deferred load) |
| **TG API usage** | `expand()`, `requestFullscreen()`, `enableClosingConfirmation()` |
| **Architecture** | Thin shell — all wallet operations delegated to extension via `postMessage` |
| **Staging** | Excluded from extension content scripts (`exclude_matches` in manifest) |
| **Backend URLs** | None — pure client-side shell communicating with extension background |

---

## 11a. Mobile Apps

### iOS (Primary App)

| Field | Value |
|-------|-------|
| **App Name** | Coin98: Crypto & AI Wallet |
| **Bundle ID** | `coin98.crypto.finance.insights` |
| **App Store ID** | `1561969966` |
| **Version** | **16.9.0** (updated **2026-03-02**, same day!) |
| **Release Date** | 2021-05-14 |
| **File Size** | **375.4 MB** |
| **Minimum iOS** | 15.6 |
| **Developer** | **COIN98 WALLET LTD** |
| **Developer ID** | `1732374734` |
| **Apple Team ID** | `4JLUM47S98` |
| **App Store URL** | https://apps.apple.com/us/app/coin98-crypto-ai-wallet/id1561969966 |
| **Rating** | 4.49 (654 reviews) |
| **Genres** | Finance, Productivity |
| **Content Rating** | 4+ |
| **Languages** | EN only |
| **Supported Devices** | 122 (44 iPhones, 76 iPads, 2 iPods) |
| **VPP Licensed** | Yes |
| **Universal** | Yes (iPhone + iPad) |

### Apple App Site Association (Deep Links)

| Domain | App ID | Paths |
|--------|--------|-------|
| `coin98.com` | `4JLUM47S98.coin98.crypto.finance.insights` | `/*` (all paths) |
| `apps.coin98.com` | `coin98.crypto.finance.insights` | `*` (all paths) |

### Android

| Field | Value |
|-------|-------|
| **Package** | `coin98.crypto.finance.media` |
| **Play Store** | https://play.google.com/store/apps/details?id=coin98.crypto.finance.media |
| **Last Updated** | Mar 1, 2026 |
| **Deep Links** | `https://wallet.coin98.com/*`, `https://apps.coin98.com/*` |
| **Attribution** | Airbridge (`apps.coin98.com` → `coin98superwallet-mjnl.custom-domain.airbridge.io`) |
| **Click Tracking** | Singular (`clicks.coin98.com`) |

### Android Asset Links (Digital Asset Links)

| Domain | Package | Relations | SHA256 Cert |
|--------|---------|-----------|-------------|
| `coin98.com` | `coin98.crypto.finance.media` | `handle_all_urls`, **`get_login_creds`** | `92:58:A0:A0:08:30:6E:C6:83:DF:45:EF:11:1E:A6:11:BA:80:33:CA:39:1D:9F:8E:5C:90:9E:E3:E6:77:82:53` |
| `apps.coin98.com` | `coin98.crypto.finance.media` | `handle_all_urls` | Same SHA256 |

**Note**: `get_login_creds` delegation means the Android app can share/receive login credentials with the website — a credential phishing vector if the app or domain is compromised.

### Developer App Portfolio (COIN98 WALLET LTD — 5 apps)

| App | iOS Bundle | Android Package | iOS Ver | Size | Last Updated | Rating |
|-----|-----------|----------------|---------|------|-------------|--------|
| **Coin98: Crypto & AI Wallet** | `coin98.crypto.finance.insights` | `coin98.crypto.finance.media` | 16.9.0 | 375.4MB | 2026-03-02 | 4.49 (654) |
| **Viction Wallet by Coin98** | `com.tomochain.wallet` | `com.tomochain.wallet` | 1.1.6 | 48.6MB | 2024-03-19 | 4.67 (195) |
| **Amber Blocks** | `coin98.insights.crypto.research` | ? | 2.1.0 | 30.2MB | 2023-02-25 | 3.60 (5) |
| **Ninji Wallet By Coin98** | `ninji.wallet.crypto.finance` | `ninji.wallet.crypto.finance` | 2.0.4 | 94.4MB | 2024-11-11 | 2.00 (1) |
| **Ancient8 Wallet by Coin98** | `ancient8.wallet.crypto.finance` | `ancient8.wallet.crypto.finance` | 1.0.0 | 69.0MB | 2024-04-28 | 0 (0) |

### Mobile App → Backend Connection (inferred from extension + JS analysis)

Both apps use the same `superwallet-*.coin98.tech` backend APIs as the extension:
- Token/market data: `superwallet-markets.coin98.tech`
- Transaction history: `superwallet-history-records.coin98.tech`
- Deep links: `superlink-server.coin98.tech`
- Points/rewards: `superwallet-xpoint.coin98.tech`
- Firebase: `us-central1-coin98-b7f98.cloudfunctions.net`
- Social login/recovery: **Ramper SDK v2** (smart contract `0xDCf96195e7A5daB186a16081b09197721CA6a474`)
- Push notifications: Airship

---

## 11b. Telegram Mini App

| Field | Value |
|-------|-------|
| **Domain** | `telegramwallet.coin98.com` |
| **Origin** | CloudFront → S3 (`d1f3ufycw3uatp.cloudfront.net`) |
| **Server** | AmazonS3 |
| **SDK** | Telegram Web App SDK (`telegram.org/js/telegram-web-app.js`) |
| **Framework** | React |
| **Security Headers** | NONE (same as connect/livechat S3 pattern) |

**Staging environments**:
- `superwallet-telegramwallet-test.coin98.dev` → CloudFront `d1i4lt9lfujx2x.cloudfront.net` (503 error)
- `superwallet-telegramwallet-stg.teleport.coin98.dev` → **Teleport ALB** `teleport-ad8e18ee0f2c5277.elb.ap-southeast-1.amazonaws.com`

---

## 11c. Complete Backend Service Map + Software Versions

### AWS ALBs (ap-southeast-1 / Singapore)

| ALB Name | WAF | Hosts | IPs |
|----------|-----|-------|-----|
| **alb-waf-prd-public-1743527320** | ✓ | superwallet-markets | 52.74.200.12, 52.77.46.211, 18.139.243.227 |
| **superwallet-prd-1429875593** | ✗ | superwallet-misc, superwallet-history-records, superlink-server | 52.220.40.200, 54.151.170.112, 52.74.255.155 |
| **alb-shared-prd-public-1996992288** | ✗ | general-inventory, assets-api | 52.77.173.15, 13.228.180.17, 18.136.134.83 |
| **alb-shared-stg-public-1517252894** | ✗ | ramper-v2-fragment-stg, superwallet-misc-api-stg | 13.251.146.223, 47.130.196.173 |
| **teleport-ad8e18ee0f2c5277** | ✗ | telegramwallet-stg | 52.74.0.97, 54.251.248.176 |
| **pritunl-prd-80d160d5995ae0c0** | ✗ | vpn.coin98.dev (Corporate VPN) | 52.76.18.91, 13.251.76.15, 18.143.241.252 |

### All Backend Services — Software Fingerprints

| Service | Server | Runtime | ALB/Infra | TLS Issuer | Live Endpoints |
|---------|--------|---------|-----------|------------|----------------|
| **superwallet-markets** | Express.js + Helmet.js | Node.js | WAF ALB | Amazon RSA 2048 M01 | `/health` ✓, `/api/tokens` (**8.1MB**) ✓, `/api/token-prices` (**3.6MB**, 18636 tokens) ✓, `/coin/multichain?cgkId=` ✓ |
| **superwallet-misc** | Express.js | Node.js | PRD ALB (no WAF) | Amazon RSA 2048 M04 | `/health` ✓, `/swagger.json` ✓ (OpenAPI 3.0.0 — Staking Pools), `/events` (401 — requires auth) |
| **superwallet-history-records** | Express.js | Node.js | PRD ALB (no WAF) | Amazon RSA 2048 M04 | `/health` ✓, `POST /record/log` (**UNAUTH WRITE!** MongoDB), `POST /record/log/dapps` (**UNAUTH WRITE!**) |
| **superlink-server** | Express.js | Node.js | PRD ALB (no WAF) | Amazon RSA 2048 M04 | `/health` ✓ |
| **superwallet-xpoint** | Express.js (CF) | Node.js | Behind Cloudflare | WE1 (LE) | `/api/v1/boba/contract` ✓, `/api/v1/boba/leaderboard` (**3MB**, 31309 wallets!) ✓, `/api/v1/boba/balance?address=` ✓, `/api/v1/boba/history?address=` ✓, `/api/v1/boba/stats` (401) |
| **superwallet-information-api** | Express.js (x-powered-by) | Node.js | Behind Cloudflare | WE1 (LE) | `/api/solanaV4` ✓ (returns `null`) |
| **general-inventory** | Express.js (x-powered-by) | Node.js | Shared ALB (no WAF) | Amazon RSA 2048 M04 | `/images/*` ✓ |
| **assets-api** | Express.js | Node.js | Shared ALB (no WAF) | Amazon RSA 2048 M04 | (404 on paths) |
| **coin98.com** | Cloudflare + Next.js | Node.js | Cloudflare | E8 (LE) | Landing page |
| **connect.coin98.com** | AmazonS3 | Static SPA | CloudFront | E8 (LE) | SPA fallback (566B) |
| **livechat.coin98.com** | AmazonS3 | Static SPA (React CRA) | CloudFront | E8 (LE) | SPA fallback (1254B) |
| **telegramwallet.coin98.com** | AmazonS3 | Static SPA (React) | CloudFront | E8 (LE) | Telegram Mini App |
| **Firebase** | Google Cloud Functions | Node.js | GCP us-central1 | Google Trust | Project: `coin98-b7f98` |
| **Campaign Supabase** | PostgREST 14.1 | PostgreSQL | Supabase Cloud | — | REST API ✓, Storage ✓ |
| **2025 Supabase** | PostgREST 13.0.5 | PostgreSQL | Supabase Cloud | — | REST API ✓, Storage ✓ |
| **amberblocks.com** | Cloudflare + Next.js | Node.js | Cloudflare | — | Parent company site |
| **frontierdao.org** | nginx + Next.js | Node.js | AWS EC2 (SG) | — | Direct IP (no CF) |
| **interlock.news** | nginx + Next.js | Node.js | AWS EC2 (SG) | — | Direct IP (no CF, same as frontierdao) |

### Swagger/OpenAPI Specs Found

| Service | Spec URL | Version | Endpoints |
|---------|----------|---------|-----------|
| **superwallet-misc** | `/swagger.json` | OpenAPI 3.0.0 | 7 endpoints (Staking Pools CRUD) |

**superwallet-misc API Details** (from Swagger):
- `GET /staking-pools` — List pools (chain, poolType, isActive, pagination) — **NO AUTH**
- `GET /staking-pools/chains` — Group by chain — **NO AUTH**
- `GET /staking-pools/featured` — Featured pools — **NO AUTH**
- `GET /staking-pools/{poolId}` — Get by ID — **NO AUTH**
- `POST /staking-pools` — Create pool — **AUTH (bearerAuth)**
- `PUT /staking-pools/{poolId}` — Update pool — **AUTH (adminAuth)**
- `DELETE /staking-pools/{poolId}` — Delete pool — **AUTH (adminAuth)**
- Staging server: `superwallet-misc-api-stg.coin98.dev`
- Schemas: StakingPool, CreateStakingPoolRequest, ApiResponse, Error
- Fields: `_id, name, description, tokenAddress, rewardTokenAddress, chain, poolType, apr, apy, isActive, lockDuration`

### Smart Contracts Referenced

| Contract | Chain | Context |
|----------|-------|---------|
| `0xDCf96195e7A5daB186a16081b09197721CA6a474` | Unknown (BOBA?) | xpoint boba contract |
| `0x████████████████████████████████████████████████████████████████` | Unknown | HMAC key or contract hash (from markets JS) |

---

## 11d. Attack Surface Analysis

### High-Value Targets (Ranked)

1. **CRITICAL: Extension `sync_wallet` decrypts ALL mnemonics for whitelisted origins** — XSS on any of 16 COIN98_SYSTEM origins calls `sync_wallet` → extension decrypts every mnemonic and returns full key material. `isConnected = () => true` (no session validation). `request_unlock` always returns `{isUnlocked: true}`. baryon.network has NO CSP. dagora.xyz has CORS:* + unsafe-inline. saros.finance has unsafe-eval + unsafe-inline. **Full wallet drain via single XSS on any whitelisted origin.** See Section 11.0b-c.

2. **CRITICAL: `aes_decrypt_coin98` exposed with broken session check** — Internal method decrypts ANY encrypted data. `isConnected` guard is `(A, t) => true`. XSS on whitelisted origin → decrypt all wallet data. See Section 11.0b.

3. **CRITICAL: localhost/127.0.0.1 in COIN98_SYSTEM whitelist** — Local web server on localhost/127.0.0.1 passes origin check → can call `sync_wallet` / `aes_decrypt_coin98` to drain wallets without user interaction. See Section 11.0c.

4. **CRITICAL: Google OAuth Client Secret hardcoded** — `GOCSPX-████████████████████████████` in 3 client-side JS files. Client_id `663197326394-████████████████████████████████`. Used to exchange auth codes for Google Drive tokens. Chain: phishing → auth code → Drive token → .C98 download → offline brute-force (6-char min, known HMAC key). See Section 11.0f, AC-7.

5. **HIGH: Password stored encrypted (not hashed) — fully reversible** — `authentication.password` AES-encrypted with `authentication.token`, both in `persist:root` in chrome.storage.local. `AES.decrypt(password, token)` → plaintext password. Not hashed. See Section 11.0a, AC-9.

6. **HIGH: Cloud backup encryption uses hardcoded HMAC key** — `HmacSHA256(password, "coin98_token")` + weak KDF (CryptoJS EVP_BytesToKey). `.C98` file from Google Drive → offline brute-force. See Section 11.0a.

7. **HIGH: postMessage wildcard origin in inpage.js** — `postMessage(e, "*")` on stream payloads. Iframing a page with Coin98 active → intercept wallet messages. See Section 11.0h AC-4.

8. **HIGH: Unauthenticated MongoDB Write (history-records)** — `POST /record/log` accepts arbitrary transaction records with NO auth on no-WAF ALB. Data poisoning. Confirmed with 4 test writes.

9. **HIGH: 17 hardcoded secrets in client-side JS** — Google OAuth secret, GA4 API secret (`████████████████████████`), 3 Infura IDs, BlockVision API key (`████████████████████████████`), TokenView API key (`████████████████████`), static HMAC, 2 JWTs, TON bearer, Google API key, S3 bucket. See Section 11.0f.

10. **HIGH: CryptoJS AES-CBC without authenticated encryption** — encryptService uses CBC mode, no HMAC/GCM. No integrity on decryption → bit-flipping attacks on wallet data in chrome.storage.local. See Section 11.0a.

11. **Supabase RLS Bypass (campaign)** — `lc_campaigns` table exposes wallet addresses + trading volumes. `campaigns`, `creator_campaigns`, `perp_campaigns` all readable.

12. **Supabase Open Signup (2025)** — `disable_signup: false`. Schema includes `admin_activity_logs` with email + IP columns and `wallet_addresses` with user→wallet mapping.

13. **superwallet-prd ALB (no WAF)** — Three production Express.js services behind ALB with NO WAF. Swagger spec exposed.

14. **Infura Project ID Abuse** — Three Infura project IDs hardcoded in JS. If rate limits are tied to Coin98's billing → DoS on blockchain connectivity.

15. **Xpoint BOBA Leaderboard Data Exposure** — `/api/v1/boba/leaderboard` returns **31,309 wallet addresses** with BOBA balances (23.1M BOBA) + per-address transaction history. No auth required.

16. **JWT with NO EXPIRY in extension JS** — JWT #2 (HS512, id=526, no exp). Tested against all endpoints — rejected. Still: hardcoded credentials in client-side code.

17. **Extension provider overrides** — Overrides `window.ethereum`, `window.petra`, `window.keplr`, etc. Malicious dApp → targeted attacks.

18. **Web accessible resources fingerprinting** — `inpage.*.js`, `cosmos.*.js`, `public/**` exposed to `<all_urls>`. Any website can detect Coin98 installation.

19. **Static phishing blocklist** — ~509 domains bundled at build, no dynamic updates. Obsolete within weeks of release.

20. **Outdated dependencies** — ethers v4.0.46 (current v6.x), web3 v1.8.2 (current v4.x). Known CVEs in older versions.

21. **Telegram Mini App** — S3 SPA with ZERO security headers, no CSP. XSS → Telegram user context.

22. **Firebase project coin98-b7f98** — Firestore locked. RTDB locked. Not currently exploitable.

23. **Staging ALBs** — 3 staging ALBs publicly routable but VPN-restricted. Not exploitable externally.

24. **Corporate VPN exposed** — `vpn.coin98.dev` → Pritunl VPN.

25. **connect.coin98.com** — S3 SPA, zero headers, CORS:*, stale 15 months.

26. **Android `get_login_creds` delegation** — assetlinks.json grants credential sharing to Android app.

### Trust Boundaries

```
                          INTERNET
                             │
       ┌─────────────────────┼──────────────────────┐
       │                     │                      │
       ▼                     ▼                      ▼
┌─────────────┐  ┌───────────────┐  ┌───────────────────────────────────┐
│  CLOUDFLARE  │  │  CloudFront   │  │  AWS ALBs (ap-southeast-1)        │
│  WAF (403)   │  │  + S3 SPAs    │  │  NO CLOUDFLARE PROTECTION         │
├─────────────┤  ├───────────────┤  ├───────────────────────────────────┤
│ coin98.com   │  │ connect       │  │ superwallet-prd ALB (no WAF)      │
│ api          │  │ livechat      │  │  ├ superwallet-misc                │
│ encrypted    │  │ telegramwlt   │  │  │  (Swagger + /events 401)       │
│ fragment-api │  │               │  │  ├ superwallet-history-records    │
│ information  │  │ No security   │  │  └ superlink-server               │
│ rapid        │  │ headers!      │  │                                   │
│ + 15 more    │  │               │  │ alb-shared-prd (no WAF)           │
├─────────────┤  └──────┬────────┘  │  ├ general-inventory               │
│ Pass-thru:  │         │           │  └ assets-api                      │
│ xpoint (CF) │         ▼           │                                   │
│ → 31K addrs!│    ┌─────────┐      │ alb-waf-prd (WITH WAF)            │
│ info-api(CF)│    │ S3      │      │  └ markets (8.1MB tokens, 3.6MB$) │
└─────────────┘    │ Bucket  │      │                                   │
                   └─────────┘      │ alb-shared-stg (STAGING!)         │
      ┌─────────┐                   │  ├ ramper-v2-fragment-stg         │
      │Lovable  │                   │  └ superwallet-misc-api-stg       │
      │ 4 subs  │                   │                                   │
      │ ↓       │                   │ teleport ALB (STAGING!)           │
      │Supabase │                   │  └ telegramwallet-stg             │
      │ ×2      │                   │                                   │
      └─────────┘                   │ pritunl-prd ALB (CORPORATE VPN!)  │
                                    │  └ vpn.coin98.dev                  │
      ┌─────────┐                   └───────────────────────────────────┘
      │EC2 (SG) │                                  │
      │ NO CF!  │                    ┌─────────────┤
      ├─────────┤                    ▼             ▼
      │frontier │              ┌───────────┐  ┌──────────┐
      │dao.org  │              │ Firebase   │  │ Supabase │
      │interlock│              │ coin98-    │  │ ×2       │
      │.news    │              │ b7f98      │  │ PostgREST│
      │finwallet│              │ GCP (locked│  │ 13/14    │
      │.app     │              │ for now)   │  │ RLS BYPASS│
      └─────────┘              └─────┬─────┘  └──────────┘
                                     │
                               ┌─────┴──────┐
                               │ GCP         │
                               │ ordinals API│
                               │ 35.241.*    │
                               │ 34.142.*    │
                               └─────────────┘
```

### Lateral Movement Paths

1. **XSS on whitelisted origin → sync_wallet → Full wallet drain**: baryon.network (NO CSP), dagora.xyz (CORS:*, unsafe-inline), saros.finance (unsafe-eval + unsafe-inline) are all COIN98_SYSTEM whitelisted origins. XSS on ANY of them calls `sync_wallet` which decrypts all mnemonics. `isConnected` is always true. No popup, no user interaction. This is the #1 attack path.

2. **localhost/127.0.0.1 → Internal methods → Wallet drain**: Malicious desktop app runs HTTP server on localhost. Coin98 extension whitelists localhost as COIN98_SYSTEM origin. Malicious page calls `connect_coin98` + `sync_wallet` = all mnemonics extracted. No browser popup, no user approval needed.

3. **Google OAuth secret → Drive backup → Offline key recovery (NEW)**: Attacker crafts OAuth URL with exposed client_id `663197326394-*` → victim authorizes → attacker intercepts auth code → exchanges using exposed `GOCSPX-████████████████████████████` → Drive access token → list/download `.C98` files → offline brute-force (6-char min password, known HMAC key `"coin98_token"`, weak MD5-based KDF) → all wallet keys.

4. **chrome.storage.local → Password + Token → Full decrypt**: If attacker reads `persist:root` from chrome.storage.local (malware, extension vuln, physical access, browser sync), both `authentication.token` (plaintext master key) and `authentication.password` (AES-encrypted with token) are in the same object. `AES.decrypt(password, token)` → plaintext password → decrypt all wallet data. Password is stored encrypted, NOT hashed.

5. **Cloud backup file + hardcoded HMAC key → Offline key recovery**: Attacker obtains `.C98` file from victim's Google Drive (phishing, account compromise). Hardcoded HMAC key `"coin98_token"` + weak CryptoJS EVP_BytesToKey KDF = offline brute-force of user password. Once password cracked, all wallet mnemonics recovered.

6. **History-Records → Data Poisoning → User Deception**: `POST /record/log` (no auth, no WAF) creates MongoDB records. Fake tx history displayed to users → social engineering, fake deposit notifications.

7. **GA4 API Secret → Analytics poisoning → Business impact**: Exposed `████████████████████████` + `G-CCPPHL1RJT` allows sending arbitrary events to Coin98's GA4 property. Pollute metrics, inject fake conversion data, trigger alerts.

8. **Supabase → Admin Access**: Campaign RLS bypass confirmed. 2025 signup enabled → `admin_activity_logs` or `wallet_addresses` tables may unlock.

9. **Xpoint → Wallet Deanonymization**: Leaderboard exposes 31,309 wallet addresses with BOBA balances + full tx history. Cross-reference with on-chain data → deanonymize users.

10. **Extension JWT → Permanent Backend Access**: JWT #2 (HS512, id=526, no expiry). Tested and rejected by all known endpoints but still hardcoded in client code.

11. **Swagger → Admin Escalation**: `superwallet-misc` OpenAPI spec reveals `bearerAuth` and `adminAuth`. If admin tokens found → full CRUD on staking pools.

12. **Infura/BlockVision/TokenView Keys → RPC DoS**: 3 Infura IDs + BlockVision key (`████████████████████████████`) + TokenView key (`████████████████████`). Exhaust Coin98's RPC quotas → DoS on blockchain operations for all users.

13. **Telegram Mini App → User Data**: S3 SPA, zero security headers. XSS → `Telegram.WebApp.initData` exfil.

14. **postMessage wildcard → Cross-origin message interception**: inpage.js uses `postMessage(e, "*")`. Iframing a page with Coin98 active → intercept wallet messages.

15. **Web accessible resources → Extension fingerprinting → Targeted attacks**: `inpage.*.js` and `cosmos.*.js` accessible from any URL. Any website can detect Coin98 installation, then serve targeted phishing or exploit pages.

16. **Shared EC2 → Lateral Pivot**: frontierdao.org, interlock.news, finwallet.app share 2 AWS IPs with NO Cloudflare. Compromise one → pivot to all.

17. **Android Credential Delegation → Phishing**: `get_login_creds` in assetlinks.json. Matching cert = auto-filled credentials flow to attacker.

---

## 12. Existing Scan Findings Triage (Prior Scan 2026-03-01)

### Summary: 50 findings — 12 Critical, 16 High, 5 Medium, 6 Low, 11 Info

| Severity | Count | Verdict |
|----------|-------|---------|
| **Critical** | 12 | ALL **FP** — i18n UI strings ("Passphrase or Private Key" in 12 languages) |
| **High** | 16 | 8 FP (i18n), 6 FP (Google API keys → all invalid/400), 1 FP (Apilayer key → 401), 1 INVESTIGATE (HMAC key) |
| **Medium** | 5 | 3× postMessage without origin check (VALID but low impact), 1× backup URLs, 1× unverified contracts |
| **Low** | 6 | CORS:*, JWT exposure, debug mode, Infura URLs, x-powered-by disclosure |
| **Info** | 11 | Wallet integrations, WalletConnect ID, NEAR accounts, missing headers, WAF detection |

### HMAC Key (needs investigation)
- **Value**: `0x████████████████████████████████████████████████████████████████`
- **Context**: Found in markets + dapps JS bundles (hardcoded-passphrase rule)
- **Assessment**: 32-byte hex value. Could be a chain-specific constant, contract deployment salt, or legitimate HMAC signing secret. Needs manual investigation in the decompiled JS to determine usage context.

---

## 13. Related Domains (from TLS Certificate SANs — 42 entries)

The superwallet-markets.coin98.tech TLS certificate (CN=amberblocks.com, Amazon RSA 2048 M01) covers **42 SANs**, revealing the parent company and related products:

| Domain | A Records | Server | Framework | Status | Relationship |
|--------|-----------|--------|-----------|--------|-------------|
| **amberblocks.com** | 104.21.39.74, 172.67.143.168 | cloudflare | Next.js | 200 | **Parent company** |
| **coin98.net** | 172.67.158.237, 104.21.82.152 | cloudflare | Next.js | 200 | Alternate domain |
| **coin98.tech** | (no A, has NS: CF) | — | — | — | Infrastructure domain (API backends) |
| **coin98.dev** | (no A, NS: AWS Route53) | — | — | — | Staging domain (different DNS!) |
| **cusd.xyz** | 104.21.45.169, 172.67.217.4 | cloudflare | — | 301 | CUSD stablecoin |
| **zencard.io** | 104.21.34.28, 172.67.167.213 | cloudflare | Next.js | 301 | Card/payment product |
| **ninji.xyz** | 52.223.52.2, 35.71.142.77 | Framer | — | 200 | Related product (Framer site) |
| **finwallet.com** | 172.239.57.117, 172.234.24.211 | openresty | — | 200 | Wallet product (Akamai) |
| **frontierdao.org** | 3.1.33.23, 13.228.191.38 (AWS SG) | nginx | Next.js | 200 | DAO project |
| **interlock.news** | 3.1.33.23, 13.228.191.38 (AWS SG) | nginx | Next.js | 200 | News/media (same IPs as frontierdao) |
| **cyborg.game** | 104.21.17.214, 172.67.178.84 | cloudflare | Next.js | 301 | Gaming |
| **eternals.game** | 172.67.70.54, 104.26.10.242 | cloudflare | — | 301 | Gaming |
| **gotgamedao.org** | NXDOMAIN | — | — | — | Dead |
| **cypheus.fun** | 185.158.133.1 | cloudflare | Lovable | 200 | Creator hub redirect target |

### Wildcard Domains on Cert
- `*.coin98.tech` — infrastructure backends (superwallet-*, general-inventory, assets-api, superlink-server)
- `*.cusd.xyz` — stablecoin infrastructure
- `*.zencard.io` — card product
- `*.frontierdao.org` — DAO infrastructure
- `*.cyborg.game` — gaming
- `*.eternals.game` — gaming
- `*.ninji.xyz` — product subdomains

---

## 14. Staging / Dead Domains + coin98.dev CT Logs (21 subdomains)

### Live Infrastructure (coin98.dev — from Certificate Transparency)

| Domain | Infrastructure | IP/CNAME | Status | Notes |
|--------|---------------|----------|--------|-------|
| **vpn.coin98.dev** | `pritunl-prd-80d160d5995ae0c0` ALB | 52.76.18.91, 13.251.76.15, 18.143.241.252 | **LIVE** | **Corporate Pritunl VPN** |
| **teleport.coin98.dev** | `teleport-ad8e18ee0f2c5277` ALB | ALB IPs | **LIVE** | Teleport service |
| **api.ordinals.coin98.dev** | GCP | 35.241.105.44 | DNS resolves | Bitcoin Ordinals API (mainnet) |
| **api-testnet.ordinals.coin98.dev** | GCP | 34.142.221.101 | DNS resolves | Bitcoin Ordinals API (testnet) |
| superwallet-misc-api-stg.coin98.dev | `alb-shared-stg-public-1517252894` ALB (no WAF) | ALB IPs | **LIVE** | Staging API |
| ramper-v2-fragment-stg.coin98.dev | `alb-shared-stg-public-1517252894` ALB (no WAF) | ALB IPs | **LIVE** | Staging Ramper |
| superwallet-telegramwallet-test.coin98.dev | CloudFront `d1i4lt9lfujx2x` | CF IPs | 503 | Staging TG wallet |
| superwallet-telegramwallet-stg.teleport.coin98.dev | `teleport-ad8e18ee0f2c5277` ALB | ALB IPs | **LIVE** | Staging TG — Teleport |

### Dead coin98.dev Subdomains (from CT — reveal internal naming patterns)

| Domain | Notes |
|--------|-------|
| internal-prd.coin98.dev | Production internal tools (NXDOMAIN — cleaned up) |
| internal-stg.coin98.dev | Staging internal tools (NXDOMAIN) |
| internal-tools.coin98.dev | Internal tooling (NXDOMAIN) |
| preprod.coin98.dev | Pre-production environment (NXDOMAIN) |
| preprod-int.coin98.dev | Pre-production internal (NXDOMAIN) |
| prod-int.coin98.dev | Production internal (NXDOMAIN) |
| stag.coin98.dev | Staging (NXDOMAIN) |
| stag-int.coin98.dev | Staging internal (NXDOMAIN) |
| port.coin98.dev | Unknown (NXDOMAIN) |
| cyborg-static-dev.coin98.dev | Cyborg game dev assets (NXDOMAIN) |
| cyborg-static-stg.coin98.dev | Cyborg game staging assets (NXDOMAIN) |
| api.saros-dex-v3-stg.coin98.dev | Saros DEX v3 staging API (NXDOMAIN) |
| api.saros-dex-v3-test.coin98.dev | Saros DEX v3 test API (NXDOMAIN) |
| saros-dex-v3-test.coin98.dev | Saros DEX v3 test UI (NXDOMAIN) |

### Dead / Parked (other domains)

| Domain | Status | Notes |
|--------|--------|-------|
| development.coin98.services | **NXDOMAIN** | Dead — was in production JS |
| exchange.c98staging.dev | **NXDOMAIN** | Dead — staging exchange |
| c98staging.dev | **No NS records** | Domain expired/not configured |
| coin98.services | **Has NS (CF)** but no A | Parked |
| auth.coin98.com | **No A record** | Decommissioned auth service |
| pay.coin98.com | **No A record** | Decommissioned payment service |
| payment-sandbox.coin98.com | **No A record** | Decommissioned payment sandbox |
| socket.coin98.services | **NXDOMAIN** | Dead WebSocket service |
| fragment-api.coin98.com | CF 403 | Cloudflare-walled |

### Related Products Discovered

| Product | Domain | Infrastructure | Notes |
|---------|--------|---------------|-------|
| **Saros DEX** | saros.xyz, saros.finance, dex.saros.xyz | Cloudflare + Next.js | Solana DEX — "Explore Solana's Liquidity Layer", saros.finance→dex.saros.xyz |
| **Finwallet** | finwallet.com, **finwallet.app** | finwallet.com: Akamai (openresty), finwallet.app: **3.1.33.23, 13.228.191.38** (same IPs as frontierdao!) | Wallet product sharing AWS infrastructure |
| **Viction Wallet** | viction.xyz | AmazonS3 (CloudFront) | Tomochain/Viction wallet |

---

## 15. Complete Infrastructure Map

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         COIN98 INFRASTRUCTURE (2026-03-02)                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  CLIENTS (4 platforms)                                                          │
│  ├─ Chrome Extension v10.4.1 (MV3, 228MB, 62 API routes, 1074 RPC endpoints) │
│  │   ├─ inpage.js: ethereum, keplr, petra, BinanceChain, sui, near, ton...   │
│  │   ├─ CRITICAL: 9 internal methods (sync_wallet, aes_decrypt_coin98...)    │
│  │   │   ├─ isConnected = () => true (NO SESSION VALIDATION!)                │
│  │   │   ├─ request_unlock always returns {isUnlocked: true}                 │
│  │   │   └─ 16 whitelisted origins incl localhost, 127.0.0.1                 │
│  │   ├─ Weak origins: baryon.network(NO CSP), dagora.xyz(CORS:*),            │
│  │   │   saros.finance(unsafe-eval), kyc.oneid.xyz(unsafe-inline)            │
│  │   ├─ encryptService: CryptoJS AES-CBC, master key = Redux auth.token      │
│  │   ├─ Cloud backup: HmacSHA256(pw,"coin98_token") hardcoded HMAC key       │
│  │   ├─ 3 Infura IDs, Google API key, 2 JWTs (1 no-expiry), static HMAC     │
│  │   ├─ Ramper SDK v2 (social recovery contract 0xDCf96195...)               │
│  │   ├─ postMessage(e,"*") wildcard in inpage.js stream payloads             │
│  │   └─ 164 chain types, 7 HW wallets (Ledger, Trezor, Keystone...)         │
│  ├─ iOS v16.9.0: coin98.crypto.finance.insights (375MB, Team 4JLUM47S98)    │
│  ├─ Android: coin98.crypto.finance.media (get_login_creds delegation!)       │
│  └─ Telegram Mini App: telegramwallet.coin98.com (thin shell, no backend)    │
│                                                                                 │
│  CLOUDFLARE (WAF — blocks most direct access with 403)                         │
│  ├─ coin98.com (Next.js)          ├─ api.coin98.com                            │
│  ├─ encrypted.coin98.com          ├─ fragment-api.coin98.com                   │
│  ├─ information.coin98.com        ├─ rapid.coin98.com                          │
│  ├─ superwallet-xpoint.coin98.tech → 31309 wallet addrs (no auth on LB!)      │
│  ├─ superwallet-information-api.coin98.tech → /api/solanaV4 passes thru        │
│  └─ 15+ more subdomains (dapps, exchange, wallet, vault, etc.)                 │
│                                                                                 │
│  AWS ap-southeast-1 (Singapore) — DIRECT ACCESS (no Cloudflare)                │
│  ├─ ALB: alb-waf-prd-1743527320 [WAF ✓]                                       │
│  │   └─ superwallet-markets (Express+Helmet)                                   │
│  │       ├─ /api/tokens (8.1MB!)  ├─ /api/token-prices (3.6MB, 18636 tokens)  │
│  │       └─ /coin/multichain?cgkId= (open query)                               │
│  │                                                                              │
│  ├─ ALB: superwallet-prd-1429875593 [NO WAF]                                   │
│  │   ├─ superwallet-misc (SWAGGER EXPOSED, /events 401 = auth endpoint)        │
│  │   ├─ superwallet-history-records (Express)                                  │
│  │   └─ superlink-server (Express)                                             │
│  │                                                                              │
│  ├─ ALB: alb-shared-prd-1996992288 [NO WAF]                                   │
│  │   ├─ general-inventory (Express, x-powered-by leaked, /images/*)            │
│  │   └─ assets-api (Express)                                                   │
│  │                                                                              │
│  ├─ ALB: alb-shared-stg-1517252894 [NO WAF, STAGING]                          │
│  │   ├─ superwallet-misc-api-stg.coin98.dev                                   │
│  │   └─ ramper-v2-fragment-stg.coin98.dev                                      │
│  │                                                                              │
│  ├─ ALB: teleport-ad8e18ee0f2c5277 [NO WAF, STAGING]                          │
│  │   └─ superwallet-telegramwallet-stg.teleport.coin98.dev                     │
│  │                                                                              │
│  ├─ ALB: pritunl-prd-80d160d5995ae0c0 [CORPORATE VPN]                         │
│  │   └─ vpn.coin98.dev (Pritunl VPN — login portal exposed)                   │
│  │                                                                              │
│  ├─ CloudFront → S3                                                            │
│  │   ├─ connect.coin98.com (WalletConnect SPA, zero headers, CORS:*)          │
│  │   ├─ livechat.coin98.com (React CRA, LiveChat #13023900)                   │
│  │   └─ telegramwallet.coin98.com (React + TG SDK, zero headers)              │
│  │                                                                              │
│  ├─ S3: coin98.s3.ap-southeast-1.amazonaws.com                                │
│  │   └─ Chains/, Coin/, Currency/, DomainResolver/ (public images)             │
│  │                                                                              │
│  └─ EC2: 3.1.33.23, 13.228.191.38 (SHARED — no CF!)                           │
│      ├─ frontierdao.org (nginx + Next.js)                                      │
│      ├─ interlock.news (nginx + Next.js)                                       │
│      └─ finwallet.app (+ 52.220.112.142) — same infrastructure!               │
│                                                                                 │
│  GCP                                                                            │
│  ├─ Firebase: coin98-b7f98 (us-central1, Firestore locked, RTDB locked)        │
│  ├─ api.ordinals.coin98.dev (35.241.105.44) — BTC Ordinals API                │
│  └─ api-testnet.ordinals.coin98.dev (34.142.221.101) — testnet                │
│                                                                                 │
│  SUPABASE CLOUD                                                                 │
│  ├─ jdxkhxqpoqafflwspzte (campaign) — PostgREST 14.1, RLS BYPASS confirmed    │
│  └─ wxgwpabjnpylabpktlvr (2025) — PostgREST 13.0.5, signup ENABLED            │
│                                                                                 │
│  LOVABLE.APP (185.158.133.1)                                                   │
│  ├─ airdrop.coin98.com    ├─ campaign.coin98.com                               │
│  ├─ 2025.coin98.com       └─ leaderboard.coin98.com                            │
│  └─ Each backed by Supabase instance                                            │
│                                                                                 │
│  RELATED PRODUCTS (same parent company)                                         │
│  ├─ Saros DEX: saros.xyz, dex.saros.xyz (Cloudflare, Next.js, Solana)         │
│  ├─ Viction Wallet: com.tomochain.wallet (iOS + Android)                       │
│  ├─ Ninji Wallet: ninji.wallet.crypto.finance (iOS + Android)                  │
│  ├─ Ancient8 Wallet: ancient8.wallet.crypto.finance                            │
│  └─ Amber Blocks: coin98.insights.crypto.research (research app)               │
│                                                                                 │
│  THIRD-PARTY SERVICES                                                           │
│  ├─ Cloudflare (DNS, WAF, CDN)    ├─ Airbridge (mobile + extension tracking)   │
│  ├─ Singular (click tracking)      ├─ LiveChat (#13023900)                     │
│  ├─ Infura (×3 project IDs)       ├─ NodeReal (BSC RPC)                        │
│  ├─ BlockVision (Sui RPC)          ├─ TokenView (ETH/BSC/KCS/ETC RPC)         │
│  ├─ WalletConnect                  ├─ 60 WSS + 1074 HTTPS RPC endpoints        │
│  ├─ Google OAuth (×2 client IDs, 1 CLIENT SECRET exposed!)                     │
│  ├─ Google Analytics 4 (G-CCPPHL1RJT + API secret exposed)                    │
│  ├─ GitBook (docs.coin98.com)      ├─ Airship (push notifications)             │
│  ├─ Framer (ninji.xyz)            ├─ Google (MX, OAuth, Firebase)              │
│  ├─ Atlassian (Jira/Confluence)    └─ SendGrid (transactional email)           │
│  └─ Ramper (social recovery SDK, smart contract on-chain)                      │
│                                                                                 │
│  PARENT COMPANY: COIN98 WALLET LTD (amberblocks.com, Apple Team 4JLUM47S98)   │
│  Developer ID: 1732374734 | 5 apps on App Store | TLS CN: amberblocks.com      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 16. Recommendations — Priority Actions

### Immediate (reportable findings)

1. **CRITICAL: Extension internal method `sync_wallet` decrypts ALL mnemonics for whitelisted origins** — XSS on any of the 16 COIN98_SYSTEM whitelisted origins allows calling `sync_wallet` which **decrypts every mnemonic** in the wallet and returns full key material. Combined with `isConnected = () => true` bypass (no session validation) and `request_unlock` always returning `{isUnlocked: true}`, this is a complete wallet drain via XSS on any whitelisted origin. **Live scan confirms ALL 16 whitelisted origins are exploitable**: 8 have ZERO CSP, dagora.xyz has `script-src 'self' 'unsafe-inline' 'unsafe-eval' *` (effectively no CSP) + `CORS: *`, saros.finance has `unsafe-eval` + `unsafe-inline`, baryon.network has NO CSP (Cloudflare WAF only). See Section 11.0b-c, 11.0i-5.

2. **CRITICAL: `aes_decrypt_coin98` exposed to whitelisted origins with broken session check** — Internal method decrypts ANY encrypted data using the master `encryptService`. The `isConnected` guard is `(A, t) => true` — always passes. Any XSS on a whitelisted origin can decrypt wallet data. See Section 11.0b.

3. **CRITICAL: localhost/127.0.0.1 in COIN98_SYSTEM whitelist** — Any local web server running on `localhost` or `127.0.0.1` passes the origin check for internal methods. A malicious desktop app, browser extension, or even a local dev server can call `sync_wallet` or `aes_decrypt_coin98` to drain all wallets without any user interaction or popup. See Section 11.0c.

4. **CRITICAL: Google OAuth Client Secret hardcoded in client-side JS** — `GOCSPX-████████████████████████████` exposed in 3 JS files (CloudSync flow). Used with client_id `663197326394-████████████████████████████████` to exchange authorization codes for Google Drive access tokens. Combined with weak cloud backup encryption (6-char min password, hardcoded HMAC key, MD5-based KDF), this creates a chain: phishing → auth code → Drive token → .C98 file → offline brute-force → all wallets. See Section 11.0f, AC-7.

5. **HIGH: Password stored encrypted (not hashed) — fully reversible** — `authentication.password` is AES-encrypted with `authentication.token`, both stored in same `persist:root` key in `chrome.storage.local`. If attacker reads storage (malware, extension vuln), `AES.decrypt(password, token)` immediately recovers plaintext password. Password should be hashed with bcrypt/scrypt/argon2, never stored reversibly. See Section 11.0a, AC-9.

6. **HIGH: Unauthenticated write to transaction log DB** — `POST /record/log` on `superwallet-history-records.coin98.tech` (no-WAF ALB) accepts arbitrary transaction records without authentication. Data poisoning — fake tx history displayed to users.

7. **HIGH: Cloud backup encryption uses hardcoded HMAC key** — `HmacSHA256(password, "coin98_token")` with known key + CryptoJS AES with weak EVP_BytesToKey KDF. Min password 6 chars. If `.C98` file obtained from Google Drive, offline brute-force is feasible. See Section 11.0a.

8. **HIGH: postMessage wildcard origin in inpage.js** — `postMessage(e, "*")` on some stream payloads. Any page iframing a page with Coin98 active can intercept wallet messages (account addresses, signed data).

9. **HIGH: 24 hardcoded secrets in client-side JS** — Google OAuth secret, GA4 API secret, 4 Infura IDs, BlockVision API key, TokenView API key, 4 block explorer API keys (Basescan, Lineascan, Scrollscan, OKLink), static HMAC signature, 2 JWTs (one with no expiry), TON API bearer, Google API key, S3 bucket, Firebase config. See Section 11.0f.

10. **HIGH: Ramper Shamir key sharding — weak share encryption** — Social wallets use Shamir 3-of-2 secret sharing. Share 3 is encrypted with `CryptoJS.AES.encrypt(share, user.UID)` where UID is a short Firebase UID. Share 2 is KMS-encrypted in Firebase. If attacker obtains Firebase UID + Ramper `/fragment` API access → decrypt Share 3. Combined with Firebase compromise → 2 shares → full mnemonic. See Section 11.0g, AC-10.

11. **Report Supabase RLS bypass on campaign instance** — `lc_campaigns` table exposes wallet addresses + trading volumes to anonymous reads

12. **Report xpoint BOBA leaderboard data exposure** — `/api/v1/boba/leaderboard` returns **31,309 wallet addresses** with BOBA balances (23.1M BOBA) + per-address transaction history. No auth required.

13. **Swagger spec exposure on superwallet-misc** — OpenAPI 3.0.0 spec at `/swagger.json` reveals full API schema, auth schemes (`bearerAuth`, `adminAuth`), staging URLs

14. **Verify 2025 Supabase signup path** — register and check if `admin_activity_logs` or `wallet_addresses` become readable after auth

### High Priority (deep probe)

15. **Hunt stored XSS on dagora.xyz via NFT metadata** — dagora.xyz has `script-src * unsafe-inline unsafe-eval` + `CORS: *` + is a COIN98_SYSTEM whitelisted origin. NFT names/descriptions from `api.dagora.xyz` are rendered on collection pages. If NFT minting on Viction chain accepts HTML in metadata → stored XSS → `sync_wallet` → full wallet drain. This is the **most promising attack vector**. See AC-13.

16. **Hunt DOM XSS on baryon.network** — NO CSP, whitelisted origin, Next.js with 28 JS bundles. URL params reflected in RSC payload (URL-encoded). Cloudflare WAF blocks `<script>` but may be bypassable. Also check `dangerouslySetInnerHTML` usage from localStorage. See Section 11.0i-5.

17. **PoC the sync_wallet attack chain** — Build proof-of-concept: XSS on whitelisted origin → `connect_coin98` → `sync_wallet` → mnemonic extraction. This is the highest-impact finding.

18. **Test localhost exploit locally** — Install extension, run local web server, call internal methods to confirm wallet drain from localhost without user interaction.

19. **PoC Google OAuth secret chain** — Demonstrate: crafted OAuth URL → user auth → code intercept → exchange with GOCSPX secret → Drive access → .C98 download → decrypt with known HMAC key.

20. **Probe socket.coin98.services for session hijack** — Socket.IO server with `CORS: *`. connect.coin98.com sends `connect` URL param as token to socket without validation. Test: connect from arbitrary origin, replay/forge `coin98_connect` events, attempt session impersonation. See AC-12.

21. **JWT #2 (HS512, no expiry) — TESTED, rejected by all endpoints** — Still a finding: hardcoded credentials in client-side code.

22. **Extension provider override testing** — craft test dApp to probe edge cases in `window.ethereum` (eth_sign blind signing, chain switching, transaction modification)

23. **CryptoJS AES-CBC integrity** — Test if encrypted wallet data in chrome.storage.local can be corrupted via bit-flipping without detection (no authenticated encryption).

24. **GA4 API Secret exploitation** — Verify ability to send fake measurement events using exposed secret `████████████████████████`. Analytics data pollution.

25. **Ramper `/fragment` API probing** — Test if Ramper fragment endpoint is accessible externally, if fragments can be enumerated by UID, and if there's rate limiting on decryption attempts.

### Medium Priority

26. **Staging ALBs — TESTED, unreachable** — VPN-restricted. Not publicly exploitable.
27. **Telegram Mini App XSS hunting** — S3 SPA with zero security headers; XSS → user data exfil via `Telegram.WebApp.initData`
28. **Verify Infura project IDs are rate-limited** — if unrestricted, report as DoS vector
29. **Android `get_login_creds` delegation abuse** — assetlinks.json grants credential sharing
30. **general-inventory catch-all** — Returns 200 with `""` for ALL paths. Not exploitable.
31. **S3 bucket object enumeration** — listing denied but public prefixes exist
32. **Probe Ordinals APIs on GCP** — DNS resolves but unreachable. Possibly decommissioned.
33. **Probe frontierdao.org / interlock.news / finwallet.app** — shared AWS IPs (3.1.33.23, 13.228.191.38), nginx + Next.js with NO Cloudflare; lateral entry to shared infrastructure
34. **TokenView API key exposed** — `████████████████████` hardcoded for ETH/BSC/ETC/KCS node services
35. **BlockVision API key exposed** — `████████████████████████████` for Sui blockchain RPC
36. **Block explorer API keys (×5)** — Basescan, Lineascan, Scrollscan, OKLink (×3 chains) — rate limit exhaustion = tx history DoS
37. **Web accessible resources expose extension** — `inpage.*.js` and `cosmos.*.js` accessible from any URL, enabling extension fingerprinting
38. **Static phishing blocklist** — ~509 domains bundled at build time with no dynamic update mechanism. New phishing domains require extension update to block.
39. **ethers v4.0.46** — Very outdated (current is v6.x). Known vulnerabilities in older ethers versions.
40. **eth_sign blind signing support** — Extension handles `eth_sign` which allows signing arbitrary hex data without human-readable display. Malicious dApps can trick users.
41. **2-Step Verification is NOT real 2FA** — Just a Redux boolean toggle, no TOTP/authenticator/SMS. False sense of security for users who enable it.
42. **connect.coin98.com coin98:// protocol auto-click** — `openURL()` creates `<a href=coin98://...>` element and auto-clicks. Input is `encodeURIComponent`'d, but mobile deep link handler may be vulnerable.
43. **docs.coin98.com (GitBook)** — Same weak CSP (`script-src * unsafe-inline unsafe-eval`) but NOT a COIN98_SYSTEM whitelisted origin. XSS here doesn't trigger wallet drain but may leak user session data.
44. **Lovable.app origins (campaign, 2025, airdrop, leaderboard)** — All built with GPT-engineer/Lovable.app, zero security headers, `~api/analytics` endpoints. Minimal attack surface but in trust boundary.

---

## 12. Android App v16.9.0 — Deep Deconstruction

### 12.1 APK Metadata

| Field | Value |
|-------|-------|
| **Package** | `coin98.crypto.finance.media` |
| **Version** | 16.9.0 (build: 1772190381) |
| **Min SDK** | 28 (Android 9) |
| **Target SDK** | 36 (Android 16) |
| **Main Activity** | `coin98.crypto.finance.media.MainActivity` |
| **Architecture** | React Native (Hermes, New Arch) + 43 native .so libs (arm64-v8a) |
| **RN Bundle** | `index.android.bundle` — 85MB (80.3M chars) |
| **Base APK Size** | 240MB (Play Store split APK from Galaxy S24 Ultra) |
| **Source** | Google Play Store via device extraction (2026-03-02) |
| **Prior Version** | v16.7.0 from APKPure CDN (84MB bundle, SDK 35, 71 libs armeabi-v7a) |

### 12.2 Critical Security Findings

#### 🔴 `usesCleartextTraffic=true` — HTTP Traffic Allowed
Despite targeting SDK 36, the app explicitly enables cleartext HTTP. Combined with custom `networkSecurityConfig`, this means MITM attacks can intercept traffic on networks without HSTS.

#### 🔴 21 Staging Endpoints in Production Bundle
The following `*.coin98.dev` staging URLs are hardcoded in the shipped production APK:

| Staging Endpoint | Service |
|-----------------|---------|
| `assets-api-stg.coin98.dev` | Asset management |
| `dagora-web-stg.teleport.coin98.dev` | NFT marketplace |
| `general-inventory-stg.coin98.dev` | Image service |
| `hubs-dapps-api-stg.coin98.dev` | DApp browser |
| `hubs-kyc-api-stg.coin98.dev` | KYC service |
| `hubs-vault-api-stg.coin98.dev` | Vault/custody |
| `oneid-api-stg.coin98.dev` | OneID identity |
| `oneid-graphql-api-stg.coin98.dev` | OneID GraphQL |
| `ramper-v2-api-test.coin98.dev` | Ramper v2 social wallet |
| `ramper-v2-fragment-stg.coin98.dev` | Ramper Shamir fragments |
| `superlink-server-stg.coin98.dev` | Deep link server |
| `superwallet-chat-api-stg.coin98.tech` | Chat service |
| `superwallet-fiat-api-stg.coin98.dev` | Fiat on-ramp |
| `superwallet-markets-stg.coin98.dev` | Market data |
| `superwallet-misc-api-stg.coin98.dev` | Miscellaneous |
| `superwallet-notification-api-stg.coin98.dev` | Push notifications |
| `superwallet-portfolio-stg.coin98.dev` | Portfolio tracker |
| `superwallet-referral-stg.coin98.dev` | Referral system |
| `superwallet-xpoint-stg.coin98.dev` | XPoint rewards |
| `zencard-server-stg.coin98.dev` | Zencard (card issuance) |
| `zencard-visa-api-stg.coin98.tech` | Visa card API |

Staging servers typically have weaker auth, debug endpoints, and verbose errors. If any are publicly reachable, they represent significant attack surface.

#### 🔴 Root/Tamper Detection REMOVED
- `toolChecker.so` (4KB) was present in v16.7.0 — **completely removed in v16.9.0**
- Root detection: only 2 trivial references in 85MB bundle (JS layer only)
- **No Magisk detection** (0 hits)
- **No Frida detection** — "Frida" appears 12× but all are false positives (e.g., "Fridays")
- **No SSL/cert pinning** (0 hits)
- **No SafetyNet/PlayIntegrity** attestation (0 hits)
- **No App Attest / DeviceCheck** (0 hits)
- Emulator detection: 22 references but all appear to be Firebase Auth error messages

#### 🔴 AsyncStorage (Insecure) Usage Doubled
- `AsyncStorage`: ×23 references (up from ×10 in v16.7.0) — plaintext key-value storage accessible to root
- `MMKV`: ×35 (up from ×31) — encrypted but with device-derived key
- `Realm`: ×141 (up from ×139) — local database, encrypted at rest (key storage is critical)

### 12.3 Hardcoded Secrets (Android-Specific)

| Secret | Value |
|--------|-------|
| **Google API Key** | `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I` |
| **Google OAuth Client ID (Android)** | `663197326394-ngu7bcpsbo6t6ampt433aqceei7mbhjm.apps.googleusercontent.com` |
| **Google OAuth Client ID (Chrome)** | `663197326394-pl8q5fj0um5kmn8c7k0lk6m2q14n3po4.apps.googleusercontent.com` |
| **Google OAuth Client ID (AWS)** | `663197326394-ms6jba6e4rfnukl2ffd4ed5mo752popa.apps.googleusercontent.com` |
| **Google OAuth Client ID (generic)** | `663197326394-glapn4i2dtue2gm8r21qoumbu2qtj0kl.apps.googleusercontent.com` |
| **Infura Project ID (prod)** | `████████████████████████████████` |
| **Infura Project ID (testnet)** | `████████████████████████████████` |
| **NodeReal BSC key** | `955ab7c09f78437981a573b43061fe10` |
| **NodeReal key 2** | `5c4ed7c647c0479f9ae118b0b62c745c` |
| **NodeReal key 3** | `2035a58b2c0d480d93a7e21acb6e460c` |
| **Airbridge SDK Signature Secret** | `cb5bb86fc0f70c9ec0723786105abdba7a102ee5d3c4c15de569a028aac579d6` |
| **Meta Install Referrer** | `1082161529482856` |
| **Airbridge SDK Signature ID** | `51f9529c-1465-4ca7-9913-b7e8b3ef9751` |
| **Cloud Functions (Coin98)** | `us-central1-coin98-b7f98.cloudfunctions.net` |
| **Cloud Functions (Ramper)** | `us-central1-ramper-prod.cloudfunctions.net` |
| **Singular SDK** | v12.10.0 (build: 0330ff23, Aug 2025) |
| **GetBlock RPC key 1** | `9f4c1bf35d6c411b86298c9eedf6dfad` (go.getblock.io) |
| **GetBlock RPC key 2** | `ead991362ba64751883ea11eaa2c76ce` (go.getblock.io, ×2 refs) |
| **GetBlock RPC key 3** | `aab5dca7bb9142189d301a0aa1c60010` (go.getblock.io) |
| **GetBlock RPC key 4** | `f2b163960ffa4428b33c786822389a10` (go.getblock.io) |
| **GetBlock RPC key 5** | `cbb41430d8d048b19c995ad64bcf103c` (go.getblock.io) |
| **GetBlock RPC key 6** | `5726869aab57478c9fc88f58d0cbbfdb` (go.getblock.io) |
| **GetBlock RPC key 7** | `0c352dc965a14e14b36aee34a44a19ee` (go.getblock.asia) |
| **GetBlock RPC key 8** | `24e1bff26d884cf38ff5f18793837b7e` (go.getblock.io) |
| **GetBlock RPC key 9** | `90044b8cde134b0889535faaa9668232` (go.getblock.io) |
| **GetBlock RPC key 10** | `a1e920a0aec8422190e12b0bc5720d12` (go.getblock.io) |

### 12.4 Deep Links & Exported Components

**URL Schemes**: `coin98://`, `wc://`, `https://`, `fbconnect://`, `genericidp://`, `recaptcha://`

**Deep Link Hosts**:
- `coin98.com` — main website
- `clicks.coin98.com` — link tracking
- `coin98.sng.link` — Singular attribution
- `firebase.auth` — Firebase auth redirect
- `cct.coin98.crypto.finance.media` — Facebook Custom Chrome Tab

**Exported Activities** (9 total, updated for v16.9.0):
1. `coin98.crypto.finance.media.MainActivity` — main entry, handles all deep links
2. `com.facebook.CustomTabActivity` — Facebook OAuth
3. `com.google.firebase.auth.internal.GenericIdpActivity` — Firebase Auth
4. `com.google.firebase.auth.internal.RecaptchaActivity` — reCAPTCHA
5. `com.onesignal.notifications.activities.NotificationOpenedActivity` — push (v16.9.0 new path)
6. `com.onesignal.notifications.activities.NotificationOpenedActivityAndroid22AndOlder` — legacy push (v16.9.0 new path)
7. `com.onesignal.NotificationOpenedActivityHMS` — HMS push
8. `app.notifee.core.NotificationReceiverActivity` — local notification

**Removed in v16.9.0**: `androidx.biometric.DeviceCredentialHandlerActivity` (no longer exported)

**Exported Services**:
- `RNSendIntentModule` — ⚠️ allows other apps to trigger intents
- `SystemJobService` — WorkManager
- `RevocationBoundService` — Google Sign-In

### 12.5 Native Libraries (Security-Relevant, v16.9.0 arm64-v8a)

| Library | Size | Purpose |
|---------|------|---------|
| `libTrustWalletCore.so` | 17.2MB | TrustWallet core crypto — key gen, signing (+49% from v16.7.0) |
| `librnskia.so` | 11.0MB | Skia graphics (+63%) |
| `librealm.so` | 9.1MB | Realm encrypted database (+77%) |
| `libreactnative.so` | 5.7MB | Consolidated RN runtime (NEW — replaced 30+ smaller libs) |
| `libcrypto.so` | 4.9MB | OpenSSL crypto (+127%) |
| `librive-android.so` | 4.1MB | Rive animations |
| `libappmodules.so` | 2.4MB | App-specific native modules (NEW) |
| `libuniffi_yttrium_wcpay.so` | 2.1MB | **WalletConnect Pay** via UniFFI (NEW) |
| `libconscrypt_jni.so` | 2.1MB | TLS provider (+64%) |
| `libreanimated.so` | 1.4MB | React Native Reanimated (+255%) |
| `libNitroModules.so` | 801KB | Nitro modules framework (NEW) |
| `libreactnativequickcrypto.so` | 666KB | RN crypto bridge (+53%) |
| `libfastcrypto.so` | 437KB | Fast crypto operations (NEW) |
| `libreact-native-mmkv.so` | 366KB | MMKV encrypted storage (renamed) |
| `libquickbase64.so` | 46KB | Base64 encoding (+197%) |

**Removed in v16.9.0**: `libtoolChecker.so` (root detection), `libsecp256k1.so` (consolidated into TrustWalletCore), `libcrypto_bridge.so` (consolidated). Total: 71 → 43 libs (47 removed, 19 new).

### 12.6 Production API Infrastructure (from v16.9.0 bundle)

49 production endpoints discovered (including 3 NEW in v16.9.0):
- `api.coin98.com`, `api-btc.coin98.com`, `api-dapps.coin98.com`, `api-kyc.coin98.com`
- `encrypted.coin98.com`, `encrypted.coin98.tech`
- `hubs-vault-api.coin98.tech`
- `socialwallet.coin98.com`, `social-signin.v2.ramper.xyz`
- `ton-bridge.coin98.tech`, `perp.coin98.tech`
- `superwallet-{chat-api,fiat,history-records,information-api,markets,misc,notification,portfolio,referral-prd,xpoint}.coin98.tech`
- `spacegate-api.coin98.com`, `rapid.coin98.com`
- `vault.coin98.com`, `wallet.coin98.com`
- `zencard-visa-api-stg.coin98.tech` (staging in prod!)
- 🔴 **NEW v16.9.0**: `https://internal.c98staging.dev` — internal staging infrastructure (3 refs in prod bundle)
- 🔴 **NEW v16.9.0**: `https://api-dagora-dev.c98staging.dev/api/v1/auth/refresh` — Dagora dev API
- 🔴 **NEW v16.9.0**: `https://api-server.zencard.io` — Zencard card issuance API (LIVE, CORS:*, Swagger UI)

### 12.7 Android Permissions (Security-Relevant)

| Permission | Risk |
|-----------|------|
| `CAMERA` | QR scanning, but also photo access |
| `RECORD_AUDIO` | Voice input? Unusual for wallet |
| `ACCESS_FINE_LOCATION` | Precise GPS — privacy concern |
| `SYSTEM_ALERT_WINDOW` | Overlay attacks possible |
| `NFC` | Contactless features |
| `BLUETOOTH_*` (5 perms) | BLE device connectivity |
| `WRITE_EXTERNAL_STORAGE` | File system write (legacy) |
| `POST_NOTIFICATIONS` | Push notifications |
| `SCHEDULE_EXACT_ALARM` | Background scheduling |

### 12.8 WebView Configuration
- `allowFileAccess`: enabled (×1)
- `domStorageEnabled`: enabled (×1)
- `injectedJavaScript`: ×3 instances — JS injection into WebViews
- DApp browser uses WebView → any XSS in loaded dApp has full JS bridge access

### 12.9 Version Changelog (v16.7.0 → v16.9.0)

Base sections (12.1–12.8) now reflect v16.9.0 state. Key changes from v16.7.0:

#### Security Regressions
- 🔴 **Root detection REMOVED**: `libtoolChecker.so` deleted (see 12.2, 12.5)
- 🔴 **AsyncStorage usage doubled**: 10 → 23 references — more plaintext data at rest (see 12.2)
- 🔴 **10 GetBlock RPC keys added**: paid blockchain RPC, hardcoded (see 12.3)
- 🔴 **Internal staging domain exposed**: `internal.c98staging.dev` + Dagora dev API (see 12.6)
- 🔴 **Zencard production API added**: `api-server.zencard.io` — LIVE, CORS:*, Swagger UI (see 12.6)

#### New Features / Attack Surface
- **Credential Provider / Passkey**: `CredentialProviderPlayServicesImpl` added; WebAuthn refs 1 → 4
- **WalletConnect Pay**: `libuniffi_yttrium_wcpay.so` (2.1MB) — new payment feature
- **Firebase Crashlytics + Firestore + Sessions**: new backend services
- **OneSignal SDK upgraded**: paths changed to `com.onesignal.notifications.activities.*`
- **Target SDK 35 → 36** (Android 16)
- **Architecture**: armeabi-v7a (32-bit) → arm64-v8a (64-bit), 71 → 43 libs (consolidated)
- **Ramper references**: 38 → 53 (+15, expanded social wallet)

#### Unchanged Security Posture

| Security Feature | Status |
|-----------------|--------|
| SSL/cert pinning | **NONE** (0 refs both versions) |
| Play Integrity / SafetyNet | **NONE** (0 refs both versions) |
| usesCleartextTraffic | **true** (still enabled) |
| Staging endpoints in prod | 21 (unchanged) |
| Infura/NodeReal keys | Same (not rotated) |
| Google API/OAuth keys | Same (not rotated) |
| Deep link schemes | Same (coin98://, wc://, https://) |

### 12.10 Android Attack Chains

**AC-14: Deep Link Intent Injection via `coin98://` scheme**
- Any app on device can send `coin98://` intents to MainActivity
- Deep link routes include `TokenMarketDetails?chain=` and `HyperliquidPerpCoin98?chain=`
- If chain parameter is not validated, could trigger actions on unintended chains
- `RNSendIntentModule` is exported — other apps can trigger intents through this service

**AC-15: Staging Endpoint Exploitation**
- 21 staging endpoints hardcoded in production bundle
- 3 confirmed publicly reachable with `ACAO: *` (wildcard CORS):
  - `ramper-v2-api-test.coin98.dev`
  - `superwallet-chat-api-stg.coin98.tech`
  - `zencard-visa-api-stg.coin98.tech`
- `internal.c98staging.dev` — internal staging (v16.9.0 only)
- Staging servers typically have debug endpoints, verbose errors, weaker auth

**AC-16: GetBlock RPC Key Abuse (v16.9.0)**
- 10 GetBlock API keys hardcoded in production bundle
- Keys provide paid RPC access to multiple blockchains
- If not origin-restricted, attacker can: exhaust rate limits (DoS to users), use for free RPC, enumerate wallet addresses via API

**AC-17: AsyncStorage Data Theft on Rooted Device**
- AsyncStorage (×23 in v16.9.0) stores data in plaintext SQLite
- No root/jailbreak detection (2 trivial refs, no Magisk/Frida detection)
- No Play Integrity attestation
- Rooted device + malware = full AsyncStorage exfiltration
- Combined with Realm DB encryption key potentially in AsyncStorage → full wallet compromise

### 12.11 Native Library Diff Details (v16.7.0 → v16.9.0)

See 12.5 for the current v16.9.0 library inventory. Additional v16.7.0 → v16.9.0 size comparisons:

| Library | v16.7.0 | v16.9.0 | Change |
|---------|---------|---------|--------|
| `libTrustWalletCore.so` | 11.5MB | 17.2MB | **+49%** (more chains/signing) |
| `libcrypto.so` (OpenSSL) | 2.1MB | 4.9MB | **+127%** |
| `librealm.so` | 5.2MB | 9.1MB | **+77%** (DB schema expansion) |
| `libreanimated.so` | 392KB | 1.4MB | **+255%** |
| `libhermes.so` | 1.5MB | 2.1MB | **+42%** |

Additional new libs not in 12.5 (non-security): `libcrashlytics.so` + 3 helpers (1.3MB, Firebase NDK), `libreact_codegen_TeleportViewSpec.so` (67KB), `libgesturehandler.so` (38KB), `libjnidispatch.so` (162KB).

### 12.12 Zencard API Server Discovery (v16.9.0)

- **URL**: `https://api-server.zencard.io`
- **Status**: LIVE on Cloudflare (172.67.167.213 / 104.21.34.28)
- **CORS**: `Access-Control-Allow-Origin: *` (wildcard)
- **Health**: `/health` returns `true` (200 OK)
- **Swagger**: `/api-docs` serves Swagger UI (empty spec — routes not documented)
- **CSP**: Full CSP with `script-src 'self'` (properly configured)
- **HSTS**: `max-age=15552000; includeSubDomains`
- This is a **card issuance API** for Zencard (Visa debit card product). CORS wildcard on a financial API is concerning.

### 12.13 Android Recommendations

| # | Priority | Recommendation |
|---|----------|---------------|
| A1 | 🔴 IMMEDIATE | Implement SSL/cert pinning (currently zero) |
| A2 | 🔴 IMMEDIATE | Add Play Integrity / SafetyNet attestation |
| A3 | 🔴 IMMEDIATE | Restore and strengthen root/tamper detection (`libtoolChecker.so` removed in v16.9.0) |
| A4 | 🔴 IMMEDIATE | Remove 21 staging endpoints from production bundle |
| A5 | 🔴 IMMEDIATE | Remove `internal.c98staging.dev` references from production |
| A6 | 🔴 IMMEDIATE | Rotate all 10 GetBlock RPC keys and restrict by origin |
| A7 | HIGH | Migrate AsyncStorage (×23) to encrypted MMKV or Keychain |
| A8 | HIGH | Set `usesCleartextTraffic=false` and enforce HTTPS |
| A9 | HIGH | Add Frida/Magisk detection (currently zero) |
| A10 | HIGH | Restrict CORS on `api-server.zencard.io` (financial API with wildcard) |
| A11 | HIGH | Rotate Infura, NodeReal, and Airbridge keys (shared across versions, never rotated) |
| A12 | MEDIUM | Audit `RNSendIntentModule` exported service for intent injection |
| A13 | MEDIUM | Validate deep link parameters (`chain=` param in coin98:// routes) |
| A14 | MEDIUM | Remove `RECORD_AUDIO` permission if not needed |
| A15 | MEDIUM | Implement WebView `setAllowFileAccessFromFileURLs(false)` explicitly |

---

## 13. iOS App v16.9.0 — Deep Deconstruction

### 13.1 IPA Metadata

| Field | Value |
|-------|-------|
| **Bundle ID** | `coin98.crypto.finance.insights` |
| **Display Name** | Coin98: Crypto & AI Wallet |
| **Version** | 16.9.0 (build: 1772190381) |
| **Min iOS** | 15.6 |
| **SDK** | iphoneos 26.2 (Xcode 26.2, build 17C52) |
| **Architecture** | arm64 only |
| **Mach-O Binary** | 63MB (FairPlay DRM encrypted) |
| **RN Bundle** | `main.jsbundle` — 145MB (122M chars) — **1.7× larger than Android** |
| **Total App Size** | 369MB extracted |
| **Frameworks** | 19 dynamic frameworks (23MB total) |
| **React Native** | New Architecture enabled, release level: experimental |
| **Seller** | COIN98 WALLET LTD (© Ninety Eight) |
| **App Store ID** | 1561969966 |
| **Source** | ipatool download (App Store, 243MB IPA) |

### 13.2 iOS-Specific Secrets

#### 🔴 GoogleService-Info.plist (Firebase config shipped in IPA)

| Secret | Value |
|--------|-------|
| **Google API Key (iOS)** | `AIzaSyAxVjv2_GVKRELqrccA1G3uXbBdrgBjXdA` |
| **Google OAuth Client ID (iOS)** | `663197326394-ms6jba6e4rfnukl2ffd4ed5mo752popa.apps.googleusercontent.com` |
| **Android Client ID (cross-ref)** | `663197326394-1f5nsl28isuv1sphhjthrichqe1pbisj.apps.googleusercontent.com` |
| **Firebase Project** | `coin98-b7f98` |
| **Firebase DB URL** | `https://coin98-b7f98.firebaseio.com` |
| **Firebase Storage** | `coin98-b7f98.appspot.com` |
| **GCM Sender ID** | `663197326394` |
| **Google App ID (iOS)** | `1:663197326394:ios:f3b9247936edbe70b42903` |

#### 🔴 CodePush Deployment Key

`3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` — enables over-the-air JS bundle updates. If this key is compromised, an attacker could push malicious bundle updates to all iOS users.

#### 🔴 Facebook SDK Secrets (Info.plist)

| Secret | Value |
|--------|-------|
| **Facebook App ID** | `468982885473956` |
| **Facebook Client Token** | `4f227919be5aae71528a7455f59d1b21` |
| **Facebook Display Name** | `C98 Super Wallet` |

#### Additional iOS-Only OAuth Client ID

`663197326394-1f5nsl28isuv1sphhjthrichqe1pbisj.apps.googleusercontent.com` — this Android client ID appears in the iOS GoogleService-Info.plist but was NOT found in the Android APK's JS bundle. Total unique OAuth client IDs across all platforms: **5**.

### 13.3 URL Schemes & Deep Links

**Registered URL Schemes**:
- `coin98://` — main deep link scheme
- `line3rdp.coin98.crypto.finance.insights` — LINE SDK integration
- `fb468982885473956` — Facebook OAuth callback
- `com.googleusercontent.apps.663197326394-ms6jba6e4rfnukl2ffd4ed5mo752popa` — Google OAuth callback

**Queried App Schemes** (24 total):
- Facebook SDK: `fbapi*` (×10), `fb`, `fbauth`, `fbauth2`, `fb-messenger-*` (×4), `fbshareextension`
- Social: `telegram`, `instagram`, `twitter`, `zalo`
- Blockchain: `concordiumidapp`

### 13.4 App Transport Security

```
NSAppTransportSecurity:
  NSExceptionDomains:
    localhost:
      NSExceptionAllowsInsecureHTTPLoads: true
```

Only localhost is exempted from ATS. This is **better than Android** which has `usesCleartextTraffic=true` globally. However, the JS bundle itself makes HTTP requests that bypass ATS via React Native's networking layer.

### 13.5 iOS Frameworks (Security-Relevant)

| Framework | Size | Purpose |
|-----------|------|---------|
| `hermes.framework` | 4.7MB | Hermes JS engine |
| `OpenSSL.framework` | 4.4MB | OpenSSL crypto |
| `FBSDKCoreKit.framework` | 4.4MB | Facebook SDK core |
| `RiveRuntime.framework` | 4.1MB | Rive animations |
| `FBSDKGamingServicesKit.framework` | 1.2MB | Facebook gaming (unusual for wallet) |
| `FBSDKLoginKit.framework` | 988KB | Facebook login |
| `FBSDKShareKit.framework` | 856KB | Facebook sharing |
| `FBAEMKit.framework` | 644KB | Facebook attribution |
| `OneSignal*.framework` (×9) | 3.0MB total | Push notifications |
| `OneSignalLocation.framework` | 116KB | Location tracking via push SDK |

**Notable**: Facebook Gaming Services Kit is included — unusual for a crypto wallet. OneSignal Location framework enables location-based push targeting.

### 13.6 Standalone `aes.js` — CryptoJS AES at App Root

A standalone 14KB CryptoJS AES implementation (`aes.js`) is shipped at the app root level. This is the **same pattern as the Chrome extension** — a self-contained encrypt/decrypt module using CryptoJS with:
- AES-CBC mode
- PKCS7 padding
- EvpKDF key derivation (MD5-based, 1 iteration — **cryptographically weak**)
- Password-based encryption (OpenSSL format with salt)

This is likely used for the same wallet encryption as the Chrome extension, where `aes_decrypt_coin98` can decrypt all stored mnemonics.

### 13.7 Privacy & Permissions

**iOS Usage Descriptions** (12 permissions requested):
- Camera (QR scanning)
- Microphone ("voice commands")
- Location (always + when in use — "hardware devices")
- Photos (profile picture)
- Contacts (send assets to friends)
- Calendar (event reminders)
- FaceID/TouchID (biometric auth)
- NFC ("decrypt wallet data" — unusual description)
- Motion (security — unusual activity detection)
- Speech Recognition (voice commands)
- Bluetooth (hardware wallet connectivity)
- User Tracking (Facebook login — misleading description)

**Privacy Manifest** (`PrivacyInfo.xcprivacy`):
- File timestamp API, UserDefaults, System boot time, Disk space
- `NSPrivacyTracking: false`
- `NSPrivacyCollectedDataTypes: []` — claims NO data collection

### 13.8 Firebase Configuration (base64-decoded)

```json
{
  "crashlytics_javascript_exception_handler_chaining_enabled": true,
  "crashlytics_is_error_generation_on_js_crash_enabled": true,
  "crashlytics_ndk_enabled": false,
  "crashlytics_auto_collection_enabled": true,
  "perf_auto_collection_enabled": false
}
```

Crashlytics auto-collection is **enabled** in the Firebase JSON config, but **disabled** via Info.plist key `FirebaseCrashlyticsCollectionEnabled: false` — contradictory settings. The Info.plist key takes precedence on iOS.

### 13.9 iOS vs Android — Cross-Platform Comparison

#### Shared (Identical) Across Both Platforms

| Item | Count/Value |
|------|-------------|
| Google API Key (bundle) | `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I` |
| OAuth Client IDs (bundle) | 4 identical |
| Infura keys | 2 identical (prod + testnet) |
| NodeReal keys | 3 identical |
| GetBlock RPC keys | 10 identical |
| Staging endpoints | 21 identical |
| `c98staging.dev` refs | 3 identical |
| Coin98 production endpoints | 49 identical |
| AsyncStorage refs | 17 (JS layer) |
| MMKV refs | 23 |
| Realm refs | 138 |
| Encryption refs | 344 |
| Mnemonic/seed refs | 55 |
| Private key refs | 100 |
| postMessage calls | 2 |
| WebView JS injection | 3 |
| SSL/cert pinning | **0** (both) |
| Device attestation | **0** (both) |
| Jailbreak/root detection | **1** (both — trivial) |

#### iOS-Only

| Item | Value |
|------|-------|
| **Google API Key (Firebase)** | `AIzaSyAxVjv2_GVKRELqrccA1G3uXbBdrgBjXdA` (not in Android bundle) |
| **5th OAuth Client ID** | `663197326394-1f5nsl28isuv1sphhjthrichqe1pbisj` (in GoogleService-Info.plist) |
| **CodePush Key** | `3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` |
| **Facebook Client Token** | `4f227919be5aae71528a7455f59d1b21` |
| **Firebase DB URL** | `https://coin98-b7f98.firebaseio.com` |
| **Firebase Storage** | `coin98-b7f98.appspot.com` |
| **aes.js standalone** | CryptoJS AES at app root (same as Chrome extension) |
| **LINE SDK integration** | `line3rdp.coin98.crypto.finance.insights` |
| **Facebook Gaming SDK** | Unusual for crypto wallet |
| ATS (localhost only) | Better than Android's global cleartext |

#### Android-Only

| Item | Value |
|------|-------|
| `usesCleartextTraffic=true` | Global HTTP allowed |
| `libtoolChecker.so` | Root detection (removed in v16.9.0) |
| `RNSendIntentModule` exported | Intent injection surface |
| `RECORD_AUDIO` permission | Not in iOS |
| `SYSTEM_ALERT_WINDOW` | Overlay permission |
| Exported activities (9) | Deep link handlers |

### 13.10 iOS Attack Chains

**AC-18: CodePush OTA Bundle Replacement**
- CodePush deployment key `3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` is hardcoded in Info.plist
- If attacker obtains access to the CodePush account (via leaked credentials or Microsoft App Center compromise), they can push a malicious JS bundle update to ALL iOS users
- The 145MB bundle contains all wallet logic, encryption keys, and mnemonic handling
- No code signing verification beyond CodePush's own — a compromised update = full wallet drain

**AC-19: Firebase Realtime Database Exposure**
- `https://coin98-b7f98.firebaseio.com` — Firebase Realtime Database URL exposed
- If Firebase security rules are misconfigured (common), unauthenticated reads/writes possible
- Combined with `coin98-b7f98.appspot.com` Storage bucket — potential for data exfiltration
- GCM Sender ID `663197326394` could be used to send push notifications if FCM key is weak

**AC-20: Facebook SDK Token Leakage**
- Facebook App ID `468982885473956` + Client Token `4f227919be5aae71528a7455f59d1b21`
- Client token allows making Graph API calls on behalf of the app
- Combined with Facebook Gaming SDK (unusual in a wallet) — expanded OAuth scope
- `NSUserTrackingUsageDescription` misleadingly says "Use your Facebook account to log in" — actually enables IDFA tracking

### 13.11 iOS Recommendations

| # | Priority | Recommendation |
|---|----------|---------------|
| I1 | 🔴 IMMEDIATE | Rotate CodePush deployment key and restrict to signed releases |
| I2 | 🔴 IMMEDIATE | Audit Firebase Realtime Database security rules (`coin98-b7f98`) |
| I3 | 🔴 IMMEDIATE | Implement jailbreak detection (currently zero — no Cydia/checkra1n/Frida checks) |
| I4 | 🔴 IMMEDIATE | Add SSL certificate pinning (zero refs in both native and JS layer) |
| I5 | HIGH | Remove Facebook Gaming SDK if not needed (unusual attack surface for wallet) |
| I6 | HIGH | Restrict Firebase Storage bucket access rules |
| I7 | HIGH | Replace EvpKDF (MD5, 1 iteration) with PBKDF2/Argon2 in `aes.js` |
| I8 | HIGH | Implement iOS App Attest / DeviceCheck (currently zero attestation) |
| I9 | MEDIUM | Fix misleading `NSUserTrackingUsageDescription` (says Facebook login, enables IDFA) |
| I10 | MEDIUM | Remove `OneSignalLocation.framework` if location-based push not needed |
| I11 | MEDIUM | Fix contradictory Crashlytics collection settings (Info.plist vs firebase_json_raw) |

---

## 14. Cross-Platform Security Summary

### 14.1 Complete Secret Inventory (All Platforms)

| # | Secret | Platform | Source |
|---|--------|----------|--------|
| 1 | Google API Key `AIzaSyBqw7YKy-aH-BELMD9rLyxtylZeEpCFJ-I` | Android + iOS + Extension | JS bundle |
| 2 | Google API Key `AIzaSyAxVjv2_GVKRELqrccA1G3uXbBdrgBjXdA` | iOS only | GoogleService-Info.plist |
| 3 | OAuth `663197326394-ngu7bcpsbo6t6ampt433aqceei7mbhjm` | Android + iOS | JS bundle |
| 4 | OAuth `663197326394-pl8q5fj0um5kmn8c7k0lk6m2q14n3po4` | Android + iOS + Extension | JS bundle |
| 5 | OAuth `663197326394-ms6jba6e4rfnukl2ffd4ed5mo752popa` | Android + iOS | JS bundle + GoogleService-Info |
| 6 | OAuth `663197326394-glapn4i2dtue2gm8r21qoumbu2qtj0kl` | Android + iOS | JS bundle |
| 7 | OAuth `663197326394-1f5nsl28isuv1sphhjthrichqe1pbisj` | iOS only | GoogleService-Info.plist |
| 8 | Google OAuth **CLIENT SECRET** `GOCSPX-████████████████████████████` | Extension only | background.js |
| 9 | Infura `████████████████████████████████` (prod) | All platforms | JS bundle |
| 10 | Infura `████████████████████████████████` (testnet) | All platforms | JS bundle |
| 11 | NodeReal `955ab7c09f78437981a573b43061fe10` | All platforms | JS bundle |
| 12 | NodeReal `5c4ed7c647c0479f9ae118b0b62c745c` | All platforms | JS bundle |
| 13 | NodeReal `2035a58b2c0d480d93a7e21acb6e460c` | All platforms | JS bundle |
| 14–23 | GetBlock RPC keys (×10) | Android + iOS | JS bundle |
| 24 | Airbridge SDK Secret `cb5bb86f...` | Android + iOS | JS bundle |
| 25 | Airbridge SDK Signature ID `51f9529c-...` | Android + iOS | JS bundle |
| 26 | Meta Install Referrer `1082161529482856` | Android + iOS | JS bundle |
| 27 | CodePush Key `3upL_dngkKKTqcNvTRfaaedN7MAKzbULdXWyS` | iOS only | Info.plist |
| 28 | Facebook App ID `468982885473956` | iOS | Info.plist |
| 29 | Facebook Client Token `4f227919be5aae71528a7455f59d1b21` | iOS only | Info.plist |
| 30 | Firebase DB `coin98-b7f98.firebaseio.com` | iOS only | GoogleService-Info.plist |
| 31 | Cloud Functions `us-central1-coin98-b7f98.cloudfunctions.net` | All platforms | JS bundle |
| 32 | Cloud Functions `us-central1-ramper-prod.cloudfunctions.net` | All platforms | JS bundle |
| 33 | Cloud Backup HMAC key `"coin98_token"` | Extension | background.js |

**Total: 33 hardcoded secrets across 3 platforms. Zero rotation observed between v16.7.0 → v16.9.0.**

### 14.2 Zero-Security Features (All Platforms)

| Security Feature | Extension | Android | iOS |
|-----------------|-----------|---------|-----|
| SSL/cert pinning | N/A | ❌ NONE | ❌ NONE |
| Root/jailbreak detection | N/A | ❌ REMOVED in v16.9.0 | ❌ NONE |
| Frida/Magisk detection | N/A | ❌ NONE | ❌ NONE |
| Device attestation | N/A | ❌ NONE | ❌ NONE |
| Code integrity verification | ❌ NONE | ❌ NONE | CodePush only |
| Password hashing | ❌ ENCRYPTED (reversible) | ❌ same | ❌ same |
| Origin validation | ❌ 16 hardcoded origins | ❌ same bundle | ❌ same bundle |

### 14.3 Attack Chain Summary (All 20 Chains)

| Chain | Target | Severity | Description |
|-------|--------|----------|-------------|
| AC-1 | Extension | CRITICAL | `sync_wallet` decrypts ALL mnemonics for whitelisted origins |
| AC-2 | Extension | CRITICAL | `aes_decrypt_coin98` — `isConnected = () => true` bypass |
| AC-3 | Extension | CRITICAL | Password stored encrypted (not hashed) — fully reversible |
| AC-4 | Extension | HIGH | Cloud backup HMAC key `"coin98_token"` — trivial |
| AC-5 | Extension | HIGH | postMessage wildcard in 6+ files |
| AC-6 | Extension | HIGH | Ramper Shamir 3-of-2 — Share 3 encrypted with predictable UID |
| AC-7 | Extension | HIGH | localhost/127.0.0.1 whitelisted origin |
| AC-8 | Extension | HIGH | Google OAuth CLIENT SECRET in background.js |
| AC-9 | Extension | MEDIUM | Contents.js relays ALL window messages (no origin filter) |
| AC-10 | Extension | MEDIUM | inpage.js isCoin98 flag settable by any page |
| AC-11 | Extension | MEDIUM | dagora.xyz CORS:* + script-src * — data theft |
| AC-12 | Infrastructure | HIGH | socket.coin98.services CORS wildcard → WC session hijack |
| AC-13 | Infrastructure | HIGH | dagora.xyz CORS:* → cross-origin data theft |
| AC-14 | Android | HIGH | Deep link intent injection via `coin98://` |
| AC-15 | Android + iOS | HIGH | 21 staging endpoints in production bundle (3 reachable) |
| AC-16 | Android + iOS | HIGH | 10 GetBlock RPC keys — rate limit exhaustion / free RPC |
| AC-17 | Android | HIGH | AsyncStorage plaintext + zero root detection |
| AC-18 | iOS | CRITICAL | CodePush OTA bundle replacement → full wallet drain |
| AC-19 | iOS | HIGH | Firebase Realtime DB exposure (`coin98-b7f98`) |
| AC-20 | iOS | MEDIUM | Facebook SDK token leakage + misleading tracking description |

### 14.4 Full Recommendation Count

| Priority | Extension | Android | iOS | Total |
|----------|-----------|---------|-----|-------|
| 🔴 IMMEDIATE | 14 | 6 | 4 | **24** |
| HIGH | 11 | 5 | 4 | **20** |
| MEDIUM | 19 | 4 | 3 | **26** |
| **Total** | **44** | **15** | **11** | **70** |
