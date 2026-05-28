// Server-side proxy — ALL secrets injected from env vars, never exposed to client
// Client sends: { url, method, body, authHint }
// authHint tells proxy WHICH credential set to inject (e.g. "supabase_campaign", "jwt_hs512", "ton")
// Secrets are read from process.env (set via Netlify env vars)

const ALLOWED_TARGETS = [
    'coin98.tech', 'coin98.com', 'coin98.dev', 'coin98.services',
    'coin98-b7f98.cloudfunctions.net', 'coin98-b7f98.firebaseio.com',
    'coin98.s3.ap-southeast-1.amazonaws.com',
    'supabase.co',
    'dagora.xyz', 'baryon.network', 'saros.finance', 'saros.xyz', 'oneid.xyz',
    'infura.io', 'nodereal.io', 'blockvision.org', 'tonapi.io',
    'basescan.org', 'lineascan.build', 'scrollscan.com', 'oklink.com',
    'googleapis.com', 'google-analytics.com', 'firebaseapp.com',
    'amberblocks.com', 'frontierdao.org', 'interlock.news',
];

// Resolve auth from env vars based on authHint
// Returns { headers: {}, urlSuffix: '' } — proxy injects both
function resolveAuth(authHint) {
    const env = process.env;
    const r = { headers: {}, urlSuffix: '' };
    switch (authHint) {
        case 'supabase_campaign':
            if (env.SUPABASE_CAMPAIGN_ANON_KEY) {
                r.headers = { apikey: env.SUPABASE_CAMPAIGN_ANON_KEY, Authorization: `Bearer ${env.SUPABASE_CAMPAIGN_ANON_KEY}` };
            } break;
        case 'supabase_campaign_anon':
            if (env.SUPABASE_CAMPAIGN_ANON_KEY) {
                r.headers = { apikey: env.SUPABASE_CAMPAIGN_ANON_KEY };
            } break;
        case 'supabase_2025':
            if (env.SUPABASE_2025_ANON_KEY) {
                r.headers = { apikey: env.SUPABASE_2025_ANON_KEY, Authorization: `Bearer ${env.SUPABASE_2025_ANON_KEY}` };
            } break;
        case 'supabase_2025_anon':
            if (env.SUPABASE_2025_ANON_KEY) {
                r.headers = { apikey: env.SUPABASE_2025_ANON_KEY };
            } break;
        case 'jwt_hs512':
            if (env.JWT_HS512_NO_EXPIRY) {
                r.headers = { Authorization: `Bearer ${env.JWT_HS512_NO_EXPIRY}` };
            } break;
        case 'ton':
            if (env.TON_API_BEARER) {
                r.headers = { Authorization: `Bearer ${env.TON_API_BEARER}` };
            } break;
        case 'hmac':
            if (env.STATIC_HMAC_SIGNATURE) {
                r.headers = { 'X-Signature': env.STATIC_HMAC_SIGNATURE };
            } break;
        case 'oklink':
            if (env.OKLINK_KEY) {
                r.headers = { 'Ok-Access-Key': env.OKLINK_KEY };
            } break;
        // URL-embedded keys — proxy appends key to URL path or query
        case 'infura_1':
            if (env.INFURA_ID_1) r.urlSuffix = env.INFURA_ID_1;
            break;
        case 'infura_2':
            if (env.INFURA_ID_2) r.urlSuffix = env.INFURA_ID_2;
            break;
        case 'infura_3':
            if (env.INFURA_ID_3) r.urlSuffix = env.INFURA_ID_3;
            break;
        case 'infura_default':
            if (env.INFURA_ID_DEFAULT) r.urlSuffix = env.INFURA_ID_DEFAULT;
            break;
        case 'nodereal_bsc':
            if (env.NODEREAL_BSC_KEY) r.urlSuffix = env.NODEREAL_BSC_KEY;
            break;
        case 'blockvision_sui':
            if (env.BLOCKVISION_SUI_KEY) r.urlSuffix = env.BLOCKVISION_SUI_KEY;
            break;
        case 'basescan':
            if (env.BASESCAN_KEY) r.urlSuffix = `&apikey=${env.BASESCAN_KEY}`;
            break;
        case 'lineascan':
            if (env.LINEASCAN_KEY) r.urlSuffix = `&apikey=${env.LINEASCAN_KEY}`;
            break;
        case 'scrollscan':
            if (env.SCROLLSCAN_KEY) r.urlSuffix = `&apikey=${env.SCROLLSCAN_KEY}`;
            break;
        case 'ga4':
            if (env.GA4_MEASUREMENT_ID && env.GA4_API_SECRET) {
                r.urlSuffix = `&measurement_id=${env.GA4_MEASUREMENT_ID}&api_secret=${env.GA4_API_SECRET}`;
            } break;
        case 'firebase':
            if (env.FIREBASE_API_KEY) r.urlSuffix = env.FIREBASE_API_KEY;
            break;
    }
    return r;
}

export default async (req) => {
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (req.method === 'OPTIONS') {
        return new Response('', { status: 204, headers: corsHeaders });
    }

    const log = { ts: new Date().toISOString() };

    try {
        const reqBody = await req.json();
        const { url, method = 'GET', body: proxyBody, authHint } = reqBody;

        log.url = url;
        log.method = method;
        log.authHint = authHint || 'none';

        if (!url) {
            return Response.json({ error: 'Missing url parameter', log }, { status: 400, headers: corsHeaders });
        }

        // Domain allowlist check
        const urlObj = new URL(url);
        const isAllowed = ALLOWED_TARGETS.some(d => urlObj.hostname.endsWith(d));
        if (!isAllowed) {
            log.blocked = urlObj.hostname;
            return Response.json({ error: `Domain not in allowlist: ${urlObj.hostname}`, log }, { status: 403, headers: corsHeaders });
        }

        // Build headers + URL — auth injected from env vars
        const auth = authHint ? resolveAuth(authHint) : { headers: {}, urlSuffix: '' };
        const finalUrl = auth.urlSuffix ? url + auth.urlSuffix : url;
        const finalHeaders = {
            'Accept': 'application/json, text/html, */*',
            'User-Agent': 'CPK-2026-001/ApiProbe (c98staging.dev)',
            ...auth.headers,
        };

        log.authInjected = Object.keys(auth.headers);
        log.urlModified = !!auth.urlSuffix;
        log.finalUrlDomain = new URL(finalUrl).hostname;
        log.missingEnvKeys = [];
        if (authHint && Object.keys(auth.headers).length === 0 && !auth.urlSuffix) {
            log.missingEnvKeys.push(authHint);
        }

        const fetchOpts = { method, headers: finalHeaders };

        if (proxyBody && (method === 'POST' || method === 'PUT')) {
            fetchOpts.body = proxyBody;
            fetchOpts.headers['Content-Type'] = 'application/json';
            log.hasBody = true;
            log.bodyLength = proxyBody.length;
            // Log first 200 chars of body for debugging (no secrets)
            log.bodyPreview = proxyBody.slice(0, 200);
        } else {
            log.hasBody = false;
        }

        log.sentHeaderKeys = Object.keys(fetchOpts.headers);

        const t0 = Date.now();
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        let resp;
        try {
            resp = await fetch(finalUrl, { ...fetchOpts, signal: controller.signal });
        } finally {
            clearTimeout(timeout);
        }
        const dt = Date.now() - t0;

        log.responseStatus = resp.status;
        log.responseTime = dt;

        const respHeaders = {};
        resp.headers.forEach((v, k) => { respHeaders[k] = v; });

        let respBody = '';
        try {
            respBody = await resp.text();
            log.responseSize = respBody.length;
            if (respBody.length > 8000) {
                respBody = respBody.slice(0, 8000) + `\n\n... truncated (${respBody.length} bytes total)`;
            }
        } catch (e) {
            respBody = `[Could not read body: ${e.message}]`;
            log.bodyError = e.message;
        }

        console.log('[PROXY]', JSON.stringify(log));

        return Response.json({
            status: resp.status,
            statusText: resp.statusText,
            headers: respHeaders,
            body: respBody,
            timing: dt,
            log,
        }, { headers: corsHeaders });

    } catch (e) {
        log.error = e.message;
        log.stack = e.stack?.split('\n').slice(0, 3).join(' | ');
        console.error('[PROXY ERROR]', JSON.stringify(log));

        return Response.json({
            error: e.message,
            log,
        }, { status: 502, headers: corsHeaders });
    }
};
