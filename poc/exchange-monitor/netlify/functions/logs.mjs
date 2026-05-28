// Returns all captured traffic logs from the blob store
// Dashboard fetches this to display intercepted requests

import { getStore } from "@netlify/blobs";

export default async (req) => {
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (req.method === 'OPTIONS') {
        return new Response('', { status: 204, headers: corsHeaders });
    }

    try {
        const store = getStore("traffic-log");
        const { blobs } = await store.list();

        // Get most recent 100 entries
        const entries = [];
        const recent = blobs.slice(-100).reverse();

        for (const blob of recent) {
            try {
                const data = await store.get(blob.key, { type: "json" });
                if (data) entries.push({ key: blob.key, ...data });
            } catch (e) {
                entries.push({ key: blob.key, error: e.message });
            }
        }

        return Response.json({
            count: blobs.length,
            showing: entries.length,
            entries,
        }, { headers: corsHeaders });

    } catch (e) {
        console.error('[LOGS ERROR]', e.message, e.stack);
        return Response.json({
            error: e.message,
            stack: (e.stack || '').split('\n').slice(0, 5),
            hint: "Netlify Blobs may not be available in local dev — deploy to test",
            hasBlobsContext: !!process.env.NETLIFY_BLOBS_CONTEXT,
            hasSiteId: !!process.env.SITE_ID,
            nodeVersion: process.version,
        }, { status: 500, headers: corsHeaders });
    }
};

// No config.path needed — function is accessible at /.netlify/functions/logs by default
