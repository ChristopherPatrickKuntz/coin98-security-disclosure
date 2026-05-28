const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Allow-Headers": "*",
    "Content-Type": "application/json",
};

const LISTENER_NAME = "internal";

async function logToSupabase(entry) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_KEY;
    if (!url || !key) {
        console.error("SUPABASE_URL or SUPABASE_KEY not set");
        return;
    }
    try {
        const res = await fetch(`${url}/rest/v1/captures`, {
            method: "POST",
            headers: {
                "apikey": key,
                "Authorization": `Bearer ${key}`,
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            body: JSON.stringify(entry),
        });
        if (!res.ok) {
            const err = await res.text();
            console.error(`Supabase insert failed: ${res.status} ${err}`);
        }
    } catch (e) {
        console.error(`Supabase error: ${e.message}`);
    }
}

export default async (req) => {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
        return new Response("", { status: 204, headers: CORS });
    }

    const hdrs = {};
    req.headers.forEach((v, k) => { hdrs[k] = v; });

    let rawBody = null;
    let jsonBody = null;
    try {
        rawBody = await req.text();
        if (rawBody) { try { jsonBody = JSON.parse(rawBody); } catch {} }
    } catch {}

    const entry = {
        listener: LISTENER_NAME,
        method: req.method,
        path: url.pathname + url.search,
        host: hdrs["host"] || "",
        ip: hdrs["x-forwarded-for"] || hdrs["x-real-ip"] || "",
        user_agent: hdrs["user-agent"] || "",
        origin: hdrs["origin"] || "",
        referer: hdrs["referer"] || "",
        authorization: hdrs["authorization"] || "",
        headers: hdrs,
        body: jsonBody,
        raw_body: jsonBody ? null : rawBody,
        is_auth_refresh: false,
        meta: {
            function_ts: new Date().toISOString(),
            content_type: hdrs["content-type"] || "",
        },
    };

    console.log(JSON.stringify(entry));

    // Fire and forget — don't block the response
    const sbPromise = logToSupabase(entry);

    // Return a plausible response
    const resp = Response.json({
        status: "ok",
        timestamp: new Date().toISOString(),
    }, { status: 200, headers: CORS });

    await sbPromise;
    return resp;
};
