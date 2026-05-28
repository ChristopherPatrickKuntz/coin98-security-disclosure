import json, urllib.request

url = "https://[REDACTED].supabase.co/rest/v1/captures?select=created_at,listener,method,path,host,ip,user_agent,authorization,is_auth_refresh&order=created_at.desc"
key = "[REDACTED_SUPABASE_SERVICE_ROLE_JWT]"

req = urllib.request.Request(url, headers={
    "apikey": key,
    "Authorization": f"Bearer {key}",
})
with urllib.request.urlopen(req, timeout=10) as resp:
    data = json.loads(resp.read())

print(f"Total captures: {len(data)}\n")
for r in data:
    ts = r["created_at"][:19]
    ip = r["ip"]
    ua = (r["user_agent"] or "none")[:65]
    auth = "AUTH=" + r["authorization"][:30] if r.get("authorization") else ""
    refresh = " *** AUTH-REFRESH ***" if r.get("is_auth_refresh") else ""
    domain = "CUSTOM-DOMAIN" if "c98staging" in (r.get("host") or "") else "netlify-app"
    print(f"{ts} | {r['listener']:8} | {r['method']:4} | {domain}")
    print(f"  IP: {ip} | {auth}{refresh}")
    print(f"  UA: {ua}")
    print(f"  Path: {r['path']}")
    print()
