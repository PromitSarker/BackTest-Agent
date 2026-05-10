import uuid
import time
from agent.api_client import call_api
from agent.logger import logger

def _scan_for_secrets(data):
    """Recursively scan JSON for sensitive fields."""
    if not isinstance(data, (dict, list)): return None
    if isinstance(data, list):
        for item in data:
            found = _scan_for_secrets(item)
            if found: return found
    else:
        for k, v in data.items():
            if k.lower() == "password_hash": return k
            found = _scan_for_secrets(v)
            if found: return found
    return None

def _classify_500(resp, path):
    body = (resp.get("text") or "").lower()
    if "validation" in body or "field required" in body: return "low", "Server crashed on input validation"
    if "null" in body or "none" in body: return "medium", "Server returned 500 (likely null reference)"
    if "/auth/" in path: return "low", "Auth middleware crash"
    return "low", "Unclassified server error"

def run_all_tests(state: dict) -> dict:
    base_url = state["base_url"].rstrip("/")
    endpoints = state.get("endpoints", [])
    token_a, token_b = state.get("user_a_token"), state.get("user_b_token")
    post_id, user_a_id = state.get("created_post_id"), state.get("user_a_id")
    
    findings = []
    tested_endpoints = set()

    def add(cat, sev, ep, method, title, desc, req, resp, exp, act, conf="high"):
        findings.append({
            "id": f"BUG-{uuid.uuid4().hex[:6]}", "category": cat, "severity": sev,
            "endpoint": ep, "method": method, "title": title, "description": desc,
            "evidence": {"request": req, "response": resp},
            "reproduction": f"Send {method} to {ep}", "expected": exp, "actual": act, "confidence": conf
        })

    def url_for(path):
        return f"{base_url}{path.replace('{user_id}', str(user_a_id or 1)).replace('{post_id}', str(post_id or 1))}"

    # 1. ELITE CHAINED EXPLOITS & BUSINESS LOGIC (Run first while state is fresh)
    
    # A. Mass Assignment / Privilege Escalation
    if token_a:
        u = url_for("/users/me")
        r = call_api("PATCH", u, headers={"Authorization": f"Bearer {token_a}"}, json={"role": "admin", "email": "attacker@example.com"})
        if r["status_code"] in (200, 204) and (r.get("json") or {}).get("role") == "admin":
            add("authorization", "critical", "/users/me", "PATCH", "Mass assignment allows role escalation",
                "The API allowed updating the 'role' field to 'admin' via a standard user profile update.",
                {"url": u, "payload": {"role": "admin", "email": "attacker@example.com"}}, r, 
                "Role changes should be ignored or rejected for normal users.", "role=admin accepted")

    # B. Verified IDOR (Cross-user state mutation)
    if token_a and token_b and post_id:
        u = url_for("/posts/{post_id}")
        val = f"IDOR_{uuid.uuid4().hex[:4]}"
        r = call_api("PATCH", u, headers={"Authorization": f"Bearer {token_b}"}, json={"body": val})
        if r["status_code"] in (200, 201, 204):
            add("authorization", "critical", "/posts/{post_id}", "PATCH", "Cross-user resource modification allowed",
                "User B successfully modified User A's post.",
                {"url": u, "attacker": "User B"}, r, "403 or 404", str(r["status_code"]))

    # C. Duplicate Like
    if token_a and post_id:
        u = url_for("/posts/{post_id}/like")
        call_api("POST", u, headers={"Authorization": f"Bearer {token_a}"}) # First like
        r2 = call_api("POST", u, headers={"Authorization": f"Bearer {token_a}"}) # Duplicate like
        if r2["status_code"] in (200, 201, 204):
            like_count = (r2.get("json") or {}).get("like_count", "unknown")
            add("business_logic", "medium", "/posts/{post_id}/like", "POST", "Duplicate like request succeeds",
                f"Liking a post twice succeeded. like_count={like_count} proves non-idempotent mutable engagement behavior.",
                {"url": u}, r2, "409 Conflict or idempotent 200 without count increment", f"{r2['status_code']}, like_count={like_count}")

    # D. Duplicate Unlike
    if token_a and post_id:
        u = url_for("/posts/{post_id}/like")
        call_api("DELETE", u, headers={"Authorization": f"Bearer {token_a}"}) # First unlike
        r2 = call_api("DELETE", u, headers={"Authorization": f"Bearer {token_a}"}) # Duplicate unlike
        if r2["status_code"] in (200, 201, 204):
            like_count = (r2.get("json") or {}).get("like_count", "unknown")
            add("business_logic", "medium", "/posts/{post_id}/like", "DELETE", "Duplicate unlike request succeeds",
                f"Unliking a post twice succeeded. like_count={like_count} proves non-idempotent mutable engagement behavior.",
                {"url": u}, r2, "409 Conflict or idempotent 200 without count decrement", f"{r2['status_code']}, like_count={like_count}")

    # E. Self Follow
    if token_a and user_a_id:
        u = url_for("/users/{user_id}/follow")
        r = call_api("POST", u, headers={"Authorization": f"Bearer {token_a}"})
        if r["status_code"] in (200, 201, 204):
            add("business_logic", "medium", "/users/{user_id}/follow", "POST", "User can follow themselves",
                "User successfully followed themselves.",
                {"url": u}, r, "400 Bad Request", str(r["status_code"]))

    # F. Schema Consistency (password_hash leak check)
    if token_a and user_a_id:
        me_resp = call_api("GET", url_for("/users/me"), headers={"Authorization": f"Bearer {token_a}"})
        pub_resp = call_api("GET", url_for("/users/{user_id}"))
        me_json = me_resp.get("json") or {}
        pub_json = pub_resp.get("json") or {}
        if "password_hash" in me_json and "password_hash" not in pub_json:
            add("consistency", "medium", "/users/me", "GET", "Private user response exposes password_hash",
                "The private /users/me endpoint exposes the password hash, but the public endpoint does not.",
                {"url": url_for("/users/me")}, me_resp, "password_hash should be omitted from both", "password_hash present in /users/me only")

    # 2. BROAD SCAN (Endpoint Iteration)
    
    # Sort endpoints to put DELETE operations at the very end to avoid destroying state
    sorted_endpoints = sorted(endpoints, key=lambda x: 1 if x["method"] == "DELETE" else 0)
    
    for ep in sorted_endpoints:
        path, method = ep["path"], ep["method"]
        url = url_for(path)
        tested_endpoints.add(f"{method} {path}")
        
        # Authenticated scan for coverage
        headers = {"Authorization": f"Bearer {token_a}"} if (ep["requires_auth"] and token_a) else {}
        resp = call_api(method, url, headers=headers)
        logger.info(f"Testing {method:6s} {path:35s} → {resp['status_code']}")

        # Security Headers & CORS (Run on root or any GET)
        if path == "/" and method == "GET":
            hdrs = resp.get("headers", {})
            if hdrs.get("access-control-allow-origin") == "*" and hdrs.get("access-control-allow-credentials") == "true":
                add("headers_cors", "medium", "/", "GET", "Wildcard CORS origin allows credentials",
                    "Wildcard CORS allows credentials.", {"url": url}, resp, "Restricted origin or credentials=false", "origin=*, credentials=true")

        # Error Handling
        if resp["status_code"] >= 500:
            sev, cause = _classify_500(resp, path)
            add("error_handling", sev, path, method, f"Server Error ({cause})", cause, {"url": url}, resp, "4xx", "500")
            continue

        # Schema Leakage (password_hash globally)
        if resp["status_code"] in (200, 201) and resp.get("json"):
            secret = _scan_for_secrets(resp["json"])
            if secret == "password_hash":
                add("schema_contract", "high", path, method, "Sensitive field returned outside documented schema", 
                    f"Response contains sensitive field '{secret}'.", {"url": url}, resp, "Response should not expose password hashes.", "password_hash present in response JSON")

        # Authentication Bypass (Explicit Check)
        if ep["requires_auth"] and method in ["POST", "PATCH", "PUT", "DELETE"]:
            unauth_resp = call_api(method, url, headers={})
            if unauth_resp["status_code"] in (200, 201, 204):
                add("authentication", "high", path, method, "Authentication bypass",
                    "Protected mutation endpoint succeeded without an Authorization header.",
                    {"url": url}, unauth_resp, "401 or 403", str(unauth_resp["status_code"]))

        # Schema Drift
        s_resp = ep.get("operation", {}).get("responses", {}).get("200", {}).get("content", {}).get("application/json", {}).get("schema", {})
        if s_resp and isinstance(resp["json"], dict):
            expected = s_resp.get("properties", {}).keys()
            if expected:
                extra = [k for k in resp["json"].keys() if k not in expected]
                if extra:
                    add("schema_contract", "low", path, method, "Undocumented Response Fields (Schema Drift)",
                        f"API returned fields not in spec: {', '.join(extra)}", {"url": url}, resp, "Match spec", f"Extra: {', '.join(extra)}", conf="medium")

    # 3. Rate Limit (Auth Burst)
    l_u = url_for("/auth/login")
    statuses = []
    for _ in range(12):
        res = call_api("POST", l_u, json={"username": "a", "password": "b"})
        statuses.append(str(res["status_code"]))
    
    if "429" not in statuses:
        add("rate_limiting", "medium", "/auth/login", "POST", "No observable rate limit on repeated failed login attempts", 
            "Sent 12 failed login attempts without being throttled.", {"url": l_u}, {}, "429 or a clear throttling response", ", ".join(statuses), conf="high")

    return {"findings": findings, "tested_endpoints": list(tested_endpoints)}
