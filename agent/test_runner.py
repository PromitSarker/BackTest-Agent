import uuid
from agent.api_client import call_api
from agent.logger import logger

def run_all_tests(state: dict) -> dict:
    """
    Executes tests across all endpoints to ensure 100% coverage while 
    maintaining high-signal logical tests.
    """
    base_url = state["base_url"].rstrip("/")
    endpoints = state.get("endpoints", [])
    token_a = state.get("user_a_token")
    token_b = state.get("user_b_token")
    post_id = state.get("created_post_id") or 1
    user_a_id = state.get("user_a_id") or 1
    
    findings = []
    tested_endpoints = set()

    def add_finding(category, severity, endpoint, method, title, desc, req, resp, expected, actual):
        findings.append({
            "id": f"BUG-{uuid.uuid4().hex[:6]}",
            "category": category,
            "severity": severity,
            "endpoint": endpoint,
            "method": method,
            "title": title,
            "description": desc,
            "evidence": {"request": req, "response": resp},
            "reproduction": f"Send {method} to {endpoint}",
            "expected": expected,
            "actual": actual
        })

    # Helper to interpolate paths
    def get_url(path):
        return f"{base_url}{path.replace('{user_id}', str(user_a_id)).replace('{post_id}', str(post_id))}"

    # 1. Broad Coverage Phase: Hit every single endpoint at least once
    # We'll check for security headers and auth enforcement on ALL endpoints
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"]
        url = get_url(path)
        
        # Mark as tested (method + path combination)
        tested_endpoints.add(f"{method} {path}")
        
        # Basic request (unauthenticated)
        resp = call_api(method, url)
        
        # A. Security Header Check (Generic but good for coverage)
        missing = [h for h in ["content-security-policy", "x-content-type-options", "strict-transport-security"] if h not in resp["headers"]]
        if missing:
            add_finding("headers_cors", "low", path, method, "Missing Security Headers",
                        f"Missing: {', '.join(missing)}", {"url": url}, resp, "Security headers present", "Headers missing")

        # B. Authentication Enforcement Check
        if ep["requires_auth"]:
            if resp["status_code"] not in (401, 403):
                add_finding("authentication", "critical", path, method, "Authentication Bypass",
                            "Endpoint succeeded without token", {"url": url}, resp, "401 or 403", str(resp["status_code"]))

    # 2. Targeted Deep-Dive Phase: Logical vulnerabilities
    
    # IDOR: User B tries to modify User A's post
    if token_b and post_id:
        url = get_url("/posts/{post_id}")
        resp = call_api("PATCH", url, headers={"Authorization": f"Bearer {token_b}"}, json={"body": "Hacked"})
        if resp["status_code"] in (200, 201, 204):
            add_finding("authorization", "high", "/posts/{post_id}", "PATCH", "IDOR on Post Update",
                        "User B modified User A's post", {"url": url, "auth": "User B Token"}, resp, "403/404", str(resp["status_code"]))

    # Input Validation: POST with empty body
    if token_a:
        url = get_url("/posts")
        resp = call_api("POST", url, headers={"Authorization": f"Bearer {token_a}"}, json={})
        if resp["status_code"] not in (400, 422):
            add_finding("input_validation", "medium", "/posts", "POST", "Inadequate Input Validation",
                        "Empty payload accepted on resource creation", {"url": url}, resp, "400/422", str(resp["status_code"]))

    # Business Logic: Following self
    if token_a and user_a_id:
        url = get_url("/users/{user_id}/follow")
        resp = call_api("POST", url, headers={"Authorization": f"Bearer {token_a}"})
        if resp["status_code"] in (200, 201, 204):
            add_finding("business_logic", "medium", "/users/{user_id}/follow", "POST", "Invalid Self-Follow",
                        "User was allowed to follow their own account", {"url": url}, resp, "400/422", str(resp["status_code"]))

    # Rate Limiting: Login burst
    login_url = get_url("/auth/login")
    for _ in range(10):
        resp = call_api("POST", login_url, json={"username": "alice", "password": "wrong_password"})
    if resp["status_code"] != 429:
        add_finding("rate_limiting", "medium", "/auth/login", "POST", "No Throttling",
                    "Rapid failed logins did not trigger rate limiting", {"url": login_url}, resp, "429", str(resp["status_code"]))

    return {
        "findings": findings,
        "tested_endpoints": list(tested_endpoints)
    }
