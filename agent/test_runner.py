import requests
import re
import uuid
from agent.api_client import call_api
from agent.data_factory import get_payload

def run_tests(base_url: str, endpoints: list[dict], token: str = None) -> list[dict]:
    results = []
    base_url = base_url.rstrip("/")
    context = {"token": token, "user_id": None, "post_id": None, "username": None}
    
    # Discover state from API
    context = _discover_state(base_url, context, endpoints)
    
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"]
        
        # Test 1: Authenticated request (if token available)
        if token:
            results.append(_test_endpoint(base_url, path, method, token, context))
        
        # Test 2: Unauthenticated request (if endpoint might require auth)
        results.append(_test_endpoint(base_url, path, method, None, context))
        
        # Test 3: Invalid data (for POST/PATCH endpoints)
        if method in ("POST", "PATCH"):
            results.append(_test_endpoint(base_url, path, method, token, context, invalid=True))
    
    return results

def _discover_state(base_url: str, context: dict, endpoints: list[dict]) -> dict:
    """Discover existing state and create test data"""
    token = context.get("token")
    if not token:
        return context
    
    # Get current user
    try:
        resp = call_api("GET", f"{base_url}/users/me", headers={"Authorization": f"Bearer {token}"})
        if resp["status_code"] == 200 and resp["json"]:
            context["user_id"] = resp["json"].get("id")
            context["username"] = resp["json"].get("username")
    except Exception:
        pass
    
    # Get a post to test with
    try:
        resp = call_api("GET", f"{base_url}/posts", headers={"Authorization": f"Bearer {token}"})
        if resp["status_code"] == 200 and resp["json"]:
            posts = resp["json"] if isinstance(resp["json"], list) else resp["json"].get("items", [])
            if posts:
                context["post_id"] = posts[0].get("id")
    except Exception:
        pass
    
    return context

def _test_endpoint(base_url: str, path: str, method: str, token: str = None, 
                   context: dict = None, invalid: bool = False) -> dict:
    """Test a single endpoint with given parameters"""
    context = context or {}
    
    # Replace path parameters
    test_path = _interpolate_path(path, context)
    url = f"{base_url.rstrip('/')}/{test_path.lstrip('/')}"
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    kwargs = {"headers": headers} if headers else {}
    
    body = None
    if method in ("POST", "PATCH"):
        body = get_payload(path, method, invalid)
        kwargs["json"] = body
    
    try:
        resp = requests.request(method, url, **kwargs, timeout=10)
        response_data = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:1000]
        }
        try:
            response_data["json"] = resp.json()
        except:
            pass
    except Exception as e:
        response_data = {"error": str(e)}
    
    test_type = "invalid_data" if invalid else ("unauthenticated" if not token else "normal")
    
    request_info = {
        "method": method,
        "url": url,
        "headers": {k: v for k, v in headers.items() if k.lower() != "authorization"},
        "has_auth": bool(token)
    }
    if body:
        request_info["body"] = body
    
    return {
        "endpoint": path,
        "method": method,
        "test_type": test_type,
        "has_auth": bool(token),
        "url": url,
        "request": request_info,
        "response": response_data
    }

def _interpolate_path(path: str, context: dict) -> str:
    """Replace path parameters with actual values from context"""
    def replacer(match):
        param = match.group(1)
        # Remove fallbacks to '1'
        val = context.get(param)
        return str(val) if val is not None else match.group(0)
    
    return re.sub(r'\{(\w+)\}', replacer, path)

