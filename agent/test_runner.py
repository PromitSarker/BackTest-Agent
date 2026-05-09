import requests

def run_tests(base_url: str, endpoints: list[dict], token: str = None) -> list[dict]:
    results = []
    
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"]
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        kwargs = {"headers": headers}
        if method in ("POST", "PATCH", "PUT"):
            kwargs["json"] = {}
            
        try:
            resp = requests.request(method, url, **kwargs)
            response_data = {
                "status_code": resp.status_code,
                "body": resp.text
            }
        except Exception as e:
            response_data = {"error": str(e)}
            
        results.append({
            "endpoint": path,
            "method": method,
            "response": response_data
        })
        
    return results
