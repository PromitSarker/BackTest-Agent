import json


def load_spec(filepath: str = "openapi.json") -> dict:
    with open(filepath, "r") as f:
        return json.load(f)


def extract_endpoints(spec: dict) -> list[dict]:
    endpoints = []
    global_security = spec.get("security", [])

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() in ("get", "post", "patch", "delete", "put"):
                requires_auth = _check_auth(details, global_security)
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "requires_auth": requires_auth,
                    "operation": details
                })

    return endpoints


def _check_auth(operation: dict, global_security: list) -> bool:
    """Check if endpoint requires authentication"""
    
    # Check operation-level security
    operation_security = operation.get("security")
    if operation_security is not None:
        return len(operation_security) > 0
    
    # Fall back to global security
    if global_security:
        return len(global_security) > 0
    
    # Check for explicit Authorization header parameter
    parameters = operation.get("parameters", [])
    for param in parameters:
        if param.get("in") == "header":
            if param.get("name", "").lower() == "authorization":
                return True
    
    return False
