import json


def load_spec(filepath: str = "openapi.json") -> dict:
    with open(filepath, "r") as f:
        return json.load(f)


def extract_endpoints(spec: dict) -> list[dict]:
    endpoints = []

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            requires_auth = _check_auth(details)
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "requires_auth": requires_auth,
            })

    return endpoints


def _check_auth(operation: dict) -> bool:
    parameters = operation.get("parameters", [])
    for param in parameters:
        if param.get("in") == "header":
            if param.get("name", "").lower() == "authorization":
                return True
    return False
