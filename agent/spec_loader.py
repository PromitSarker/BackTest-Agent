import json


def load_spec(filepath: str = "openapi.json") -> dict:
    """
    Loads an OpenAPI specification from a JSON file.
    
    Args:
        filepath: Path to the OpenAPI JSON file.
        
    Returns:
        The loaded specification as a dictionary.
    """
    with open(filepath, "r") as f:
        return json.load(f)


def extract_endpoints(spec: dict) -> list[dict]:
    """
    Extracts endpoint details (path, method, auth requirements) from an OpenAPI spec.
    
    Args:
        spec: The OpenAPI specification dictionary.
        
    Returns:
        A list of dictionaries, each representing an endpoint.
    """
    endpoints = []
    global_security = spec.get("security", [])

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() in ("get", "post", "patch", "delete", "put"):
                requires_auth = _check_auth(details, global_security)
                
                # Extract deeper metadata
                parameters = details.get("parameters", [])
                request_body = details.get("requestBody", {})
                has_request_body = bool(request_body)
                request_schema = request_body.get("content", {}).get("application/json", {}).get("schema", {})
                
                responses = details.get("responses", {})
                expected_status_codes = list(responses.keys())
                response_schemas = {
                    code: resp.get("content", {}).get("application/json", {}).get("schema", {})
                    for code, resp in responses.items()
                }

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "requires_auth": requires_auth,
                    "parameters": parameters,
                    "has_request_body": has_request_body,
                    "request_schema": request_schema,
                    "expected_status_codes": expected_status_codes,
                    "response_schemas": response_schemas,
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
