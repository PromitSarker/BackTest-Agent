import uuid
from typing import Any, Dict

def get_payload(path: str, method: str, invalid: bool = False) -> Dict[str, Any]:
    """
    Generates appropriate request body based on endpoint path and method.
    
    Args:
        path: The API endpoint path.
        method: The HTTP method (POST, PATCH, etc.)
        invalid: If True, returns intentionally incorrect data for validation testing.
        
    Returns:
        A dictionary containing the payload.
    """
    if invalid:
        return {"invalid_field": "invalid_value"}
    
    method = method.upper()
    if method not in ("POST", "PATCH", "PUT"):
        return {}

    # Define mappings for different endpoints
    # We use path fragments for matching
    payload_templates = {
        "/auth/register": lambda: {
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "password": "password123"
        },
        "/auth/login": lambda: {
            "username": "alice", 
            "password": "alice123"
        },
        "/posts": lambda: {
            "body": "Test post content"
        },
        "/comments": lambda: {
            "body": "Test comment"
        },
        "/users/me": lambda: {
            "bio": "Updated bio", 
            "age": 25
        }
    }

    # Match path to templates
    for fragment, template in payload_templates.items():
        if fragment in path:
            # Special case for comments which also contains /posts usually
            if fragment == "/posts" and "/comments" in path:
                continue
            return template()

    return {}
