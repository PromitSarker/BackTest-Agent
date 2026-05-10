import uuid
from typing import Any, Dict, Optional
from agent.llm_client import llm_client
from agent.logger import logger

def get_payload(path: str, method: str, test_type: str = "normal", operation_spec: Optional[dict] = None) -> Dict[str, Any]:
    """
    Generates appropriate request body based on endpoint, method, and test type.
    Uses LLM if available, otherwise falls back to basic templates.
    """
    method = method.upper()
    if method not in ("POST", "PATCH", "PUT"):
        return {}

    # Try LLM generation first if spec is provided
    if operation_spec:
        logger.debug(f"Generating {test_type} payload via LLM for {method} {path}")
        llm_payload = llm_client.generate_payload(operation_spec, test_type)
        if llm_payload:
            return llm_payload

    # Fallback to hardcoded templates or generic invalid data
    if test_type == "invalid_data":
        return {"invalid_field": "invalid_value"}
    
    if test_type == "fuzzing":
        return {"fuzz": "A" * 10000, "injection": "'; DROP TABLE users; --"}

    # Define mappings for different endpoints as fallback
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
            if fragment == "/posts" and "/comments" in path:
                continue
            return template()

    return {}
