import requests
import uuid
from agent.logger import logger


SUPPORTED_METHODS = {"GET", "POST", "PATCH", "DELETE"}


def call_api(method: str, url: str, headers: dict = None, json: dict = None) -> dict:
    method = method.upper()
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"Unsupported method: {method}. Use one of {SUPPORTED_METHODS}")

    response = requests.request(method, url, headers=headers, json=json)

    try:
        response_json = response.json()
    except Exception:
        response_json = None

    return {
        "status_code": response.status_code,
        "json": response_json,
        "text": response.text,
    }


def login(base_url: str, username: str, password: str) -> str:
    base_url = base_url.rstrip("/")  
    url = f"{base_url}/auth/login"

    payload = {"username": username, "password": password}

    logger.debug(f"LOGIN URL: {url}")

    response = call_api("POST", url, json=payload)

    if response["status_code"] != 200:
        logger.info(f"Login failed with status {response['status_code']}, trying to register new user...")
        # Try to register a new unique user instead
        return register(base_url)

    data = response["json"] or {}
    token = data.get("access_token") or data.get("token")

    if not token:
        raise RuntimeError("Login succeeded but no access_token found in response")

    return token


def register(base_url: str, username: str = None, password: str = None) -> str:
    """Register a new user with generated credentials"""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/auth/register"
    
    if not username:
        username = f"testuser_{uuid.uuid4().hex[:8]}"
    if not password:
        password = f"pass_{uuid.uuid4().hex[:8]}"
    
    payload = {"username": username, "password": password}
    
    logger.debug(f"REGISTER URL: {url} with username {username}")
    
    response = call_api("POST", url, json=payload)
    
    if response["status_code"] not in (200, 201):
        raise RuntimeError(
            f"Registration failed with status {response['status_code']}: {response['text']}"
        )
    
    data = response["json"] or {}
    token = data.get("access_token") or data.get("token")
    
    if not token:
        raise RuntimeError("Registration succeeded but no access_token found in response")
    
    return token