import time
import uuid
import requests
from agent.logger import logger


SUPPORTED_METHODS = {"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS", "HEAD"}


def call_api(
    method: str,
    url: str,
    headers: dict = None,
    json: dict = None,
    timeout: int = 20,
) -> dict:
    method = method.upper()
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"Unsupported method: {method}")

    t0 = time.time()
    try:
        response = requests.request(
            method, url, headers=headers, json=json, timeout=timeout
        )
        latency = time.time() - t0
        try:
            response_json = response.json()
        except Exception:
            response_json = None

        return {
            "status_code": response.status_code,
            "json": response_json,
            "text": response.text[:2000],
            "headers": dict(response.headers),
            "latency": round(latency, 4),
        }
    except requests.exceptions.Timeout:
        return {"status_code": 0, "json": None, "text": "TIMEOUT", "headers": {}, "latency": timeout}
    except Exception as e:
        return {"status_code": 0, "json": None, "text": str(e), "headers": {}, "latency": 0}


def login(base_url: str, username: str, password: str) -> str:
    """Login with existing credentials; falls back to register if credentials fail."""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/auth/login"
    payload = {"username": username, "password": password}
    logger.debug(f"LOGIN → {url} as {username}")
    response = call_api("POST", url, json=payload)

    if response["status_code"] == 200:
        data = response["json"] or {}
        token = data.get("access_token") or data.get("token")
        if token:
            return token

    logger.info(
        f"Login failed ({response['status_code']}) for {username}; registering a fresh user..."
    )
    token, _ = register_and_login(base_url)
    return token


def register_and_login(base_url: str, username: str = None, password: str = None) -> tuple[str, int]:
    """Register a new unique user and return (access_token, user_id)."""
    base_url = base_url.rstrip("/")
    if not username:
        username = f"agent_{uuid.uuid4().hex[:10]}"
    if not password:
        password = f"Pwd_{uuid.uuid4().hex[:10]}!"

    reg_url = f"{base_url}/auth/register"
    payload = {"username": username, "password": password, "email": f"{username}@test.local"}
    logger.debug(f"REGISTER → {reg_url} as {username}")
    response = call_api("POST", reg_url, json=payload)

    if response["status_code"] not in (200, 201):
        raise RuntimeError(
            f"Registration failed ({response['status_code']}): {response['text']}"
        )

    data = response["json"] or {}
    token = data.get("access_token") or data.get("token")
    if not token:
        raise RuntimeError("Registration succeeded but no access_token returned")

    user_id = _get_my_id(base_url, token)
    logger.info(f"Registered user '{username}' → user_id={user_id}")
    return token, user_id


def _get_my_id(base_url: str, token: str) -> int:
    """Fetch /users/me and return the user's numeric id."""
    base_url = base_url.rstrip("/")
    resp = call_api(
        "GET",
        f"{base_url}/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp["status_code"] == 200 and resp["json"]:
        return resp["json"].get("id")
    return None