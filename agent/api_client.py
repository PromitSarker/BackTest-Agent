import requests


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
    url = f"{base_url}/auth/login"
    payload = {"username": username, "password": password}

    response = call_api("POST", url, json=payload)

    if response["status_code"] != 200:
        raise RuntimeError(
            f"Login failed with status {response['status_code']}: {response['text']}"
        )

    data = response["json"] or {}
    token = data.get("access_token") or data.get("token")

    if not token:
        raise RuntimeError("Login succeeded but no access_token found in response")

    return token
