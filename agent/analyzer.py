import uuid

# Define expected status codes for different test scenarios
# This makes the "why" behind our assertions much clearer
EXPECTED_STATUS_CODES = {
    "unauthenticated": {
        "success": (401, 403),
        "description": "Unauthorized access should be blocked with 401 or 403."
    },
    "invalid_data": {
        "success": (400, 422),
        "description": "Malformed or invalid input should be rejected with 400 or 422."
    },
    "normal": {
        "success": (200, 201, 204),
        "description": "Valid authenticated requests should succeed with 20x status codes."
    }
}

# Special cases for specific endpoints where standard rules differ
# Example: Login might return 401 on failure, but some APIs use 422 for 'Unprocessable Entity' 
# if the body is empty or missing fields even during login attempts.
ENDPOINT_SPECIFIC_EXPECTATIONS = {
    "/auth/login": {
        "normal": (200,),
        "invalid_data": (401, 422)
    }
}

def analyze(results: list[dict], endpoints_spec: list[dict] = None) -> list[dict]:
    """
    Analyzes test results to identify bugs, security vulnerabilities, or validation issues.
    
    Args:
        results: List of test execution results from test_runner.
        endpoints_spec: The list of endpoint definitions from the OpenAPI spec.
        
    Returns:
        A list of findings (bugs).
    """
    findings = []
    spec_map = {(ep["path"], ep["method"]): ep for ep in (endpoints_spec or [])}

    for test in results:
        endpoint = test["endpoint"]
        method = test["method"]
        request = test.get("request", {})
        response = test.get("response", {})
        status = response.get("status_code")
        
        test_type = test.get("test_type", "normal")
        spec = spec_map.get((endpoint, method), {})
        requires_auth = spec.get("requires_auth", False)

        evidence = {
            "request": request,
            "response": response
        }

        # Determine expected status code range
        expectations = EXPECTED_STATUS_CODES.get(test_type, EXPECTED_STATUS_CODES["normal"])
        expected_range = expectations["success"]
        
        # Override with endpoint-specific logic if applicable
        for path_fragment, overrides in ENDPOINT_SPECIFIC_EXPECTATIONS.items():
            if path_fragment in endpoint and test_type in overrides:
                expected_range = overrides[test_type]

        # Check 1: General status_code validation for 'normal' tests
        if test_type == "normal" and status not in expected_range:
            # For POST requests specifically, we often expect 201 or 200
            findings.append(_create_finding(
                category="status_code",
                severity="medium",
                endpoint=endpoint,
                method=method,
                title="Unexpected status code",
                description=f"Request returned {status} but expected one of {expected_range}.",
                evidence=evidence,
                reproduction=f"Send {method} request to {endpoint} with valid data.",
                expected=" or ".join(map(str, expected_range)),
                actual=str(status)
            ))

        # Check 2: Authentication bypass detection
        if test_type == "unauthenticated" and requires_auth and status not in expected_range:
            # If status is 2xx, it's a bypass
            if status in (200, 201, 204):
                findings.append(_create_finding(
                    category="authentication",
                    severity="high",
                    endpoint=endpoint,
                    method=method,
                    title="Authentication Bypass",
                    description="Endpoint requires authentication but succeeded without a valid token.",
                    evidence=evidence,
                    reproduction=f"Send request to {endpoint} without Authorization header",
                    expected=" or ".join(map(str, expected_range)),
                    actual=str(status)
                ))

        # Check 3: Input validation bypass detection
        if test_type == "invalid_data" and status not in expected_range:
            # If status is 2xx, it's a validation failure
            if status in (200, 201, 204):
                findings.append(_create_finding(
                    category="input_validation",
                    severity="high",
                    endpoint=endpoint,
                    method=method,
                    title="Missing Input Validation",
                    description="Endpoint succeeded despite being sent intentionally invalid data.",
                    evidence=evidence,
                    reproduction=f"Send request to {endpoint} with malformed JSON or incorrect fields.",
                    expected=" or ".join(map(str, expected_range)),
                    actual=str(status)
                ))

    return findings

def _create_finding(category, severity, endpoint, method, title, description, evidence, reproduction, expected, actual):
    return {
        "id": f"BUG-{uuid.uuid4().hex[:6]}",
        "category": category,
        "severity": severity,
        "endpoint": endpoint,
        "method": method,
        "title": title,
        "description": description,
        "evidence": evidence,
        "reproduction": reproduction,
        "expected": expected,
        "actual": actual
    }