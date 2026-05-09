import uuid

def analyze(results: list[dict], endpoints_spec: list[dict] = None) -> list[dict]:
    findings = []
    spec_map = {(ep["path"], ep["method"]): ep for ep in (endpoints_spec or [])}

    for test in results:
        endpoint = test["endpoint"]
        method = test["method"]
        response = test.get("response", {})
        status = response.get("status_code")
        
        # We assume the test_runner might attach a test_type to distinguish runs
        test_type = test.get("test_type", "normal")
        spec = spec_map.get((endpoint, method), {})
        requires_auth = spec.get("requires_auth", False)

        # Check 1: status_code
        if test_type == "normal" and method == "POST" and status not in (200, 201):
            findings.append(_create_finding(
                category="status_code",
                severity="medium",
                endpoint=endpoint,
                method=method,
                title="Unexpected POST status code",
                description="POST request returned an unexpected status code.",
                evidence=response,
                reproduction=f"Send POST request to {endpoint} with empty JSON body",
                expected="200 or 201",
                actual=str(status)
            ))

        # Check 2: authentication
        if test_type == "unauthenticated" and requires_auth and status in (200, 201, 204):
            findings.append(_create_finding(
                category="authentication",
                severity="high",
                endpoint=endpoint,
                method=method,
                title="Authentication Bypass",
                description="Endpoint requires auth but succeeded without a token.",
                evidence=response,
                reproduction=f"Send request to {endpoint} without Authorization header",
                expected="401 or 403",
                actual=str(status)
            ))

        # Check 3: input_validation
        if test_type == "invalid_data" and status in (200, 201, 204):
            findings.append(_create_finding(
                category="input_validation",
                severity="high",
                endpoint=endpoint,
                method=method,
                title="Missing Input Validation",
                description="Endpoint succeeded despite invalid input data.",
                evidence=response,
                reproduction=f"Send request to {endpoint} with incorrect data types/values",
                expected="400 or 422",
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
