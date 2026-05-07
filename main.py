from agent.spec_loader import load_spec, extract_endpoints


if __name__ == "__main__":
    print("Agent started")

    spec = load_spec("openapi.json")
    endpoints = extract_endpoints(spec)

    print(f"Found {len(endpoints)} endpoints")
