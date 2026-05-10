# BackTest-Agent: Technical Architecture & Logic

BackTest-Agent is an autonomous security auditing tool built on **LangGraph**. Unlike traditional stateless scanners, it maintains a persistent session state to perform complex, multi-user authorization and business logic tests.

---

## 1. Core Architecture (The State Machine)

The agent operates as a directed acyclic graph (DAG) where each node represents a specific phase of the audit.

### State Management (`AgentState`)
The `AgentState` is the centralized "brain" that tracks:
- **Identity Context**: Tokens and User IDs for two distinct actors (**User A** as the Victim/Owner and **User B** as the Attacker).
- **Resource IDs**: Live IDs for posts, comments, and other objects created during the audit.
- **Telemetry**: Start times, tested endpoints, and raw findings.

### The Workflow (`graph.py`)
1. **`load_spec`**: Parses the `openapi.json` to identify endpoints, methods, and authentication requirements.
2. **`setup_users`**: Dynamically registers two new users on the target API to ensure fresh, isolated testing environments.
3. **`create_resources`**: User A creates data (e.g., a post). The resulting `post_id` is saved to the state for User B to target later.
4. **`run_tests`**: Executes the security logic suite.
5. **`analyze`**: Deduplicates findings and assigns confidence scores.
6. **`generate_report`**: Compiles findings into a standardized JSON report.

---

## 2. Security Logic & Exploit Categories

The testing engine in `test_runner.py` is categorized into three layers of depth:

### A. Deep Authorization (Multi-User)
- **IDOR (Insecure Direct Object Reference)**: The agent uses User B's token to attempt a `PATCH` or `DELETE` on a resource owned by User A. A `200 OK` indicates a critical authorization failure.
- **Mass Assignment**: The agent attempts to update restricted fields (like `role` or `is_admin`) during a standard profile update.

### B. Business Logic & Consistency
- **Idempotency & Logic**: Checks if "Liking" a post twice increments the counter twice, or if a user can "Follow" themselves.
- **Sensitive Data Leakage**: Recursively scans all responses for `password_hash` or other secrets. It specifically compares private "Me" endpoints vs. public "Profile" endpoints to find inconsistent data exposure.

### C. Broad Scan & Fuzzing
- **Authentication Bypass**: Attempts to access protected `POST/PATCH/DELETE` endpoints without any Authorization header.
- **Schema Drift**: Compares the actual JSON response against the OpenAPI schema. It flags "Undocumented Fields" which often indicate hidden functionality or legacy code.
- **500 Error Classification**: Analyzes server crashes to distinguish between simple input validation errors and serious middleware failures.

---

## 3. Execution Strategies

### The "DELETE" Safety Valve
To maximize coverage, the agent sorts all endpoints before execution. All `DELETE` operations are pushed to the end of the queue. This ensures that the agent doesn't "delete its own homework" before it has finished testing read/update vulnerabilities on those resources.

### Rate Limit Bursting
The agent performs a brief, high-concurrency burst against the `/auth/login` endpoint. It looks for a `429 Too Many Requests` response. If it can send 12+ requests without being throttled, it flags a "Lack of Rate Limiting" vulnerability.

### Deduplication Signature
To keep reports actionable, findings are passed through a signature filter:
`Signature = (Category + Endpoint_Path + Issue_Title)`
If multiple endpoints suffer from the same global configuration issue (e.g., missing security headers), only one high-level finding is reported to reduce noise.

---

## 4. Getting Started

1. **Configure Environment**: Set `BASE_URL` and `GROQ_API_KEY` in `.env`.
2. **Update Spec**: Place your target's `openapi.json` in the root directory.
3. **Run**: Execute `python main.py`.
