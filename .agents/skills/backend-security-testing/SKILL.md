---
name: Backend Security Testing & OWASP Mitigation
description: A comprehensive testing methodology leveraging Mocha and Supertest to enforce strict RBAC, Tenant Isolation, and OWASP Top 10 defenses on backend APIs.
---

# Backend Security Testing & OWASP Methodology

This skill provides the standard operating procedures and code patterns for implementing robust backend security testing, derived directly from the `api.test.js` and `owasp.test.js` implementations.

## 1. Testing Framework Stack
- **Test Runner:** `mocha`
- **Assertion Library:** Node's built-in `assert`
- **HTTP Assertion:** `supertest`

## 2. Core Methodologies

### 2.1 Role-Based Access Control (RBAC) Testing
Always aggressively test your middleware (`authenticateJWT`, `isAdmin`, `isDeveloper`, etc.) boundaries.
- **Unauthenticated Access:** Verify secure endpoints return `401 Unauthorized` when tokens are omitted.
- **Vertical Escalation (Privilege Checking):** Send authenticated requests from lower-privileged actors (e.g. Riders, standard Admins) to higher-privileged routes (Superadmin modules) to guarantee a `403 Forbidden`. Avoid yielding ambiguous `500` strings.

### 2.2 Tenant Data Isolation (Cross-Pollination Security)
When dealing with multi-tenant SaaS environments, backend APIs must intrinsically distrust the payload body regarding identification context.
- **Strict Scoping:** Ensure resource creation (Stores, Riders, Deliveries) enforces ID scoping explicitly bounded by the requester's globally signed `token.tenantId`, rather than the HTTP `<body.tenantId>`.
- **Sandbox Creation Test Pattern:**
  1. Login as `Admin_X` tied to `Tenant_X`.
  2. Attempt explicitly injecting payloads targeting `Tenant_Y`.
  3. Ensure the database natively halts (`403 Unauthorized for this tenant`) or strictly ignores the requested override silently reverting to modifying `Tenant_X`.

### 2.3 OWASP Top 10 (2025) Assertions
Ensure dedicated testing coverage mapped against OWASP principles:
- **A01: Broken Access Control:** (Already covered above via RBAC handling & implicit payload trust). 
- **A02: Cryptographic Failures:** Craft maliciously forged JWT Tokens (e.g. configuring `alg: 'none'` in the Base64 header). Assert that the backend's token verification library successfully neutralizes tampering (yielding `401`).
- **A03: Injection (SQL & XSS):** 
  - Send explicit URL parameter abuse payload injections (`?id=1' OR '1'='1`). Assert that Modern ORMs or parameterized query preparations process strings physically instead of logically (returning `.length === 0`).
  - Send cross-site script hooks (`<script>alert(1)</script>`) into JSON body `POST` fields confirming the server processes the data dynamically without crashing, ensuring actual display mitigation is handed smoothly off to frontend mechanisms.
- **A05: Security Misconfiguration (HTTP Headers):** Inspect standard GET paths hitting the static frontend `/` distribution verifying integration of security packages like `helmet` (Assert presence of `X-Frame-Options: SAMEORIGIN` and `X-Content-Type-Options: nosniff`).
- **A07: Identification and Authentication Failures:** Prevent username enumeration mapping by simulating invalid logins natively on non-existent users versus valid users submitting invalid passwords—ensuring both paths homogeneously return `Invalid credentials` identical strings.

## 3. Best Practices
- **Isolation Sandbox:** Initialize completely unique DB seed prefixes (`Tenant_Y_${Date.now()}`) and localized testing arrays during setup hooks to ensure overlapping parallel Mocha testing never collides or hits `SQLITE_CONSTRAINT_UNIQUE`.
- **Automatic Cleanup:** Never leave ghost accounts inside the DB; invoke explicit `DELETE` calls during `after()` cleanup phases on targeted dynamically generated identifiers.
