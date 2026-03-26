# RiderTracker Dashboard — Test Suite

## Overview

Comprehensive test suite for all REST API endpoints on the dashboard backend server. Tests are written using **Vitest** and **Supertest**, running against a real SQLite database with seeded test data.

## Running Tests

```bash
cd dashboard
npm test
```

## Test Structure

**File:** [`server.test.mjs`](server.test.mjs)  
**Framework:** Vitest + Supertest  
**Total Tests:** 39  
**Total Suites:** 11  

---

## Test Suites

### 1. `POST /api/login` (4 tests)

| Test | Description |
|---|---|
| ✅ returns token for valid admin credentials | Verifies token, riderId, tenantId, tenantName, and stores are returned |
| ✅ returns 401 for invalid credentials | Wrong password returns 401 with error message |
| ✅ returns 400 for missing fields | Missing password returns 400 |
| ✅ returns token for valid rider credentials | Non-admin rider login returns correct riderId |

### 2. `GET /api/health` (1 test)

| Test | Description |
|---|---|
| ✅ returns ok status | Returns `{ status: "ok", activeRiders: <count> }` |

### 3. `GET /api/stores` (3 tests)

| Test | Description |
|---|---|
| ✅ returns stores for admin | Admin token returns array of stores with id, name |
| ✅ rejects non-admin token | Rider token returns 403 |
| ✅ rejects missing auth header | No auth returns 401 |

### 4. `POST /api/stores` (3 tests)

| Test | Description |
|---|---|
| ✅ creates a new store | Admin creates store with name, lat, lng → 201 with storeId |
| ✅ rejects missing store name | Missing name returns 400 |
| ✅ rejects non-admin | Rider token returns 403 |

### 5. `POST /api/location` (4 tests)

| Test | Description |
|---|---|
| ✅ accepts valid location from rider | Valid lat/lng/ts/storeId returns success |
| ✅ rejects invalid coordinates | Non-numeric lat returns 400 |
| ✅ rejects missing auth | No auth header returns 401 |
| ✅ rejects invalid token | Garbage token returns 401 |

### 6. `POST /api/riders` (4 tests)

| Test | Description |
|---|---|
| ✅ creates a new rider | Admin creates rider with username, password, storeId, tenantId → 201 |
| ✅ rejects missing fields | Missing password/storeId returns 400 |
| ✅ rejects duplicate username | Existing username returns 400 "already exists" |
| ✅ rejects non-admin | Rider token returns 403 |

### 7. `POST /api/deliveries` (5 tests)

| Test | Description |
|---|---|
| ✅ creates a new delivery | Admin creates delivery with riderUsername + storeId → 201 with deliveryId |
| ✅ rejects missing riderUsername | Missing riderUsername returns 400 |
| ✅ rejects missing storeId | Missing storeId returns 400 |
| ✅ rejects non-admin | Rider token returns 403 |
| ✅ rejects missing auth | No auth header returns 401 |

### 8. `GET /api/deliveries` (4 tests)

| Test | Description |
|---|---|
| ✅ returns active deliveries for the tenant | Returns array with store_name, rider_username |
| ✅ filters by storeId | `?storeId=<id>` returns only matching deliveries |
| ✅ returns all when storeId=all | `?storeId=all` returns all active deliveries |
| ✅ rejects non-admin | Rider token returns 403 |

### 9. `POST /api/deliveries/:id/link` (4 tests)

| Test | Description |
|---|---|
| ✅ generates a tracking link with customer JWT | Returns link with `track.html?token=`, token has correct payload (role, deliveryId, riderId, storeId, storeLat, storeLng, storeName) |
| ✅ token expires in ~1.5 hours | Verifies `exp - iat = 5400` seconds |
| ✅ returns 404 for non-existent delivery | Invalid delivery ID returns 404 |
| ✅ rejects non-admin | Rider token returns 403 |

### 10. `PATCH /api/deliveries/:id` (5 tests)

| Test | Description |
|---|---|
| ✅ marks delivery as delivered | Sets status to "delivered" in DB |
| ✅ marks delivery as expired | Sets status to "expired" in DB |
| ✅ rejects invalid status values | Status "cancelled" returns 400 |
| ✅ returns 404 for non-existent delivery | Invalid delivery ID returns 404 |
| ✅ rejects non-admin | Rider token returns 403 |

### 11. Auth Edge Cases (2 tests)

| Test | Description |
|---|---|
| ✅ rejects expired token on protected endpoint | Token with 0s expiry returns 403 |
| ✅ rejects malformed token | Garbage token string returns 401 |

---

## Test Setup & Teardown

- **beforeAll**: Reads seeded tenant/store IDs from the database and generates an admin JWT
- **beforeEach** (delivery suites): Creates fresh test deliveries tagged with `TEST` in `customer_address`
- **afterAll**: Cleans up test deliveries, closes Socket.IO and HTTP server

## Dependencies

| Package | Purpose |
|---|---|
| `vitest` | Test runner and assertion library |
| `supertest` | HTTP assertion library for Express apps |
| `jsonwebtoken` | Token generation/verification for test helpers |
