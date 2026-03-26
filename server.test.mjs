import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import { createRequire } from "module";

// Set test env before requiring server
process.env.JWT_SECRET = "test_secret_key";
process.env.NODE_ENV = "test";
process.env.ADMIN_USERNAME = "admin";
process.env.ADMIN_PASSWORD = "adminpass";

const require = createRequire(import.meta.url);
const { app, server, io, db } = require("./server");

// ============ HELPERS ============

let adminToken;
let tenantId;
let storeId;

function generateAdminToken() {
    return jwt.sign(
        { username: "admin", riderId: "rider_admin", isAdmin: true, tenantId, tenantName: "Lucciano" },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );
}

function generateRiderToken(username = "rider1") {
    return jwt.sign(
        { username, riderId: `rider_${username}`, isAdmin: false, tenantId, tenantName: "Lucciano" },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );
}

// ============ SETUP / TEARDOWN ============

beforeAll(() => {
    // Get the seeded tenant and store IDs
    const tenant = db.prepare("SELECT id FROM tenants LIMIT 1").get();
    tenantId = tenant.id;

    const store = db.prepare("SELECT id FROM stores LIMIT 1").get();
    storeId = store.id;

    adminToken = generateAdminToken();
});

afterAll(() => {
    // Clean up test deliveries
    db.prepare("DELETE FROM deliveries WHERE customer_address LIKE '%TEST%'").run();
    io.close();
    server.close();
});

// ============ POST /api/login ============

describe("POST /api/login", () => {
    it("returns token for valid admin credentials", async () => {
        const res = await request(app)
            .post("/api/login")
            .send({ username: "admin", password: "adminpass" });

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("token");
        expect(res.body).toHaveProperty("riderId", "rider_admin");
        expect(res.body).toHaveProperty("tenantId");
        expect(res.body).toHaveProperty("tenantName");
        expect(res.body).toHaveProperty("stores");
        expect(Array.isArray(res.body.stores)).toBe(true);
    });

    it("returns 401 for invalid credentials", async () => {
        const res = await request(app)
            .post("/api/login")
            .send({ username: "admin", password: "wrong" });

        expect(res.status).toBe(401);
        expect(res.body).toHaveProperty("error");
    });

    it("returns 400 for missing fields", async () => {
        const res = await request(app)
            .post("/api/login")
            .send({ username: "admin" });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/required/i);
    });

    it("returns token for valid rider credentials", async () => {
        const res = await request(app)
            .post("/api/login")
            .send({ username: "rider1", password: "password123" });

        expect(res.status).toBe(200);
        expect(res.body.token).toBeDefined();
        expect(res.body.riderId).toBe("rider_rider1");
    });
});

// ============ GET /api/health ============

describe("GET /api/health", () => {
    it("returns ok status", async () => {
        const res = await request(app).get("/api/health");

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("status", "ok");
        expect(res.body).toHaveProperty("activeRiders");
    });
});

// ============ GET /api/stores ============

describe("GET /api/stores", () => {
    it("returns stores for admin", async () => {
        const res = await request(app)
            .get("/api/stores")
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.length).toBeGreaterThan(0);
        expect(res.body[0]).toHaveProperty("id");
        expect(res.body[0]).toHaveProperty("name");
    });

    it("rejects non-admin token", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .get("/api/stores")
            .set("Authorization", `Bearer ${riderToken}`);

        expect(res.status).toBe(403);
    });

    it("rejects missing auth header", async () => {
        const res = await request(app).get("/api/stores");
        expect(res.status).toBe(401);
    });
});

// ============ POST /api/stores ============

describe("POST /api/stores", () => {
    it("creates a new store", async () => {
        const name = `Test Store ${Date.now()}`;
        const res = await request(app)
            .post("/api/stores")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ tenantId, name, lat: -38.0, lng: -57.5 });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
        expect(res.body).toHaveProperty("storeId");

        // Clean up
        db.prepare("DELETE FROM stores WHERE name = ?").run(name);
    });

    it("rejects missing store name", async () => {
        const res = await request(app)
            .post("/api/stores")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ tenantId });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/name/i);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post("/api/stores")
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ tenantId, name: "Nope" });

        expect(res.status).toBe(403);
    });
});

// ============ POST /api/location ============

describe("POST /api/location", () => {
    it("accepts valid location from rider", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post("/api/location")
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ lat: -38.0055, lng: -57.5426, ts: Date.now(), storeId });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
    });

    it("rejects invalid coordinates", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post("/api/location")
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ lat: "not_a_number", lng: -57.5426 });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/coordinates/i);
    });

    it("rejects missing auth", async () => {
        const res = await request(app)
            .post("/api/location")
            .send({ lat: -38.0, lng: -57.5 });

        expect(res.status).toBe(401);
    });

    it("rejects invalid token", async () => {
        const res = await request(app)
            .post("/api/location")
            .set("Authorization", "Bearer invalid.token.here")
            .send({ lat: -38.0, lng: -57.5 });

        expect(res.status).toBe(401);
    });
});

// ============ POST /api/riders ============

describe("POST /api/riders", () => {
    it("creates a new rider", async () => {
        const username = `testrider_${Date.now()}`;
        const res = await request(app)
            .post("/api/riders")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ username, password: "pass123", storeId, tenantId });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
        expect(res.body).toHaveProperty("userId");

        // Clean up
        db.prepare("DELETE FROM users WHERE username = ?").run(username);
    });

    it("rejects missing fields", async () => {
        const res = await request(app)
            .post("/api/riders")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ username: "incomplete" });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/required/i);
    });

    it("rejects duplicate username", async () => {
        const res = await request(app)
            .post("/api/riders")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ username: "rider1", password: "pass", storeId, tenantId });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/already exists/i);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post("/api/riders")
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ username: "x", password: "y", storeId, tenantId });

        expect(res.status).toBe(403);
    });
});

// ============ POST /api/deliveries ============

describe("POST /api/deliveries", () => {
    it("creates a new delivery", async () => {
        const res = await request(app)
            .post("/api/deliveries")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ riderUsername: "rider1", storeId, customerAddress: "TEST - Av. Colón 1234", amount: 2500.50, paymentMethod: "Efectivo", recipientName: "Juan Pérez" });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
        expect(res.body).toHaveProperty("deliveryId");
        expect(typeof res.body.deliveryId).toBe("number");
    });

    it("rejects missing riderUsername", async () => {
        const res = await request(app)
            .post("/api/deliveries")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ storeId });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/required/i);
    });

    it("rejects missing storeId", async () => {
        const res = await request(app)
            .post("/api/deliveries")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ riderUsername: "rider1" });

        expect(res.status).toBe(400);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post("/api/deliveries")
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ riderUsername: "rider1", storeId });

        expect(res.status).toBe(403);
    });

    it("rejects missing auth", async () => {
        const res = await request(app)
            .post("/api/deliveries")
            .send({ riderUsername: "rider1", storeId });

        expect(res.status).toBe(401);
    });
});

// ============ GET /api/deliveries ============

describe("GET /api/deliveries", () => {
    let testDeliveryId;

    beforeEach(() => {
        // Create a test delivery
        const result = db.prepare(
            "INSERT INTO deliveries (tenant_id, store_id, rider_username, customer_address) VALUES (?, ?, ?, ?)"
        ).run(tenantId, storeId, "rider1", "TEST - delivery list");
        testDeliveryId = result.lastInsertRowid;
    });

    it("returns active deliveries for the tenant", async () => {
        const res = await request(app)
            .get("/api/deliveries")
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.length).toBeGreaterThan(0);

        const delivery = res.body.find(d => d.id === Number(testDeliveryId));
        expect(delivery).toBeDefined();
        expect(delivery.rider_username).toBe("rider1");
        expect(delivery).toHaveProperty("store_name");
    });

    it("filters by storeId", async () => {
        const res = await request(app)
            .get(`/api/deliveries?storeId=${storeId}`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        // All returned deliveries should match the storeId
        res.body.forEach(d => {
            expect(d.store_id).toBe(storeId);
        });
    });

    it("returns all when storeId=all", async () => {
        const res = await request(app)
            .get("/api/deliveries?storeId=all")
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .get("/api/deliveries")
            .set("Authorization", `Bearer ${riderToken}`);

        expect(res.status).toBe(403);
    });
});

// ============ POST /api/deliveries/:id/link ============

describe("POST /api/deliveries/:id/link", () => {
    let testDeliveryId;

    beforeEach(() => {
        const result = db.prepare(
            "INSERT INTO deliveries (tenant_id, store_id, rider_username, customer_address, amount, payment_method, recipient_name) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).run(tenantId, storeId, "rider1", "TEST - link gen", 1500.00, "Efectivo", "María López");
        testDeliveryId = result.lastInsertRowid;
    });

    it("generates a tracking link with customer JWT", async () => {
        const res = await request(app)
            .post(`/api/deliveries/${testDeliveryId}/link`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body).toHaveProperty("link");
        expect(res.body).toHaveProperty("token");
        expect(res.body.link).toContain("track.html?token=");

        // Verify token payload
        const decoded = jwt.verify(res.body.token, process.env.JWT_SECRET);
        expect(decoded.role).toBe("customer");
        expect(decoded.deliveryId).toBe(Number(testDeliveryId));
        expect(decoded.riderId).toBe("rider_rider1");
        expect(decoded.storeId).toBe(storeId);
        expect(decoded).toHaveProperty("storeLat");
        expect(decoded).toHaveProperty("storeLng");
        expect(decoded).toHaveProperty("storeName");
        expect(decoded.recipientName).toBe("María López");
        expect(decoded.amount).toBe(1500.00);
        expect(decoded.paymentMethod).toBe("Efectivo");
    });

    it("token expires in ~1.5 hours", async () => {
        const res = await request(app)
            .post(`/api/deliveries/${testDeliveryId}/link`)
            .set("Authorization", `Bearer ${adminToken}`);

        const decoded = jwt.verify(res.body.token, process.env.JWT_SECRET);
        const expiresIn = decoded.exp - decoded.iat;
        // 1.5 hours = 5400 seconds
        expect(expiresIn).toBe(5400);
    });

    it("returns 404 for non-existent delivery", async () => {
        const res = await request(app)
            .post("/api/deliveries/999999/link")
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(404);
        expect(res.body.error).toMatch(/not found/i);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .post(`/api/deliveries/${testDeliveryId}/link`)
            .set("Authorization", `Bearer ${riderToken}`);

        expect(res.status).toBe(403);
    });
});

// ============ PATCH /api/deliveries/:id ============

describe("PATCH /api/deliveries/:id", () => {
    let testDeliveryId;

    beforeEach(() => {
        const result = db.prepare(
            "INSERT INTO deliveries (tenant_id, store_id, rider_username, customer_address, status) VALUES (?, ?, ?, ?, ?)"
        ).run(tenantId, storeId, "rider1", "TEST - patch", "active");
        testDeliveryId = result.lastInsertRowid;
    });

    it("marks delivery as delivered", async () => {
        const res = await request(app)
            .patch(`/api/deliveries/${testDeliveryId}`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ status: "delivered" });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);

        // Verify in DB
        const delivery = db.prepare("SELECT status FROM deliveries WHERE id = ?").get(testDeliveryId);
        expect(delivery.status).toBe("delivered");
    });

    it("marks delivery as expired", async () => {
        const res = await request(app)
            .patch(`/api/deliveries/${testDeliveryId}`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ status: "expired" });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);

        const delivery = db.prepare("SELECT status FROM deliveries WHERE id = ?").get(testDeliveryId);
        expect(delivery.status).toBe("expired");
    });

    it("rejects invalid status values", async () => {
        const res = await request(app)
            .patch(`/api/deliveries/${testDeliveryId}`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ status: "cancelled" });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/status/i);
    });

    it("returns 404 for non-existent delivery", async () => {
        const res = await request(app)
            .patch("/api/deliveries/999999")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({ status: "delivered" });

        expect(res.status).toBe(404);
    });

    it("rejects non-admin", async () => {
        const riderToken = generateRiderToken();
        const res = await request(app)
            .patch(`/api/deliveries/${testDeliveryId}`)
            .set("Authorization", `Bearer ${riderToken}`)
            .send({ status: "delivered" });

        expect(res.status).toBe(403);
    });
});

// ============ AUTH EDGE CASES ============

describe("Auth edge cases", () => {
    it("rejects expired token on protected endpoint", async () => {
        const expiredToken = jwt.sign(
            { username: "admin", riderId: "rider_admin", isAdmin: true, tenantId, tenantName: "Lucciano" },
            process.env.JWT_SECRET,
            { expiresIn: "0s" }
        );

        // Small delay to ensure token is expired
        await new Promise(r => setTimeout(r, 100));

        const res = await request(app)
            .get("/api/stores")
            .set("Authorization", `Bearer ${expiredToken}`);

        // verifyToken returns null for expired tokens → treated as non-admin
        expect(res.status).toBe(403);
    });

    it("rejects malformed token", async () => {
        const res = await request(app)
            .post("/api/location")
            .set("Authorization", "Bearer this.is.garbage")
            .send({ lat: -38, lng: -57 });

        expect(res.status).toBe(401);
    });
});
