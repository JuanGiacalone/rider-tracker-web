const assert = require('assert');
const request = require('supertest');
const { app, db } = require('../server');
const crypto = require('crypto');

describe('RiderTracker API Test Suite', function() {
    let superadminToken;
    let adminToken;
    let riderToken;
    let centralStoreId;
    let defaultTenantId;
    let createdTenantId;
    let createdDeliveryId;

    const randomStr = crypto.randomBytes(4).toString('hex');
    const uniqueAdmin = `admin_${randomStr}`;
    const uniqueRider = `rider_${randomStr}`;

    before(async function() {
        // Find default tenant and store
        const tenant = db.prepare('SELECT id FROM tenants ORDER BY id ASC LIMIT 1').get();
        if (!tenant) throw new Error("No tenant found. Is db seeded?");
        defaultTenantId = tenant.id;

        const store = db.prepare('SELECT id FROM stores WHERE tenant_id = ? AND name = ?').get(defaultTenantId, 'Centro');
        centralStoreId = store ? store.id : 1;

        // Insert giacatec superadmin if not exists
        const giacatecUser = db.prepare('SELECT id FROM users WHERE username = ?').get('giacatec');
        if (!giacatecUser) {
            db.prepare('INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)')
                .run(defaultTenantId, 'giacatec', 'giacatecpass', 1, centralStoreId);
        } else {
            // Ensure password is known
            db.prepare('UPDATE users SET password = ?, is_admin = 1 WHERE username = ?').run('giacatecpass', 'giacatec');
        }

        // Insert unique test admin
        db.prepare('INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)')
            .run(defaultTenantId, uniqueAdmin, 'testpass', 1, centralStoreId);

        // Insert unique test rider
        db.prepare('INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)')
            .run(defaultTenantId, uniqueRider, 'testpass', 0, centralStoreId);

        // Login as giacatec
        const resSuper = await request(app).post('/api/login').send({ username: 'giacatec', password: 'giacatecpass' });
        superadminToken = resSuper.body.token;

        // Login as unique test admin
        const resAdmin = await request(app).post('/api/login').send({ username: uniqueAdmin, password: 'testpass' });
        adminToken = resAdmin.body.token;

        // Login as unique test rider
        const resRider = await request(app).post('/api/login').send({ username: uniqueRider, password: 'testpass' });
        riderToken = resRider.body.token;
    });

    after(function() {
        // Cleanup test users
        db.prepare('DELETE FROM users WHERE username IN (?, ?)').run(uniqueAdmin, uniqueRider);
    });

    describe('Authentication & Authorization Security', function() {
        it('should return 401 for requests without token', async function() {
            const res = await request(app).get('/api/stores');
            assert.strictEqual(res.status, 401);
        });

        it('should prevent riders from accessing admin routes', async function() {
            const res = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${riderToken}`)
                .send({ tenantId: defaultTenantId, name: 'HackerStore', active: true });
            assert.strictEqual(res.status, 403);
            assert.match(res.body.error, /Unauthorized: Admin access required/);
        });

        it('should prevent regular admins from accessing superadmin/developer routes', async function() {
            const res = await request(app)
                .get('/api/admin/tenants')
                .set('Authorization', `Bearer ${adminToken}`);
            assert.strictEqual(res.status, 403);
            assert.strictEqual(res.body.error, '403');
        });
    });

    describe('Superadmin (giacatec) Functionality', function() {
        it('should fetch database stats', async function() {
            const res = await request(app)
                .get('/admin/db-stats')
                .set('Authorization', `Bearer ${superadminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(res.body.size);
            assert.ok(res.body.lastModified);
        });

        it('should let superadmin fetch tenants', async function() {
            const res = await request(app)
                .get('/api/admin/tenants')
                .set('Authorization', `Bearer ${superadminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(Array.isArray(res.body));
        });

        it('should let superadmin create a new tenant', async function() {
            const res = await request(app)
                .post('/api/admin/tenants')
                .set('Authorization', `Bearer ${superadminToken}`)
                .send({
                    name: `TestTenant_${Date.now()}`,
                    active: true,
                    endpoint: 'https://test.com',
                    icon_url: 'icon.png'
                });
            assert.strictEqual(res.status, 201);
            assert.ok(res.body.tenantId);
            createdTenantId = res.body.tenantId;
        });

        it('should let superadmin modify an existing tenant', async function() {
            assert.ok(createdTenantId, "Missing createdTenantId from prior test");
            const res = await request(app)
                .patch(`/api/admin/tenants/${createdTenantId}`)
                .set('Authorization', `Bearer ${superadminToken}`)
                .send({
                    active: false,
                    endpoint: 'https://updated.com',
                    icon_url: 'newicon.png'
                });
            assert.strictEqual(res.status, 200);

            // Verify the patch
            const updated = db.prepare('SELECT active, endpoint, icon_url FROM tenants WHERE id = ?').get(createdTenantId);
            assert.strictEqual(updated.active, 0);
            assert.strictEqual(updated.endpoint, 'https://updated.com');
            assert.strictEqual(updated.icon_url, 'newicon.png');
        });
    });

    describe('Admin Functionality', function() {
        let newStoreId;

        it('should let admin fetch stores', async function() {
            const res = await request(app)
                .get('/api/stores')
                .set('Authorization', `Bearer ${adminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(Array.isArray(res.body));
            assert.ok(res.body.some(s => s.name === 'Centro'));
        });

        it('should let admin create a new store', async function() {
            const res = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    tenantId: defaultTenantId,
                    name: `TestStore_${Date.now()}`,
                    active: true,
                    lat: -38.0,
                    lng: -57.0
                });
            assert.strictEqual(res.status, 201);
            assert.ok(res.body.storeId);
            newStoreId = res.body.storeId;
        });

        it('should let admin fetch riders', async function() {
            const res = await request(app)
                .get('/api/riders')
                .set('Authorization', `Bearer ${adminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(Array.isArray(res.body));
            // Should contain our unique test rider
            assert.ok(res.body.some(r => r.username === uniqueRider));
        });

        it('should let admin create a rider', async function() {
            const res = await request(app)
                .post('/api/riders')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    username: `new_rider_${Date.now()}`,
                    password: '123',
                    storeId: newStoreId,
                    isAdmin: false,
                    tenantId: defaultTenantId
                });
            assert.strictEqual(res.status, 201);
            assert.ok(res.body.userId);
            
            // Cleanup the created rider right away to avoid pollution
            db.prepare('DELETE FROM users WHERE id = ?').run(res.body.userId);
        });

        it('should let admin create a delivery', async function() {
            const res = await request(app)
                .post('/api/deliveries')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    riderUsername: uniqueRider,
                    storeId: centralStoreId,
                    customerAddress: 'Av. Test 123',
                    amount: 500.5,
                    paymentMethod: 'Efectivo',
                    recipientName: 'Test Customer',
                    customerLat: -38.123,
                    customerLng: -57.123
                });
            assert.strictEqual(res.status, 201);
            assert.ok(res.body.deliveryId);
            createdDeliveryId = res.body.deliveryId;
        });

        it('should let admin fetch active deliveries', async function() {
            const res = await request(app)
                .get('/api/deliveries')
                .set('Authorization', `Bearer ${adminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(Array.isArray(res.body));
            assert.ok(res.body.some(d => d.id === createdDeliveryId));
        });

        it('should let admin generate a delivery tracking link', async function() {
            assert.ok(createdDeliveryId, "Missing createdDeliveryId");
            const res = await request(app)
                .post(`/api/deliveries/${createdDeliveryId}/link`)
                .set('Authorization', `Bearer ${adminToken}`);
            assert.strictEqual(res.status, 200);
            assert.ok(res.body.link);
            assert.ok(res.body.token);
        });

        it('should let admin mark delivery as delivered', async function() {
            assert.ok(createdDeliveryId, "Missing createdDeliveryId");
            const res = await request(app)
                .patch(`/api/deliveries/${createdDeliveryId}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: 'delivered' });
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.body.success, true);
        });

        it('should allow different tenants to have stores with the same name (e.g. Alem)', async function() {
            // Priority Test: Tenant X creates 'Alem'
            const res1 = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    tenantId: defaultTenantId,
                    name: 'Alem',
                    active: true,
                    lat: -38.01,
                    lng: -57.01
                });
            assert.strictEqual(res1.status, 201);
            assert.ok(res1.body.storeId);

            // Superadmin creates Tenant Y
            const resTenant = await request(app)
                .post('/api/admin/tenants')
                .set('Authorization', `Bearer ${superadminToken}`)
                .send({
                    name: `Tenant_Y_${Date.now()}`,
                    active: true
                });
            const tenantYId = resTenant.body.tenantId;

            // Seed Admin Y for Tenant Y
            const uniqueAdminY = `admin_y_${crypto.randomBytes(4).toString('hex')}`;
            db.prepare('INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)')
                .run(tenantYId, uniqueAdminY, 'testpass', 1, null);

            // Login Admin Y
            const resAdminY = await request(app).post('/api/login').send({ username: uniqueAdminY, password: 'testpass' });
            const adminYToken = resAdminY.body.token;

            // Tenant Y creates 'Alem'
            const res2 = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${adminYToken}`)
                .send({
                    tenantId: tenantYId,
                    name: 'Alem',
                    active: true,
                    lat: -38.02,
                    lng: -57.02
                });
            
            // Should succeed without dropping into SQLITE_CONSTRAINT_UNIQUE
            assert.strictEqual(res2.status, 201);
            assert.ok(res2.body.storeId);
            assert.notStrictEqual(res1.body.storeId, res2.body.storeId);
            
            // Cleanup Admin Y so we don't pollute local testing
            db.prepare('DELETE FROM users WHERE username = ?').run(uniqueAdminY);
        });
    });

    describe('Rider Functionality', function() {
        it('should let rider update background location via REST', async function() {
            const res = await request(app)
                .post('/api/location')
                .set('Authorization', `Bearer ${riderToken}`)
                .send({
                    lat: -38.0001,
                    lng: -57.0001,
                    storeId: centralStoreId
                });
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.body.success, true);
        });
        
        it('should let anyone ping health check endpoint', async function() {
            const res = await request(app).get('/api/health');
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.body.status, 'ok');
        });
    });

    describe('Tenant Cross-Pollination & Isolation', function() {
        let isolatedTenantId;
        let isolatedStoreId;
        
        before(async function() {
            // giacatec creates a new isolated Sandbox Tenant
            const res = await request(app)
                .post('/api/admin/tenants')
                .set('Authorization', `Bearer ${superadminToken}`)
                .send({
                    name: `Isolated_Tenant_${Date.now()}`,
                    active: true
                });
            isolatedTenantId = res.body.tenantId;

            // Generate a store belonging strictly to isolated tenant
            // Note: because `adminToken` is tied to the default tenant, we will just use DB to seed the isolated store for tests
            const isoResult = db.prepare('INSERT INTO stores (tenant_id, name, lat, lng, active) VALUES (?, ?, ?, ?, ?)')
                .run(isolatedTenantId, `IsoStore_${Date.now()}`, -38.1, -57.1, 1);
            isolatedStoreId = isoResult.lastInsertRowid;
            
            // Seed a rider for isolated tenant
            db.prepare('INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)')
                .run(isolatedTenantId, `iso_rider_${Date.now()}`, 'pass', 0, isolatedStoreId);
        });

        it('should strictly block an admin from seeding a store into another tenant', async function() {
            // Default `adminToken` deliberately tries bypassing tenant walls to inject store into isolated tenant
            const res = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    tenantId: isolatedTenantId, // Malicious override attempt
                    name: 'Hacked Store',
                    active: true,
                    lat: -38.0,
                    lng: -57.0
                });
            assert.strictEqual(res.status, 201);
            // It should technically fallback securely to the admin's original tenantId instead of crashing or breaking the wall!
            const verifyObj = db.prepare('SELECT tenant_id FROM stores WHERE id = ?').get(res.body.storeId);
            assert.strictEqual(verifyObj.tenant_id, defaultTenantId);
        });

        it('should securely prohibit an admin from tying a rider to a store belonging to another tenant', async function() {
            const res = await request(app)
                .post('/api/riders')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    username: `hacked_rider_${Date.now()}`,
                    password: '123',
                    storeId: isolatedStoreId, // A cross-tenant store request
                    isAdmin: false
                });
            assert.strictEqual(res.status, 403);
            assert.match(res.body.error, /Invalid store or unauthorized for this tenant/);
        });

        it('should strictly prohibit an admin from mapping a delivery bridging to an external store', async function() {
            const res = await request(app)
                .post('/api/deliveries')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    riderUsername: uniqueRider,
                    storeId: isolatedStoreId, // Cross-tenant store payload
                    customerAddress: 'Hacked address'
                });
            assert.strictEqual(res.status, 403);
            assert.match(res.body.error, /Invalid store or unauthorized for this tenant/);
        });
    });
});
