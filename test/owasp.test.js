const assert = require('assert');
const request = require('supertest');
const { app, db } = require('../server');
const jwt = require('jsonwebtoken');

describe('OWASP Top 10 (2025) Security Test Suite', function() {
    let adminToken;
    let riderToken;
    let defaultTenantId;
    let centralStoreId;

    before(async function() {
        const tenant = db.prepare('SELECT id FROM tenants ORDER BY id ASC LIMIT 1').get();
        if (!tenant) throw new Error("No tenant found.");
        defaultTenantId = tenant.id;

        const store = db.prepare('SELECT id FROM stores WHERE tenant_id = ?').get(defaultTenantId);
        centralStoreId = store ? store.id : 1;
        
        // Ensure standard DB seed accounts are available
        const resAdmin = await request(app).post('/api/login').send({ username: 'giacatec', password: 'giacatecpass' });
        adminToken = resAdmin.body.token;
        
        // Fetch or create a pure rider
        const riderRes = db.prepare('SELECT username, password FROM users WHERE is_admin = 0 AND tenant_id = ?').get(defaultTenantId);
        if (riderRes) {
            const rLogin = await request(app).post('/api/login').send({ username: riderRes.username, password: riderRes.password });
            riderToken = rLogin.body.token;
        }
    });

    describe('A01:2025 - Broken Access Control', function() {
        it('should prevent horizontal/vertical access escalation on unauthorized IDs', async function() {
            // A rider trying to fetch admin specific store lists
            const res = await request(app)
                .get('/api/stores')
                .set('Authorization', `Bearer ${riderToken}`);
            // Must strictly be 403 Forbidden, not 401 unauth or 500 error
            assert.strictEqual(res.status, 403);
            assert.ok(res.body.error.includes('Admin access required'));
        });
        
        it('should securely filter implicit cross-tenant boundary overriding attempts', async function() {
            // Even if an admin specifies tenantId: 99999 maliciously in body, it should fallback securely or 403
            const res = await request(app)
                .post('/api/riders')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    username: 'hacker123',
                    password: '123',
                    storeId: 99999, // Store they do not own
                    isAdmin: false
                });
            // DB will throw 403 because 99999 doesnt map to the token's authenticated tenant
            assert.strictEqual(res.status, 403);
            assert.ok(res.body.error.includes('Invalid store or unauthorized'));
        });
    });

    describe('A02:2025 - Cryptographic Failures', function() {
        it('should strictly reject maliciously tampered JWT tokens (alg=none)', async function() {
            // Generating a fake token mimicking the user but bypassing signature
            const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({ username: 'giacatec', isAdmin: true })).toString('base64url');
            const forgedToken = `${header}.${payload}.`;

            const res = await request(app)
                .get('/api/stores')
                .set('Authorization', `Bearer ${forgedToken}`);
            
            assert.strictEqual(res.status, 401);
            assert.strictEqual(res.body.error, 'Invalid token');
        });
    });

    describe('A03:2025 - Injection (SQLi & XSS Mitigation)', function() {
        it('should fully neutralize SQL Injection characters in GET parameters', async function() {
            // Exploiting typical GET parameter arrays
            const payload = "1' OR '1'='1"; // Always true injection
            const res = await request(app)
                .get(`/api/deliveries?storeId=${encodeURIComponent(payload)}`)
                .set('Authorization', `Bearer ${adminToken}`);
            
            // Should return natively empty list instead of full DB dump or crashing
            // SQLite parameterized queries automatically neutralize this string as literal integer search
            assert.strictEqual(res.status, 200);
            assert.ok(Array.isArray(res.body));
            assert.strictEqual(res.body.length, 0); // No store matched the literal string "1' OR '1'='1"
        });

        it('should accept malicious XSS payloads but neutralize server-side execution', async function() {
            // Tests that the backend survives XSS submission cleanly without breaking DB storage mapping
            const maliciousName = "<script>alert('xss')</script><img>恶意";
            const res = await request(app)
                .post('/api/stores')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    name: maliciousName,
                    active: true,
                    lat: -38,
                    lng: -57
                });
            
            assert.strictEqual(res.status, 201);
            
            // Clean up to prevent UI pollution for manual testers later
            db.prepare('DELETE FROM stores WHERE id = ?').run(res.body.storeId);
        });
    });

    describe('A05:2025 - Security Misconfiguration (Frontend Headers)', function() {
        it('should configure fundamental frontend security HTTP headers natively', async function() {
            // Load frontend static files mapped via express.static
            const reqHtml = await request(app).get('/');
            
            // Assert that the Helmet middleware attaches standard protections
            // Helmet enables X-Content-Type-Options by default
            assert.strictEqual(reqHtml.headers['x-content-type-options'], 'nosniff');
            
            // X-Frame-Options prevents Clickjacking natively via helmet
            assert.strictEqual(reqHtml.headers['x-frame-options'], 'SAMEORIGIN');
        });
    });

    describe('A07:2025 - Identification and Authentication Failures', function() {
        it('should neutrally reject invalid auth attempts without enumerating usernames', async function() {
            // Test that non-existent users DO NOT yield "User not found"
            // They must strictly yield universal "Invalid credentials" matching valid users + wrong password
            const resNoUser = await request(app).post('/api/login').send({ username: 'ghost_user', password: '123' });
            assert.strictEqual(resNoUser.status, 401);
            assert.strictEqual(resNoUser.body.error, 'Invalid credentials');
            
            // Test actual user with wrong password
            const resBadPass = await request(app).post('/api/login').send({ username: 'giacatec', password: 'wrongpassword' });
            assert.strictEqual(resBadPass.status, 401);
            assert.strictEqual(resBadPass.body.error, 'Invalid credentials');
        });
    });
});
