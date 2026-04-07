require("dotenv").config();
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
    },
});

// Middleware
app.use(helmet({
    hsts: false,
    contentSecurityPolicy: false,
}));
app.use(cors());
app.use(express.json());

// In-memory storage
const activeRiders = new Map();
const userSockets = new Map(); // Track sockets by username
const activeDeliveryRiders = new Map(); // Map<riderId, Set<deliveryId>> for fast lookup

// Utility function to generate a unique rider ID
function generateRiderId(username) {
    return `rider_${username}`;
}

// JWT verification middleware
function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Authentication Middleware

const authenticateJWT = (req, res, next) => {

    let token = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.split(" ")[1];
    }

    if (!token && req.query.token) {
        token = req.query.token;
    }

    if (!token && req.headers.cookie) {
        const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
            const [name, value] = cookie.trim().split('=');
            acc[name] = value;
            return acc;
        }, {});
        token = cookies.authToken;
    }

    if (!token) {
        return res.status(401).json({ error: "Missing authorization header" });
    }
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: "Invalid token" });
    }
    req.user = decoded;
    next();
}

const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }
    next();
};

// Developer Authorization Middleware (Restricts sensitive DB tools to 'giacatec')

const isDeveloper = (req, res, next) => {
    if (!req.user || req.user.username !== 'giacatec') {
        return res.status(403).json({ error: "403" });
    }
    next();
};





// ============ REST API ENDPOINTS ============

app.get('/admin/db-stats', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    const dbPath = path.join(__dirname, 'data/database.sqlite');

    fs.stat(dbPath, (err, stats) => {
        if (err) return res.status(404).json({ error: "DB not found" });

        res.json({
            lastModified: stats.mtime,
            size: (stats.size / 1024 / 1024).toFixed(2) + " MB"
        });
    });
});

app.get('/api/admin/tenants', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    try {
        const tenants = db.prepare('SELECT id, name, active, endpoint, icon_url FROM tenants ORDER BY name ASC').all();
        res.json(tenants);
    } catch (error) {
        console.error("Error fetching tenants:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/api/admin/tenants', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    const { name, active, endpoint, icon_url } = req.body;
    if (!name) return res.status(400).json({ error: "Tenant name is required" });

    try {
        const result = db.prepare(
            'INSERT INTO tenants (name, active, endpoint, icon_url) VALUES (?, ?, ?, ?)'
        ).run(name, active === false ? 0 : 1, endpoint || null, icon_url || null);
        res.status(201).json({ success: true, tenantId: result.lastInsertRowid });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: "Tenant name already exists" });
        }
        console.error("Error creating tenant:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch('/api/admin/tenants/:id', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    const tenantId = req.params.id;
    const { active, endpoint, icon_url } = req.body;

    try {
        const result = db.prepare(
            'UPDATE tenants SET active = ?, endpoint = ?, icon_url = ? WHERE id = ?'
        ).run(active === false ? 0 : 1, endpoint || null, icon_url || null, tenantId);

        if (result.changes === 0) {
            return res.status(404).json({ error: "Tenant not found" });
        }

        res.json({ success: true });
    } catch (error) {
        console.error("Error updating tenant:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/admin/download-db', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    const liveDbPath = path.join(__dirname, 'data/database.sqlite');
    const backupPath = path.join(__dirname, 'data/backup_temp.sqlite');

    // 1. Connect to the live database
    const db = new sqlite3.Database(liveDbPath);

    // 2. Run VACUUM INTO to create a consistent snapshot
    // This safely ignores any active locks or WAL files
    db.run(`VACUUM INTO ?`, [backupPath], (err) => {
        db.close(); // Close connection to live DB

        if (err) {
            console.error(err);
            return res.status(500).send("Backup failed.");
        }

        // 3. Serve the fresh snapshot
        res.download(backupPath, 'database-backup.sqlite', (downloadErr) => {
            // 4. Cleanup: Delete the temp file after download finishes
            fs.unlink(backupPath, (unlinkErr) => {
                if (unlinkErr) console.error("Cleanup error:", unlinkErr);
            });
        });
    });
});


// Login endpoint
app.post("/api/login", (req, res) => {

    console.log("Login request:", req.body);
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password required" });
    }

    const user = db.prepare(`
        SELECT u.*, t.name as tenant_name, t.icon_url 
        FROM users u 
        JOIN tenants t ON u.tenant_id = t.id 
        WHERE u.username = ? AND u.password = ?
    `).get(username, password);

    if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const riderId = generateRiderId(username);
    const isAdmin = user.is_admin === 1;
    const token = jwt.sign(
        { username, riderId, isAdmin: isAdmin, tenantId: user.tenant_id, tenantName: user.tenant_name },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
    );

    // Fetch stores for this user's tenant
    const stores = db.prepare('SELECT id, name, lat, lng FROM stores WHERE tenant_id = ?').all(user.tenant_id);

    res.json({ token, riderId, username, tenantId: user.tenant_id, tenantName: user.tenant_name, iconUrl: user.icon_url, stores });
});

// Health check endpoint
app.get("/api/health", (req, res) => {
    res.json({ status: "ok", activeRiders: activeRiders.size });
});

app.get("/api/stores", authenticateJWT, (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    try {
        const stores = db.prepare('SELECT id, name, lat, lng FROM stores WHERE tenant_id = ?').all(decoded.tenantId);
        res.json(stores);
    } catch (error) {
        console.error("Error fetching stores:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// POST /api/stores - Add a new store
app.post("/api/stores", authenticateJWT, isAdmin, (req, res) => {

    const { name, lat, lng, active } = req.body;
    let targetTenantId = req.user.tenantId;
    
    if (req.user.username === 'giacatec' && req.body.tenantId) {
        targetTenantId = req.body.tenantId;
    }

    if (!name) {
        return res.status(400).json({ error: "Store name is required" });
    }

    try {
        const result = db.prepare(
            'INSERT INTO stores (tenant_id, name, lat, lng, active) VALUES (?, ?, ?, ?, ?)'
        ).run(targetTenantId, name, lat || null, lng || null, active === false ? 0 : 1);

        res.status(201).json({
            success: true,
            storeId: result.lastInsertRowid,
            message: "Store created successfully"
        });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: "Store name already exists" });
        }
        console.error("Error creating store:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// POST /api/location - Background location updates
app.post("/api/location", authenticateJWT, (req, res) => {


    const { riderId, tenantId, tenantName } = req.user;
    const { lat, lng, ts, storeId } = req.body;

    if (typeof lat !== "number" || typeof lng !== "number") {
        return res.status(400).json({ error: "Invalid coordinates" });
    }

    // Update internal state
    activeRiders.set(riderId, {
        lat,
        lng,
        ts: ts || Date.now(),
        storeId,
        tenantId
    });

    // Broadcast update to tenant-specific room
    const tenantRoom = tenantName || `Tenant_${tenantId}`;
    io.to(tenantRoom).emit("rider-update", {
        riderId,
        lat,
        lng,
        ts: ts || Date.now(),
        storeId,
        tenantId
    });
    console.log(`[REST-Location] ${riderId} (Tenant: ${tenantName}, Store: ${storeId}): ${lat.toFixed(4)}, ${lng.toFixed(4)}`);
    res.json({ success: true });
});

app.get('/api/admin/stores', authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    try {
        const stores = db.prepare('SELECT id, name, tenant_id FROM stores ORDER BY name ASC').all();
        res.json(stores);
    } catch (error) {
        console.error("Error fetching all stores:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// POST /api/riders - Add a new rider
app.post("/api/riders", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }
    const { username, password, storeId, isAdmin: setAdmin } = req.body;
    
    let targetTenantId = decoded.tenantId;
    if (decoded.username === 'giacatec' && req.body.tenantId) {
        targetTenantId = req.body.tenantId;
    }

    if (!username || !password || !storeId) {
        return res.status(400).json({ error: "Username, password and storeId are required" });
    }
    try {
        const storeCheck = db.prepare('SELECT id FROM stores WHERE id = ? AND tenant_id = ?').get(storeId, targetTenantId);
        if (!storeCheck) return res.status(403).json({ error: "Invalid store or unauthorized for this tenant" });

        const result = db.prepare(
            'INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)'
        ).run(targetTenantId, username, password, setAdmin ? 1 : 0, storeId);

        res.status(201).json({ success: true, userId: result.lastInsertRowid });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: "Username already exists" });
        }
        console.error("Error creating rider:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// GET /api/riders - Get all riders for the tenant (for delivery assignment)
app.get("/api/riders", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    try {
        const riders = db.prepare('SELECT id, username, store_id FROM users WHERE tenant_id = ? AND is_admin = 0 ORDER BY username ASC').all(decoded.tenantId);
        res.json(riders);
    } catch (error) {
        console.error("Error fetching riders:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ============ DELIVERY ENDPOINTS ============

// POST /api/deliveries - Create a new delivery
app.post("/api/deliveries", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    const { riderUsername, storeId, customerAddress, amount, paymentMethod, recipientName, customerLat, customerLng } = req.body;

    if (!riderUsername || !storeId) {
        return res.status(400).json({ error: "riderUsername and storeId are required" });
    }
    
    // Verify store and rider belong to this tenant
    const storeCheck = db.prepare('SELECT id, name FROM stores WHERE id = ? AND tenant_id = ?').get(storeId, decoded.tenantId);
    if (!storeCheck) return res.status(403).json({ error: "Invalid store or unauthorized for this tenant" });
    
    const riderCheck = db.prepare('SELECT id FROM users WHERE username = ? AND tenant_id = ?').get(riderUsername, decoded.tenantId);
    if (!riderCheck) return res.status(403).json({ error: "Invalid rider or unauthorized for this tenant" });

    try {
        const result = db.prepare(
            'INSERT INTO deliveries (tenant_id, store_id, rider_username, customer_address, amount, payment_method, recipient_name, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        ).run(decoded.tenantId, storeId, riderUsername, customerAddress || null, amount || null, paymentMethod || null, recipientName || null, customerLat || null, customerLng || null);

        const deliveryId = result.lastInsertRowid;

        // Track this rider's active delivery
        const riderId = `rider_${riderUsername}`;
        if (!activeDeliveryRiders.has(riderId)) {
            activeDeliveryRiders.set(riderId, new Set());
        }
        activeDeliveryRiders.get(riderId).add(Number(deliveryId));

        // Let storeName be fetched from storeCheck
        const store = storeCheck;

        // Notify the rider via WebSocket if they're connected
        const riderSocket = userSockets.get(riderUsername);
        if (riderSocket) {
            riderSocket.emit('new-delivery', {
                deliveryId: Number(deliveryId),
                storeId,
                storeName: store ? store.name : null,
                customerAddress: customerAddress || null,
                amount: amount || null,
                paymentMethod: paymentMethod || null,
                recipientName: recipientName || null,
                lat: customerLat || null,
                lng: customerLng || null
            });
            console.log(`[Delivery] Notified rider ${riderUsername} of new delivery #${deliveryId}`);
        }

        // Broadcast to tenant room so admins can see the delivery marker on map
        io.to(decoded.tenantName).emit('delivery-created', {
            id: Number(deliveryId),
            store_id: storeId,
            store_name: store ? store.name : null,
            rider_username: riderUsername,
            customer_address: customerAddress || null,
            amount: amount || null,
            payment_method: paymentMethod || null,
            recipient_name: recipientName || null,
            lat: customerLat || null,
            lng: customerLng || null,
            status: 'active'
        });

        res.status(201).json({ success: true, deliveryId });
    } catch (error) {
        console.error("Error creating delivery:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// GET /api/deliveries - List active deliveries (filtered by storeId query param)
app.get("/api/deliveries", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    try {
        const storeId = req.query.storeId;
        let deliveries;
        if (storeId && storeId !== 'all') {
            deliveries = db.prepare(
                'SELECT d.*, s.name as store_name FROM deliveries d JOIN stores s ON d.store_id = s.id WHERE d.tenant_id = ? AND d.store_id = ? AND d.status = ? ORDER BY d.created_at DESC'
            ).all(decoded.tenantId, storeId, 'active');
        } else {
            deliveries = db.prepare(
                'SELECT d.*, s.name as store_name FROM deliveries d JOIN stores s ON d.store_id = s.id WHERE d.tenant_id = ? AND d.status = ? ORDER BY d.created_at DESC'
            ).all(decoded.tenantId, 'active');
        }
        res.json(deliveries);
    } catch (error) {
        console.error("Error fetching deliveries:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// POST /api/deliveries/:id/link - Generate a temporary customer tracking link
app.post("/api/deliveries/:id/link", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    const deliveryId = parseInt(req.params.id);
    const delivery = db.prepare('SELECT * FROM deliveries WHERE id = ? AND tenant_id = ?').get(deliveryId, decoded.tenantId);

    if (!delivery) {
        return res.status(404).json({ error: "Delivery not found" });
    }

    // Get store info for the token
    const store = db.prepare('SELECT id, name, lat, lng FROM stores WHERE id = ?').get(delivery.store_id);

    const customerToken = jwt.sign(
        {
            deliveryId,
            riderId: `rider_${delivery.rider_username}`,
            storeId: delivery.store_id,
            storeLat: store ? store.lat : null,
            storeLng: store ? store.lng : null,
            storeName: store ? store.name : null,
            tenantId: delivery.tenant_id,
            recipientName: delivery.recipient_name || null,
            amount: delivery.amount || null,
            paymentMethod: delivery.payment_method || null,
            role: 'customer'
        },
        process.env.JWT_SECRET,
        { expiresIn: '1.5h' }
    );

    const protocol = req.protocol;
    const host = req.get('host');
    const link = `${protocol}://${host}/track.html?token=${customerToken}`;

    res.json({ success: true, link, token: customerToken });
});

// PATCH /api/deliveries/:id - Update delivery status
app.patch("/api/deliveries/:id", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    const deliveryId = parseInt(req.params.id);
    const { status } = req.body;

    if (!['delivered', 'expired'].includes(status)) {
        return res.status(400).json({ error: "Status must be 'delivered' or 'expired'" });
    }

    try {
        const delivery = db.prepare('SELECT * FROM deliveries WHERE id = ? AND tenant_id = ?').get(deliveryId, decoded.tenantId);
        if (!delivery) {
            return res.status(404).json({ error: "Delivery not found" });
        }

        db.prepare('UPDATE deliveries SET status = ? WHERE id = ?').run(status, deliveryId);

        // Remove from active delivery tracking
        const riderId = `rider_${delivery.rider_username}`;
        if (activeDeliveryRiders.has(riderId)) {
            activeDeliveryRiders.get(riderId).delete(deliveryId);
            if (activeDeliveryRiders.get(riderId).size === 0) {
                activeDeliveryRiders.delete(riderId);
            }
        }

        // Notify customer sockets in the delivery room
        io.to(`delivery:${deliveryId}`).emit('delivery-complete', { deliveryId, status });

        // Notify admins to remove marker
        io.to(decoded.tenantName).emit('delivery-finished', { deliveryId });

        res.json({ success: true });
    } catch (error) {
        console.error("Error updating delivery:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Serve static files (admin interface)
app.use(express.static(path.join(__dirname, "public")));

app.get("/admin/db", authenticateJWT, isAdmin, isDeveloper, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "db.html"))
})

// ============ SOCKET.IO EVENTS ============

io.on("connection", (socket) => {
    console.log(`[Socket] New connection: ${socket.id}`);

    // Authenticate socket connection
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    const decoded = verifyToken(token);

    if (!decoded) {
        console.log(`[Socket] Unauthorized connection attempt: ${socket.id}`);
        socket.disconnect(true);
        return;
    }

    // ---- Customer connection ----
    if (decoded.role === 'customer') {
        const { deliveryId, riderId, storeId, storeLat, storeLng, storeName } = decoded;
        console.log(`[Socket] Customer connected for delivery #${deliveryId} (socket: ${socket.id})`);

        // Verify delivery is still active
        const delivery = db.prepare('SELECT * FROM deliveries WHERE id = ? AND status = ?').get(deliveryId, 'active');
        if (!delivery) {
            console.log(`[Socket] Delivery #${deliveryId} not active, disconnecting customer`);
            socket.emit('delivery-complete', { deliveryId, status: 'expired' });
            socket.disconnect(true);
            return;
        }

        // Join delivery-specific room only
        socket.join(`delivery:${deliveryId}`);
        console.log(`[Socket] Customer joined room: delivery:${deliveryId}`);

        // Send store info to customer
        socket.emit('delivery-info', {
            deliveryId,
            riderId,
            storeName,
            storeLat,
            storeLng,
        });

        // Send current rider position if available
        if (activeRiders.has(riderId)) {
            const riderData = activeRiders.get(riderId);
            socket.emit('rider-location', {
                riderId,
                lat: riderData.lat,
                lng: riderData.lng,
                ts: riderData.ts,
            });
        }

        socket.on("disconnect", () => {
            console.log(`[Socket] Customer disconnected from delivery #${deliveryId}`);
        });

        return; // Customer doesn't need any other handlers
    }

    // ---- Admin / Rider connection ----
    const { username, riderId, isAdmin, tenantId, tenantName } = decoded;

    // Fallback to fetching tenant name if token doesn't have it (for backwards compatibility with old tokens)
    let activeTenantName = tenantName;

    const tenant = db.prepare('SELECT name FROM tenants WHERE id = ?').get(tenantId);
    activeTenantName = tenant ? tenant.name : `Tenant_${tenantId}`;

    console.log(`[Socket] Authenticated: ${riderId} (username: ${username}, admin: ${isAdmin}, tenant: ${activeTenantName})`);

    // Fetch storeId for riders
    let storeId = null;
    if (!isAdmin) {
        const user = db.prepare('SELECT store_id FROM users WHERE username = ?').get(username);
        storeId = user ? user.store_id : null;
    }

    // Disconnect previous session for this user if it exists
    if (userSockets.has(username)) {
        console.log(`[Socket] Disconnecting previous session for ${username}`);
        const oldSocket = userSockets.get(username);
        oldSocket.disconnect(true);
    }
    userSockets.set(username, socket);

    // Join tenant room immediately upon connection for isolation
    const tenantRoom = activeTenantName; // Using tenant name instead of ID
    socket.join(tenantRoom);
    if (!isAdmin) {
        console.log(`[Socket] ${username} joined room: ${tenantRoom}`);
    }

    // Common disconnect handler for all roles
    socket.on("disconnect", () => {
        console.log(`[Socket] Disconnected: ${riderId} (${username})`);
        if (userSockets.get(username) === socket) {
            userSockets.delete(username);
        }

        if (!isAdmin) {
            activeRiders.delete(riderId);
            io.to(tenantRoom).emit("rider-offline", { riderId });
        }
    });

    if (isAdmin) {
        console.log(`[Socket] Admin ${username} joined room: ${tenantRoom}`);

        // Send initial state to admin (filtered by their tenant)
        const initialState = Array.from(activeRiders.entries())
            .filter(([id, data]) => data.tenantId === tenantId)
            .map(([id, data]) => ({
                riderId: id,
                ...data,
            }));
        socket.emit("initial-state", initialState);
    } else {
        // Rider connection
        socket.riderId = riderId;

        // Load active deliveries for this rider into memory
        const riderDeliveries = db.prepare('SELECT id FROM deliveries WHERE rider_username = ? AND status = ?').all(username, 'active');
        if (riderDeliveries.length > 0) {
            if (!activeDeliveryRiders.has(riderId)) {
                activeDeliveryRiders.set(riderId, new Set());
            }
            riderDeliveries.forEach(d => activeDeliveryRiders.get(riderId).add(d.id));
            console.log(`[Socket] Rider ${riderId} has ${riderDeliveries.length} active deliveries`);
        }

        // Handle location updates
        socket.on("location", (data) => {
            const { lat, lng, ts, storeId: payloadStoreId, tenantName: payloadTenantName } = data;

            // Allow client to override storeId if provided, otherwise use the one fetched from DB
            const activeStoreId = payloadStoreId || storeId;
            const activeTenantName = payloadTenantName || tenantName;

            // Validate coordinates
            if (typeof lat !== "number" || typeof lng !== "number") {
                console.log(`[Socket] Invalid location data from ${riderId}`);
                return;
            }

            if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
                console.log(`[Socket] Out-of-bounds coordinates from ${riderId}`);
                return;
            }

            // Update active riders map
            activeRiders.set(riderId, { lat, lng, ts, storeId: activeStoreId, tenantName: activeTenantName });
            console.log(`[WS-Location] ${riderId} (Tenant: ${activeTenantName}, Store: ${activeStoreId}): ${lat.toFixed(4)}, ${lng.toFixed(4)}`);

            // Broadcast to tenant-specific room
            io.to(tenantRoom).emit("rider-update", {
                riderId,
                lat,
                lng,
                ts,
                storeId: activeStoreId,
                tenantName: activeTenantName,
            });

            // Broadcast to delivery-specific rooms for customer tracking
            if (activeDeliveryRiders.has(riderId)) {
                activeDeliveryRiders.get(riderId).forEach(deliveryId => {
                    io.to(`delivery:${deliveryId}`).emit('rider-location', {
                        riderId,
                        lat,
                        lng,
                        ts,
                    });
                });
            }
        });

        // Handle shift end
        socket.on("end-shift", () => {
            console.log(`[Shift] ${riderId} ended shift`);
            activeRiders.delete(riderId);
            io.to(tenantRoom).emit("rider-offline", { riderId });
        });
    }
});

// ============ SERVER START ============

const PORT = process.env.PORT || 3000;

if (require.main === module) {
    server.listen(PORT, () => {
        console.log(`[Server] RiderTracker Backend listening on port ${PORT}`);
        console.log(`[Server] Environment: ${process.env.NODE_ENV}`);
        console.log(`[Server] Ready for connections...`);
    });

    // Graceful shutdown
    process.on("SIGTERM", () => {
        console.log("[Server] SIGTERM received, shutting down gracefully...");
        server.close(() => {
            console.log("[Server] Server closed");
            process.exit(0);
        });
    });
}

module.exports = { app, server, io, db };
