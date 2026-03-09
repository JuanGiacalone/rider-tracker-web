require("dotenv").config();
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
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

// ============ REST API ENDPOINTS ============

// Login endpoint
app.post("/api/login", (req, res) => {

    console.log("Login request:", req.body);
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password required" });
    }

    const user = db.prepare(`
        SELECT u.*, t.name as tenant_name 
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

    res.json({ token, riderId, username, tenantId: user.tenant_id, tenantName: user.tenant_name, stores });
});

// Health check endpoint
app.get("/api/health", (req, res) => {
    res.json({ status: "ok", activeRiders: activeRiders.size });
});

app.get("/api/stores", (req, res) => {
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
app.post("/api/stores", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }

    const { tenantId, name, lat, lng } = req.body;

    if (!name) {
        return res.status(400).json({ error: "Store name is required" });
    }

    try {
        const result = db.prepare(
            'INSERT INTO stores (tenant_id, name, lat, lng) VALUES (?, ?, ?, ?)'
        ).run(tenantId, name, lat || null, lng || null);

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
app.post("/api/location", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) {
        return res.status(401).json({ error: "Invalid token" });
    }

    const { riderId, tenantId, tenantName } = decoded;
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

// POST /api/riders - Add a new rider
app.post("/api/riders", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing authorization header" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.isAdmin) {
        return res.status(403).json({ error: "Unauthorized: Admin access required" });
    }
    const { username, password, storeId, isAdmin, tenantId } = req.body;

    if (!username || !password || !storeId) {
        return res.status(400).json({ error: "Username, password and storeId are required" });
    }
    try {
        const result = db.prepare(
            'INSERT INTO users (tenant_id, username, password, is_admin, store_id) VALUES (?, ?, ?, ?, ?)'
        ).run(tenantId, username, password, isAdmin ? 1 : 0, storeId);

        res.status(201).json({ success: true, userId: result.lastInsertRowid });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: "Username already exists" });
        }
        console.error("Error creating rider:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Serve static files (admin interface)
app.use(express.static(path.join(__dirname, "public")));

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
