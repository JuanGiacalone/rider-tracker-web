const Database = require('better-sqlite3');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

function initDb() {
    // Create tenants table
    db.prepare(`
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            active BOOLEAN DEFAULT 1,
            last_payment_date DATE,
            endpoint TEXT,
        )
    `).run();

    // Create stores table
    db.prepare(`
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            active BOOLEAN DEFAULT 1,
            lat REAL,
            lng REAL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )
    `).run();

    // Migration: Add lat/lng to stores if they don't exist
    const tableInfo = db.prepare("PRAGMA table_info(stores)").all();
    const hasLat = tableInfo.some(col => col.name === 'lat');
    if (!hasLat) {
        console.log('[DB] Migrating stores table to include coordinates...');
        db.prepare("ALTER TABLE stores ADD COLUMN lat REAL").run();
        db.prepare("ALTER TABLE stores ADD COLUMN lng REAL").run();

        // Update default stores with coordinates near center
        db.prepare("UPDATE stores SET lat = ?, lng = ? WHERE name = ?").run(-38.0055, -57.5426, 'Master');
        db.prepare("UPDATE stores SET lat = ?, lng = ? WHERE name = ?").run(-37.9850, -57.5600, 'Slave');
    }

    // Migration: Add tenant_id to stores if it doesn't exist
    const hasTenantIdStores = tableInfo.some(col => col.name === 'tenant_id');
    if (!hasTenantIdStores) {
        console.log('[DB] Migrating stores table to include tenant_id...');
        db.prepare("ALTER TABLE stores ADD COLUMN tenant_id INTEGER REFERENCES tenants(id)").run();
    }

    // Create users table
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0,
            store_id INTEGER,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    `).run();

    // Migration: Add tenant_id to users if it doesn't exist
    const userTableInfo = db.prepare("PRAGMA table_info(users)").all();
    const hasTenantIdUsers = userTableInfo.some(col => col.name === 'tenant_id');
    if (!hasTenantIdUsers) {
        console.log('[DB] Migrating users table to include tenant_id...');
        db.prepare("ALTER TABLE users ADD COLUMN tenant_id INTEGER REFERENCES tenants(id)").run();
    }

    // Check if seeding is needed
    // Seed default tenant if it doesn't exist
    const tenantCount = db.prepare('SELECT COUNT(*) as count FROM tenants').get();
    let defaultTenantId;
    if (tenantCount.count === 0) {
        console.log('[DB] Seeding default tenant...');
        const result = db.prepare('INSERT INTO tenants (name) VALUES (?)').run('Main');
        defaultTenantId = result.lastInsertRowid;
    } else {
        defaultTenantId = db.prepare('SELECT id FROM tenants ORDER BY id ASC LIMIT 1').get().id;
    }

    // Seed stores if they don't exist
    const storeCount = db.prepare('SELECT COUNT(*) as count FROM stores').get();
    if (storeCount.count === 0) {
        console.log('[DB] Seeding stores...');
        const insertStore = db.prepare('INSERT INTO stores (tenant_id, name, lat, lng) VALUES (?, ?, ?, ?)');
        insertStore.run(defaultTenantId, 'Master', -38.0055, -57.5426);
        insertStore.run(defaultTenantId, 'Slave', -37.9850, -57.5600);
    }

    // Safety check: ensure existing stores have a tenant_id after migration
    if (!hasTenantIdStores || storeCount.count > 0) {
        db.prepare('UPDATE stores SET tenant_id = ? WHERE tenant_id IS NULL').run(defaultTenantId);
    }

    // Seed users if they don't exist
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (userCount.count === 0) {
        console.log('[DB] Seeding users...');
        const insertUser = db.prepare(`
            INSERT INTO users (tenant_id, username, password, is_admin, store_id) 
            VALUES (?, ?, ?, ?, ?)
        `);

        const centralStoreId = db.prepare('SELECT id FROM stores WHERE name = ?').get('Master').id;
        const northBranchId = db.prepare('SELECT id FROM stores WHERE name = ?').get('Slave').id;

        // Admin
        insertUser.run(
            defaultTenantId,
            process.env.ADMIN_USERNAME || 'admin',
            process.env.ADMIN_PASSWORD || 'adminpass',
            1,
            centralStoreId
        );

        // Riders
        // insertUser.run(defaultTenantId, 'rider1', 'password123', 0, centralStoreId);
        // insertUser.run(defaultTenantId, 'rider2@example.com', 'password123', 0, northBranchId);
    }

    // Safety check: ensure existing users have a tenant_id after migration
    if (!hasTenantIdUsers || userCount.count > 0) {
        db.prepare('UPDATE users SET tenant_id = ? WHERE tenant_id IS NULL').run(defaultTenantId);
    }
}

initDb();

module.exports = db;
