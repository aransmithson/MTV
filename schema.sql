-- ============================================
-- VoucherVault D1 Database Schema
-- ============================================
-- Initialise your D1 database:
--   wrangler d1 execute voucher-vault-db --file=./schema.sql
--
-- After deploying the worker, visit /api/auth/setup (GET) to check if
-- first-time setup is needed, then POST to /api/auth/setup with
-- { "username": "admin", "password": "yourpassword" } to create the
-- admin account. That endpoint is permanently disabled once any user exists.

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,   -- 1 = admin, 0 = standard user
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vouchers table
-- NOTE: image_url stores the R2 object key (e.g. vouchers/1234-abc.jpg),
-- NOT a public URL. Images are served via /api/image/:key (auth required).
CREATE TABLE IF NOT EXISTS vouchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    retailer TEXT NOT NULL,
    value REAL NOT NULL,
    code TEXT,
    expiry DATE,
    notes TEXT,
    image_url TEXT,                        -- R2 object key, not a public URL
    status TEXT DEFAULT 'unspent' CHECK (status IN ('unspent', 'spent')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    spent_at DATETIME,
    spent_by INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (spent_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_vouchers_user_id ON vouchers(user_id);
CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status);
CREATE INDEX IF NOT EXISTS idx_vouchers_spent_at ON vouchers(spent_at);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
