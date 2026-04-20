-- ============================================
-- VoucherVault D1 Database Schema
-- ============================================
-- Run this to initialize your D1 database:
-- wrangler d1 execute voucher-vault-db --file=./schema.sql

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vouchers table
CREATE TABLE IF NOT EXISTS vouchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    retailer TEXT NOT NULL,
    value REAL NOT NULL,
    code TEXT,
    expiry DATE,
    notes TEXT,
    image_url TEXT,
    status TEXT DEFAULT 'unspent' CHECK (status IN ('unspent', 'spent')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    spent_at DATETIME,
    spent_by INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (spent_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_vouchers_user_id ON vouchers(user_id);
CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status);
CREATE INDEX IF NOT EXISTS idx_vouchers_spent_at ON vouchers(spent_at);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
