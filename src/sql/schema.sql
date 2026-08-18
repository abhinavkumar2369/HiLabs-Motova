-- Run this file against your PostgreSQL database to create the required table.
-- Example: psql -U postgres -d express_demo -f src/sql/schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    reset_otp_code VARCHAR(6),
    reset_otp_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Run this if the `users` table already exists from an earlier version:
-- ALTER TABLE users DROP COLUMN IF EXISTS is_verified;
-- ALTER TABLE users DROP COLUMN IF EXISTS otp_code;
-- ALTER TABLE users DROP COLUMN IF EXISTS otp_expires_at;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_otp_code VARCHAR(6);
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_otp_expires_at TIMESTAMPTZ;