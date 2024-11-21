-- CREATE TABLE IF NOT EXISTS users (
--     id SERIAL PRIMARY KEY,
--     email VARCHAR(255) UNIQUE NOT NULL,
--     password_hash VARCHAR(255) NOT NULL,
--     encryption_key_hash VARCHAR(255),
--     encryption_key_version INTEGER NOT NULL DEFAULT 0,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
-- );

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    encryption_key_hash VARCHAR(255),
    encryption_key_version INTEGER NOT NULL DEFAULT 0,
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(50),
    subscription_end_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    refresh_token TEXT NOT NULL UNIQUE,
    device_id_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_id_hash)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS temporary_registrations (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    encrypted_data TEXT NOT NULL,
    nonce TEXT NOT NULL,
    uid TEXT NOT NULL,
    last_updated BIGINT NOT NULL DEFAULT 0,
    is_orphaned BOOL NOT NULL DEFAULT FALSE,
    user_id INTEGER REFERENCES users(id),
    known_by_devices TEXT[] DEFAULT '{}',
    UNIQUE(user_id, uid),
    PRIMARY KEY (user_id, uid)
);

CREATE TABLE IF NOT EXISTS shortcuts (
    encrypted_data TEXT NOT NULL,
    nonce TEXT NOT NULL,
    uid TEXT NOT NULL,
    last_updated BIGINT NOT NULL DEFAULT 0,
    is_orphaned BOOL NOT NULL DEFAULT FALSE,
    known_by_devices TEXT[] DEFAULT '{}',
    user_id INTEGER REFERENCES users(id),
    UNIQUE(user_id, uid),
    PRIMARY KEY (user_id, uid)
);
