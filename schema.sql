CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    encryption_key_hash VARCHAR(255),
    encryption_key_version INTEGER NOT NULL DEFAULT 0,
    organization_id INTEGER REFERENCES organizations(id),
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_invites (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    role_id INTEGER REFERENCES organization_roles(id),
    invited_by INTEGER REFERENCES users(id),
    invite_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id INTEGER REFERENCES organizations(id),
    user_id INTEGER REFERENCES users(id),
    role_id INTEGER REFERENCES organization_roles(id),
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (organization_id, user_id)
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

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    new_email VARCHAR(255) NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
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
    user_id INTEGER REFERENCES users(id),
    known_by_devices TEXT[] DEFAULT '{}',
    UNIQUE(user_id, uid),
    PRIMARY KEY (user_id, uid)
);
