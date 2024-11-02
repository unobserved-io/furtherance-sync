CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    encryption_salt BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    encrypted_data TEXT NOT NULL,
    nonce TEXT NOT NULL,
    uuid UUID DEFAULT gen_random_uuid(),
    last_updated BIGINT,
    user_id INTEGER REFERENCES users(id),
    UNIQUE(user_id, uuid),
    PRIMARY KEY (user_id, uuid)
);

CREATE TABLE IF NOT EXISTS shortcuts (
    encrypted_data TEXT NOT NULL,
    nonce TEXT NOT NULL,
    uuid UUID DEFAULT gen_random_uuid(),
    last_updated BIGINT,
    user_id INTEGER REFERENCES users(id),
    UNIQUE(user_id, uuid),
    PRIMARY KEY (user_id, uuid)
);
