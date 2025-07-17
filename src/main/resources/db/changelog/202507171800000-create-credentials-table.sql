--liquibase changeset TiagoBem:202507171800000
--comment: Create credentials table

CREATE TABLE credentials (
    id BIGINT PRIMARY KEY,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    user_id BIGINT NOT NULL,
    aaguid VARCHAR(255),
    signature_count BIGINT NOT NULL,
    registration_time TIMESTAMP NOT NULL,
    last_used_time TIMESTAMP NOT NULL,
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    created_by VARCHAR(255) DEFAULT 'system' NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW() NOT NULL,
    updated_by VARCHAR(255) DEFAULT 'system' NOT NULL,
    CONSTRAINT fk_credentials_user_id FOREIGN KEY (user_id) REFERENCES users (id)
);