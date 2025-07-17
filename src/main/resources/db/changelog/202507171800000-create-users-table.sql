--liquibase changeset TiagoBem:202507171800000
--comment: Create users table

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    created_by VARCHAR(255) DEFAULT 'system' NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW() NOT NULL,
    updated_by VARCHAR(255) DEFAULT 'system' NOT NULL
);