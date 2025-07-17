-- liquibase formatted sql
-- changeset TiagoBem:20250717202500000

ALTER TABLE users ADD COLUMN role VARCHAR(255) NOT NULL DEFAULT 'USER';
