--liquibase formatted sql
--changeset TiagoBem:202507181600000

CREATE TABLE refresh_token (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id BIGINT NOT NULL,
    CONSTRAINT fk_refresh_token_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);