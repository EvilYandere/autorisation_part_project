CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id SERIAL PRIMARY KEY,
                                              user_id VARCHAR(255) NOT NULL,
                                              token_hash VARCHAR(255) NOT NULL
);