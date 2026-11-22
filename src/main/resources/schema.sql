-- WARNING: INTENTIONALLY VULNERABLE SECURITY-TRAINING PROJECT. DO NOT DEPLOY.
CREATE TABLE users (
    id       BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50)  NOT NULL UNIQUE,
    -- VULN (A02:2021 Cryptographic Failures): passwords stored in plaintext, no hashing
    password VARCHAR(100) NOT NULL,
    role     VARCHAR(20)  NOT NULL
);

CREATE TABLE notes (
    id       BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner_id BIGINT        NOT NULL,
    title    VARCHAR(200)  NOT NULL,
    content  VARCHAR(4000) NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);
