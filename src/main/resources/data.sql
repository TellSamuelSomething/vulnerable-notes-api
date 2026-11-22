-- WARNING: INTENTIONALLY VULNERABLE SECURITY-TRAINING PROJECT. DO NOT DEPLOY.
-- VULN (A02:2021 Cryptographic Failures): cleartext passwords
INSERT INTO users (id, username, password, role) VALUES (1, 'alice', 'alicepass',   'USER');
INSERT INTO users (id, username, password, role) VALUES (2, 'bob',   'bobpass',     'USER');
INSERT INTO users (id, username, password, role) VALUES (3, 'admin', 'sup3rs3cr3t', 'ADMIN');

INSERT INTO notes (id, owner_id, title, content) VALUES (1, 1, 'Alice private diary', 'Do not tell bob about the surprise party.');
INSERT INTO notes (id, owner_id, title, content) VALUES (2, 1, 'Alice bank PIN',      'My PIN is 4821.');
INSERT INTO notes (id, owner_id, title, content) VALUES (3, 2, 'Bob shopping list',   'Milk, eggs, a better password.');
INSERT INTO notes (id, owner_id, title, content) VALUES (4, 3, 'Admin: prod creds',   'Root DB password: hunter2 (rotate soon!)');

ALTER TABLE users ALTER COLUMN id RESTART WITH 100;
ALTER TABLE notes ALTER COLUMN id RESTART WITH 100;
