-- `secure` branch: fixed version of the training app.
-- FIXED (A02:2021 Cryptographic Failures): passwords stored as BCrypt hashes, never in cleartext.
-- (Seed logins are unchanged: alice/alicepass, bob/bobpass, admin/sup3rs3cr3t.)
INSERT INTO users (id, username, password, role) VALUES (1, 'alice', '$2a$10$ed.6LzgOToFjAMpyMOUZUux9WZxWMqU/oqH8CI83309vVGQE1QcYC', 'USER');
INSERT INTO users (id, username, password, role) VALUES (2, 'bob',   '$2a$10$GVz0U6J0zU3zQpUApcD.dO2JT04LlMV4Vx0kCKY8yfy8RV321M6I2', 'USER');
INSERT INTO users (id, username, password, role) VALUES (3, 'admin', '$2a$10$2VjLbyNUVW70OYWNSb9dHOFXv0IiLskqVY1VnvuouGz.PzcXFUHD2', 'ADMIN');

INSERT INTO notes (id, owner_id, title, content) VALUES (1, 1, 'Alice private diary', 'Do not tell bob about the surprise party.');
INSERT INTO notes (id, owner_id, title, content) VALUES (2, 1, 'Alice bank PIN',      'My PIN is 4821.');
INSERT INTO notes (id, owner_id, title, content) VALUES (3, 2, 'Bob shopping list',   'Milk, eggs, a better password.');
INSERT INTO notes (id, owner_id, title, content) VALUES (4, 3, 'Admin: prod creds',   'Root DB password: hunter2 (rotate soon!)');

ALTER TABLE users ALTER COLUMN id RESTART WITH 100;
ALTER TABLE notes ALTER COLUMN id RESTART WITH 100;
