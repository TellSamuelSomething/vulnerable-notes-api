# 5. Plaintext passwords (A02 Cryptographic Failures)

## Why it matters
Any read access to the database (SQL injection, a backup, the H2 console, a log) reveals every password
directly. Users reuse passwords, so the damage spreads to their other accounts.

## Root cause
Passwords were stored and compared as plain strings, so the login check needed the password itself.

## Fix
Passwords are stored as BCrypt hashes (`spring-security-crypto`) and checked with
`BCryptPasswordEncoder.matches`. BCrypt is a one-way, salted and deliberately slow hash: the server can
check a password without being able to recover it, identical passwords get different hashes (salt), and
brute-forcing a leaked hash is expensive (cost factor 10).

## Why this is the right fix
Encryption would be the wrong tool: anything encrypted can be decrypted by whoever steals the key.
A fast hash such as SHA-256 is also wrong, since attackers can try billions of guesses per second.

## Verified by
`storedPasswordsAreBcryptHashes`, plus `correctCredentialsStillWork` (hashing didn't break login).
