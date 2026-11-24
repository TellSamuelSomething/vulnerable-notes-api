# Writeups

One writeup per flaw: why it is dangerous, why it happened, and why the fix on the `secure` branch works.
The exploit commands are in the [main README](../../README.md#exploits); every exploit is replayed as an
automated test in [`SecurityRegressionTest`](../../src/test/java/com/example/vulnnotes/SecurityRegressionTest.java),
so the build fails if a flaw comes back.

| # | Flaw | OWASP Top 10 (2021) |
|---|------|---------------------|
| 1 | [SQL injection in login](01-sql-injection.md) | A03 Injection |
| 2 | [IDOR on notes](02-idor.md) | A01 Broken Access Control |
| 3 | [Stored XSS](03-stored-xss.md) | A03 Injection |
| 4 | [Weak JWT](04-weak-jwt.md) | A02 Cryptographic Failures, A07 Identification and Authentication Failures |
| 5 | [Plaintext passwords](05-plaintext-passwords.md) | A02 Cryptographic Failures |
