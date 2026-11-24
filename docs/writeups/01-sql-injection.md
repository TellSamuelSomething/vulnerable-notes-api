# 1. SQL injection in login (A03 Injection)

## Why it matters
An attacker logs in as any user, including admin, without a password, and can read any table
(combined with #5 this leaks every password). The database trusts whatever SQL reaches it.

## Root cause
On `main` the login query is built by string concatenation:

```java
"SELECT ... FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

User input becomes part of the SQL *code*. `admin'--` closes the string and comments out the password check;
`' OR '1'='1` makes the condition always true; `' UNION SELECT ...` appends a query of the attacker's choice.

## Fix
`UserService.authenticate` uses a parameterized query (`WHERE username = ?`). The SQL text is fixed at
compile time and the driver sends the input separately as *data*, so no input can change the query's structure.
The password is no longer in the query at all; it is checked in Java against a BCrypt hash (see #5).

## Why this is the right fix
Escaping or blocklisting characters is fragile (encodings, new syntax). Parameterization removes the
whole class of bug instead of filtering known payloads.

## Verified by
`commentOutPasswordCheckIsRejected`, `tautologyIsRejected`, `unionSelectDoesNotLeakPasswords`,
`correctCredentialsStillWork`.
