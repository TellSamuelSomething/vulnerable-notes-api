# 4. Weak JWT (A02 Cryptographic Failures, A07 Identification and Authentication Failures)

JWT = JSON Web Token: a signed token that says who the user is. The server trusts it only because of the signature.

## Why it matters
1. The HMAC (keyed hash) signing secret was hard-coded in `JwtUtil` and committed to Git. Anyone who reads
   the repo can sign a token saying `"sub":"admin","role":"ADMIN"` and the server accepts it.
2. Tokens had no `exp` (expiry) claim, so a stolen token worked forever.

## Root cause
A secret was treated as configuration in source code, and token lifetime was never designed.
Git history keeps the secret even after it is deleted from the file.

## Fix
- The secret comes from the `JWT_SECRET` environment variable, with **no default**: the app refuses to start
  without it, and refuses secrets shorter than 32 bytes (256 bits, the minimum for HS256).
- Tokens expire after 15 minutes (`app.jwt.ttl`), and parsing rejects expired or wrongly signed tokens.

## Why this is the right fix
Failing to start is safer than silently running with a weak or known key. Short-lived tokens limit how long
a leaked token is useful. Because the old secret is public in `main`'s history, it must never be reused.

## Verified by
`tokenSignedWithLeakedMainSecretIsRejected`, `tokensHaveAnExpiry`, `expiredTokenIsRejected`,
`shortSecretRefusesToStart`.
