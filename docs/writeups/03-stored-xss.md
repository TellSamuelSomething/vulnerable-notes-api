# 3. Stored XSS (A03 Injection)

XSS = Cross-Site Scripting: attacker-controlled HTML/JavaScript runs in another user's browser.

## Why it matters
A note titled `<img src=x onerror=alert(1)>` is saved, and the script runs for **every** visitor of
`/notes`. Real payloads steal session data, act as the victim, or rewrite the page (phishing).

## Root cause
`notes.html` rendered notes with `th:utext` (unescaped text), so stored data was interpreted as markup.
The bug is at *output*, not input: the data is harmless until it is placed in HTML unescaped.

## Fix
Two layers:
1. **Output encoding**: `th:text` HTML-escapes the value (`<` becomes `&lt;`), so the payload is shown as text.
2. **Content-Security-Policy header** (`ContentSecurityPolicyFilter`): `script-src 'self'` tells the
   browser to refuse inline scripts and event handlers, so even a missed escape elsewhere can't execute.
   The page's CSS was moved to a file so the policy can forbid all inline code.

## Why this is the right fix
Escaping on output is correct for the context where the data is used; input filtering can't know every
future context. CSP is defence in depth: it limits the damage of the next mistake.

## Verified by
`payloadIsEscapedOnOutput`, `cspHeaderBlocksInlineScripts`.
