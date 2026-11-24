# 2. IDOR on notes (A01 Broken Access Control)

IDOR = Insecure Direct Object Reference: the client names an object (here a note id) and the server
hands it over without checking whether the caller may see it.

## Why it matters
`GET /api/notes/4` returned admin's "prod creds" note to anyone, logged in or not. Ids are sequential,
so an attacker simply counts upwards and dumps every note.

## Root cause
The endpoint asked only "does this note exist?", never "who is asking?" and "is it theirs?".
Authentication and authorization were both missing.

## Fix
`NoteApiController` now:
1. requires a valid JWT (401 otherwise), and
2. puts the ownership check *in the query*: `WHERE n.id = ? AND u.username = ?`, with the username taken
   from the verified token, never from the request.

Someone else's note gives **404, not 403**, so the attacker can't even learn which ids exist.
The HTML page got the same treatment: `/notes` requires a login and lists only the user's own notes, the
note owner comes from the server-side session, and forms carry a CSRF token (Cross-Site Request Forgery:
another site making the victim's browser submit a form) so other sites can't post through the session.
The H2 database console, which gave direct access to all data, is disabled.

## Why this is the right fix
Filtering in the query means there is no code path that loads a note and *then* forgets to check the owner.

## Verified by
`noTokenIsRejected`, `otherUsersNoteIsNotFound`, `ownNoteIsReadable`, `notesPageRequiresLogin`,
`h2ConsoleIsDisabled`, `postWithoutCsrfTokenIsForbidden`.
