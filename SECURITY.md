# Security

SIGNAL is a security tool, so it must not become the easy target. This page says what it
protects, from whom, and how.

## Threat model

- **Attackers control the data.** Every log line, hostname, command line, URL and user
  agent SIGNAL ingests may be written by an adversary. The main risks are stored XSS
  through a log line, injection through the search language, and a malicious file
  masquerading as a log.
- **Attackers may reach the web interface** (a compromised workstation on the same
  network). Risks: credential guessing, session theft, CSRF, privilege escalation from
  analyst to admin.
- **Out of scope for v1:** a malicious admin, a compromised host running SIGNAL,
  multi-tenant isolation, and denial of service by a determined attacker with valid
  credentials. SIGNAL is meant to run inside your network, behind HTTPS.

## Mitigations

**Authentication and sessions**
- Local accounts; passwords hashed with **Argon2id**; 12-character minimum; the first
  admin comes from environment variables, and there are **no default credentials**.
- Sessions are random 256-bit tokens in `HttpOnly`, `SameSite=Lax` (and `Secure`)
  cookies. Only a SHA-256 hash is stored, so a leaked database cannot be replayed.
  Logout, role change, deactivation and password change revoke sessions immediately.
- **CSRF:** every state-changing request needs a per-session token in `X-CSRF-Token`
  (constant-time compare); the token is never stored in a readable cookie.
- Logins are rate-limited; unknown-user and wrong-password take the same time and give
  the same message.

**Authorisation**
- `admin` and `analyst` roles are enforced **on the server** for every route (users,
  rules, ingest tokens, settings, audit log). Hiding a button is cosmetic only. The last
  active admin cannot be demoted or disabled.

**Untrusted input**
- All inputs are validated with Pydantic (unknown fields are rejected, lengths bounded).
- The hunt query language is parsed into an AST and compiled with SQLAlchemy using
  allow-listed columns and bound parameters. Nothing a user types is concatenated into
  SQL; `%`, `_` and `\` in values are escaped. Tests throw injection strings at it.
- **Uploads:** size-limited while streaming (never fully in memory), file type decided
  by **content**, not extension (zips, executables, PDFs and binaries are rejected),
  the stored filename is random, and the user-supplied name is display-only.
- XML (EVTX) is parsed with `defusedxml`; entity-expansion payloads are refused. No
  `eval`, no shell calls, no deserialising untrusted pickles.
- **Log injection / XSS:** raw log data is rendered only as React text nodes. There is no
  `dangerouslySetInnerHTML` anywhere (enforced by an ESLint rule), analyst notes render
  Markdown with raw HTML and images disabled, and the printable report HTML-escapes
  everything and carries a CSP with no scripts.

**Transport and browser hardening**
- Strict CSP (`default-src 'self'`, no inline script or style), `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP.
- CORS is locked to the front-end origin. The WebSocket checks the session **and** the
  `Origin` header (cross-site WebSocket hijacking).
- Request bodies are size-limited; errors use one format and never include stack traces.

**Secrets and auditability**
- Configuration is environment-only; `.env` is git-ignored; nothing sensitive is in the
  repo or the front-end bundle. Ingest tokens (for `signal-tail`) are shown once, stored
  hashed, scoped to posting events, and revocable.
- An append-only **audit log** records logins (and failures), user and rule changes,
  settings, token issue/revoke, every triage action, notes and report exports.
- Docker runs the API as a non-root user with a read-only filesystem and
  `no-new-privileges`.

## Known limits

- Run it behind HTTPS (set `SIGNAL_COOKIE_SECURE=true`, the default). The dev setup runs
  over plain HTTP on localhost and says so on startup.
- No MFA, SSO or password-reset flow in v1; an admin resets passwords.
- The dependency set was audited (`npm audit`: 0 issues) when this was written; run
  `uv lock --upgrade` / `npm audit` regularly.
- The Docker setup has not been exercised end to end by the author yet.

## Reporting a problem

Open a private security advisory on the repository, or contact the maintainer directly.
