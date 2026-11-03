# Web Security Lab (IT-30001 Assignment)

An **intentionally vulnerable** app and a **hardened twin**, built from the same code (`server.js`).
For local, authorised coursework testing only. Never deploy the vulnerable instance on a public network.

| Instance   | URL                     | Purpose                                   |
|------------|-------------------------|-------------------------------------------|
| Vulnerable | http://localhost:3000   | flaws present                             |
| Secure     | http://localhost:3001   | same features, one mitigation per flaw    |
| Attacker   | http://localhost:4000   | CSRF demo page (`/` and `/secure`)        |

## Run
```bash
npm install
npm start
```
Seed users: `admin / admin123`, `alice / alice123`, `bob / bob123`.
Use `localhost` (not `127.0.0.1`) in the browser so the CSRF demo is same-site.

## Variants implemented
| Category | Variant | Where |
|---|---|---|
| SQL injection | V1 Authentication bypass | `POST /login` |
| SQL injection | V2 UNION-based extraction | `GET /products?q=` |
| OS command injection | V1 In-band | `GET /ping?host=` |
| XSS | V1 Stored | `/guestbook` |
| CSRF | V1 GET-based | `GET /account/email?email=` |

## Exploits (run on :3000), then repeat the SAME payload on :3001

**SQLi V1** - username: `admin'--` (any password) -> logged in as admin.
Also `' OR 1=1--`.
*Root cause:* input concatenated into `WHERE username='...'`; `'` closes the string, `--` comments out the password check.
*Fix:* parameterised query (`?` placeholders). Input is bound as data after the SQL is parsed.

**SQLi V2** - search: `zzz' UNION SELECT id,username,password FROM users--`
Column count (3) and compatible types are required; find the count with `' ORDER BY 3--` (4 errors).
*Fix:* parameterised `LIKE ?` + generic error message (no SQL error leakage).

**Command injection** - host:
- Windows: `127.0.0.1 & whoami`
- Linux/macOS: `127.0.0.1; whoami`

*Root cause:* string passed to `exec()`, which spawns a shell; `& ; |` are shell metacharacters.
*Fix:* allow-list regex `^(?!-)[a-zA-Z0-9.-]{1,253}$` + `execFile('ping',[flag,'1',host])` (no shell, argument vector).

**Stored XSS** - post comment: `<img src=x onerror="alert(document.cookie)">`
Every visitor's browser runs it. On :3000 the alert shows the session cookie.
*Root cause:* stored comment written into HTML unencoded.
*Fix:* HTML output encoding (`esc()`); also CSP blocks inline handlers and the cookie is `HttpOnly`.

**CSRF (GET)** - log in on :3000 as alice, then open http://localhost:4000 in the same browser.
The hidden `<img>` fires `GET /account/email?email=hacked@evil.com` with your cookie; check `/account`.
*Root cause:* state-changing GET with no proof of intent.
*Fix:* POST only + synchronizer token (`csrf` hidden field checked against the session) + `SameSite=Strict`.
Demonstrate the block: log in on :3001, open http://localhost:4000/secure -> forged GET gets 405, forged POST gets 403.

> Note: `localhost:3000` and `localhost:4000` are *same-site* (ports don't matter for "site"), so SameSite alone would not stop
> this local demo; the token is what blocks it. Cookies are named per mode (`sid_vulnerable` / `sid_secure`) so the two
> instances don't overwrite each other's cookie.

## Theory of other mitigations (Table 2e): write in your own words
Use the slide list: SQLi (allow-list validation, least-privilege DB account, safe errors); CMDi (avoid shell, least privilege);
XSS (framework auto-escaping, sanitiser, CSP, HttpOnly, safe DOM sinks); CSRF (SameSite, re-authentication, avoid GET changes).

## Ownership declaration (Table 3)
| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
|  |  | SQL injection | V1 / V2 |
|  |  | OS command injection | V1 |
|  |  | XSS | V1 (Stored) |
|  |  | CSRF | V1 (GET) |

## Hosting note
Run both instances locally for the video and viva. If you must host online, host only the **secure** instance publicly.
`/ping` on the vulnerable instance gives anyone remote code execution on the host.
