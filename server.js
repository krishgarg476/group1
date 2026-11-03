/**
 * Web Server Security Lab: INTENTIONALLY VULNERABLE demo (coursework use only).
 * One codebase, two modes:
 *   vulnerable -> port 3000  (flaws present)
 *   secure     -> port 3001  (same features, one fix per flaw)
 * Plus an "attacker" site on port 4000 used for the CSRF demo.
 *
 * Covers: SQLi V1 (auth bypass) + V2 (UNION), OS command injection V1 (in-band),
 *         Stored XSS (V1), GET-based CSRF (V1).
 * Binds to 127.0.0.1 only. Do NOT expose the vulnerable instance to a network.
 */
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const { exec, execFile } = require('child_process');

const HOST = process.env.HOST || '127.0.0.1';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function createApp(mode, port) {
  const SECURE = mode === 'secure';
  const COOKIE = `sid_${mode}`; // separate names: cookies are shared across ports on "localhost"
  const db = new Database(':memory:');

  db.exec(`
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT);
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE comments(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
  `);
  const iu = db.prepare('INSERT INTO users(username,password,role,email) VALUES (?,?,?,?)');
  iu.run('admin', sha('admin123'), 'admin', 'admin@example.com');
  iu.run('alice', sha('alice123'), 'user', 'alice@example.com');
  iu.run('bob', sha('bob123'), 'user', 'bob@example.com');
  const ip = db.prepare('INSERT INTO products(name,price) VALUES (?,?)');
  [['Laptop', 55000], ['Mouse', 499], ['Keyboard', 1299], ['Monitor', 11999], ['Headphones', 2499]].forEach((p) => ip.run(...p));

  const sessions = new Map();
  const getSession = (req) => {
    const m = new RegExp(`(?:^|;\\s*)${COOKIE}=([a-f0-9]+)`).exec(req.headers.cookie || '');
    return m ? sessions.get(m[1]) : undefined;
  };

  const page = (title, body, s) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} &bull; ${SECURE ? 'Secure' : 'Vulnerable'} Lab</title>
  <style>
    :root {
      --bg: #0f172a;
      --page-bg: #f8fafc;
      --card-bg: #ffffff;
      --text-main: #1e293b;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --brand: ${SECURE ? '#059669' : '#dc2626'};
      --brand-hover: ${SECURE ? '#047857' : '#b91c1c'};
      --brand-light: ${SECURE ? '#ecfdf5' : '#fef2f2'};
      --brand-border: ${SECURE ? '#a7f3d0' : '#fecaca'};
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--page-bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 1.75rem 1rem 3rem;
    }
    .wrapper {
      max-width: 860px;
      margin: 0 auto;
    }
    .header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.75rem;
      padding: 0.9rem 1.4rem;
      color: #ffffff;
      border-radius: 12px;
      background: ${SECURE ? 'linear-gradient(135deg, #059669, #10b981)' : 'linear-gradient(135deg, #b91c1c, #ef4444)'};
      box-shadow: 0 4px 14px 0 rgba(${SECURE ? '16,185,129' : '239,68,68'}, 0.25);
      margin-bottom: 1.25rem;
    }
    .banner-title {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      font-weight: 700;
      font-size: 1.05rem;
      letter-spacing: -0.01em;
    }
    .banner-pill {
      background: rgba(255, 255, 255, 0.22);
      border: 1px solid rgba(255, 255, 255, 0.35);
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.05em;
    }
    .user-pill {
      font-size: 0.88rem;
      background: rgba(0, 0, 0, 0.18);
      padding: 0.3rem 0.8rem;
      border-radius: 8px;
    }
    nav {
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.4rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
      box-shadow: 0 1px 3px 0 rgba(0,0,0,0.04);
    }
    nav a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      padding: 0.45rem 0.85rem;
      border-radius: 8px;
      transition: all 0.15s ease-in-out;
    }
    nav a:hover {
      background: #f1f5f9;
      color: var(--text-main);
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.8rem;
      box-shadow: 0 2px 8px 0 rgba(0,0,0,0.04);
    }
    h2 {
      font-size: 1.35rem;
      font-weight: 700;
      color: #0f172a;
      margin-bottom: 1.25rem;
      border-bottom: 2px solid #f1f5f9;
      padding-bottom: 0.65rem;
    }
    input[type=text], input[type=password] {
      padding: 0.6rem 0.85rem;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      font-size: 0.925rem;
      color: #1e293b;
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    input[type=text]:focus, input[type=password]:focus {
      border-color: var(--brand);
      box-shadow: 0 0 0 3px ${SECURE ? 'rgba(16,185,129,0.18)' : 'rgba(239,68,68,0.18)'};
    }
    button {
      background: var(--brand);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      padding: 0.6rem 1.2rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.15s, transform 0.05s;
    }
    button:hover {
      background: var(--brand-hover);
    }
    button:active {
      transform: scale(0.98);
    }
    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-top: 1rem;
    }
    th {
      background: #f8fafc;
      font-weight: 600;
      font-size: 0.825rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }
    td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.925rem;
    }
    tr:last-child td {
      border-bottom: none;
    }
    tr:hover td {
      background: #f8fafc;
    }
    pre {
      background: #0f172a;
      color: #f1f5f9;
      padding: 1rem 1.2rem;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 0.875rem;
      line-height: 1.6;
      overflow-x: auto;
      margin-top: 1rem;
    }
    .badge-tag {
      display: inline-block;
      padding: 0.2rem 0.55rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 6px;
      background: var(--brand-light);
      color: var(--brand);
      border: 1px solid var(--brand-border);
    }
    .comment-item {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      margin-bottom: 0.65rem;
    }
    .comment-author {
      font-weight: 600;
      color: #0f172a;
      margin-right: 0.4rem;
    }
    .msg-box {
      padding: 0.85rem 1.1rem;
      border-radius: 8px;
      margin: 1rem 0;
      font-size: 0.9rem;
    }
    .msg-error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #991b1b;
    }
    .info-card {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem;
    }
  </style>
</head>
<body>
<div class="wrapper">
  <div class="header-banner">
    <div class="banner-title">
      <span>${SECURE ? '🛡️ SECURE INSTANCE' : '⚠️ VULNERABLE INSTANCE'}</span>
      <span class="banner-pill">PORT ${port}</span>
    </div>
    <div class="user-pill">
      ${s ? '👤 Logged in as <b>' + esc(s.username) + '</b>' : '🔒 Not logged in'}
    </div>
  </div>
  <nav>
    <a href="/">Home</a>
    <a href="/login">Login</a>
    <a href="/products">Products (SQLi)</a>
    <a href="/ping">Ping (CMDi)</a>
    <a href="/guestbook">Guestbook (XSS)</a>
    <a href="/account">Account (CSRF)</a>
    <a href="/logout">Logout</a>
  </nav>
  <div class="card">
    <h2>${esc(title)}</h2>
    ${body}
  </div>
</div>
</body>
</html>`;

  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));

  // Secure mode: Content Security Policy (blocks inline script / inline event handlers)
  app.use((req, res, next) => {
    if (SECURE) res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'");
    next();
  });

  app.get('/', (req, res) =>
    res.send(page('Web Security Lab', `
      <div style="display:flex; flex-direction:column; gap:1.25rem;">
        <p style="font-size:1rem; color:#334155;">
          Current mode: <span class="badge-tag">${mode.toUpperCase()}</span>. Choose a vulnerability module from the navigation bar above.
        </p>
        <div class="info-card">
          <h3 style="font-size:0.95rem; font-weight:600; margin-bottom:0.4rem; color:#334155;">🔑 Seed Credentials</h3>
          <p style="margin:0; font-family:monospace; font-size:0.875rem; color:#0f172a;">
            admin / admin123 &bull; alice / alice123 &bull; bob / bob123
          </p>
        </div>
        <div class="info-card">
          <h3 style="font-size:0.95rem; font-weight:600; margin-bottom:0.5rem; color:#334155;">🧪 Implemented Modules</h3>
          <ul style="padding-left:1.25rem; font-size:0.9rem; color:#475569; line-height:1.7;">
            <li><b>Products:</b> SQL Injection (UNION-based extraction)</li>
            <li><b>Login:</b> SQL Injection (Authentication bypass)</li>
            <li><b>Ping:</b> OS Command Injection</li>
            <li><b>Guestbook:</b> Stored Cross-Site Scripting (XSS)</li>
            <li><b>Account:</b> Cross-Site Request Forgery (CSRF)</li>
          </ul>
        </div>
      </div>
    `, getSession(req)))
  );

  // ---------- SQL INJECTION V1: authentication bypass ----------
  app.get('/login', (req, res) =>
    res.send(page('Login', `<form method="POST" action="/login" style="display:flex; flex-direction:column; gap:0.85rem; max-width:380px;">
<div>
  <label style="display:block; font-size:0.85rem; font-weight:600; margin-bottom:0.35rem; color:#475569;">Username</label>
  <input type="text" name="username" placeholder="e.g. admin" style="width:100%;">
</div>
<div>
  <label style="display:block; font-size:0.85rem; font-weight:600; margin-bottom:0.35rem; color:#475569;">Password</label>
  <input type="password" name="password" placeholder="e.g. admin123" style="width:100%;">
</div>
<button style="margin-top:0.4rem;">Login</button>
</form>`, getSession(req)))
  );

  app.post('/login', (req, res) => {
    const { username = '', password = '' } = req.body;
    const hash = sha(password);
    let user, query = '';
    try {
      if (SECURE) {
        // FIX: parameterised query - input is bound as data, never parsed as SQL
        user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, hash);
      } else {
        // VULNERABLE: user input concatenated into the SQL string
        query = `SELECT * FROM users WHERE username='${username}' AND password='${hash}'`;
        user = db.prepare(query).get();
      }
    } catch (e) {
      const detail = SECURE ? '<div class="msg-box msg-error">Login failed.</div>' : `<pre>${esc(e.message)}\n${esc(query)}</pre>`;
      return res.status(500).send(page('Error', detail));
    }
    if (!user) return res.status(401).send(page('Login failed', '<div class="msg-box msg-error">Invalid credentials.</div>'));
    const sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { id: user.id, username: user.username, csrf: crypto.randomBytes(16).toString('hex') });
    // Secure: HttpOnly (JS can't read cookie) + SameSite=Strict
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/` + (SECURE ? '; HttpOnly; SameSite=Strict' : ''));
    res.redirect('/account');
  });

  app.get('/logout', (req, res) => {
    res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; Max-Age=0`);
    res.redirect('/');
  });

  // ---------- SQL INJECTION V2: UNION-based extraction ----------
  app.get('/products', (req, res) => {
    const q = req.query.q || '';
    let rows = [], err = '';
    try {
      rows = SECURE
        ? db.prepare('SELECT id, name, price FROM products WHERE name LIKE ?').all(`%${q}%`) // FIX
        : db.prepare(`SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`).all(); // VULNERABLE
    } catch (e) {
      err = SECURE ? 'Something went wrong.' : e.message; // safe errors in secure mode
    }
    const table = `<table><tr><th style="width:60px;">ID</th><th>Name</th><th style="width:120px;">Price</th></tr>${rows
      .map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>₹${esc(r.price)}</td></tr>`)
      .join('')}</table>`;
    res.send(page('Product search', `
<form style="display:flex; gap:0.5rem; max-width:540px;">
  <input type="text" name="q" value="${esc(q)}" placeholder="Search products (e.g. Laptop)..." style="flex:1;">
  <button>Search</button>
</form>
${err ? `<div class="msg-box msg-error">${esc(err)}</div>` : ''}
${table}`, getSession(req)));
  });

  // ---------- OS COMMAND INJECTION V1: in-band ----------
  app.get('/ping', (req, res) => {
    const host = req.query.host;
    const form = `
<form style="display:flex; gap:0.5rem; max-width:540px;">
  <input type="text" name="host" value="${host ? esc(host) : ''}" placeholder="127.0.0.1" style="flex:1;">
  <button>Ping</button>
</form>`;
    const s = getSession(req);
    if (!host) return res.send(page('Ping tool', form, s));
    const flag = process.platform === 'win32' ? '-n' : '-c';
    const done = (e, out, errOut) =>
      res.send(page('Ping tool', `${form}<pre>${esc(out || '')}${esc(errOut || '')}${e && !out ? esc(e.message) : ''}</pre>`, s));

    if (SECURE) {
      // FIX: allow-list validation + no shell (execFile with an argument vector)
      if (!/^(?!-)[a-zA-Z0-9.-]{1,253}$/.test(host))
        return res.status(400).send(page('Ping tool', `${form}<div class="msg-box msg-error" style="margin-top:1rem;">Invalid host.</div>`, s));
      execFile('ping', [flag, '1', host], { timeout: 8000 }, done);
    } else {
      // VULNERABLE: string handed to a shell, so ; & | etc. start new commands
      exec(`ping ${flag} 1 ${host}`, { timeout: 8000 }, done);
    }
  });

  // ---------- STORED XSS V1 ----------
  app.get('/guestbook', (req, res) => {
    const s = getSession(req);
    const rows = db.prepare('SELECT * FROM comments ORDER BY id DESC').all();
    const list = rows
      .map((c) =>
        SECURE
          ? `<div class="comment-item"><span class="comment-author">${esc(c.author)}:</span><span>${esc(c.body)}</span></div>` // FIX: output encoding
          : `<div class="comment-item"><span class="comment-author">${c.author}:</span><span>${c.body}</span></div>` // VULNERABLE: raw HTML
      )
      .join('');
    res.send(page('Guestbook', `
<form method="POST" action="/guestbook" style="display:flex; gap:0.5rem; max-width:620px;">
  <input type="text" name="body" placeholder="Leave a public comment..." style="flex:1;">
  <button>Post Comment</button>
</form>
<div style="margin-top:1.5rem;">
  <h3 style="font-size:1.05rem; font-weight:600; margin-bottom:0.75rem; color:#334155;">Community Comments</h3>
  ${list || '<p style="color:#94a3b8; font-size:0.9rem;">No comments yet.</p>'}
</div>`, s));
  });

  app.post('/guestbook', (req, res) => {
    const s = getSession(req);
    db.prepare('INSERT INTO comments(author, body) VALUES (?, ?)').run(s ? s.username : 'guest', req.body.body || '');
    res.redirect('/guestbook');
  });

  // ---------- CSRF V1: GET-based forged action ----------
  app.get('/account', (req, res) => {
    const s = getSession(req);
    if (!s) return res.redirect('/login');
    const u = db.prepare('SELECT username, email FROM users WHERE id = ?').get(s.id);
    const form = SECURE
      ? `<form method="POST" action="/account/email" style="display:flex; gap:0.5rem; max-width:500px; margin-top:0.75rem;">
<input type="hidden" name="csrf" value="${s.csrf}">
<input type="text" name="email" placeholder="new email address" style="flex:1;">
<button>Change email</button></form>`
      : `<form method="GET" action="/account/email" style="display:flex; gap:0.5rem; max-width:500px; margin-top:0.75rem;">
<input type="text" name="email" placeholder="new email address" style="flex:1;">
<button>Change email</button></form>`;
    res.send(page('My account', `
<div class="info-card" style="max-width:500px; margin-bottom:1.25rem;">
  <p style="margin-bottom:0.4rem; font-size:0.95rem;">Username: <b>${esc(u.username)}</b></p>
  <p style="margin:0; font-size:0.95rem;">Current Email: <b style="color:var(--brand);">${esc(u.email)}</b></p>
</div>
<h3 style="font-size:0.95rem; font-weight:600; margin-bottom:0.35rem; color:#475569;">Update Email Address</h3>
${form}`, s));
  });

  if (SECURE) {
    // FIX: state change only via POST + synchronizer token (+ SameSite=Strict cookie)
    app.get('/account/email', (req, res) => res.status(405).send(page('Blocked', '<div class="msg-box msg-error">405 - GET not allowed for this action.</div>')));
    app.post('/account/email', (req, res) => {
      const s = getSession(req);
      if (!s) return res.redirect('/login');
      if (!req.body.csrf || req.body.csrf !== s.csrf)
        return res.status(403).send(page('Blocked', '<div class="msg-box msg-error">403 - missing/invalid CSRF token.</div>'));
      db.prepare('UPDATE users SET email = ? WHERE id = ?').run(req.body.email || '', s.id);
      res.redirect('/account');
    });
  } else {
    // VULNERABLE: state-changing GET, no proof of user intent
    app.get('/account/email', (req, res) => {
      const s = getSession(req);
      if (!s) return res.redirect('/login');
      db.prepare('UPDATE users SET email = ? WHERE id = ?').run(req.query.email || '', s.id);
      res.redirect('/account');
    });
  }

  app.listen(port, HOST, () => console.log(`[${mode}] http://localhost:${port}`));
}

// ---------- Attacker site (CSRF demo) ----------
function createAttacker(port) {
  const a = express();
  const attackerStyle = `
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fffbeb; padding: 2rem; color: #78350f; text-align: center; }
    .prize-box { background: #ffffff; max-width: 520px; margin: 3rem auto; padding: 2.5rem 2rem; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(245, 158, 11, 0.15); border: 2px dashed #f59e0b; }
    .prize-pill { display: inline-block; padding: 0.3rem 0.8rem; background: #fee2e2; color: #991b1b; border-radius: 9999px; font-size: 0.825rem; font-weight: 600; margin-bottom: 1.25rem; }
    h2 { font-size: 1.85rem; color: #b45309; margin-bottom: 0.6rem; font-weight: 800; }
    p { margin-bottom: 0.85rem; color: #92400e; font-size: 1rem; }
    .note { font-size: 0.825rem; color: #b45309; opacity: 0.85; margin-top: 1rem; }
  `;

  a.get('/', (req, res) =>
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Prize Winner!</title><style>${attackerStyle}</style></head><body>
<div class="prize-box">
  <span class="prize-pill">Attacker Site (Port ${port})</span>
  <h2>🎉 Congratulations! You Won!</h2>
  <p>Claim your <b>\$1,000 Shopping Voucher</b> today!</p>
  <p class="note">(This page invisibly triggers <code>GET /account/email?email=hacked@evil.com</code> on the VULNERABLE app at :3000)</p>
  <img src="http://localhost:3000/account/email?email=hacked@evil.com" width="1" height="1">
</div></body></html>`)
  );
  a.get('/secure', (req, res) =>
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Prize Winner!</title><style>${attackerStyle}</style></head><body>
<div class="prize-box">
  <span class="prize-pill">Attacker Site (Port ${port})</span>
  <h2>🎉 Congratulations! You Won!</h2>
  <p>Claim your <b>\$1,000 Shopping Voucher</b> today!</p>
  <p class="note">(This page fires forged GET & POST requests against the SECURE app at :3001)</p>
  <img src="http://localhost:3001/account/email?email=hacked@evil.com" width="1" height="1">
  <form id="f" method="POST" action="http://localhost:3001/account/email">
    <input type="hidden" name="email" value="hacked@evil.com">
  </form>
  <script>document.getElementById('f').submit()</script>
</div></body></html>`)
  );
  a.listen(port, HOST, () => console.log(`[attacker] http://localhost:${port}  (and /secure)`));
}

createApp('vulnerable', 3000);
createApp('secure', 3001);
createAttacker(4000);
