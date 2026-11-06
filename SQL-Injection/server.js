// =====================================================================
//  SQL Injection Lab — เว็บที่ "ตั้งใจ" ให้มีช่องโหว่ SQL Injection เพื่อการเรียนรู้
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
//  - ถ้าเป็น Node 24+ จะใช้ฐานข้อมูล SQLite จริง (node:sqlite) → สาธิต UNION ได้
//  - ถ้า node:sqlite ใช้ไม่ได้ จะ fallback ไปใช้ "เอนจินจำลอง" ในหน่วยความจำ
//    ที่ยังสาธิต SQL injection ได้ (login bypass + ดึงข้อมูลทุกแถว + UNION)
// =====================================================================

const http = require('http');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในเน็ตเวิร์กเข้าไม่ได้
const PORT = Number(process.env.PORT) || 4200;

// ---------------------------------------------------------------------
// ข้อมูลตัวอย่างในตาราง users (ปิดเซิร์ฟเวอร์แล้ว / กด /reset แล้วกลับมาเหมือนเดิม)
// password เก็บเป็น plain text เพื่อความง่ายของแล็บ — ของจริงห้ามทำแบบนี้เด็ดขาด
// ---------------------------------------------------------------------
const USER_COLS = ['id', 'username', 'password', 'email', 'role'];
function seedUsers() {
  return [
    { id: 1, username: 'admin',   password: 'S3cr3t_@dm1n!',  email: 'admin@siamsecure.test',   role: 'admin' },
    { id: 2, username: 'somchai', password: 'somchai2024',    email: 'somchai@mail.test',       role: 'user' },
    { id: 3, username: 'nida',    password: 'nida!rak99',      email: 'nida@mail.test',          role: 'user' },
    { id: 4, username: 'guest',   password: 'guest',           email: 'guest@mail.test',         role: 'user' },
    { id: 5, username: 'support', password: 'help-desk-01',    email: 'support@siamsecure.test', role: 'staff' },
  ];
}

// =====================================================================
//  ชั้นฐานข้อมูล: ลองใช้ node:sqlite ก่อน ถ้าไม่ได้ค่อย fallback เป็น mock
//  ทั้งสองเอนจินมี interface เดียวกัน:  all(sql, params)  และ  reset()
// =====================================================================
function initEngine() {
  try {
    const { DatabaseSync } = require('node:sqlite');
    return makeSqliteEngine(DatabaseSync);
  } catch (e) {
    console.log(`\x1b[33m[DB] node:sqlite ใช้ไม่ได้ (${e.message}) → ใช้เอนจินจำลองในหน่วยความจำแทน\x1b[0m`);
    return makeMockEngine();
  }
}

// ----- เอนจินจริง: node:sqlite (Node 24+) -----
function makeSqliteEngine(DatabaseSync) {
  let db;
  function reset() {
    if (db) { try { db.close(); } catch { /* ignore */ } }
    db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)');
    const ins = db.prepare('INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)');
    for (const u of seedUsers()) ins.run(u.id, u.username, u.password, u.email, u.role);
  }
  reset();
  return {
    kind: 'node:sqlite — ฐานข้อมูล SQLite จริง (in-memory)',
    real: true,
    all(sql, params = []) {
      // .prepare(sql).all(...) คือจุดที่ SQL ถูกส่งเข้าเอนจินจริง
      // ฝั่ง vuln: sql ถูกต่อ string มาแล้ว params ว่าง
      // ฝั่ง safe: sql มี ? และส่ง params แยก → ปลอดภัย
      return db.prepare(sql).all(...params);
    },
    reset,
  };
}

// ----- เอนจินจำลอง (fallback): ตีความ SQL เองในหน่วยความจำ -----
// ไม่ได้แกล้งทำผล แต่ "รัน" SQL ที่ถูกต่อ string จริง ๆ จึงยัง inject ได้จริง
function makeMockEngine() {
  let rows = seedUsers();
  return {
    kind: 'เอนจินจำลองในหน่วยความจำ (mock SQL engine)',
    real: false,
    all(sql, params = []) { return runMock(sql, params, rows); },
    reset() { rows = seedUsers(); },
  };
}

// --- tokenizer เล็ก ๆ: แปลง SQL เป็น token และแทรกค่า param เป็น "ลิเทอรัล" ---
function tokenize(sql, params) {
  const toks = [];
  let i = 0, pi = 0;
  const n = sql.length;
  const isIdStart = (c) => /[A-Za-z_]/.test(c);
  const isId = (c) => /[A-Za-z0-9_]/.test(c);
  const KW = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'LIKE', 'UNION', 'ALL', 'AS', 'NULL', 'IS'];
  while (i < n) {
    const c = sql[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    // คอมเมนต์ -- จนจบบรรทัด  (หัวใจของ login bypass แบบ admin' --)
    if (c === '-' && sql[i + 1] === '-') { i += 2; while (i < n && sql[i] !== '\n') i++; continue; }
    if (c === '/' && sql[i + 1] === '*') { i += 2; while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++; i += 2; continue; }
    if (c === "'") {
      i++; let s = '';
      while (i < n) {
        if (sql[i] === "'") { if (sql[i + 1] === "'") { s += "'"; i += 2; continue; } i++; break; }
        s += sql[i++];
      }
      toks.push({ t: 'str', v: s }); continue;
    }
    if (c === '?') { const v = params[pi++]; toks.push({ t: 'str', v: v === undefined ? null : v }); i++; continue; }
    if (/[0-9]/.test(c)) { let s = ''; while (i < n && /[0-9.]/.test(sql[i])) s += sql[i++]; toks.push({ t: 'num', v: Number(s) }); continue; }
    if (isIdStart(c)) {
      let s = ''; while (i < n && isId(sql[i])) s += sql[i++];
      const up = s.toUpperCase();
      toks.push(KW.includes(up) ? { t: up } : { t: 'id', v: s });
      continue;
    }
    const two = sql.substr(i, 2);
    if (two === '<>' || two === '!=' || two === '<=' || two === '>=') { toks.push({ t: two }); i += 2; continue; }
    if ('=<>(),*;.'.includes(c)) { toks.push({ t: c }); i++; continue; }
    throw new Error(`ไวยากรณ์ SQL ไม่ถูกต้องใกล้ตัวอักษร "${c}"`);
  }
  return toks;
}

function runMock(sql, params, rows) {
  const toks = tokenize(sql, params || []);
  let pos = 0;
  const peek = () => toks[pos];
  const expect = (t) => { if (!toks[pos] || toks[pos].t !== t) throw new Error(`SQL ไม่ถูกต้อง: คาดว่าจะเจอ "${t}"`); return toks[pos++]; };
  const accept = (t) => { if (toks[pos] && toks[pos].t === t) { pos++; return true; } return false; };

  function parseSelect() {
    expect('SELECT'); accept('ALL');
    const items = parseSelectList();
    let table = null;
    if (accept('FROM')) table = expect('id').v;
    let where = null;
    if (accept('WHERE')) where = parseExpr();
    return { items, table, where };
  }
  function parseSelectList() {
    const items = [];
    do {
      if (peek() && peek().t === '*') { pos++; items.push({ star: true }); }
      else { const e = parseExpr(); let alias = null; if (accept('AS')) alias = expect('id').v; items.push({ expr: e, alias }); }
    } while (accept(','));
    return items;
  }
  const parseExpr = () => parseOr();
  function parseOr() { let l = parseAnd(); while (peek() && peek().t === 'OR') { pos++; l = { op: 'OR', l, r: parseAnd() }; } return l; }
  function parseAnd() { let l = parseNot(); while (peek() && peek().t === 'AND') { pos++; l = { op: 'AND', l, r: parseNot() }; } return l; }
  function parseNot() { if (accept('NOT')) return { op: 'NOT', e: parseNot() }; return parseCmp(); }
  function parseCmp() {
    const l = parsePrimary();
    const t = peek() && peek().t;
    if (['=', '<>', '!=', '<', '>', '<=', '>=', 'LIKE'].includes(t)) { pos++; return { op: 'cmp', cmp: t, l, r: parsePrimary() }; }
    if (t === 'IS') { pos++; const neg = accept('NOT'); expect('NULL'); return { op: 'isnull', neg, l }; }
    return l;
  }
  function parsePrimary() {
    const tk = peek();
    if (!tk) throw new Error('นิพจน์ SQL ไม่สมบูรณ์');
    if (tk.t === '(') { pos++; const e = parseExpr(); expect(')'); return e; }
    if (tk.t === 'str') { pos++; return { lit: tk.v === null ? null : String(tk.v) }; }
    if (tk.t === 'num') { pos++; return { lit: tk.v }; }
    if (tk.t === 'NULL') { pos++; return { lit: null }; }
    if (tk.t === 'id') { pos++; return { col: tk.v }; }
    throw new Error(`ไม่เข้าใจ SQL token: "${tk.t}"`);
  }

  const eq = (a, b) => (typeof a === 'number' && typeof b === 'number') ? a === b : String(a) === String(b);
  function likeToRe(p) {
    let re = '';
    for (const ch of String(p)) {
      if (ch === '%') re += '[\\s\\S]*';
      else if (ch === '_') re += '.';
      else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp('^' + re + '$', 'i');
  }
  function val(node, row) {
    if ('lit' in node) return node.lit;
    if ('col' in node) {
      if (!row) throw new Error(`อ้างถึงคอลัมน์ "${node.col}" นอกบริบทตาราง`);
      if (!(node.col in row)) throw new Error(`ไม่รู้จักคอลัมน์ "${node.col}"`);
      return row[node.col];
    }
    return evalBool(node, row) ? 1 : 0;
  }
  function evalBool(node, row) {
    switch (node.op) {
      case 'OR': return evalBool(node.l, row) || evalBool(node.r, row);
      case 'AND': return evalBool(node.l, row) && evalBool(node.r, row);
      case 'NOT': return !evalBool(node.e, row);
      case 'isnull': { const v = val(node.l, row); const isn = (v === null || v === undefined); return node.neg ? !isn : isn; }
      case 'cmp': {
        const a = val(node.l, row), b = val(node.r, row);
        switch (node.cmp) {
          case '=': return eq(a, b);
          case '<>': case '!=': return !eq(a, b);
          case 'LIKE': return likeToRe(b).test(String(a));
          case '<': return a < b; case '>': return a > b; case '<=': return a <= b; case '>=': return a >= b;
        }
        return false;
      }
      default: { const v = val(node, row); return !!v && v !== 0; }
    }
  }
  function runOne(sel) {
    const cols = [];
    for (const it of sel.items) {
      if (it.star) USER_COLS.forEach((c) => cols.push(c));
      else cols.push(it.alias || (it.expr.col ? it.expr.col : 'expr'));
    }
    const source = sel.table ? rows : [null]; // ไม่มี FROM → แถวสังเคราะห์ 1 แถว (ใช้กับ UNION SELECT ค่าคงที่)
    const out = [];
    for (const row of source) {
      if (sel.where && !evalBool(sel.where, row)) continue;
      const vals = [];
      for (const it of sel.items) {
        if (it.star) USER_COLS.forEach((c) => vals.push(row ? row[c] : null));
        else vals.push(val(it.expr, row));
      }
      out.push(vals);
    }
    return { cols, vals: out };
  }

  const first = parseSelect();
  const result = runOne(first);
  while (accept('UNION')) {
    accept('ALL');
    const r = runOne(parseSelect());
    if (r.cols.length !== result.cols.length) throw new Error('SELECT ทางซ้ายและขวาของ UNION มีจำนวนคอลัมน์ไม่เท่ากัน');
    result.vals = result.vals.concat(r.vals);
  }
  accept(';');
  return result.vals.map((arr) => {
    const o = {};
    result.cols.forEach((c, idx) => { o[c] = arr[idx] === undefined ? null : arr[idx]; });
    return o;
  });
}

let ENGINE = initEngine();

// =====================================================================
//  ฟังก์ชันช่วยทั่วไป
// =====================================================================
function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
function redLog(msg) { console.log(`\x1b[31m${msg}\x1b[0m`); }
function looksLikeInjection(s) { return /('|--|\/\*|\bunion\b|\bor\b|=)/i.test(String(s)); }

function send(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function redirect(res, location) { res.writeHead(303, { Location: location }); res.end(); }
function readForm(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 50_000) { req.destroy(); reject(new Error('body too large')); } });
    req.on('end', () => resolve(new URLSearchParams(data)));
    req.on('error', reject);
  });
}

// =====================================================================
//  CSS ฝังในโค้ด (ไม่ต้องมีไฟล์แยก)
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#1d4ed8;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px;line-height:1.5}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
.engine{margin-left:auto;font-size:12px;color:var(--muted)}
form{display:flex;flex-direction:column;gap:8px;margin:14px 0;max-width:420px}
input{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#64748b}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.result.ok{background:var(--green-bg);border-color:#bfe3c9}
.result.bad{background:var(--red-bg);border-color:#f3c9c9}
.result.err{background:#fff7ed;border-color:#fed7aa}
table{width:100%;border-collapse:collapse;background:var(--card);margin:10px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left}
th{background:#f1f4f8}
code{font-family:Consolas,"Courier New",monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}
.switch{margin-top:26px;color:var(--muted)}
.sqlwrap{margin:12px 0}
.sqllabel{font-size:13px;color:var(--muted);margin:10px 0 4px}
pre.sql{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-all;margin:0}
pre.sql .inj{color:#ff7b72;font-weight:700}
pre.sql.params{color:#7ee787}
.payloads{list-style:none;padding:0}
.payloads li{margin:7px 0;padding:8px 10px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.payloads code{background:#fff3cd}
details{margin:14px 0}
summary{cursor:pointer;font-weight:600}
`;

// =====================================================================
//  ส่วนประกอบหน้าเว็บ
// =====================================================================
function page(title, body, mode) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · SQL Injection Lab</title>
  <style>${STYLE}</style>
</head><body>
  <header>
    <a href="/" class="logo">💉 SQL Injection Lab</a>${badge}
    <span class="engine">DB: ${escapeHtml(ENGINE.kind)}</span>
  </header>
  <main>${body}</main>
  <footer>
    ⚠ เว็บนี้ตั้งใจให้มีช่องโหว่เพื่อการศึกษาการป้องกัน ใช้บนเครื่องตัวเองเท่านั้น<br>
    ห้าม deploy ขึ้นเซิร์ฟเวอร์จริง และห้ามนำเทคนิคไปใช้กับระบบที่ไม่ได้รับอนุญาต — ผิด พ.ร.บ. คอมพิวเตอร์ฯ<br>
    Anti-hacking matters
  </footer>
</body></html>`;
}

// แสดง SQL ที่ "ถูกสร้างขึ้นจริง" (escape แล้ว) + ไฮไลต์ส่วนที่ผู้ใช้แทรกเข้ามา
function sqlBlock(sql, params, injected) {
  let shown = escapeHtml(sql);
  if (injected) {
    for (const piece of injected) {
      if (!piece) continue;
      const esc = escapeHtml(piece);
      shown = shown.split(esc).join(`<span class="inj">${esc}</span>`);
    }
  }
  let h = `<div class="sqlwrap"><div class="sqllabel">SQL ที่ถูกสร้างและส่งเข้าฐานข้อมูลจริง (ส่วนสีแดง = สิ่งที่ผู้ใช้พิมพ์เข้ามา):</div><pre class="sql">${shown}</pre>`;
  if (params && params.length) {
    h += `<div class="sqllabel">ค่าพารามิเตอร์ ที่ส่ง "แยก" จาก SQL (ฐานข้อมูลถือเป็นข้อมูลล้วน ๆ ไม่ใช่โค้ด):</div>`;
    h += `<pre class="sql params">${params.map((p, i) => `? ตัวที่ ${i + 1}  =  ${escapeHtml(JSON.stringify(p))}`).join('\n')}</pre>`;
  }
  return h + `</div>`;
}

function resultTable(rows, error) {
  if (error) {
    return `<div class="result err">ฐานข้อมูลตอบกลับข้อผิดพลาด:<br><code>${escapeHtml(error)}</code><br>
      <small>ข้อความ error แบบนี้เองที่แฮกเกอร์ใช้เดาโครงสร้างฐานข้อมูล (error-based SQL injection)</small></div>`;
  }
  if (!rows) return '';
  if (rows.length === 0) return `<div class="result">คิวรีสำเร็จ แต่ไม่พบข้อมูล (0 แถว)</div>`;
  const headers = Object.keys(rows[0]);
  const thead = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const trows = rows.map((r) =>
    `<tr>${headers.map((h) => `<td>${escapeHtml(r[h] === null || r[h] === undefined ? 'NULL' : String(r[h]))}</td>`).join('')}</tr>`
  ).join('');
  return `<div class="result"><b>ผลลัพธ์ที่ฐานข้อมูลคืนกลับมา: ${rows.length} แถว</b></div><table><tr>${thead}</tr>${trows}</table>`;
}

// =====================================================================
//  Lab 1: Login bypass
// =====================================================================
function runLogin(u, p, safe) {
  let sql, params, injected;
  if (safe) {
    // ✅ prepared statement: SQL คงที่ ค่าถูกส่งแยกเป็น parameter
    sql = `SELECT id, username, password, email, role FROM users WHERE username = ? AND password = ?`;
    params = [u, p];
    injected = null;
  } else {
    // ❌ ต่อ string ตรง ๆ: input ของผู้ใช้กลายเป็นส่วนหนึ่งของ "โค้ด" SQL
    sql = `SELECT id, username, password, email, role FROM users WHERE username = '${u}' AND password = '${p}'`;
    params = [];
    injected = [u, p];
  }
  let rows, error;
  try { rows = ENGINE.all(sql, params); }
  catch (e) { error = e.message; }

  const success = !!(rows && rows.length);
  const legit = seedUsers().some((x) => x.username === u && x.password === p);
  if (!safe && success && !legit) {
    redLog(`[SQLi] Login bypass สำเร็จ!  username="${u}"  password="${p}"  → เข้าระบบเป็น "${rows[0].username}" (${rows[0].role}) โดยไม่รู้รหัสผ่านจริง`);
  }
  return { sql, params, injected, rows, error, success, legit, u, p };
}

function loginPage(res, u, p, safe, submitted) {
  const base = safe ? '/safe/login' : '/login';
  let outcome = '';
  let r = null;
  if (submitted) {
    r = runLogin(u, p, safe);
    let banner = '';
    if (r.error) banner = '';
    else if (r.success) {
      const who = r.rows[0];
      banner = `<div class="result ok">✅ <b>ล็อกอินสำเร็จ</b> — ระบบคิดว่าคุณคือ <b>${escapeHtml(who.username)}</b> (สิทธิ์: ${escapeHtml(who.role)})
        ${r.legit ? '<br><small>(ครั้งนี้รหัสผ่านถูกต้องจริง)</small>'
                  : '<br><small>⚠ แต่คุณ <b>ไม่ได้</b> กรอกรหัสผ่านที่ถูกต้องเลย — นี่คือการ bypass ด้วย SQL injection</small>'}</div>`;
    } else {
      banner = `<div class="result bad">❌ เข้าสู่ระบบไม่สำเร็จ (ไม่พบผู้ใช้ที่ตรงกับเงื่อนไข)</div>`;
    }
    outcome = `
      ${banner}
      ${sqlBlock(r.sql, r.params, r.injected)}
      ${resultTable(r.rows, r.error)}
    `;
  }

  const payloads = [
    { u: `admin' --`, p: `อะไรก็ได้`, note: `ปิดท้ายด้วย -- เพื่อ "คอมเมนต์ทิ้ง" เงื่อนไข AND password ทั้งหมด → เข้าเป็น admin` },
    { u: `' OR '1'='1' -- `, p: `อะไรก็ได้`, note: `'1'='1' จริงเสมอ + -- ตัดส่วนที่เหลือ → ได้ผู้ใช้คนแรกในตาราง` },
    { u: `' OR 1=1 -- `, p: `อะไรก็ได้`, note: `แบบใช้ตัวเลข 1=1` },
    { u: `' UNION SELECT 1,'x','y','z','w' -- `, p: `อะไรก็ได้`, note: `แทรกแถวปลอมที่ควบคุมค่าเองได้` },
  ];
  const links = payloads.map((x) =>
    `<li><a href="${base}?u=${encodeURIComponent(x.u)}&p=${encodeURIComponent(x.p)}&go=1">ลอง</a>
      username = <code>${escapeHtml(x.u)}</code> · password = <code>${escapeHtml(x.p)}</code>
      <br><small class="muted">${escapeHtml(x.note)}</small></li>`
  ).join('');

  send(res, 200, page(safe ? 'Login (ปลอดภัย)' : 'Login (มีช่องโหว่)', `
    <h1>Lab 1: ${safe ? 'Login (ปลอดภัย — Prepared Statement)' : 'Login Bypass (มีช่องโหว่)'}</h1>
    <p>หน้าเข้าสู่ระบบ ${safe
      ? 'เวอร์ชันนี้ใช้ <b>prepared statement</b> (<code>WHERE username = ? AND password = ?</code>) ค่าที่กรอกถูกส่งแยกจาก SQL เสมอ → inject ไม่ได้'
      : 'เวอร์ชันนี้สร้างคำสั่ง SQL ด้วยการ <b>ต่อ string</b> โดยตรง จึงถูก SQL injection ได้'}</p>

    <form method="post" action="${base}">
      <input name="username" placeholder="ชื่อผู้ใช้" value="${escapeHtml(u || '')}" autocomplete="off">
      <input name="password" placeholder="รหัสผ่าน" value="${escapeHtml(p || '')}" autocomplete="off">
      <button>เข้าสู่ระบบ</button>
    </form>

    ${outcome}

    <details ${submitted ? '' : 'open'}><summary>💡 payload ให้ลองกด (กรอกในช่อง หรือกด "ลอง")</summary>
      <ul class="payloads">${links}</ul>
      <p class="muted">บัญชีที่ล็อกอินได้จริง เช่น <code>somchai</code> / <code>somchai2024</code> (ลองเทียบว่า flow ปกติทำงานยังไง)</p>
    </details>

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/login">/login</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/login">/safe/login</a>'} · <a href="/">หน้าแรก</a></p>
  `, safe ? 'safe' : 'vuln'));
}

// =====================================================================
//  Lab 2: Data exfiltration ผ่านช่องค้นหา
// =====================================================================
function runSearch(q, safe) {
  let sql, params, injected;
  if (safe) {
    // ✅ prepared statement: wildcard อยู่ใน parameter ไม่ใช่ใน SQL
    sql = `SELECT id, username, email, role FROM users WHERE username LIKE ?`;
    params = ['%' + q + '%'];
    injected = null;
  } else {
    // ❌ ต่อ string: input หลุดเข้าไปในโครง SQL ได้เต็มที่ (รวมถึง UNION)
    sql = `SELECT id, username, email, role FROM users WHERE username LIKE '%${q}%'`;
    params = [];
    injected = [q];
  }
  let rows, error;
  try { rows = ENGINE.all(sql, params); }
  catch (e) { error = e.message; }
  if (!safe && !error && rows && looksLikeInjection(q)) {
    redLog(`[SQLi] Data exfiltration: ช่องค้นหาคืนข้อมูล ${rows.length} แถว ด้วย input="${q}"`);
  }
  return { sql, params, injected, rows, error };
}

function searchPage(res, q, safe) {
  const base = safe ? '/safe/search' : '/search';
  let outcome = '';
  if (q !== null && q !== undefined) {
    const r = runSearch(q, safe);
    outcome = `${sqlBlock(r.sql, r.params, r.injected)}${resultTable(r.rows, r.error)}`;
  }

  const payloads = [
    { q: `somchai`, note: `การค้นหาปกติ — เจอผู้ใช้ชื่อ somchai` },
    { q: `' OR '1'='1' -- `, note: `ทำให้เงื่อนไขเป็นจริงทุกแถว → ดึงผู้ใช้ออกมาทั้งตาราง` },
    { q: `' UNION SELECT id, username, password, role FROM users -- `, note: `UNION ดึงคอลัมน์ password มาโผล่ในช่อง email!` },
    { q: `zzz' UNION SELECT 1, sqlite_version(), 'db-version', 'x' -- `, note: `ดึงเวอร์ชันฐานข้อมูล (ได้ผลเมื่อเป็น SQLite จริง)` },
  ];
  const links = payloads.map((x) =>
    `<li><a href="${base}?q=${encodeURIComponent(x.q)}">ลอง</a> <code>${escapeHtml(x.q)}</code>
      <br><small class="muted">${escapeHtml(x.note)}</small></li>`
  ).join('');

  send(res, 200, page(safe ? 'ค้นหาผู้ใช้ (ปลอดภัย)' : 'ค้นหาผู้ใช้ (มีช่องโหว่)', `
    <h1>Lab 2: ${safe ? 'ค้นหาผู้ใช้ (ปลอดภัย)' : 'ดึงข้อมูลผ่านช่องค้นหา (มีช่องโหว่)'}</h1>
    <p>ช่องค้นหาผู้ใช้จากชื่อ (ค้นแบบ <code>LIKE</code>). ${safe
      ? 'เวอร์ชันนี้ใช้ prepared statement — wildcard <code>%</code> อยู่ในพารามิเตอร์ ค่าที่พิมพ์ไม่มีทางกลายเป็นคำสั่ง'
      : 'เวอร์ชันนี้ต่อ string ลงใน <code>WHERE</code> โดยตรง จึงใช้ <code>UNION SELECT</code> ดึงข้อมูลตารางอื่นได้'}</p>

    <form method="get" action="${base}">
      <input name="q" placeholder="พิมพ์ชื่อผู้ใช้ที่ต้องการค้นหา..." value="${escapeHtml(q || '')}" autocomplete="off">
      <button>ค้นหา</button>
    </form>

    ${outcome}

    <details ${q ? '' : 'open'}><summary>💡 payload ให้ลองกด</summary>
      <ul class="payloads">${links}</ul>
    </details>

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/search">/search</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/search">/safe/search</a>'} · <a href="/">หน้าแรก</a></p>
  `, safe ? 'safe' : 'vuln'));
}

// =====================================================================
//  หน้าแรก
// =====================================================================
function homePage(res) {
  const rows = ENGINE.all(`SELECT id, username, email, role FROM users`).map((r) =>
    `<tr><td>${r.id}</td><td>${escapeHtml(r.username)}</td><td>${escapeHtml(r.email)}</td><td>${escapeHtml(r.role)}</td></tr>`
  ).join('');
  send(res, 200, page('หน้าแรก', `
    <h1>SQL Injection Lab 💉</h1>
    <p>แล็บฝึกทำความเข้าใจ <b>SQL Injection</b> — ช่องโหว่ที่เกิดจากการเอา input ของผู้ใช้
       ไปต่อเป็นคำสั่ง SQL ตรง ๆ ทำให้ผู้ใช้ "เขียนคำสั่ง" ให้ฐานข้อมูลได้เอง</p>
    <p class="muted">เอนจินฐานข้อมูลที่กำลังใช้อยู่: <b>${escapeHtml(ENGINE.kind)}</b></p>

    <table>
      <tr><th>Lab</th><th>หัวข้อ</th><th>มีช่องโหว่</th><th>แก้แล้ว</th></tr>
      <tr><td>1</td><td>Login bypass</td><td><a href="/login">/login</a></td><td><a href="/safe/login">/safe/login</a></td></tr>
      <tr><td>2</td><td>ดึงข้อมูลผ่านช่องค้นหา (UNION)</td><td><a href="/search">/search</a></td><td><a href="/safe/search">/safe/search</a></td></tr>
    </table>

    <h2>ข้อมูลในตาราง <code>users</code> (ตัวอย่าง)</h2>
    <p class="muted">คอลัมน์: <code>id, username, password, email, role</code> — เป้าหมายของแฮกเกอร์คือดึง <code>password</code> ออกมา</p>
    <table><tr><th>id</th><th>username</th><th>email</th><th>role</th></tr>${rows}</table>
    <p class="muted">(ตารางด้านบนไม่โชว์ password — แต่เดี๋ยวเราจะใช้ SQL injection ดึงมันออกมาเองใน Lab 2)</p>

    <h2>เริ่มยังไงดี</h2>
    <ol>
      <li>เปิด <a href="/login">/login</a> แล้วลองล็อกอินด้วย <code>admin' --</code> (รหัสอะไรก็ได้)</li>
      <li>เปิด <a href="/search">/search</a> แล้วใช้ UNION ดึง password ของทุกคน</li>
      <li>เทียบกับหน้า <b>/safe/*</b> ที่ใช้ prepared statement — payload เดิมจะไม่ทำงาน</li>
    </ol>

    <p class="switch"><a href="/reset">♻ รีเซ็ตข้อมูลในฐานข้อมูล</a> (ข้อมูลเป็น in-memory รีสตาร์ทเซิร์ฟเวอร์ก็รีเซ็ตเช่นกัน)</p>
  `, null));
}

// =====================================================================
//  Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const path = url.pathname;

  try {
    if (req.method === 'GET') {
      switch (path) {
        case '/': return homePage(res);
        case '/reset': ENGINE.reset(); return redirect(res, '/');
        case '/login':
          return loginPage(res, url.searchParams.get('u') || '', url.searchParams.get('p') || '', false, url.searchParams.has('go'));
        case '/safe/login':
          return loginPage(res, url.searchParams.get('u') || '', url.searchParams.get('p') || '', true, url.searchParams.has('go'));
        case '/search':
          return searchPage(res, url.searchParams.has('q') ? url.searchParams.get('q') : null, false);
        case '/safe/search':
          return searchPage(res, url.searchParams.has('q') ? url.searchParams.get('q') : null, true);
      }
    }

    if (req.method === 'POST') {
      const form = await readForm(req);
      switch (path) {
        case '/login':
          return loginPage(res, form.get('username') || '', form.get('password') || '', false, true);
        case '/safe/login':
          return loginPage(res, form.get('username') || '', form.get('password') || '', true, true);
      }
    }

    send(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>', null));
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  SQL Injection Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เอนจินฐานข้อมูล: \x1b[36m${ENGINE.kind}\x1b[0m`);
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ลองล็อกอินที่ /login ด้วย  admin\' --  แล้วดูที่ /search');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
