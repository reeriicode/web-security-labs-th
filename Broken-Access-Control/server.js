// =====================================================================
//  Broken Access Control Lab — เว็บที่ "ตั้งใจ" ให้มีช่องโหว่
//  เพื่อการเรียนรู้ (IDOR + Privilege Escalation)
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
// =====================================================================

const http = require('http');
const crypto = require('crypto');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในเน็ตเวิร์กเข้าไม่ได้
const PORT = Number(process.env.PORT) || 4100;

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์แล้วรีเซ็ตใหม่ หรือเข้า /reset)
// ---------------------------------------------------------------------
function seed() {
  return {
    users: {
      alice: { password: 'alice123', role: 'user',  name: 'คุณอลิซ' },
      bob:   { password: 'bob123',   role: 'user',  name: 'คุณบ๊อบ' },
      admin: { password: 'admin123', role: 'admin', name: 'ผู้ดูแลระบบ' },
    },
    // order id เป็นเลขเรียงเดาง่ายมาก (101,102 ของ alice / 201,202 ของ bob)
    // แต่ละ order มีข้อมูล "ความลับ" ของเจ้าของ: ที่อยู่ เบอร์โทร ยอดเงิน
    orders: {
      101: { owner: 'alice', item: 'หูฟังไร้สาย รุ่น Pro',  amount: 2990,  address: '88/1 ซ.ลาดพร้าว 15 กทม. 10900', phone: '081-111-1111' },
      102: { owner: 'alice', item: 'สมาร์ตวอทช์',           amount: 5490,  address: '88/1 ซ.ลาดพร้าว 15 กทม. 10900', phone: '081-111-1111' },
      201: { owner: 'bob',   item: 'โน้ตบุ๊กเกมมิง',          amount: 42900, address: '203 ถ.สุขุมวิท ชลบุรี 20150',   phone: '089-222-2222' },
      202: { owner: 'bob',   item: 'จอมอนิเตอร์ 27 นิ้ว',     amount: 8990,  address: '203 ถ.สุขุมวิท ชลบุรี 20150',   phone: '089-222-2222' },
    },
    sessions: new Map(), // session id -> username
  };
}
let db = seed();

function newId() { return crypto.randomBytes(8).toString('hex'); }

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > -1) out[kv.slice(0, i).trim()] = decodeURIComponent(kv.slice(i + 1).trim());
  });
  return out;
}
// คืนข้อมูลผู้ใช้ปัจจุบันจากคุกกี้ session
function currentUser(req) {
  const sid = parseCookies(req).bac_session;
  const username = db.sessions.get(sid);
  return username && db.users[username] ? { username, sid, ...db.users[username] } : null;
}

// ✅ ป้องกัน XSS หลุดใน UI ของแล็บเอง: แปลงอักขระพิเศษให้เป็นข้อความธรรมดา
function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// =====================================================================
// CSS ฝังไว้ในโค้ดเลย ไม่ต้องมีไฟล์แยก
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#2563eb;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
.who{margin-left:auto;font-size:14px;color:var(--muted)}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px;line-height:1.8}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
form.stack{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:360px}
input,select{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#e2e8f0;color:#334155}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.result{border-left:4px solid var(--accent)}
.result.danger{border-left-color:var(--red);background:var(--red-bg)}
.result.ok{border-left-color:var(--green);background:var(--green-bg)}
table{width:100%;border-collapse:collapse;background:var(--card);margin:10px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f1f4f8}
code{font-family:Consolas,monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
.idbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}
.idbar a{display:inline-block;padding:4px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;text-decoration:none}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;background:#e2e8f0;color:#334155}
.pill.admin{background:#fef3c7;color:#92400e}
ol li,ul li{margin:4px 0}
`;

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, mode, req) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  const user = req ? currentUser(req) : null;
  const who = user
    ? `ล็อกอินเป็น <b>${escapeHtml(user.username)}</b> <span class="pill ${user.role === 'admin' ? 'admin' : ''}">${escapeHtml(user.role)}</span> · <a href="/logout">ออกจากระบบ</a>`
    : `<a href="/login">เข้าสู่ระบบ</a>`;
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Broken Access Control Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head><body>
  <header>
    <a href="/" class="logo">🛒 ShopDemo</a>${badge}
    <span class="who">${who}</span>
  </header>
  <main>${body}</main>
  <footer>
    ⚠ เว็บนี้ตั้งใจให้มีช่องโหว่เพื่อการเรียนรู้ ใช้บนเครื่องตัวเองเท่านั้น<br>
    ห้าม deploy · ห้ามใช้เทคนิคนี้กับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ) · Anti-hacking matters
  </footer>
</body></html>`;
}

function send(res, status, html, { cookie } = {}) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(status, headers);
  res.end(html);
}
function redirect(res, location, cookie) {
  const headers = { Location: location };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(303, headers);
  res.end();
}
function readForm(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 50_000) { req.destroy(); reject(new Error('big')); } });
    req.on('end', () => resolve(new URLSearchParams(data)));
    req.on('error', reject);
  });
}

// แสดงข้อมูล order หนึ่งรายการ (ข้อมูลผ่าน escapeHtml ทุกจุด)
function renderOrder(id, o) {
  return `<div class="card">
    <h2>คำสั่งซื้อ #${escapeHtml(id)}</h2>
    <table>
      <tr><th>เจ้าของบัญชี</th><td>${escapeHtml(o.owner)}</td></tr>
      <tr><th>สินค้า</th><td>${escapeHtml(o.item)}</td></tr>
      <tr><th>ยอดชำระ</th><td>${o.amount.toLocaleString()} บาท</td></tr>
      <tr><th>🔒 ที่อยู่จัดส่ง</th><td>${escapeHtml(o.address)}</td></tr>
      <tr><th>🔒 เบอร์โทร</th><td>${escapeHtml(o.phone)}</td></tr>
    </table>
  </div>`;
}

// แถบลองเปลี่ยน id ง่ายๆ
function idBar(base, current) {
  const ids = Object.keys(db.orders);
  const links = ids.map((id) =>
    `<a href="${base}/${id}">#${id}${db.orders[id].owner === 'alice' ? ' (alice)' : ' (bob)'}</a>`
  ).join('');
  return `<div class="idbar">
    <span>ลองเปลี่ยน id:</span>${links}
    <form method="get" action="${base}/go" style="display:flex;gap:6px;margin:0">
      <input name="id" value="${escapeHtml(current || '')}" placeholder="เช่น 201" style="width:110px">
      <button class="secondary">เปิด</button>
    </form>
  </div>`;
}

// =====================================================================
// หน้าแรก
// =====================================================================
function homePage(req) {
  const user = currentUser(req);
  return page('หน้าแรก', `
    <h1>Broken Access Control Lab 🧪</h1>
    <p>แล็บฝึกทำความเข้าใจ <b>Broken Access Control</b> — ช่องโหว่ที่พบบ่อยที่สุดอันดับ 1
       (OWASP Top 10 ปี 2021) สาธิต 2 รูปแบบที่เจอบ่อย คือ <b>IDOR</b> และ <b>Privilege Escalation</b></p>

    ${user
      ? `<p class="result">ตอนนี้ล็อกอินเป็น <b>${escapeHtml(user.username)}</b> (สิทธิ์: ${escapeHtml(user.role)}) · <a href="/dashboard">ไปหน้าบัญชีของฉัน</a></p>`
      : `<p class="result">ยังไม่ได้ล็อกอิน — <a href="/login">เข้าสู่ระบบ</a> เป็น alice เพื่อเริ่มทดลอง</p>`}

    <table>
      <tr><th>Lab</th><th>ชนิด</th><th>มีช่องโหว่</th><th>แก้แล้ว</th></tr>
      <tr><td>1</td><td>IDOR — ดูคำสั่งซื้อของคนอื่น</td>
          <td><a href="/orders/101">/orders/:id</a></td><td><a href="/safe/orders/101">/safe/orders/:id</a></td></tr>
      <tr><td>2</td><td>Privilege Escalation — เข้าหน้าแอดมิน</td>
          <td><a href="/admin">/admin</a></td><td><a href="/safe/admin">/safe/admin</a></td></tr>
    </table>

    <h2>🎯 ไอเดียการโจมตีสั้นๆ</h2>
    <ol>
      <li>ล็อกอินเป็น <b>alice</b> (ผู้ใช้ธรรมดา) ที่ <a href="/login">/login</a></li>
      <li><b>IDOR:</b> เปิดคำสั่งซื้อของตัวเอง <code>/orders/101</code> แล้ว<b>เปลี่ยนเลขใน URL</b>เป็น
          <code>/orders/201</code> (ของ bob) — หน้า vuln คืนข้อมูลให้เลย!</li>
      <li><b>Privilege Escalation:</b> ลองเปิด <a href="/admin">/admin</a> ทั้งที่ alice เป็นผู้ใช้ธรรมดา —
          หน้า vuln เช็กแค่ "ล็อกอินแล้ว" ไม่เช็ก role จึงเห็นข้อมูลทุกคน</li>
      <li>เทียบกับหน้า <span class="badge safe">SAFE</span> ที่เช็กสิทธิ์จริง แล้วตอบ <code>403</code></li>
    </ol>

    <h2>บัญชีทดสอบ</h2>
    <table>
      <tr><th>บัญชี</th><th>รหัสผ่าน</th><th>สิทธิ์</th><th>คำสั่งซื้อของตัวเอง</th></tr>
      <tr><td><code>alice</code></td><td><code>alice123</code></td><td>user (เหยื่อ/ผู้โจมตี)</td><td>101, 102</td></tr>
      <tr><td><code>bob</code></td><td><code>bob123</code></td><td>user</td><td>201, 202</td></tr>
      <tr><td><code>admin</code></td><td><code>admin123</code></td><td>admin (แอดมินตัวจริง)</td><td>-</td></tr>
    </table>
  `, null, req);
}

// =====================================================================
// ล็อกอิน / ออกจากระบบ / dashboard
// =====================================================================
function loginPage(msg) {
  return page('เข้าสู่ระบบ', `
    <h1>เข้าสู่ระบบ</h1>
    ${msg ? `<p class="result danger">${escapeHtml(msg)}</p>` : ''}
    <form method="post" action="/login" class="stack">
      <input name="username" placeholder="ชื่อผู้ใช้ (alice / bob / admin)" required>
      <input name="password" type="password" placeholder="รหัสผ่าน" required>
      <button>เข้าสู่ระบบ</button>
    </form>
    <div class="result"><b>บัญชีทดสอบ</b><br>
      <code>alice</code> / <code>alice123</code> (ผู้ใช้ธรรมดา — ใช้เป็นผู้โจมตี)<br>
      <code>bob</code> / <code>bob123</code> (ผู้ใช้ธรรมดา — เป็นเหยื่อ)<br>
      <code>admin</code> / <code>admin123</code> (แอดมินตัวจริง)
    </div>
  `, null);
}

function dashboard(req) {
  const user = currentUser(req);
  const myOrders = Object.entries(db.orders).filter(([, o]) => o.owner === user.username);
  const rows = myOrders.map(([id, o]) =>
    `<tr><td><a href="/orders/${id}">#${escapeHtml(id)}</a></td><td>${escapeHtml(o.item)}</td><td>${o.amount.toLocaleString()} บาท</td></tr>`
  ).join('') || '<tr><td colspan="3" class="muted">คุณยังไม่มีคำสั่งซื้อ</td></tr>';

  return page('บัญชีของฉัน', `
    <h1>สวัสดี ${escapeHtml(user.name)}</h1>
    <p>คุณล็อกอินเป็น <b>${escapeHtml(user.username)}</b> · สิทธิ์
       <span class="pill ${user.role === 'admin' ? 'admin' : ''}">${escapeHtml(user.role)}</span></p>

    <h2>คำสั่งซื้อของฉัน</h2>
    <table><tr><th>เลขที่</th><th>สินค้า</th><th>ยอด</th></tr>${rows}</table>

    <h2>ลองโจมตีต่อ</h2>
    <ul>
      <li>IDOR: ลองเปิดคำสั่งซื้อที่ "ไม่ใช่ของคุณ" เช่น
          <a href="/orders/201">/orders/201</a> (หน้า vuln) เทียบ
          <a href="/safe/orders/201">/safe/orders/201</a> (หน้า safe)</li>
      <li>Privilege Escalation: ลองเข้า <a href="/admin">/admin</a> เทียบ
          <a href="/safe/admin">/safe/admin</a></li>
    </ul>

    <p class="switch"><a href="/">กลับหน้าแรก</a></p>
  `, null, req);
}

// =====================================================================
// Lab 1: IDOR (Insecure Direct Object Reference)
// =====================================================================
function orderPage(req, id, safe) {
  const base = safe ? '/safe/orders' : '/orders';
  const user = currentUser(req);
  const o = db.orders[id];

  // intro + idbar + สลับโหมด
  const head = `
    <h1>Lab 1: IDOR — ${safe ? 'เช็กความเป็นเจ้าของ' : 'ไม่เช็กความเป็นเจ้าของ'}</h1>
    <p>ระบบดูคำสั่งซื้อ อ้างอิงด้วย <b>id ที่เรียงเดาง่าย</b> ตรงๆ ใน URL (<code>${base}/&lt;id&gt;</code>)
       ลองเปลี่ยนเลข id เป็นของคนอื่นดู</p>
    ${idBar(base, id)}
  `;
  const foot = `<p class="switch">${safe
    ? `ดูแบบมีช่องโหว่: <a href="/orders/${escapeHtml(id)}">/orders/${escapeHtml(id)}</a>`
    : `ดูแบบแก้แล้ว: <a href="/safe/orders/${escapeHtml(id)}">/safe/orders/${escapeHtml(id)}</a>`}
    · <a href="/dashboard">บัญชีของฉัน</a></p>`;

  if (!o) {
    return page('IDOR', `${head}<p class="result danger">ไม่พบคำสั่งซื้อ #${escapeHtml(id)}</p>${foot}`, safe ? 'safe' : 'vuln', req);
  }

  if (!safe) {
    // ❌ ช่องโหว่: เช็กแค่ว่า "ล็อกอินแล้ว" ไม่เช็กว่า order นี้เป็นของผู้ล็อกอินจริงไหม
    const stolen = o.owner !== user.username;
    if (stolen) {
      console.log(`\x1b[31m[IDOR] ${user.username} เปิดดูคำสั่งซื้อ #${id} ของ ${o.owner} ได้ (ข้อมูลหลุด!)\x1b[0m`);
    }
    const warn = stolen
      ? `<p class="result danger">⚠ คำสั่งซื้อนี้เป็นของ <b>${escapeHtml(o.owner)}</b> ไม่ใช่ของคุณ
         แต่ระบบ (แบบมีช่องโหว่) ก็ยังแสดงข้อมูลลับให้เห็นทั้งหมด</p>`
      : `<p class="result">นี่คือคำสั่งซื้อของคุณเอง</p>`;
    return page('IDOR', `${head}${warn}${renderOrder(id, o)}${foot}`, 'vuln', req);
  }

  // ✅ แก้แล้ว: ต้องเป็นเจ้าของ order เท่านั้น (หรือเป็น admin) ไม่งั้น 403
  if (o.owner !== user.username && user.role !== 'admin') {
    console.log(`\x1b[32m[SAFE] ปฏิเสธ: ${user.username} พยายามเปิด #${id} ของ ${o.owner} -> 403\x1b[0m`);
    const body = `${head}
      <p class="result danger">⛔ 403 Forbidden — คำสั่งซื้อ #${escapeHtml(id)} เป็นของ
         <b>${escapeHtml(o.owner)}</b> คุณ (<b>${escapeHtml(user.username)}</b>) ไม่มีสิทธิ์เข้าถึง</p>
      ${foot}`;
    return page('IDOR (403)', body, 'safe', req);
  }
  return page('IDOR', `${head}<p class="result ok">คุณมีสิทธิ์เข้าถึงคำสั่งซื้อนี้</p>${renderOrder(id, o)}${foot}`, 'safe', req);
}

// =====================================================================
// Lab 2: Privilege Escalation — หน้าแอดมิน
// =====================================================================
function adminPage(req, safe) {
  const user = currentUser(req);

  const userRows = Object.entries(db.users).map(([uname, u]) =>
    `<tr><td>${escapeHtml(uname)}</td><td>${escapeHtml(u.name)}</td><td><span class="pill ${u.role === 'admin' ? 'admin' : ''}">${escapeHtml(u.role)}</span></td><td><code>${escapeHtml(u.password)}</code></td></tr>`
  ).join('');
  const orderRows = Object.entries(db.orders).map(([id, o]) =>
    `<tr><td>#${escapeHtml(id)}</td><td>${escapeHtml(o.owner)}</td><td>${escapeHtml(o.item)}</td><td>${o.amount.toLocaleString()}</td><td>${escapeHtml(o.address)}</td></tr>`
  ).join('');

  const adminBody = `
    <p class="result danger">หน้านี้ควรเห็นได้เฉพาะ <b>admin</b> เท่านั้น เพราะมีข้อมูลลับของทุกคน
       (รวมถึงรหัสผ่านและที่อยู่)</p>
    <h2>ผู้ใช้ทั้งหมด</h2>
    <table><tr><th>บัญชี</th><th>ชื่อ</th><th>สิทธิ์</th><th>รหัสผ่าน</th></tr>${userRows}</table>
    <h2>คำสั่งซื้อทั้งหมด</h2>
    <table><tr><th>เลขที่</th><th>เจ้าของ</th><th>สินค้า</th><th>ยอด</th><th>ที่อยู่</th></tr>${orderRows}</table>
  `;

  const head = `<h1>Lab 2: Privilege Escalation — หน้าแอดมิน ${safe ? '(เช็ก role)' : '(ไม่เช็ก role)'}</h1>`;
  const foot = `<p class="switch">${safe
    ? 'ดูแบบมีช่องโหว่: <a href="/admin">/admin</a>'
    : 'ดูแบบแก้แล้ว: <a href="/safe/admin">/safe/admin</a>'} · <a href="/dashboard">บัญชีของฉัน</a></p>`;

  if (!safe) {
    // ❌ ช่องโหว่: เช็กแค่ว่า "ล็อกอินแล้ว" ไม่เช็ก role → ผู้ใช้ธรรมดาเข้าได้
    if (user.role !== 'admin') {
      console.log(`\x1b[31m[PRIV-ESC] ${user.username} (role=${user.role}) เข้าหน้า /admin ได้ ทั้งที่ไม่ใช่แอดมิน!\x1b[0m`);
    }
    const note = user.role !== 'admin'
      ? `<p class="result danger">⚠ คุณคือ <b>${escapeHtml(user.username)}</b> สิทธิ์
         <b>${escapeHtml(user.role)}</b> — ไม่ใช่แอดมิน แต่ก็ยังเข้าหน้านี้และเห็นข้อมูลทุกคนได้</p>`
      : '';
    return page('Admin (vuln)', `${head}${note}${adminBody}${foot}`, 'vuln', req);
  }

  // ✅ แก้แล้ว: ต้องมี role === 'admin' เท่านั้น
  if (user.role !== 'admin') {
    console.log(`\x1b[32m[SAFE] ปฏิเสธ: ${user.username} (role=${user.role}) พยายามเข้า /safe/admin -> 403\x1b[0m`);
    return page('Admin (403)', `${head}
      <p class="result danger">⛔ 403 Forbidden — ต้องเป็น <b>admin</b> เท่านั้น
         คุณคือ <b>${escapeHtml(user.username)}</b> (สิทธิ์ ${escapeHtml(user.role)})
         ลองล็อกอินด้วย <code>admin</code> / <code>admin123</code> แล้วเข้าใหม่</p>
      ${foot}`, 'safe', req);
  }
  return page('Admin (safe)', `${head}<p class="result ok">ยินดีต้อนรับแอดมิน — ผ่านการตรวจสิทธิ์แล้ว</p>${adminBody}${foot}`, 'safe', req);
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;

  try {
    if (req.method === 'GET' && p === '/static/style.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(STYLE);
    }

    const user = currentUser(req);

    // ---------- GET ----------
    if (req.method === 'GET') {
      if (p === '/') return send(res, 200, homePage(req));
      if (p === '/login') {
        if (user) return redirect(res, '/dashboard');
        return send(res, 200, loginPage());
      }
      if (p === '/logout') {
        if (user) db.sessions.delete(user.sid);
        return redirect(res, '/login', 'bac_session=; Path=/; Max-Age=0');
      }
      if (p === '/reset') { db = seed(); return redirect(res, '/login', 'bac_session=; Path=/; Max-Age=0'); }

      // หน้าที่ต้องล็อกอินก่อน
      if (p === '/dashboard') {
        if (!user) return redirect(res, '/login');
        return send(res, 200, dashboard(req));
      }

      // แถบ "เปิด" id จากฟอร์ม -> redirect ไปหน้า order
      let m;
      if ((m = p.match(/^(\/safe)?\/orders\/go$/))) {
        const prefix = m[1] ? '/safe/orders' : '/orders';
        const id = (url.searchParams.get('id') || '').trim();
        return redirect(res, `${prefix}/${encodeURIComponent(id)}`);
      }

      // Lab 1: IDOR  /orders/:id และ /safe/orders/:id
      if ((m = p.match(/^(\/safe)?\/orders\/([^/]+)$/))) {
        if (!user) return redirect(res, '/login');
        const safe = !!m[1];
        const id = decodeURIComponent(m[2]);
        return send(res, 200, orderPage(req, id, safe));
      }

      // Lab 2: Privilege Escalation  /admin และ /safe/admin
      if (p === '/admin' || p === '/safe/admin') {
        if (!user) return redirect(res, '/login');
        return send(res, 200, adminPage(req, p === '/safe/admin'));
      }
    }

    // ---------- POST ----------
    if (req.method === 'POST') {
      const form = await readForm(req);
      if (p === '/login') {
        const username = (form.get('username') || '').trim();
        const u = db.users[username];
        if (u && form.get('password') === u.password) {
          const sid = newId();
          db.sessions.set(sid, username);
          return redirect(res, '/dashboard', `bac_session=${sid}; Path=/; SameSite=Lax`);
        }
        return send(res, 200, loginPage('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'));
      }
    }

    send(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null, req));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>', null, req));
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  Broken Access Control Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ล็อกอินเป็น alice แล้วลองเปลี่ยนเลขใน /orders/101 เป็น /orders/201 หรือเปิด /admin');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
