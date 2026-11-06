// =====================================================================
//  Authentication Lab — เว็บที่ "ตั้งใจ" ให้มีช่องโหว่เรื่องการยืนยันตัวตน
//  เพื่อการเรียนรู้การป้องกัน
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
//  ใช้เฉพาะโมดูลที่มากับ Node.js (http, crypto, url) ไม่มี npm package
// =====================================================================

const http = require('http');
const crypto = require('crypto');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 4300;

// ค่าคงที่สำหรับเดโม
const MAX_FAILS = 5;        // ผิดเกินกี่ครั้งถึงจะล็อก (หน้า safe)
const LOCK_MS = 30_000;     // ล็อกนานกี่มิลลิวินาที
const TOKEN_TTL = 60_000;   // อายุ token ของหน้า safe (มิลลิวินาที)

// รายการรหัสผ่านยอดฮิตที่ "เครื่องมือเดารหัส" จะไล่ลอง (เรียงตามความนิยม)
// หมายเหตุ: '123456' (รหัสของ user) ถูกวางไว้ลำดับที่ 8 โดยตั้งใจ
// เพื่อให้เห็นว่าหน้า safe ล็อกบัญชีได้ "ก่อน" จะเดาถึงรหัสจริง
const COMMON_PASSWORDS = [
  'password', 'qwerty', 'letmein', '111111', 'iloveyou',
  'admin', 'welcome', '123456', 'monkey', 'dragon', 'abc123', 'sunshine',
];

// ---------------------------------------------------------------------
// การแฮชรหัสผ่านด้วย crypto.scryptSync + salt (built-in ของ Node.js)
//   ในงานจริงนิยมใช้ bcrypt หรือ argon2 (ออกแบบมาเพื่อรหัสผ่านโดยเฉพาะ
//   ปรับความยากได้ และมีการทดสอบด้านความปลอดภัยอย่างกว้างขวาง)
//   แต่ scrypt เป็น KDF ที่ "หน่วงเวลา + กินหน่วยความจำ" และมากับ Node.js
//   เลยใช้ในแล็บนี้เพื่อไม่ต้องลง npm — แนวคิดเหมือนกัน: เก็บ hash ไม่เก็บรหัสจริง
// ---------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex'); // salt สุ่มต่อผู้ใช้ กันตาราง rainbow
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function verifyPassword(password, stored) {
  const [, salt, hash] = stored.split('$');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(test, 'hex');
  // timingSafeEqual: เทียบแบบเวลาคงที่ กันการจับเวลาเดาทีละตัวอักษร
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์หรือกด /reset แล้วรีเซ็ตใหม่)
// ---------------------------------------------------------------------
function seed() {
  // รหัสผ่าน "ต้นฉบับ" ที่ใช้สร้างทั้งฝั่ง vuln (plain) และ safe (hash)
  const raw = {
    user:  { password: '123456',          role: 'สมาชิกทั่วไป' },   // ตั้งใจให้รหัสอ่อน -> เดาเจอ
    admin: { password: 'Tr0ub4dor&3xK',   role: 'ผู้ดูแลระบบ' },     // รหัสแข็ง -> ไม่อยู่ใน wordlist
  };

  // ❌ ฝั่ง vuln: เก็บรหัสผ่านเป็น plain text ตรงๆ
  const vulnUsers = {};
  for (const [name, u] of Object.entries(raw)) {
    vulnUsers[name] = { password: u.password, role: u.role };
  }

  // ✅ ฝั่ง safe: เก็บเป็น scrypt hash + salt (ไม่มีรหัสจริงอยู่เลย)
  const safeUsers = {};
  for (const [name, u] of Object.entries(raw)) {
    safeUsers[name] = { hash: hashPassword(u.password), role: u.role };
  }

  return {
    vulnUsers,
    safeUsers,
    // การนับความล้มเหลวของการล็อกอิน (ใช้เฉพาะหน้า safe) : key=ชื่อผู้ใช้
    loginAttempts: new Map(),
    // token ของหน้า safe : token -> { user, expires }
    safeTokens: new Map(),
  };
}
let db = seed();

// ---------------------------------------------------------------------
// token ของหน้า vuln : เดาได้ = base64 ของชื่อผู้ใช้ และไม่มีวันหมดอายุ
//   เช่น admin -> YWRtaW4=  (ใครก็คำนวณย้อนกลับได้ ปลอมได้ทันที)
// ---------------------------------------------------------------------
function vulnTokenFor(username) {
  return Buffer.from(username, 'utf8').toString('base64');
}
function userFromVulnToken(token) {
  try {
    const name = Buffer.from(token, 'base64').toString('utf8');
    return db.vulnUsers[name] ? name : null;
  } catch { return null; }
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > -1) out[kv.slice(0, i).trim()] = decodeURIComponent(kv.slice(i + 1).trim());
  });
  return out;
}
// ผู้ใช้ปัจจุบันฝั่ง vuln (ตัดสินจากคุกกี้ auth ที่เดาได้)
function currentVulnUser(req) {
  const name = userFromVulnToken(parseCookies(req).auth || '');
  return name ? { name, ...db.vulnUsers[name] } : null;
}
// ผู้ใช้ปัจจุบันฝั่ง safe (ตัดสินจาก token สุ่มที่ยังไม่หมดอายุ)
function currentSafeUser(req) {
  const tok = parseCookies(req).safe_auth || '';
  const rec = db.safeTokens.get(tok);
  if (!rec) return null;
  if (rec.expires < Date.now()) { db.safeTokens.delete(tok); return null; } // หมดอายุ -> ล็อกเอาต์
  return { name: rec.user, token: tok, expires: rec.expires, ...db.safeUsers[rec.user] };
}

function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// ---------------------------------------------------------------------
// การนับ/ล็อก การล็อกอินผิด (ใช้เฉพาะหน้า safe)
// ---------------------------------------------------------------------
function lockState(key) {
  const now = Date.now();
  const rec = db.loginAttempts.get(key);
  if (rec && rec.lockedUntil > now) return { locked: true, retry: Math.ceil((rec.lockedUntil - now) / 1000) };
  return { locked: false };
}
function recordFail(key) {
  const rec = db.loginAttempts.get(key) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= MAX_FAILS) { rec.lockedUntil = Date.now() + LOCK_MS; rec.fails = 0; } // ครบโควตา -> ล็อก
  db.loginAttempts.set(key, rec);
}
function recordSuccess(key) { db.loginAttempts.delete(key); }

// ---------------------------------------------------------------------
// การส่ง response
// ---------------------------------------------------------------------
function send(res, status, html, { cookie, safe = false } = {}) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(status, headers);
  res.end(html);
}
function sendText(res, status, text, { cookie } = {}) {
  const headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(status, headers);
  res.end(text);
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

// =====================================================================
// CSS (ฝังไว้ในโค้ด ไม่ต้องมีไฟล์แยก)
// =====================================================================
const STYLE = `
:root{--bg:#eef2f8;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dbe1ea;--accent:#1d4ed8;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb;--amber:#9a6700;--amber-bg:#fff6e0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
.who{margin-left:auto;font-size:14px;color:var(--muted)}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px;border-top:1px solid var(--line);margin-top:30px}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
form.stack{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:380px}
input,select{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#64748b}
button.danger{background:#dc2626}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
table{width:100%;border-collapse:collapse;background:var(--card);margin:10px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f1f4f9}
code{font-family:Consolas,monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;word-break:break-all}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;line-height:1.5}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
.plain{color:var(--red);font-weight:700}
.hash{color:var(--green);font-weight:600;font-size:12px}
.log{background:#0d1117;color:#c9d1d9;border-radius:10px;padding:12px;font-family:Consolas,monospace;font-size:13px;min-height:120px;max-height:320px;overflow:auto;white-space:pre-wrap}
.ok{color:#56d364}
.fail{color:#f85149}
.warn{color:#e3b341}
.pill{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700}
.pill.n{background:var(--amber-bg);color:var(--amber)}
ul.tight{margin:6px 0}
`;

// =====================================================================
// โครงหน้าเว็บ
// =====================================================================
function page(title, body, { mode, req } = {}) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  const vu = req ? currentVulnUser(req) : null;
  const su = req ? currentSafeUser(req) : null;
  const who = [];
  if (vu) who.push(`vuln: <b>${escapeHtml(vu.name)}</b>`);
  if (su) who.push(`safe: <b>${escapeHtml(su.name)}</b>`);
  const whoHtml = who.length ? who.join(' · ') : 'ยังไม่ได้ล็อกอิน';
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Authentication Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head><body>
  <header>
    <a href="/" class="logo">🔐 Authentication Lab</a>${badge}
    <span class="who">${whoHtml}</span>
  </header>
  <main>${body}</main>
  <footer>
    ⚠ เว็บนี้ตั้งใจให้มีช่องโหว่ เพื่อการเรียนรู้การป้องกันบนเครื่องตัวเองเท่านั้น<br>
    ห้าม deploy ขึ้นเซิร์ฟเวอร์จริง · ห้ามใช้เทคนิคกับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ) · Anti-hacking matters
  </footer>
</body></html>`;
}

// =====================================================================
// หน้าแรก
// =====================================================================
function homePage(req) {
  return page('หน้าแรก', `
    <h1>Authentication Lab 🔐</h1>
    <p>แล็บฝึกทำความเข้าใจ <b>การยืนยันตัวตนที่ไม่ปลอดภัย (Broken Authentication)</b>
       มี 3 เดโม แต่ละเดโมมีฝั่ง <span class="badge vuln">VULNERABLE</span> ให้ลองโจมตี
       และฝั่ง <span class="badge safe">SAFE</span> ที่แก้แล้วให้เทียบกัน</p>

    <table>
      <tr><th>เดโม</th><th>เรื่อง</th><th>มีช่องโหว่</th><th>แก้แล้ว</th></tr>
      <tr><td>1</td><td>การเก็บรหัสผ่าน (plain text vs hash)</td>
          <td><a href="/leak">/leak</a></td><td><a href="/safe/leak">/safe/leak</a></td></tr>
      <tr><td>2</td><td>Brute force / rate limiting</td>
          <td><a href="/login">/login</a> + <a href="/guess">/guess</a></td>
          <td><a href="/safe/login">/safe/login</a> + <a href="/safe/guess">/safe/guess</a></td></tr>
      <tr><td>3</td><td>Session token ที่เดาได้ / ไม่หมดอายุ</td>
          <td><a href="/token">/token</a></td><td><a href="/safe/token">/safe/token</a></td></tr>
    </table>

    <h2>บัญชีทดสอบ</h2>
    <table>
      <tr><th>บัญชี</th><th>รหัสผ่าน</th><th>สิทธิ์</th><th>หมายเหตุ</th></tr>
      <tr><td><code>user</code></td><td><code>123456</code></td><td>สมาชิกทั่วไป</td>
          <td class="plain">รหัสอ่อนมาก อยู่ในลิสต์รหัสยอดฮิต → เครื่องมือเดารหัสเจอแน่</td></tr>
      <tr><td><code>admin</code></td><td><code>Tr0ub4dor&amp;3xK</code></td><td>ผู้ดูแลระบบ</td>
          <td>รหัสแข็งกว่า ไม่อยู่ในลิสต์ → เดาด้วย wordlist สั้นๆ ไม่เจอ</td></tr>
    </table>

    <h2>แนะนำลำดับการทดลอง</h2>
    <ol>
      <li>เปิด <a href="/leak">/leak</a> ดู "ฐานข้อมูลรั่ว" ฝั่ง vuln → เห็นรหัสผ่านจริงทุกคน แล้วเทียบ <a href="/safe/leak">/safe/leak</a></li>
      <li>เปิด <a href="/guess">/guess</a> กดปุ่มเดารหัสของ <code>user</code> → เดาเจอ แล้วเทียบ <a href="/safe/guess">/safe/guess</a> → โดนล็อก</li>
      <li>เปิด <a href="/token">/token</a> ดู token ที่เดาได้ แล้วลองสวมรอยเป็น admin โดยไม่ต้องรู้รหัส</li>
    </ol>
    <p class="muted">อยากเริ่มใหม่ทั้งหมด (คืนค่ารหัส/ปลดล็อก/ลบ token): <a href="/reset">/reset</a></p>
  `, { req });
}

// =====================================================================
// เดโม 1: การเก็บรหัสผ่าน — หน้า "ฐานข้อมูลรั่ว"
// =====================================================================
function leakPage(req, safe) {
  if (!safe) {
    console.log('\x1b[31m[DB LEAK] มีคนเปิดดูฐานข้อมูลฝั่ง vuln — เห็นรหัสผ่าน plain text ของทุกบัญชีทันที\x1b[0m');
  }
  const rows = Object.entries(safe ? db.safeUsers : db.vulnUsers).map(([name, u]) => {
    const pw = safe
      ? `<span class="hash">${escapeHtml(u.hash)}</span>`
      : `<span class="plain">${escapeHtml(u.password)}</span>`;
    return `<tr><td><code>${escapeHtml(name)}</code></td><td>${escapeHtml(u.role)}</td><td>${pw}</td></tr>`;
  }).join('');

  const col = safe ? 'password_hash (scrypt$salt$hash)' : 'password (plain text)';

  return page(`ฐานข้อมูลรั่ว ${safe ? '(เก็บแบบ hash)' : '(เก็บ plain text)'}`, `
    <h1>เดโม 1: การเก็บรหัสผ่าน</h1>
    <p>สมมติว่าแฮกเกอร์เจาะฐานข้อมูลออกมาได้ (SQL injection, backup หลุด, insider ฯลฯ)
       ตารางผู้ใช้ที่หลุดออกมาหน้าตาเป็นแบบนี้</p>

    <div class="card">
      <b>ตาราง users ${safe ? 'ฝั่ง SAFE' : 'ฝั่ง VULNERABLE'}</b>
      <table>
        <tr><th>username</th><th>role</th><th>${escapeHtml(col)}</th></tr>
        ${rows}
      </table>
    </div>

    ${safe ? `
      <div class="result">
        <p>✔ ฝั่ง safe เก็บเป็น <b>scrypt hash + salt</b> ไม่มีรหัสจริงอยู่ในฐานข้อมูลเลย</p>
        <ul class="tight">
          <li>DB หลุด แฮกเกอร์ก็เห็นแค่ค่า hash ยาวๆ เอาไปล็อกอินตรงๆ ไม่ได้</li>
          <li>ต้องมานั่งเดา (brute force / dictionary) ทีละรหัสแล้ว hash เทียบ ซึ่งช้ามากเพราะ scrypt จงใจหน่วงเวลา</li>
          <li>มี <b>salt</b> สุ่มต่อผู้ใช้ → ต่อให้สองคนตั้งรหัสเดียวกัน ค่า hash ก็ต่างกัน ใช้ rainbow table ไม่ได้</li>
        </ul>
      </div>` : `
      <div class="result" style="border-color:var(--red)">
        <p class="plain">❌ ฝั่ง vuln เก็บรหัสผ่านเป็น plain text</p>
        <ul class="tight">
          <li>DB หลุดเมื่อไร = เห็นรหัสผ่านจริงของทุกคน <b>ทันที</b> เอาไปล็อกอินได้เลย</li>
          <li>คนส่วนใหญ่ใช้รหัสซ้ำกันหลายเว็บ → แฮกเกอร์เอารหัสนี้ไปลองเว็บอื่นของเหยื่อต่อ (credential stuffing)</li>
          <li>แอดมิน/คนในองค์กรก็เห็นรหัสผ่านผู้ใช้หมด ซึ่งไม่ควรเกิดขึ้น</li>
        </ul>
      </div>`}

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/leak">/leak</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/leak">/safe/leak</a>'} · <a href="/">หน้าแรก</a></p>
  `, { mode: safe ? 'safe' : 'vuln', req });
}

// =====================================================================
// เดโม 2: Login + Brute force / rate limiting
// =====================================================================
function loginPage(req, safe, msg, msgType) {
  const base = safe ? '/safe/login' : '/login';
  const cls = msgType === 'ok' ? 'color:var(--green)' : msgType === 'warn' ? 'color:var(--amber)' : 'color:var(--red)';
  return page(`เข้าสู่ระบบ ${safe ? '(ปลอดภัย)' : ''}`, `
    <h1>เดโม 2: เข้าสู่ระบบ ${safe ? '✔ มี rate limit' : '⚠ ไม่จำกัดจำนวนครั้ง'}</h1>
    ${msg ? `<p class="result" style="${cls}">${escapeHtml(msg)}</p>` : ''}
    <form method="post" action="${base}" class="stack">
      <input name="username" placeholder="ชื่อผู้ใช้ (user หรือ admin)" required>
      <input name="password" type="password" placeholder="รหัสผ่าน" required>
      <button>เข้าสู่ระบบ</button>
    </form>
    <div class="result">
      <p>${safe
        ? `หน้านี้จำกัดจำนวนครั้ง: กรอกรหัสผิดเกิน <b>${MAX_FAILS} ครั้ง</b> บัญชีจะถูกล็อกชั่วคราว <b>${LOCK_MS / 1000} วินาที</b>`
        : `หน้านี้ <b>ไม่จำกัด</b> จำนวนครั้งที่กรอกผิด → ยิงเดารหัสได้ไม่อั้น`}</p>
      <p class="muted">บัญชีทดสอบ: <code>user</code>/<code>123456</code> · <code>admin</code>/<code>Tr0ub4dor&amp;3xK</code></p>
    </div>
    <p class="switch">
      ${safe ? 'ดูแบบมีช่องโหว่: <a href="/login">/login</a>' : 'ดูแบบแก้แล้ว: <a href="/safe/login">/safe/login</a>'}
      · เครื่องมือเดารหัส: <a href="${safe ? '/safe/guess' : '/guess'}">${safe ? '/safe/guess' : '/guess'}</a>
      · <a href="/">หน้าแรก</a>
    </p>
  `, { mode: safe ? 'safe' : 'vuln', req });
}

// หน้าแสดงผลหลังล็อกอินสำเร็จ (มี marker คำว่า "สำเร็จ" ให้เครื่องมือตรวจจับได้)
function loginResultPage(req, safe, username) {
  const acct = safe ? '/safe/account' : '/account';
  return page('ผลการเข้าสู่ระบบ', `
    <h1>✅ เข้าสู่ระบบสำเร็จ</h1>
    <p class="result" style="color:var(--green)">ยินดีต้อนรับ <b>${escapeHtml(username)}</b> — เข้าสู่ระบบสำเร็จแล้ว</p>
    <p><a href="${acct}">ไปหน้าบัญชีของฉัน</a> · <a href="/">หน้าแรก</a></p>
  `, { mode: safe ? 'safe' : 'vuln', req });
}

function accountPage(req, safe) {
  const u = safe ? currentSafeUser(req) : currentVulnUser(req);
  if (!u) {
    return page('บัญชีของฉัน', `
      <h1>บัญชีของฉัน ${safe ? '(ปลอดภัย)' : ''}</h1>
      <p class="result">ยังไม่ได้ล็อกอิน (หรือ token หมดอายุแล้ว) — <a href="${safe ? '/safe/login' : '/login'}">เข้าสู่ระบบ</a></p>
    `, { mode: safe ? 'safe' : 'vuln', req });
  }
  const tokenInfo = safe
    ? `<p>token ปัจจุบัน: <code>${escapeHtml(u.token)}</code></p>
       <p>หมดอายุใน: <b id="countdown">—</b> (ตั้งไว้ ${TOKEN_TTL / 1000} วินาที)</p>
       <script>
         const exp=${u.expires};
         function tick(){const s=Math.max(0,Math.round((exp-Date.now())/1000));
           document.getElementById('countdown').textContent=s+' วินาที';
           if(s<=0){document.getElementById('countdown').textContent='หมดอายุแล้ว (รีเฟรชจะเด้งออก)';}}
         tick();setInterval(tick,1000);
       </script>`
    : `<p>คุกกี้ token ปัจจุบัน: <code>${escapeHtml(vulnTokenFor(u.name))}</code>
         = <code>base64("${escapeHtml(u.name)}")</code></p>
       <p class="plain">token นี้เดาได้ และไม่มีวันหมดอายุ</p>`;

  return page('บัญชีของฉัน', `
    <h1>บัญชีของฉัน ${safe ? '(ปลอดภัย)' : ''}</h1>
    <div class="result">
      <p>คุณเข้าใช้งานในชื่อ: <b>${escapeHtml(u.name)}</b></p>
      <p>สิทธิ์: ${escapeHtml(u.role)}</p>
      ${tokenInfo}
    </div>
    <p class="switch">
      <a href="${safe ? '/safe/logout' : '/logout'}">ออกจากระบบ</a> ·
      ${safe ? 'ดูเรื่อง token แบบ vuln: <a href="/token">/token</a>' : 'ดูเรื่อง token แบบ safe: <a href="/safe/token">/safe/token</a>'} ·
      <a href="/">หน้าแรก</a>
    </p>
  `, { mode: safe ? 'safe' : 'vuln', req });
}

// เครื่องมือ "เดารหัส" (จำลอง) — ยิงลองรหัสจาก wordlist ไปที่ /login หรือ /safe/login
function guessPage(req, safe) {
  const endpoint = safe ? '/safe/login' : '/login';
  const list = JSON.stringify(COMMON_PASSWORDS);
  return page(`เครื่องมือเดารหัส ${safe ? '(ยิงใส่หน้า safe)' : '(ยิงใส่หน้า vuln)'}`, `
    <h1>🤖 เครื่องมือเดารหัส (จำลอง)</h1>
    <p>เครื่องมือนี้จะไล่ลองรหัสผ่านยอดฮิต ${COMMON_PASSWORDS.length} ตัว ยิงไปที่ <code>${endpoint}</code> ทีละตัว
       แล้วดูว่าตัวไหนล็อกอินผ่าน ${safe
         ? '<b>(หน้านี้ยิงใส่เวอร์ชัน safe ที่มี rate limit)</b>'
         : '<b>(หน้านี้ยิงใส่เวอร์ชัน vuln ที่ไม่จำกัดจำนวนครั้ง)</b>'}</p>

    <form class="stack" onsubmit="return false">
      <input id="target" value="user" placeholder="ชื่อผู้ใช้ที่จะเดา">
      <button id="go" type="button">เริ่มเดารหัส</button>
    </form>

    <div class="log" id="log">พร้อมเริ่ม...</div>

    <p class="switch">
      ${safe ? 'ลองยิงใส่หน้ามีช่องโหว่: <a href="/guess">/guess</a>' : 'ลองยิงใส่หน้าแก้แล้ว: <a href="/safe/guess">/safe/guess</a>'}
      · <a href="/">หน้าแรก</a>
    </p>

    <script>
      const WORDLIST = ${list};
      const ENDPOINT = ${JSON.stringify(endpoint)};
      const log = document.getElementById('log');
      function line(html){ log.innerHTML += '\\n' + html; log.scrollTop = log.scrollHeight; }
      document.getElementById('go').onclick = async () => {
        const username = document.getElementById('target').value.trim() || 'user';
        log.innerHTML = 'เริ่มเดารหัสของบัญชี "' + username + '" ...';
        let found = null, blocked = false;
        for (let i = 0; i < WORDLIST.length; i++) {
          const pw = WORDLIST[i];
          const body = new URLSearchParams({ username, password: pw, tool: '1' });
          let text = '';
          try {
            const r = await fetch(ENDPOINT, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body });
            text = await r.text();
          } catch (e) { line('<span class="fail">ครั้งที่ '+(i+1)+': error</span>'); continue; }
          if (text.includes('สำเร็จ')) {
            line('<span class="ok">ครั้งที่ '+(i+1)+': ลอง "'+pw+'" → ✅ สำเร็จ! รหัสคือ \\''+pw+'\\'</span>');
            found = pw; break;
          } else if (text.includes('ถูกล็อกชั่วคราว')) {
            line('<span class="warn">ครั้งที่ '+(i+1)+': ลอง "'+pw+'" → 🔒 บัญชีถูกล็อกชั่วคราว! เครื่องมือยิงต่อไม่ได้</span>');
            blocked = true; break;
          } else {
            line('ครั้งที่ '+(i+1)+': ลอง "'+pw+'" → ผิด');
          }
        }
        if (found) line('\\n<span class="ok">=== เดารหัสสำเร็จใน '+(WORDLIST.indexOf(found)+1)+' ครั้ง: '+username+' / '+found+' ===</span>');
        else if (blocked) line('\\n<span class="warn">=== ถูก rate limit บล็อกก่อนเดาเจอ การโจมตีล้มเหลว ===</span>');
        else line('\\n<span class="fail">=== เดาไม่เจอจาก wordlist นี้ (รหัสแข็งเกินไป) ===</span>');
      };
    </script>
  `, { mode: safe ? 'safe' : 'vuln', req });
}

// =====================================================================
// เดโม 3: Session token
// =====================================================================
function tokenPageVuln(req) {
  const names = Object.keys(db.vulnUsers);
  const rows = names.map((n) =>
    `<tr><td><code>${escapeHtml(n)}</code></td><td><code>${escapeHtml(vulnTokenFor(n))}</code></td>
     <td><a href="/forge?user=${encodeURIComponent(n)}">สวมรอยเป็น ${escapeHtml(n)}</a></td></tr>`
  ).join('');
  return page('Session token (เดาได้)', `
    <h1>เดโม 3: Session token ที่เดาได้ ⚠</h1>
    <p>หน้า vuln นี้ออก token แบบง่ายๆ: <code>token = base64(ชื่อผู้ใช้)</code> และ <b>ไม่มีวันหมดอายุ</b>
       ใครก็คำนวณ token ของคนอื่นได้ทันที แล้วเอาไปตั้งเป็นคุกกี้ <code>auth</code> เพื่อสวมรอย</p>

    <div class="card">
      <b>token ของแต่ละบัญชี (คำนวณได้โดยไม่ต้องรู้รหัสผ่าน)</b>
      <table>
        <tr><th>username</th><th>token = base64(username)</th><th>ลองสวมรอย</th></tr>
        ${rows}
      </table>
    </div>

    <p>กดลิงก์ "สวมรอยเป็น admin" ด้านบน → เซิร์ฟเวอร์จะตั้งคุกกี้ <code>auth</code> ให้เป็น token ของ admin
       แล้วพาไป <a href="/account">/account</a> ซึ่งจะกลายเป็น admin ทันที <b>โดยไม่ต้องกรอกรหัสผ่านเลย</b></p>

    <div class="result" style="border-color:var(--red)">
      <p class="plain">ทำไมถึงอันตราย</p>
      <ul class="tight">
        <li>token คาดเดาได้ → แฮกเกอร์ปลอม session ของใครก็ได้</li>
        <li>ไม่มีวันหมดอายุ → token ที่หลุดครั้งเดียว ใช้ได้ตลอดกาล ถอน (revoke) ก็ไม่ได้เพราะไม่ได้เก็บไว้ที่เซิร์ฟเวอร์</li>
      </ul>
    </div>

    <p class="switch">ดูแบบแก้แล้ว: <a href="/safe/token">/safe/token</a> · <a href="/">หน้าแรก</a></p>
  `, { mode: 'vuln', req });
}

function tokenPageSafe(req) {
  const su = currentSafeUser(req);
  const demo = crypto.randomBytes(16).toString('hex'); // โชว์ให้ดูว่าหน้าตา token สุ่มเป็นยังไง
  return page('Session token (สุ่ม + หมดอายุ)', `
    <h1>เดโม 3: Session token ที่ปลอดภัย ✔</h1>
    <p>หน้า safe ออก token ด้วย <code>crypto.randomBytes(16)</code> (สุ่ม 128 บิต) เก็บไว้ที่เซิร์ฟเวอร์พร้อม
       <b>เวลาหมดอายุ</b> ตัวอย่าง token ที่สุ่มได้ตอนนี้: <code>${demo}</code></p>

    <div class="result">
      <p>✔ ทำไมถึงปลอดภัยกว่า</p>
      <ul class="tight">
        <li><b>เดาไม่ได้:</b> สุ่ม 128 บิต ไม่มีความเชื่อมโยงกับชื่อผู้ใช้ จะไล่เดาก็แทบเป็นไปไม่ได้</li>
        <li><b>หมดอายุได้:</b> token อยู่ได้ ${TOKEN_TTL / 1000} วินาที (ในแล็บตั้งสั้นเพื่อให้เห็นชัด) แล้วใช้ต่อไม่ได้</li>
        <li><b>ถอนได้:</b> token เก็บอยู่ที่เซิร์ฟเวอร์ (Map) อยากตัด session ก็ลบทิ้งได้ทันที (logout = ลบออกจาก Map)</li>
      </ul>
    </div>

    ${su
      ? `<p>ตอนนี้คุณล็อกอินฝั่ง safe เป็น <b>${escapeHtml(su.name)}</b> — ไปดู countdown เวลาหมดอายุที่
         <a href="/safe/account">/safe/account</a></p>`
      : `<p>ลองล็อกอินฝั่ง safe ที่ <a href="/safe/login">/safe/login</a> แล้วดู token + countdown ที่ <a href="/safe/account">/safe/account</a></p>`}

    <p class="switch">ดูแบบมีช่องโหว่: <a href="/token">/token</a> · <a href="/">หน้าแรก</a></p>
  `, { mode: 'safe', req });
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

    // ----- GET -----
    if (req.method === 'GET') {
      switch (p) {
        case '/': return send(res, 200, homePage(req));
        case '/reset': db = seed(); return redirect(res, '/');

        // เดโม 1
        case '/leak': return send(res, 200, leakPage(req, false));
        case '/safe/leak': return send(res, 200, leakPage(req, true));

        // เดโม 2
        case '/login': return send(res, 200, loginPage(req, false));
        case '/safe/login': return send(res, 200, loginPage(req, true));
        case '/account': return send(res, 200, accountPage(req, false));
        case '/safe/account': return send(res, 200, accountPage(req, true));
        case '/guess': return send(res, 200, guessPage(req, false));
        case '/safe/guess': return send(res, 200, guessPage(req, true));
        case '/logout': return redirect(res, '/login', 'auth=; Path=/; Max-Age=0');
        case '/safe/logout': {
          const tok = parseCookies(req).safe_auth;
          if (tok) db.safeTokens.delete(tok);
          return redirect(res, '/safe/login', 'safe_auth=; Path=/; Max-Age=0');
        }

        // เดโม 3
        case '/token': return send(res, 200, tokenPageVuln(req));
        case '/safe/token': return send(res, 200, tokenPageSafe(req));

        // สวมรอยด้วย token ที่เดาได้ (ฝั่ง vuln) — ตั้งคุกกี้ auth = base64(user) โดยไม่ต้องรู้รหัส
        case '/forge': {
          const user = url.searchParams.get('user') || '';
          if (!db.vulnUsers[user]) { res.writeHead(400); return res.end('ไม่พบบัญชีนี้'); }
          console.log(`\x1b[31m[TOKEN FORGE] สวมรอยเป็น "${user}" ด้วย token ที่เดาได้ (base64) โดยไม่ต้องใช้รหัสผ่าน\x1b[0m`);
          return redirect(res, '/account', `auth=${vulnTokenFor(user)}; Path=/; SameSite=Lax`);
        }
      }
    }

    // ----- POST -----
    if (req.method === 'POST') {
      const form = await readForm(req);
      const username = (form.get('username') || '').trim();
      const password = form.get('password') || '';
      const byTool = form.get('tool') === '1';

      // ❌ ล็อกอินแบบมีช่องโหว่: เทียบรหัส plain text + ไม่จำกัดจำนวนครั้ง
      if (p === '/login') {
        const u = db.vulnUsers[username];
        if (u && password === u.password) {
          if (byTool) console.log(`\x1b[31m[BRUTE FORCE] เดารหัสของ "${username}" สำเร็จ: ${password} (ไม่มี rate limit จึงยิงได้ไม่อั้น)\x1b[0m`);
          const cookie = `auth=${vulnTokenFor(username)}; Path=/; SameSite=Lax`;
          if (byTool) return sendText(res, 200, 'เข้าสู่ระบบสำเร็จ', { cookie });
          return send(res, 200, loginResultPage(req, false, username), { cookie });
        }
        if (byTool) return sendText(res, 200, 'รหัสผ่านไม่ถูกต้อง');
        return send(res, 200, loginPage(req, false, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'err'));
      }

      // ✅ ล็อกอินแบบปลอดภัย: เทียบ hash + จำกัดจำนวนครั้ง (lockout)
      if (p === '/safe/login') {
        const key = username || '(ว่าง)';
        const st = lockState(key);
        if (st.locked) {
          const msg = `บัญชี "${username}" ถูกล็อกชั่วคราว ลองใหม่ในอีก ${st.retry} วินาที`;
          if (byTool) return sendText(res, 429, msg);
          return send(res, 200, loginPage(req, true, msg, 'warn'));
        }
        const u = db.safeUsers[username];
        if (u && verifyPassword(password, u.hash)) {
          recordSuccess(key);
          const tok = crypto.randomBytes(16).toString('hex');
          db.safeTokens.set(tok, { user: username, expires: Date.now() + TOKEN_TTL });
          const cookie = `safe_auth=${tok}; Path=/; HttpOnly; SameSite=Lax`;
          if (byTool) return sendText(res, 200, 'เข้าสู่ระบบสำเร็จ', { cookie });
          return send(res, 200, loginResultPage(req, true, username), { cookie });
        }
        recordFail(key);
        const st2 = lockState(key);
        const msg = st2.locked
          ? `กรอกผิดเกิน ${MAX_FAILS} ครั้ง — บัญชี "${username}" ถูกล็อกชั่วคราว ${LOCK_MS / 1000} วินาที`
          : 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง';
        if (byTool) return sendText(res, st2.locked ? 429 : 200, st2.locked ? `ถูกล็อกชั่วคราว: ${msg}` : msg);
        return send(res, 200, loginPage(req, true, msg, st2.locked ? 'warn' : 'err'));
      }
    }

    send(res, 404, page('404', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', { req }));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) { res.writeHead(500); res.end('error'); }
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  Authentication Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ลอง: /leak (ฐานข้อมูลรั่ว) · /guess (เดารหัส) · /token (สวมรอย)');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
