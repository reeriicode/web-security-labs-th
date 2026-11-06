// =====================================================================
//  Secrets Lab — เว็บที่ "ตั้งใจ" ให้ความลับรั่วไหล เพื่อการเรียนรู้การป้องกัน
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
//
//  ⚠ ค่า secret ทุกตัวในแล็บนี้เป็น "ค่าปลอม" ที่เห็นชัดว่าเป็น placeholder
//     เช่น DEMO_FAKE_API_KEY_... / sk_test_FAKE_... ห้ามนำไปใช้จริง
// =====================================================================

const http = require('http');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในวง LAN เข้าไม่ได้
const PORT = Number(process.env.PORT) || 4600;

// ---------------------------------------------------------------------
// ความลับฝั่งเซิร์ฟเวอร์ (ปกติมาจาก environment variable / .env ที่ "ไม่" อยู่ในเว็บรูท)
// ในแล็บนี้ถ้าไม่ตั้ง env ไว้ จะใช้ค่าปลอมที่เห็นชัดว่าเป็น placeholder
// จุดสำคัญ: ค่าพวกนี้อยู่ในหน่วยความจำของ "เซิร์ฟเวอร์" เท่านั้น ไม่เคยถูกส่งไปที่เบราว์เซอร์
// ---------------------------------------------------------------------
const CONFIG = {
  TRANSLATE_API_KEY: process.env.TRANSLATE_API_KEY || 'sk_test_FAKE_not_a_real_key_0000',
  DB_PASSWORD: process.env.DB_PASSWORD || 'DEMO_FAKE_DB_PASSWORD_change_me',
  JWT_SECRET: process.env.JWT_SECRET || 'DEMO_FAKE_JWT_SECRET_do_not_use',
};

// นับว่าช่องทางไหนถูกเรียกด้วย key ที่ "มองเห็นได้จากฝั่งเบราว์เซอร์" บ้าง (ไว้โชว์ผล)
const stats = { exposedCalls: 0, proxyCalls: 0, envLeaks: 0 };

// ---------------------------------------------------------------------
// เนื้อหาไฟล์ .env ปลอม (ค่า dummy ทั้งหมด) — จำลองไฟล์ที่ "เผลอ" วางไว้ในเว็บรูท
// ---------------------------------------------------------------------
const FAKE_ENV_FILE = `# ไฟล์ตั้งค่าลับของแอป (ตัวอย่างปลอมสำหรับแล็บ ห้ามใช้จริง)
TRANSLATE_API_KEY=sk_test_FAKE_not_a_real_key_0000
DB_HOST=127.0.0.1
DB_USER=app_admin
DB_PASSWORD=DEMO_FAKE_DB_PASSWORD_change_me
JWT_SECRET=DEMO_FAKE_JWT_SECRET_do_not_use
SESSION_SECRET=DEMO_FAKE_SESSION_SECRET_1234
`;

// ---------------------------------------------------------------------
// ✅ ฟังก์ชันหัวใจของการแสดงผลอย่างปลอดภัย: แปลงอักขระพิเศษให้เป็นข้อความธรรมดา
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
// CSS ฝังในโค้ด (ไม่ต้องมีไฟล์แยก)
// ---------------------------------------------------------------------
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#1d4ed8;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb;--amber:#b45309;--amber-bg:#fff7e6}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px;line-height:1.8}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
form{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:420px}
input{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#64748b}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.leak{background:var(--red-bg);border:1px solid #f1b0b0;border-radius:12px;padding:16px 20px;margin:14px 0}
.ok{background:var(--green-bg);border:1px solid #bfe3c9;border-radius:12px;padding:16px 20px;margin:14px 0}
.warn{background:var(--amber-bg);border:1px solid #f0d49a;border-radius:12px;padding:12px 16px;margin:14px 0;color:var(--amber)}
table{width:100%;border-collapse:collapse;background:var(--card);margin:12px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f1f4f8}
code{font-family:Consolas,"Courier New",monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;line-height:1.5}
.keyout{font-family:Consolas,monospace;font-size:15px;font-weight:700;color:var(--red)}
`;

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, mode) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  return `<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Secrets Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header><a href="/" class="logo">🔐 Secrets Lab</a>${badge}</header>
  <main>${body}</main>
  <footer>
    ⚠ แล็บนี้ตั้งใจให้มีช่องโหว่ ใช้บนเครื่องตัวเองเท่านั้น · ห้าม deploy · ห้ามใช้กับระบบที่ไม่ได้รับอนุญาต<br>
    การเข้าถึง/ทดสอบระบบของผู้อื่นโดยไม่ได้รับอนุญาตผิด พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ฯ · Anti-hacking matters
  </footer>
</body>
</html>`;
}

// ---------------------------------------------------------------------
// การส่ง response
// ---------------------------------------------------------------------
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function sendText(res, status, text, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type });
  res.end(text);
}
function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function redirect(res, location) {
  res.writeHead(303, { Location: location });
  res.end();
}

// ---------------------------------------------------------------------
// จำลอง "ผู้ให้บริการภายนอก" (third-party API) ที่ต้องใช้ API key
// เช่น บริการแปลภาษา ในชีวิตจริงคือโดเมนของผู้ให้บริการ เช่น api.provider.com
// มันจะยอมทำงานก็ต่อเมื่อ apikey ถูกต้องเท่านั้น
// ---------------------------------------------------------------------
const MINI_DICT = {
  'สวัสดี': 'hello', 'ขอบคุณ': 'thank you', 'แมว': 'cat', 'หมา': 'dog',
  'บ้าน': 'house', 'น้ำ': 'water', 'กิน': 'eat', 'รัก': 'love', 'หนังสือ': 'book',
};
function callProvider(apikey, text) {
  if (apikey !== CONFIG.TRANSLATE_API_KEY) {
    return { ok: false, error: 'API key ไม่ถูกต้อง — ผู้ให้บริการปฏิเสธคำขอ' };
  }
  const t = (text || '').trim();
  const translated = MINI_DICT[t] || `[แปลจำลอง] ${t}`;
  return { ok: true, input: t, translated };
}

// ---------------------------------------------------------------------
// JavaScript ฝั่งเบราว์เซอร์ของ Lab 1 (เสิร์ฟเป็นไฟล์ .js จริง → เห็นใน View Source / DevTools Sources)
// ---------------------------------------------------------------------

// ❌ โหมด vuln: API key (ปลอม) ถูกฝังอยู่ในโค้ดฝั่ง client ตรงๆ
const APP_VULN_JS = `// ====== โค้ดฝั่งเบราว์เซอร์ (โหมดมีช่องโหว่) ======
// ⚠ API key ถูกฝังไว้ในไฟล์นี้ตรงๆ — ไฟล์นี้ถูกส่งไปที่เบราว์เซอร์ของทุกคน
//    ใครเปิด View Source หรือ DevTools > Sources ก็เห็นค่านี้ได้ทันที
const API_KEY = ${JSON.stringify(CONFIG.TRANSLATE_API_KEY)};  // ← ความลับที่ไม่ควรอยู่ตรงนี้!

async function translate() {
  const text = document.getElementById('text').value;
  // เบราว์เซอร์ยิงตรงไปที่ผู้ให้บริการ พร้อมแนบ key ไปใน URL (เห็นได้ในแท็บ Network ด้วย)
  const url = '/thirdparty/translate?apikey=' + encodeURIComponent(API_KEY)
            + '&text=' + encodeURIComponent(text);
  const res = await fetch(url);
  const data = await res.json();
  document.getElementById('out').textContent =
    data.ok ? ('คำแปล: ' + data.translated) : ('ผิดพลาด: ' + data.error);
}
document.getElementById('go').addEventListener('click', translate);
`;

// ✅ โหมด safe: ไม่มี key ในฝั่ง client เลย เรียกผ่าน backend proxy ของเราเอง
const APP_SAFE_JS = `// ====== โค้ดฝั่งเบราว์เซอร์ (โหมดปลอดภัย) ======
// ✅ ไม่มี API key อยู่ในไฟล์นี้เลย ค้นหาคำว่า KEY ในไฟล์นี้ก็ไม่เจอ
//    frontend เรียก backend ของเราเอง (/api/translate) แล้วเซิร์ฟเวอร์เป็นคนแนบ key ให้ผู้ให้บริการ
async function translate() {
  const text = document.getElementById('text').value;
  const res = await fetch('/api/translate?text=' + encodeURIComponent(text)); // ไม่มี key ใน URL
  const data = await res.json();
  document.getElementById('out').textContent =
    data.ok ? ('คำแปล: ' + data.translated) : ('ผิดพลาด: ' + data.error);
}
document.getElementById('go').addEventListener('click', translate);
`;

// ---------------------------------------------------------------------
// "เว็บรูท" จำลองของ static server (Lab 2)
// ในโลกจริงนี่คือโฟลเดอร์ที่เว็บเซิร์ฟเวอร์เปิดให้ดาวน์โหลดไฟล์ได้
// ปัญหา: มีคนเผลอวางไฟล์ .env ไว้ในโฟลเดอร์นี้
// ---------------------------------------------------------------------
const WEBROOT = {
  'index.html': '<!doctype html><meta charset="utf-8"><h1>ไฟล์สาธารณะของเว็บ</h1><p>นี่คือไฟล์ปกติที่ตั้งใจให้คนทั่วไปโหลดได้</p>',
  'app.js': 'console.log("ไฟล์ JavaScript ปกติในเว็บรูท ไม่มีความลับ");',
  'robots.txt': 'User-agent: *\nDisallow:',
  '.env': FAKE_ENV_FILE, // ← เผลอวางไฟล์ลับไว้ในเว็บรูท นี่คือต้นเหตุ
};

// เสิร์ฟไฟล์จากเว็บรูทจำลอง
//  - blockDotfiles=false (vuln): ใครขอไฟล์อะไรก็เสิร์ฟหมด รวมถึง .env
//  - blockDotfiles=true  (safe): บล็อกไฟล์ dotfiles (ขึ้นต้นด้วยจุด) และกัน path traversal
function serveFromWebroot(res, rawName, { blockDotfiles }) {
  const name = decodeURIComponent(rawName);

  // กัน path traversal เสมอ (ทั้งสองโหมด) — ไม่ให้หลุดออกนอกเว็บรูท
  if (name.includes('..') || name.includes('/') || name.includes('\\')) {
    return sendText(res, 400, 'คำขอไม่ถูกต้อง');
  }

  const ext = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.env': 'text/plain; charset=utf-8' };

  if (blockDotfiles && name.startsWith('.')) {
    // ✅ ปิดการเข้าถึง dotfiles เช่น .env .git ฯลฯ
    console.log(`\x1b[32m[SAFE] บล็อกการเข้าถึง dotfile: ${name} → 403\x1b[0m`);
    return sendText(res, 403, '403 Forbidden — ไม่อนุญาตให้เข้าถึงไฟล์นี้');
  }

  if (!(name in WEBROOT)) {
    return sendText(res, 404, '404 Not Found');
  }

  const type = ext['.' + name.split('.').pop()] || 'text/plain; charset=utf-8';
  if (name === '.env') {
    stats.envLeaks++;
    console.log(`\x1b[31m[LEAK] ไฟล์ .env ถูกเสิร์ฟออกไป! (รั่วครั้งที่ ${stats.envLeaks})\x1b[0m`);
  }
  return sendText(res, 200, WEBROOT[name], type);
}

// =====================================================================
// หน้าแรก
// =====================================================================
function homePage() {
  return page('หน้าแรก', `
    <h1>Secrets Lab 🔐</h1>
    <p>แล็บฝึกทำความเข้าใจ <b>Secrets Exposure (ความลับรั่วไหล)</b> — API key, รหัสผ่าน และ token
       ที่หลุดออกไปในที่ที่ไม่ควรอยู่ แต่ละหัวข้อมีหน้า
       <span class="badge vuln">VULNERABLE</span> ให้ลองดูของจริง และหน้า
       <span class="badge safe">SAFE</span> ที่แก้แล้วให้เทียบกัน</p>

    <div class="warn">ℹ ค่า secret ทุกตัวในแล็บนี้เป็น <b>ค่าปลอม</b> ที่เห็นชัดว่าเป็น placeholder
      (เช่น <code>sk_test_FAKE_not_a_real_key_0000</code>) ไม่ใช่ key จริงของผู้ให้บริการใด</div>

    <table>
      <tr><th>Lab</th><th>หัวข้อ</th><th>มีช่องโหว่</th><th>แก้แล้ว</th></tr>
      <tr><td>1</td><td>Secret ฝังอยู่ใน frontend (client-side)</td>
          <td><a href="/frontend">/frontend</a></td><td><a href="/safe/frontend">/safe/frontend</a></td></tr>
      <tr><td>2</td><td>ไฟล์ <code>.env</code> ถูกเสิร์ฟโดยไม่ตั้งใจ</td>
          <td><a href="/envleak">/envleak</a></td><td><a href="/safe/envleak">/safe/envleak</a></td></tr>
    </table>

    <h2>แนวคิดหลักข้อเดียวที่ต้องจำ</h2>
    <div class="card">
      <p>🧠 <b>อะไรก็ตามที่ถูกส่งไปถึงเบราว์เซอร์ของผู้ใช้ ถือว่า "เปิดเผย" ทั้งหมด</b></p>
      <p>HTML, JavaScript, ไฟล์ static — ผู้ใช้เปิดดู ดาวน์โหลด และแกะได้หมด
         ความลับ (API key, รหัสผ่าน, token) จึงต้องอยู่<b>ฝั่งเซิร์ฟเวอร์เท่านั้น</b>
         และต้องไม่ถูกวางไว้ในที่ที่ดาวน์โหลดได้</p>
    </div>

    <p class="switch">อยากรีเซ็ตตัวนับสถิติของแล็บ: <a href="/reset">/reset</a></p>
  `, null);
}

// =====================================================================
// Lab 1: Secret ฝังใน frontend
// =====================================================================
function frontendPage(safe) {
  const base = safe ? '/safe/frontend' : '/frontend';
  const jsFile = safe ? '/static/app-safe.js' : '/static/app-vuln.js';

  const explain = safe
    ? `<div class="ok">
         <b>✔ โหมดปลอดภัย:</b> หน้านี้โหลด <code>/static/app-safe.js</code> ซึ่ง
         <b>ไม่มี API key อยู่เลย</b> frontend เรียก backend ของเราเอง (<code>/api/translate</code>)
         แล้วเซิร์ฟเวอร์เป็นคนแนบ key ให้ผู้ให้บริการภายนอก key จึงไม่เคยออกไปถึงเบราว์เซอร์
       </div>`
    : `<div class="leak">
         <b>⚠ โหมดมีช่องโหว่:</b> หน้านี้โหลด <code>/static/app-vuln.js</code> ซึ่งมี
         API key ฝังอยู่ในโค้ด <b>ตรงๆ</b> ลองเปิดดูได้เลย:
         <ul>
           <li>คลิกขวา → <b>View Page Source</b> หรือเปิดไฟล์ <a href="${escapeHtml(jsFile)}" target="_blank">${escapeHtml(jsFile)}</a> ตรงๆ</li>
           <li>เปิด DevTools (F12) → แท็บ <b>Sources</b> → ไฟล์ <code>app-vuln.js</code></li>
           <li>เปิด DevTools → แท็บ <b>Network</b> แล้วกดแปล จะเห็น key ถูกส่งไปใน URL ด้วย</li>
         </ul>
       </div>`;

  return page('Lab 1: Secret ใน frontend', `
    <h1>Lab 1: Secret ฝังใน frontend ${safe ? '✔' : '⚠'}</h1>
    <p>แอปแปลภาษาที่เรียกใช้บริการแปลภายนอก (third-party API) ซึ่งต้องใช้ API key</p>

    ${explain}

    <div class="card">
      <h2>ลองใช้งานแอปแปลภาษา</h2>
      <p class="muted">ลองพิมพ์: สวัสดี / ขอบคุณ / แมว / หมา / น้ำ</p>
      <input id="text" placeholder="พิมพ์คำภาษาไทย" value="สวัสดี">
      <button id="go">แปล</button>
      <p id="out" class="result">ผลลัพธ์จะแสดงตรงนี้</p>
    </div>

    <p>${safe
      ? 'ลองค้นหาคำว่า <code>KEY</code> ในไฟล์ <a href="/static/app-safe.js" target="_blank">app-safe.js</a> — จะไม่เจอ'
      : 'เปิดไฟล์ <a href="/static/app-vuln.js" target="_blank">app-vuln.js</a> แล้วมองหาบรรทัด <code>const API_KEY = ...</code>'}</p>

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/frontend">/frontend</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/frontend">/safe/frontend</a>'}</p>

    <script src="${escapeHtml(jsFile)}"></script>
  `, safe ? 'safe' : 'vuln');
}

// =====================================================================
// Lab 2: ไฟล์ .env ถูกเสิร์ฟโดยไม่ตั้งใจ
// =====================================================================
function envLeakPage(safe) {
  const rawBase = safe ? '/safe/raw' : '/raw';

  const explain = safe
    ? `<div class="ok">
         <b>✔ โหมดปลอดภัย:</b> static server บล็อกไฟล์ที่ขึ้นต้นด้วยจุด (dotfiles เช่น
         <code>.env</code>, <code>.git</code>) และกัน path traversal ลองกดลิงก์ <code>.env</code> ด้านล่าง
         จะได้ <b>403 Forbidden</b>
       </div>`
    : `<div class="leak">
         <b>⚠ โหมดมีช่องโหว่:</b> static server เสิร์ฟทุกไฟล์ในเว็บรูท <b>รวมถึง <code>.env</code></b>
         ที่มีคนเผลอวางไว้ ใครเดา URL ถูกก็โหลดความลับทั้งไฟล์ไปได้เลย
       </div>`;

  return page('Lab 2: .env รั่ว', `
    <h1>Lab 2: ไฟล์ .env ถูกเสิร์ฟโดยไม่ตั้งใจ ${safe ? '✔' : '⚠'}</h1>
    <p>เว็บมีโฟลเดอร์ static สำหรับเสิร์ฟไฟล์สาธารณะ แต่มีคนเผลอวางไฟล์ <code>.env</code>
       (ที่เก็บความลับ) ไว้ในโฟลเดอร์เดียวกัน</p>

    ${explain}

    <div class="card">
      <h2>ไฟล์ในเว็บรูทจำลอง</h2>
      <table>
        <tr><th>ไฟล์</th><th>ควรเข้าถึงได้ไหม</th><th>ลองโหลด</th></tr>
        <tr><td><code>index.html</code></td><td>✔ ไฟล์สาธารณะปกติ</td><td><a href="${rawBase}/index.html" target="_blank">เปิด</a></td></tr>
        <tr><td><code>app.js</code></td><td>✔ ไฟล์สาธารณะปกติ</td><td><a href="${rawBase}/app.js" target="_blank">เปิด</a></td></tr>
        <tr><td><code>robots.txt</code></td><td>✔ ไฟล์สาธารณะปกติ</td><td><a href="${rawBase}/robots.txt" target="_blank">เปิด</a></td></tr>
        <tr><td><code class="keyout">.env</code></td><td>✘ <b>ไม่ควร!</b> มีความลับ</td><td><a href="${rawBase}/.env" target="_blank">เปิด /.env</a></td></tr>
      </table>
      <p class="muted">${safe
        ? 'ไฟล์สาธารณะยังโหลดได้ปกติ แต่ <code>.env</code> จะโดนบล็อก (403)'
        : 'ลองกด "เปิด /.env" จะเห็นเนื้อหาไฟล์ลับทั้งไฟล์ (ค่าปลอมในแล็บนี้)'}</p>
    </div>

    <div class="warn">
      ℹ แนวโจมตีจริง: แฮกเกอร์มักลองเดา URL อย่าง <code>/.env</code>, <code>/.git/config</code>,
      <code>/config.php.bak</code>, <code>/.env.backup</code> กับเว็บเป้าหมายแบบอัตโนมัติ
      ถ้าเซิร์ฟเวอร์เผลอเสิร์ฟให้ ก็ได้ความลับไปฟรีๆ
    </div>

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/envleak">/envleak</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe/envleak">/safe/envleak</a>'}</p>
  `, safe ? 'safe' : 'vuln');
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;

  try {
    // ---- ไฟล์ static ของตัวแล็บเอง ----
    if (req.method === 'GET' && p === '/static/style.css') {
      return sendText(res, 200, STYLE, 'text/css; charset=utf-8');
    }
    if (req.method === 'GET' && p === '/static/app-vuln.js') {
      return sendText(res, 200, APP_VULN_JS, 'text/javascript; charset=utf-8');
    }
    if (req.method === 'GET' && p === '/static/app-safe.js') {
      return sendText(res, 200, APP_SAFE_JS, 'text/javascript; charset=utf-8');
    }

    if (req.method === 'GET') {
      // ---- หน้าเว็บ ----
      if (p === '/') return sendHtml(res, 200, homePage());
      if (p === '/frontend') return sendHtml(res, 200, frontendPage(false));
      if (p === '/safe/frontend') return sendHtml(res, 200, frontendPage(true));
      if (p === '/envleak') return sendHtml(res, 200, envLeakPage(false));
      if (p === '/safe/envleak') return sendHtml(res, 200, envLeakPage(true));

      if (p === '/reset') {
        stats.exposedCalls = 0; stats.proxyCalls = 0; stats.envLeaks = 0;
        console.log('[RESET] รีเซ็ตตัวนับสถิติของแล็บแล้ว');
        return redirect(res, '/');
      }

      // ---- Lab 2: static server จำลอง ----
      // ❌ vuln: ไม่บล็อก dotfiles → /raw/.env รั่ว
      if (p.startsWith('/raw/')) {
        return serveFromWebroot(res, p.slice('/raw/'.length), { blockDotfiles: false });
      }
      // ✅ safe: บล็อก dotfiles → /safe/raw/.env ได้ 403
      if (p.startsWith('/safe/raw/')) {
        return serveFromWebroot(res, p.slice('/safe/raw/'.length), { blockDotfiles: true });
      }

      // ---- Lab 1: ผู้ให้บริการภายนอกจำลอง (รับ key ทาง query — จุดที่ key รั่วในโหมด vuln) ----
      if (p === '/thirdparty/translate') {
        stats.exposedCalls++;
        const apikey = url.searchParams.get('apikey') || '';
        console.log(`\x1b[31m[EXPOSED] /thirdparty/translate ถูกเรียกพร้อม key ที่มองเห็นได้จากเบราว์เซอร์: ${apikey}\x1b[0m`);
        return sendJson(res, 200, callProvider(apikey, url.searchParams.get('text')));
      }

      // ---- Lab 1: backend proxy ที่ปลอดภัย (frontend ไม่ต้องรู้ key) ----
      if (p === '/api/translate') {
        stats.proxyCalls++;
        // เซิร์ฟเวอร์เป็นคนแนบ key ให้เอง จาก CONFIG (มาจาก env) — ไม่เคยส่ง key กลับไปที่ client
        const result = callProvider(CONFIG.TRANSLATE_API_KEY, url.searchParams.get('text'));
        console.log('\x1b[32m[PROXY] /api/translate ทำงานโดยไม่เปิดเผย key ให้ client\x1b[0m');
        return sendJson(res, 200, result);
      }
    }

    sendHtml(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) sendHtml(res, 500, page('Error', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>', null));
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  Secrets Lab — เว็บนี้ตั้งใจให้ความลับรั่วไหล ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log('  \x1b[33m   ค่า secret ทั้งหมดเป็นค่าปลอม (placeholder) ไม่ใช่ key จริง\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ลอง Lab 1 (/frontend) แล้วเปิด DevTools > Sources ดู key ที่ฝังในหน้าเว็บ');
  console.log('  ลอง Lab 2 (/envleak) แล้วกดเปิด /.env ดูไฟล์ลับที่รั่ว');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
