// =====================================================================
//  Error-Handling Lab — เว็บที่ "ตั้งใจ" ให้จัดการ error แบบผิดๆ เพื่อการเรียนรู้
//  หัวข้อ: Improper Error Handling / Information Disclosure
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
const PORT = Number(process.env.PORT) || 4800;

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์แล้ว / กด /reset แล้วเริ่มใหม่)
// ---------------------------------------------------------------------
function seed() {
  return {
    // "ฐานข้อมูล" ผู้ใช้จำลอง (id เป็นเลขเท่านั้น)
    users: {
      1: { id: 1, username: 'alice', email: 'alice@corp.local', role: 'admin' },
      2: { id: 2, username: 'somchai', email: 'somchai@corp.local', role: 'user' },
    },
    // log ฝั่งเซิร์ฟเวอร์ (เลียนแบบไฟล์ log ที่ dev เปิดดูได้ ผู้ใช้ทั่วไปเห็นไม่ได้)
    serverLog: [],
  };
}
let db = seed();

// บันทึก error ไว้ฝั่งเซิร์ฟเวอร์ พร้อม error id เดียวกับที่ตอบผู้ใช้
function logServerSide(errorId, err, context) {
  const entry = {
    time: new Date().toLocaleTimeString('th-TH'),
    errorId,
    where: context,
    name: err.name,
    message: err.message,
    stack: err.stack,
  };
  db.serverLog.unshift(entry);
  db.serverLog.length = Math.min(db.serverLog.length, 50);
  // ✅ รายละเอียดจริง (stack trace) ถูก log ไว้ที่ server เท่านั้น ผู้ใช้ไม่เห็น
  console.log(`\x1b[33m[SERVER-LOG] error id=${errorId} ที่ ${context}\x1b[0m`);
  console.error(err);
}

function newErrorId() {
  return crypto.randomBytes(5).toString('hex'); // เช่น "9f3a1c7b2e"
}

// ---------------------------------------------------------------------
// ✅ แปลงอักขระพิเศษให้เป็นข้อความธรรมดา (กัน XSS ตอนแสดง error กลับไป)
// ---------------------------------------------------------------------
function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

// =====================================================================
// CSS ฝังไว้ในโค้ดเลย ไม่ต้องมีไฟล์แยก
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#2563eb;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb;--amber:#b45309}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px;border-top:1px solid var(--line);margin-top:24px}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
.who{margin-left:auto;color:var(--muted);font-size:14px}
form{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:420px}
input{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#6b7280}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.result.ok{background:var(--green-bg);border-color:#b6ddc3}
.result.bad{background:var(--red-bg);border-color:#f0c4c4}
table{width:100%;border-collapse:collapse;background:var(--card);margin:12px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f1f4f8}
code{font-family:Consolas,monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-word}
pre.leak{background:#2a0d0d;color:#ffb4b4;border:1px solid #7f1d1d}
.payloads li{margin:6px 0}
.payloads code{display:inline-block}
small{color:var(--muted)}
.kbd{display:inline-block;border:1px solid var(--line);border-bottom-width:2px;border-radius:5px;padding:0 6px;background:#f7f9fc;font-family:Consolas,monospace;font-size:13px}
`;

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, mode) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} · Error-Handling Lab</title><link rel="stylesheet" href="/static/style.css">
</head><body>
  <header>
    <a href="/" class="logo">🧯 Error-Handling Lab</a>${badge}
    <span class="who"><a href="/logs">📜 server log</a> · <a href="/reset">รีเซ็ต</a></span>
  </header>
  <main>${body}</main>
  <footer>เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น · ห้าม deploy · ห้ามใช้กับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ) · Anti-hacking matters</footer>
</body></html>`;
}

function send(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function redirect(res, location) {
  res.writeHead(303, { Location: location });
  res.end();
}

// =====================================================================
// ❤️ หัวใจของแล็บ: ตัวจัดการ error — vuln เทียบ safe
// =====================================================================

// ❌ โหมดมีช่องโหว่: โยน stack trace เต็ม + error ของระบบ/DB กลับไปแสดงบนหน้าเว็บ
//    ผู้โจมตีได้ path ไฟล์, เวอร์ชัน, ชื่อตาราง/คอลัมน์, query ไปวางแผนโจมตีต่อ
function renderErrorVuln(res, err, context) {
  // log ไว้ฝั่ง server ด้วย (เผื่อเทียบ) — แต่ปัญหาคือ "ยังส่งออกไปให้ผู้ใช้เห็นด้วย"
  console.error(`\x1b[31m[VULN] ${context}:\x1b[0m`, err);
  const body = `
    <h1>❌ เกิดข้อผิดพลาด (500 Internal Server Error)</h1>
    <p class="muted">หน้านี้ตอบกลับผู้ใช้ด้วย <b>รายละเอียด error ทั้งหมด</b> ซึ่งเป็นสิ่งที่ "ไม่ควรทำ"</p>

    <div class="result bad">
      <p><b>ชนิด:</b> <code>${escapeHtml(err.name)}</code>
        ${err.code ? `· <b>code:</b> <code>${escapeHtml(err.code)}</code>` : ''}</p>
      <p><b>ข้อความ:</b> ${escapeHtml(err.message)}</p>
    </div>

    <h2>Stack trace (หลุดไปถึงผู้ใช้)</h2>
    <pre class="leak">${escapeHtml(err.stack || '(ไม่มี stack)')}</pre>

    <h2>ข้อมูลระบบที่หลุดไปด้วย</h2>
    <pre class="leak">Node.js: ${escapeHtml(process.version)}
Platform: ${escapeHtml(process.platform)} (${escapeHtml(process.arch)})
App root: ${escapeHtml(__dirname)}
Working dir: ${escapeHtml(process.cwd())}</pre>

    <p class="switch">ข้อมูลพวกนี้บอกผู้โจมตีว่า: ใช้เทคโนโลยีอะไร เวอร์ชันไหน ไฟล์อยู่ path ไหน
       ฐานข้อมูลชื่อตาราง/คอลัมน์อะไร query หน้าตาแบบไหน → เอาไปหาช่องโหว่/เขียน payload ต่อได้ทันที</p>
    <p class="switch">ลองหน้าเดียวกันแบบแก้แล้ว แล้วเทียบว่าผู้ใช้เห็นอะไร:
       <a href="/safe">ไปหน้า SAFE</a> · <a href="/">กลับหน้าแรก</a></p>
  `;
  send(res, 500, page('500 — รายละเอียดหลุด', body, 'vuln'));
}

// ✅ โหมดปลอดภัย: ส่งข้อความทั่วไป + error id ให้ผู้ใช้ (HTTP 500)
//    แต่ log รายละเอียดจริง (stack trace) ไว้ฝั่ง server ด้วย error id เดียวกัน
//    → dev ตามสืบได้จาก log โดยไม่ต้องเปิดเผยอะไรต่อผู้ใช้เลย
function renderErrorSafe(res, err, context) {
  const errorId = newErrorId();
  logServerSide(errorId, err, context); // รายละเอียดจริงอยู่ที่ server เท่านั้น
  const body = `
    <h1>❌ ขออภัย เกิดข้อผิดพลาดบางอย่าง</h1>
    <div class="result bad">
      <p>ระบบไม่สามารถดำเนินการให้ได้ในขณะนี้ กรุณาลองใหม่อีกครั้ง</p>
      <p>หากติดต่อเจ้าหน้าที่ กรุณาแจ้งรหัสอ้างอิงนี้: <b>error id: <code>${escapeHtml(errorId)}</code></b></p>
    </div>
    <p class="muted">ผู้ใช้เห็นแค่นี้ — ไม่มี stack trace, ไม่มี path ไฟล์, ไม่มีชื่อตาราง/คอลัมน์, ไม่มีเวอร์ชัน</p>
    <p class="muted">รายละเอียดจริงทั้งหมด (stack trace) ถูกบันทึกไว้ฝั่งเซิร์ฟเวอร์ด้วย error id เดียวกันนี้
       → dev เปิดดูได้ที่ <a href="/logs">📜 server log</a> หรือใน terminal แล้วตามสืบต่อได้</p>
    <p class="switch">ลองหน้าเดียวกันแบบมีช่องโหว่ แล้วเทียบ: <a href="/">ไปหน้า VULNERABLE</a></p>
  `;
  send(res, 500, page('500 — ข้อผิดพลาด', body, 'safe'));
}

function handleError(res, err, mode, context) {
  if (mode === 'safe') return renderErrorSafe(res, err, context);
  return renderErrorVuln(res, err, context);
}

// =====================================================================
// งานเบื้องหลัง (จงใจให้ throw error ที่ "เผย" ข้อมูลภายใน)
// =====================================================================

// จำลอง query ไปที่ฐานข้อมูล PostgreSQL — error ของ driver เผยชื่อตาราง/คอลัมน์/query
function queryUserFromDb(id) {
  if (!/^\d+$/.test(String(id).trim())) {
    // เลียนแบบ error จริงจาก node-postgres (pg) เวลา id ผิดชนิด
    const err = new Error(
      `invalid input syntax for type integer: "${id}"\n` +
      `QUERY: SELECT id, username, email, password_hash, role FROM app_users WHERE id = '${id}' LIMIT 1\n` +
      `schema: public · table: app_users · driver: pg@8.11.3 · db: corp_prod@db-01.internal:5432`
    );
    err.name = 'DatabaseError';
    err.code = '22P02'; // รหัส error จริงของ PostgreSQL = invalid_text_representation
    throw err;
  }
  const user = db.users[Number(id)];
  if (!user) {
    const err = new Error(
      `no rows returned\n` +
      `QUERY: SELECT id, username, email, password_hash, role FROM app_users WHERE id = ${id} LIMIT 1`
    );
    err.name = 'DatabaseError';
    err.code = 'ROW_NOT_FOUND';
    throw err;
  }
  return user;
}

// จำลองเครื่องคิดเลขของระบบ — หารด้วยศูนย์ / ค่าไม่ใช่ตัวเลข ก็ throw
function calcDivide(a, b) {
  const x = Number(a), y = Number(b);
  if (!Number.isFinite(x) || !Number.isFinite(y)) {
    throw new TypeError(`ตัวตั้ง/ตัวหารต้องเป็นตัวเลข แต่ได้ a="${a}", b="${b}"`);
  }
  if (y === 0) {
    const err = new RangeError(`division by zero: ${x} / ${y}`);
    err.code = 'E_DIV_ZERO';
    throw err;
  }
  return x / y;
}

// =====================================================================
// หน้าเนื้อหา (คืน HTML body; ถ้ามีปัญหาให้ throw แล้ว router จะไปเข้า handleError)
// =====================================================================
function homePage() {
  return page('หน้าแรก', `
    <h1>Error-Handling Lab 🧯</h1>
    <p>แล็บฝึกเรื่อง <b>Improper Error Handling / Information Disclosure</b> —
       การเผยรายละเอียด error มากเกินไปจนกลายเป็นเบาะแสให้ผู้โจมตี</p>
    <p>ทุก endpoint มี 2 โหมดให้เทียบกัน: หน้าปกติ (prefix <code>/</code>)
       <span class="badge vuln">VULNERABLE</span> ส่ง error เต็มกลับไป
       ส่วนหน้า <code>/safe/...</code> <span class="badge safe">SAFE</span> ส่งแค่ข้อความทั่วไป + error id</p>

    <div class="result">
      <p>💡 <b>วิธีเล่น:</b> กดลิงก์ "ทำให้พัง" ในทั้งสองโหมด แล้วดูว่าหน้าเว็บ (และผู้โจมตี) เห็นอะไรต่างกัน
         จากนั้นเปิด <a href="/logs">📜 server log</a> เพื่อดูว่าโหมด SAFE เก็บรายละเอียดจริงไว้ฝั่งเซิร์ฟเวอร์ยังไง</p>
    </div>

    <table>
      <tr><th>Endpoint</th><th>อินพุตปกติ (ไม่ error)</th><th>อินพุตที่ทำให้พัง</th></tr>

      <tr><td><b>/user</b><br><small>ค้นผู้ใช้จาก id (DB error)</small></td>
          <td><a href="/user?id=1">/user?id=1</a></td>
          <td><a href="/user?id=abc">?id=abc</a> ·
              <a href="/user?id=999">?id=999</a></td></tr>

      <tr><td><b>/parse</b><br><small>JSON.parse ข้อมูลที่ส่งมา</small></td>
          <td><a href='/parse?data=%7B%22a%22%3A1%7D'>/parse?data={"a":1}</a></td>
          <td><a href="/parse?data=%7Bbad">?data={bad</a></td></tr>

      <tr><td><b>/divide</b><br><small>หารเลขด้วยเครื่องคิดเลขของระบบ</small></td>
          <td><a href="/divide?a=10&b=2">/divide?a=10&b=2</a></td>
          <td><a href="/divide?a=10&b=0">?b=0</a> ·
              <a href="/divide?a=x&b=2">?a=x</a></td></tr>

      <tr><td><b>/config</b><br><small>อ่านไฟล์ตั้งค่า (ไฟล์หาย → ENOENT เผย path)</small></td>
          <td class="muted">(ไฟล์ตั้งใจไม่มี)</td>
          <td><a href="/config">/config</a></td></tr>
    </table>

    <p class="switch">อยากดูทุกอย่างในโหมด SAFE ให้เติม <code>/safe</code> นำหน้า เช่น
       <a href="/safe/user?id=abc">/safe/user?id=abc</a>,
       <a href="/safe/parse?data=%7Bbad">/safe/parse?data={bad</a>,
       <a href="/safe/divide?a=10&b=0">/safe/divide?a=10&b=0</a>,
       <a href="/safe/config">/safe/config</a></p>
  `, null);
}

function userPage(id) {
  const u = queryUserFromDb(id); // อาจ throw DatabaseError
  return page('ค้นหาผู้ใช้', `
    <h1>พบผู้ใช้ id = ${escapeHtml(String(id))}</h1>
    <div class="result ok">
      <p><b>username:</b> ${escapeHtml(u.username)}</p>
      <p><b>email:</b> ${escapeHtml(u.email)}</p>
      <p><b>role:</b> ${escapeHtml(u.role)}</p>
    </div>
    <p class="muted">ลองใส่ id ที่ไม่ใช่ตัวเลข เช่น <a href="/user?id=abc">?id=abc</a>
       หรือ id ที่ไม่มีจริง <a href="/user?id=999">?id=999</a> เพื่อให้เกิด error</p>
    <p class="switch"><a href="/">กลับหน้าแรก</a></p>
  `, null);
}

function parsePage(data) {
  const obj = JSON.parse(data); // อาจ throw SyntaxError
  return page('Parse JSON', `
    <h1>แปลง JSON สำเร็จ ✔</h1>
    <div class="result ok">
      <p>อินพุต: <code>${escapeHtml(data)}</code></p>
      <p>ผลลัพธ์ (ฟอร์แมตแล้ว):</p>
      <pre>${escapeHtml(JSON.stringify(obj, null, 2))}</pre>
    </div>
    <p class="muted">ลองส่ง JSON พัง เช่น <a href="/parse?data=%7Bbad">?data={bad</a> เพื่อให้เกิด error</p>
    <p class="switch"><a href="/">กลับหน้าแรก</a></p>
  `, null);
}

function dividePage(a, b) {
  const result = calcDivide(a, b); // อาจ throw TypeError / RangeError
  return page('หารเลข', `
    <h1>ผลลัพธ์ = ${escapeHtml(String(result))}</h1>
    <div class="result ok"><p>${escapeHtml(String(a))} ÷ ${escapeHtml(String(b))} = <b>${escapeHtml(String(result))}</b></p></div>
    <p class="muted">ลองหารด้วยศูนย์ <a href="/divide?a=10&b=0">?a=10&b=0</a>
       หรือใส่ตัวอักษร <a href="/divide?a=x&b=2">?a=x&b=2</a> เพื่อให้เกิด error</p>
    <p class="switch"><a href="/">กลับหน้าแรก</a></p>
  `, null);
}

function configPage() {
  // ไฟล์นี้ตั้งใจไม่มีอยู่จริง → fs จะ throw ENOENT ที่มี path เต็มติดมาด้วย
  const cfgPath = path.join(__dirname, 'config', 'database.secret.json');
  const raw = fs.readFileSync(cfgPath, 'utf8'); // throw ENOENT
  return page('Config', `<h1>โหลด config สำเร็จ</h1><pre>${escapeHtml(raw)}</pre>`, null);
}

function logsPage() {
  const rows = db.serverLog.map((e) => `
    <tr>
      <td>${escapeHtml(e.time)}</td>
      <td><code>${escapeHtml(e.errorId)}</code></td>
      <td>${escapeHtml(e.where)}</td>
      <td><code>${escapeHtml(e.name)}</code>: ${escapeHtml(e.message.split('\n')[0])}</td>
    </tr>`).join('') || '<tr><td colspan="4" class="muted">ยังไม่มี log — ลองยิง endpoint ในโหมด /safe ให้เกิด error ก่อน</td></tr>';

  const latest = db.serverLog[0];
  return page('Server Log', `
    <h1>📜 Server-side log (เฉพาะ dev เห็น)</h1>
    <p class="muted">นี่คือ log ที่อยู่ "ฝั่งเซิร์ฟเวอร์" ผู้ใช้ทั่วไปเข้าไม่ถึง (ในแล็บเปิดให้ดูเพื่อการเรียนรู้)
       โหมด SAFE จะเก็บ stack trace เต็มไว้ที่นี่ โดยผูกกับ <b>error id</b> เดียวกับที่ตอบกลับผู้ใช้</p>
    <table>
      <tr><th>เวลา</th><th>error id</th><th>ที่</th><th>สรุป</th></tr>
      ${rows}
    </table>
    ${latest ? `
      <h2>รายละเอียดล่าสุด (error id: <code>${escapeHtml(latest.errorId)}</code>)</h2>
      <pre>${escapeHtml(latest.stack || '(ไม่มี stack)')}</pre>
      <p class="muted">เมื่อผู้ใช้แจ้ง "error id ${escapeHtml(latest.errorId)}" dev ก็ค้น log เจอ stack เต็มทันที
         — ตามสืบได้โดยไม่ต้องเปิดเผยอะไรให้ผู้ใช้เลย</p>` : ''}
    <p class="switch"><a href="/">กลับหน้าแรก</a> · <a href="/reset">ล้าง log</a></p>
  `, null);
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  let p = url.pathname;

  // ❗ try/catch รอบนอกสุด: ตัวเองก็ไม่ควรเผย error ถ้าเกิดพลาดนอกเหนือที่คาดไว้
  try {
    if (req.method === 'GET' && p === '/static/style.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(STYLE);
    }
    if (req.method === 'GET' && p === '/reset') {
      db = seed();
      return redirect(res, '/');
    }
    if (req.method === 'GET' && p === '/') return send(res, 200, homePage());
    if (req.method === 'GET' && p === '/logs') return send(res, 200, logsPage());

    // แยกโหมด safe / vuln จาก prefix /safe
    const mode = p.startsWith('/safe/') || p === '/safe' ? 'safe' : 'vuln';
    const route = mode === 'safe' ? p.replace(/^\/safe/, '') || '/' : p;

    if (req.method === 'GET') {
      // แต่ละ endpoint ครอบด้วย try/catch แล้วส่ง error เข้า handleError ตามโหมด
      switch (route) {
        case '/':
          // /safe เฉยๆ → อธิบายสั้นๆ แล้วลิงก์ไปลอง
          return send(res, 200, page('โหมด SAFE', `
            <h1>โหมด SAFE ✔</h1>
            <p>เติมพาธต่อท้ายเพื่อลอง เช่น <a href="/safe/user?id=abc">/safe/user?id=abc</a>,
               <a href="/safe/parse?data=%7Bbad">/safe/parse?data={bad</a>,
               <a href="/safe/divide?a=10&b=0">/safe/divide?a=10&b=0</a>,
               <a href="/safe/config">/safe/config</a></p>
            <p class="switch"><a href="/">กลับหน้าแรก</a></p>`, 'safe'));
        case '/user':
          try { return send(res, 200, userPage(url.searchParams.get('id') ?? '')); }
          catch (err) { return handleError(res, err, mode, 'GET /user'); }
        case '/parse':
          try { return send(res, 200, parsePage(url.searchParams.get('data') ?? '')); }
          catch (err) { return handleError(res, err, mode, 'GET /parse'); }
        case '/divide':
          try { return send(res, 200, dividePage(url.searchParams.get('a') ?? '', url.searchParams.get('b') ?? '')); }
          catch (err) { return handleError(res, err, mode, 'GET /divide'); }
        case '/config':
          try { return send(res, 200, configPage()); }
          catch (err) { return handleError(res, err, mode, 'GET /config'); }
      }
    }

    send(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null));
  } catch (err) {
    // ถ้ามี error ที่ไม่คาดคิดหลุดมาถึงตรงนี้ อย่าเผยรายละเอียด
    console.error('\x1b[31m[UNEXPECTED]\x1b[0m', err);
    if (!res.headersSent) send(res, 500, page('500', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>', null));
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  Error-Handling Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ลองยิง /user?id=abc เทียบกับ /safe/user?id=abc แล้วดู server log');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
