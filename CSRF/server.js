// =====================================================================
//  CSRF Lab — เว็บธนาคารจำลองที่ "ตั้งใจ" ให้มีช่องโหว่ CSRF เพื่อการเรียนรู้
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
// =====================================================================

const http = require('http');
const crypto = require('crypto');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 4000;

// ---------------------------------------------------------------------
// ข้อมูลในหน่วยความจำ (ปิดเซิร์ฟเวอร์แล้วรีเซ็ตใหม่)
// ---------------------------------------------------------------------
function seed() {
  return {
    users: {
      alice:  { password: 'alice123', name: 'คุณอลิซ (เหยื่อ)', balance: 10000 },
      hacker: { password: 'hacker123', name: 'บัญชีของแฮกเกอร์', balance: 0 },
    },
    // session id -> username และ csrf token ประจำ session
    sessions: new Map(),
    log: [], // ประวัติการโอน
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
function currentSession(req) {
  const sid = parseCookies(req).bank_session;
  const s = db.sessions.get(sid);
  return s ? { sid, ...s } : null;
}
function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body, { mode, evil } = {}) {
  const badge =
    mode === 'vuln' ? '<span class="badge vuln">⚠ VULNERABLE</span>' :
    mode === 'safe' ? '<span class="badge safe">✔ SAFE</span>' : '';
  const theme = evil ? 'evil' : 'bank';
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title><link rel="stylesheet" href="/static/style.css">
</head><body class="${theme}">
  <header>
    <a href="/" class="logo">${evil ? '😈 FreeMoviesHD (เว็บของแฮกเกอร์)' : '🏦 SiamSecure Bank'}</a>${badge}
  </header>
  <main>${body}</main>
  <footer>สำหรับการเรียนรู้บนเครื่องตัวเองเท่านั้น · Anti-hacking matters</footer>
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

// ย้ายเงินจริง + บันทึก log
function doTransfer(fromUser, to, amount, via) {
  const amt = Math.floor(Number(amount));
  if (!db.users[to]) return { ok: false, msg: `ไม่พบบัญชีผู้รับ "${to}"` };
  if (!Number.isFinite(amt) || amt <= 0) return { ok: false, msg: 'จำนวนเงินไม่ถูกต้อง' };
  if (db.users[fromUser].balance < amt) return { ok: false, msg: 'ยอดเงินไม่พอ' };
  db.users[fromUser].balance -= amt;
  db.users[to].balance += amt;
  db.log.unshift({ time: new Date().toLocaleTimeString('th-TH'), from: fromUser, to, amt, via });
  db.log.length = Math.min(db.log.length, 30);
  console.log(`\x1b[31m[โอนเงิน] ${fromUser} -> ${to} : ${amt} บาท (${via})\x1b[0m`);
  return { ok: true };
}

// =====================================================================
// หน้า static (CSS ฝังไว้ในโค้ดเลย ไม่ต้องมีไฟล์แยก)
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#15803d;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
body.evil{--accent:#6d28d9;background:#1a1626;color:#eee}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
body.evil header{background:#120f1c;border-color:#2a2440}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
body.evil .logo{color:#c4b5fd}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:16px}
a{color:var(--accent)}
h1{margin-top:0}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
form{display:flex;flex-direction:column;gap:8px;margin:16px 0;max-width:360px}
input{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.evil{background:#dc2626;font-size:18px;padding:14px}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
body.evil .card,body.evil .result{background:#231d33;border-color:#3a3151}
.balance{font-size:34px;font-weight:800;color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card)}
body.evil table{background:#231d33}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left}
body.evil th,body.evil td{border-color:#3a3151}
th{background:#f1f4f8}
body.evil th{background:#1a1626}
code{font-family:Consolas,monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px}
body.evil code{background:#140f20;color:#d6bcfa}
.muted{color:var(--muted)}
.switch{margin-top:24px;color:var(--muted)}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px}
`;

// =====================================================================
// หน้าธนาคาร
// =====================================================================
function loginPage(msg) {
  return page('เข้าสู่ระบบ · SiamSecure Bank', `
    <h1>เข้าสู่ระบบธนาคาร</h1>
    ${msg ? `<p class="result" style="color:var(--red)">${escapeHtml(msg)}</p>` : ''}
    <form method="post" action="/login">
      <input name="username" placeholder="ชื่อผู้ใช้" required>
      <input name="password" type="password" placeholder="รหัสผ่าน" required>
      <button>เข้าสู่ระบบ</button>
    </form>
    <div class="result"><b>บัญชีทดสอบ:</b><br>
      เหยื่อ: <code>alice</code> / <code>alice123</code> (มีเงิน 10,000)<br>
      แฮกเกอร์: <code>hacker</code> / <code>hacker123</code> (มีเงิน 0)
    </div>
  `);
}

function dashboard(req, safe) {
  const s = currentSession(req);
  const u = db.users[s.user];
  const base = safe ? '/safe' : '';
  const rows = db.log.map((l) =>
    `<tr><td>${escapeHtml(l.time)}</td><td>${escapeHtml(l.from)}</td><td>${escapeHtml(l.to)}</td><td>${l.amt.toLocaleString()}</td><td>${escapeHtml(l.via)}</td></tr>`
  ).join('') || '<tr><td colspan="5" class="muted">ยังไม่มีรายการ</td></tr>';

  return page(`หน้าหลัก${safe ? ' (ปลอดภัย)' : ''} · SiamSecure Bank`, `
    <h1>สวัสดี ${escapeHtml(u.name)}</h1>
    <div class="card">ยอดเงินคงเหลือ<div class="balance">${u.balance.toLocaleString()} บาท</div></div>

    <div class="card">
      <h2>โอนเงิน ${safe ? '✔ (มี CSRF token)' : '⚠ (ไม่มีการป้องกัน)'}</h2>
      <form method="post" action="${base}/transfer">
        ${safe ? `<input type="hidden" name="csrf" value="${escapeHtml(s.csrf)}">` : ''}
        <input name="to" placeholder="บัญชีผู้รับ (เช่น hacker)" required>
        <input name="amount" type="number" placeholder="จำนวนเงิน" required>
        <button>โอนเงิน</button>
      </form>
    </div>

    <h2>ประวัติการโอน</h2>
    <table><tr><th>เวลา</th><th>จาก</th><th>ไป</th><th>บาท</th><th>ช่องทาง</th></tr>${rows}</table>

    <p class="switch">
      ${safe ? 'ดูแบบมีช่องโหว่: <a href="/">หน้าหลักปกติ</a>' : 'ดูแบบแก้แล้ว: <a href="/safe">หน้าหลักปลอดภัย</a>'}
      · <a href="/evil">เปิดหน้าเว็บของแฮกเกอร์</a> · <a href="/logout">ออกจากระบบ</a>
    </p>
  `, { mode: safe ? 'safe' : 'vuln' });
}

// =====================================================================
// หน้าเว็บของแฮกเกอร์ (จำลองว่าเป็นอีกเว็บหนึ่ง)
// เหยื่อที่ล็อกอินธนาคารค้างไว้ แล้วหลงเข้ามาเว็บนี้ จะโดนโอนเงินอัตโนมัติ
// =====================================================================
function evilPage(safe) {
  const action = safe ? '/safe/transfer' : '/transfer';
  return page('ดูหนังฟรี HD!', `
    <h1>🎬 ดูหนังใหม่ชนโรง ฟรี! ไม่ต้องสมัคร</h1>
    <p>กำลังโหลดวิดีโอ... โปรดรอสักครู่</p>
    <div class="card">
      <p class="muted">(เบื้องหลัง: หน้านี้กำลังแอบส่งฟอร์มโอนเงินไปที่ธนาคาร โดยใช้คุกกี้ของคุณที่ล็อกอินค้างไว้)</p>
      <!-- ❌ ฟอร์มที่ซ่อนไว้ ส่งไปยังธนาคารทันทีที่หน้าโหลด -->
      <form id="attack" method="post" action="${action}" style="display:none">
        <input name="to" value="hacker">
        <input name="amount" value="5000">
      </form>
      <p id="status">⏳ กำลังเล่นวิดีโอ...</p>
    </div>
    <p class="switch">${safe
      ? 'นี่คือการยิงใส่หน้า <b>ปลอดภัย</b> — จะล้มเหลวเพราะไม่มี CSRF token (ดูข้อความด้านบน)'
      : 'นี่คือการยิงใส่หน้า <b>มีช่องโหว่</b> — เงินถูกโอนทันทีโดยเหยื่อไม่รู้ตัว'}
      <br>กลับไปดูยอดเงินที่ <a href="${safe ? '/safe' : '/'}">หน้าธนาคาร</a></p>

    <script>
      // จำลองการโจมตี: ส่งฟอร์มอัตโนมัติเมื่อหน้าโหลด
      const f = document.getElementById('attack');
      const status = document.getElementById('status');
      fetch(f.action, {
        method: 'POST',
        credentials: 'include', // ส่งคุกกี้ของธนาคารไปด้วย (นี่คือหัวใจของ CSRF)
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ to: 'hacker', amount: '5000' }),
      }).then(r => r.text()).then(t => {
        status.innerHTML = t.includes('สำเร็จ')
          ? '✅ (เบื้องหลัง) โอนเงิน 5,000 บาทจากเหยื่อไปบัญชี hacker สำเร็จ!'
          : '❌ (เบื้องหลัง) โจมตีล้มเหลว: ' + t;
      }).catch(e => status.textContent = 'error: ' + e);
    </script>
  `, { evil: true, mode: safe ? 'safe' : 'vuln' });
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

    const s = currentSession(req);

    // ----- GET -----
    if (req.method === 'GET') {
      if (p === '/login') return send(res, 200, loginPage());
      if (p === '/logout') { if (s) db.sessions.delete(s.sid); return redirect(res, '/login', 'bank_session=; Path=/; Max-Age=0'); }
      if (p === '/evil') return send(res, 200, evilPage(false));
      if (p === '/safe/evil') return send(res, 200, evilPage(true));
      if (p === '/reset') { db = seed(); return redirect(res, '/login'); }

      // หน้าที่ต้องล็อกอิน
      if (p === '/' || p === '/safe') {
        if (!s) return redirect(res, '/login');
        return send(res, 200, dashboard(req, p === '/safe'));
      }

      // ❌ ช่องโหว่เสริม: ยอมรับการโอนผ่าน GET ด้วย (เช่น <img src="/transfer?to=hacker&amount=1000">)
      if (p === '/transfer' && (url.searchParams.get('to') || url.searchParams.get('amount'))) {
        if (!s) { res.writeHead(401); return res.end('ยังไม่ได้ล็อกอิน'); }
        const r = doTransfer(s.user, url.searchParams.get('to'), url.searchParams.get('amount'), 'GET/รูปภาพ');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(r.ok ? 'โอนสำเร็จ (ผ่าน GET)' : 'ล้มเหลว: ' + r.msg);
      }
    }

    // ----- POST -----
    if (req.method === 'POST') {
      const form = await readForm(req);

      if (p === '/login') {
        const username = (form.get('username') || '').trim();
        const u = db.users[username];
        if (u && form.get('password') === u.password) {
          const sid = newId();
          db.sessions.set(sid, { user: username, csrf: newId() });
          return redirect(res, username === 'hacker' ? '/' : '/', `bank_session=${sid}; Path=/; SameSite=Lax`);
        }
        return send(res, 200, loginPage('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'));
      }

      // ❌ โอนเงินแบบมีช่องโหว่: ไม่ตรวจ CSRF token เลย ใครยิงมาก็ทำตาม ขอแค่มีคุกกี้
      if (p === '/transfer') {
        if (!s) { res.writeHead(401); return res.end('ยังไม่ได้ล็อกอิน'); }
        const r = doTransfer(s.user, form.get('to'), form.get('amount'), 'POST');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(r.ok ? 'โอนเงินสำเร็จ' : 'ล้มเหลว: ' + r.msg);
      }

      // ✅ โอนเงินแบบปลอดภัย: ต้องแนบ CSRF token ที่ตรงกับ session
      if (p === '/safe/transfer') {
        if (!s) { res.writeHead(401); return res.end('ยังไม่ได้ล็อกอิน'); }
        if (form.get('csrf') !== s.csrf) {
          res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('ถูกปฏิเสธ: CSRF token ไม่ถูกต้องหรือไม่มี (เว็บของแฮกเกอร์เดา token นี้ไม่ได้)');
        }
        const r = doTransfer(s.user, form.get('to'), form.get('amount'), 'POST+token');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(r.ok ? 'โอนเงินสำเร็จ' : 'ล้มเหลว: ' + r.msg);
      }
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
  console.log('  \x1b[33m⚠  CSRF Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ล็อกอินเป็น alice แล้วลองเปิดหน้า /evil');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
