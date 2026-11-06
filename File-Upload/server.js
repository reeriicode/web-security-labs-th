// =====================================================================
//  File Upload Lab — เว็บที่ "ตั้งใจ" ให้มีช่องโหว่ Insecure File Upload
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//  รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
//  (ใช้เฉพาะโมดูลที่มากับ Node.js: http, crypto, fs, path, url)
// =====================================================================

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในเน็ตเวิร์กเข้าไม่ได้
const PORT = Number(process.env.PORT) || 4500;

// โฟลเดอร์เก็บไฟล์ที่อัปโหลด — โค้ดสร้างเองตอนรัน
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ขนาดสูงสุดที่ยอมอ่าน body เข้ามา (กัน RAM ระเบิด)
// โหมด safe บังคับ 1 MB จริงๆ  ส่วนโหมด vuln ตั้งเพดานหลวมๆ ไว้แค่กันเครื่องพัง
const SAFE_MAX = 1 * 1024 * 1024;        // 1 MB
const VULN_MAX = 30 * 1024 * 1024;       // 30 MB (บทเรียน: โหมด vuln "ไม่จำกัดขนาด")

// allowlist ของโหมด safe: นามสกุล + magic bytes (เลขไบต์ต้นไฟล์จริง)
const IMAGE_SIGNATURES = [
  { ext: 'png', type: 'image/png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { ext: 'jpg', type: 'image/jpeg', magic: [0xff, 0xd8, 0xff] },
  { ext: 'gif', type: 'image/gif', magic: [0x47, 0x49, 0x46, 0x38] }, // "GIF8"
];

// ---------------------------------------------------------------------
// ✅ ฟังก์ชันหัวใจของการป้องกัน XSS ในหน้าเว็บ: แปลงอักขระพิเศษเป็นข้อความธรรมดา
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
// อ่าน body แบบ "ไบต์ดิบ" (Buffer) เพราะไฟล์อาจเป็นไบนารี (รูปภาพ ฯลฯ)
// ---------------------------------------------------------------------
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) {
        req.destroy();
        reject(new Error('TOO_LARGE'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------
// Parser multipart/form-data ง่ายๆ ที่เขียนเอง (รองรับไฟล์เดียว + ฟิลด์ข้อความ)
//   - อ่าน boundary จาก Content-Type
//   - ตัด body ด้วย delimiter "--<boundary>"
//   - แต่ละส่วน (part) = headers + \r\n\r\n + เนื้อหา
// ทำงานบน Buffer ตลอด เพื่อไม่ให้ไบต์ของไฟล์ไบนารีเพี้ยน
// ---------------------------------------------------------------------
function parseMultipart(buffer, boundary) {
  const result = { fields: {}, file: null };
  const delimiter = Buffer.from('--' + boundary);
  const parts = [];

  let start = buffer.indexOf(delimiter);
  if (start === -1) return result;
  start += delimiter.length;

  while (start < buffer.length) {
    // หลัง delimiter: ถ้าเป็น "--" คือจบแล้ว, ถ้าเป็น "\r\n" คือมี part ต่อ
    if (buffer[start] === 0x2d && buffer[start + 1] === 0x2d) break; // "--" = end
    start += 2; // ข้าม \r\n ที่ตามหลัง boundary

    const next = buffer.indexOf(delimiter, start);
    if (next === -1) break;

    // เนื้อ part คือ start..next โดยตัด \r\n ท้ายสุด (2 ไบต์) ที่คั่นก่อน delimiter ถัดไป
    parts.push(buffer.slice(start, next - 2));
    start = next + delimiter.length;
  }

  const headerSep = Buffer.from('\r\n\r\n');
  for (const part of parts) {
    const sep = part.indexOf(headerSep);
    if (sep === -1) continue;
    const headerStr = part.slice(0, sep).toString('utf8');
    const content = part.slice(sep + headerSep.length);

    const nameMatch = /name="([^"]*)"/i.exec(headerStr);
    const fileMatch = /filename="([^"]*)"/i.exec(headerStr);
    const ctMatch = /Content-Type:\s*([^\r\n]+)/i.exec(headerStr);
    const name = nameMatch ? nameMatch[1] : '';

    if (fileMatch) {
      result.file = {
        field: name,
        filename: fileMatch[1], // ชื่อไฟล์ "ดิบ" จากผู้ใช้ (ยังไม่กรองอะไร)
        contentType: ctMatch ? ctMatch[1].trim() : 'application/octet-stream',
        data: content,
      };
    } else {
      result.fields[name] = content.toString('utf8');
    }
  }
  return result;
}

// ---------------------------------------------------------------------
// map นามสกุล -> Content-Type (ใช้ในโหมด vuln ตอน serve ไฟล์)
//   สังเกต: .html และ .svg เป็นช่องทาง XSS ได้ เพราะเบราว์เซอร์ตีความเป็น markup
// ---------------------------------------------------------------------
const MIME = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  svg: 'image/svg+xml',
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json; charset=utf-8',
  xml: 'application/xml; charset=utf-8',
  txt: 'text/plain; charset=utf-8',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  pdf: 'application/pdf',
};
function mimeByExt(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return MIME[ext] || 'application/octet-stream';
}
// นามสกุลที่ "อันตราย" เพราะเบราว์เซอร์อาจรันเป็นสคริปต์/markup ในโดเมนเรา
function isDangerousExt(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return ['html', 'htm', 'svg', 'xml', 'js', 'xhtml'].includes(ext);
}

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
  <title>${title} · File Upload Lab</title><link rel="stylesheet" href="/static/style.css">
</head><body>
  <header><a href="/" class="logo">📤 File Upload Lab</a>${badge}
    <span class="who"><a href="/">มีช่องโหว่</a> · <a href="/safe">แก้แล้ว</a></span>
  </header>
  <main>${body}</main>
  <footer>เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น · ห้าม deploy · ห้ามใช้กับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ) · Anti-hacking matters</footer>
</body></html>`;
}

function send(res, status, html, { safe = false } = {}) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  if (safe) {
    headers['X-Content-Type-Options'] = 'nosniff';
  }
  res.writeHead(status, headers);
  res.end(html);
}
function redirect(res, location) {
  res.writeHead(303, { Location: location });
  res.end();
}

// static (กำหนดรายชื่อตายตัว กัน path traversal)
const STATIC = {
  '/static/style.css': ['style.css', 'text/css; charset=utf-8'],
};

// อ่านรายการไฟล์ในโฟลเดอร์ uploads (เฉพาะไฟล์ที่อยู่ในโฟลเดอร์จริงๆ)
function listUploads() {
  try {
    return fs.readdirSync(UPLOAD_DIR, { withFileTypes: true })
      .filter((d) => d.isFile())
      .map((d) => {
        const full = path.join(UPLOAD_DIR, d.name);
        let size = 0;
        try { size = fs.statSync(full).size; } catch (_) {}
        return { name: d.name, size };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch (_) {
    return [];
  }
}

function humanSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

// =====================================================================
// หน้า upload (ใช้ร่วมกันทั้งโหมด vuln และ safe)
// =====================================================================
function uploadPage(safe, msg) {
  const base = safe ? '/safe' : '';
  const action = safe ? '/safe/upload' : '/upload';
  const files = listUploads();

  const fileRows = files.length
    ? files.map((f) => {
        const danger = isDangerousExt(f.name);
        return `<tr>
          <td><code>${escapeHtml(f.name)}</code>${danger ? ' <span class="tag">อาจรันเป็นสคริปต์</span>' : ''}</td>
          <td>${humanSize(f.size)}</td>
          <td>
            <a href="/uploads/${encodeURIComponent(f.name)}" target="_blank">เปิด (vuln)</a> ·
            <a href="/safe/uploads/${encodeURIComponent(f.name)}">ดาวน์โหลด (safe)</a>
          </td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="3" class="muted">ยังไม่มีไฟล์ที่อัปโหลด</td></tr>';

  const vulnExplain = `
    <ul>
      <li>รับไฟล์ <b>ทุกชนิด</b> ไม่เช็กนามสกุล ไม่เช็กชนิดไฟล์จริง</li>
      <li>ไม่จำกัดขนาด (เพดานในแล็บตั้งหลวมๆ แค่กันเครื่องพัง)</li>
      <li>บันทึกด้วย <b>ชื่อไฟล์เดิมจากผู้ใช้</b> → ถ้าชื่อมี <code>../</code> ไฟล์หลุดออกนอกโฟลเดอร์ (path traversal)</li>
      <li>เสิร์ฟที่ <code>/uploads/&lt;ชื่อ&gt;</code> โดยตั้ง <code>Content-Type</code> ตามนามสกุล → อัปโหลด <code>.html</code> ที่มี <code>&lt;script&gt;</code> แล้วเปิด = โค้ดรันในโดเมนเรา (stored XSS)</li>
    </ul>`;

  const safeExplain = `
    <ul>
      <li>ตรวจชนิดไฟล์จริงจาก <b>magic bytes</b> (ต้นไฟล์) ไม่เชื่อแค่นามสกุล — รับเฉพาะรูป PNG / JPEG / GIF</li>
      <li>จำกัดขนาด <b>1 MB</b></li>
      <li>ตั้งชื่อไฟล์ใหม่เองด้วยค่าสุ่ม (crypto) ไม่ใช้ชื่อจากผู้ใช้ → กัน path traversal</li>
      <li>เสิร์ฟเป็น <code>application/octet-stream</code> + <code>Content-Disposition: attachment</code> + <code>X-Content-Type-Options: nosniff</code> → เบราว์เซอร์ "ดาวน์โหลด" ไม่ "รัน"</li>
    </ul>`;

  const sampleHtml = `<html><body><h1>hacked</h1>\n<script>alert('Stored XSS จากไฟล์ที่อัปโหลด: '+document.domain)</script>\n<script>new Image().src='/uploads/__steal?c='+encodeURIComponent(document.cookie)</script>\n</body></html>`;

  return page(safe ? 'โหมดปลอดภัย' : 'โหมดมีช่องโหว่', `
    <h1>${safe ? 'อัปโหลดไฟล์ ✔ (ตรวจสอบแล้ว)' : 'อัปโหลดไฟล์ ⚠ (ไม่มีการป้องกัน)'}</h1>
    ${msg ? `<div class="result ${msg.ok ? 'ok' : 'err'}">${msg.html}</div>` : ''}

    <div class="card">
      <h2>${safe ? 'โหมดปลอดภัยทำอะไรบ้าง' : 'โหมดนี้ (จงใจ) พลาดตรงไหน'}</h2>
      ${safe ? safeExplain : vulnExplain}
    </div>

    <form method="post" action="${action}" enctype="multipart/form-data" class="stack">
      <input type="file" name="file" required>
      <button>อัปโหลด</button>
    </form>

    <h2>ไฟล์ที่อัปโหลดแล้ว (${files.length})</h2>
    <p class="muted">ไฟล์ทั้งหมดอยู่ในโฟลเดอร์ <code>uploads/</code> ของแล็บ · ลองเปิดลิงก์ "เปิด (vuln)" เทียบกับ "ดาวน์โหลด (safe)" ของไฟล์เดียวกัน</p>
    <table><tr><th>ชื่อไฟล์</th><th>ขนาด</th><th>เปิด / ดาวน์โหลด</th></tr>${fileRows}</table>

    <form method="post" action="/reset" style="margin-top:14px">
      <input type="hidden" name="back" value="${base || '/'}">
      <button class="secondary">ล้างไฟล์ที่อัปโหลดทั้งหมด</button>
    </form>

    <details open style="margin-top:20px"><summary>🧪 ลองโจมตีโหมดมีช่องโหว่</summary>
      <ol>
        <li><b>Stored XSS:</b> สร้างไฟล์ชื่อ <code>evil.html</code> เนื้อหาด้านล่าง แล้วอัปโหลดในหน้า
            <a href="/">มีช่องโหว่</a> จากนั้นคลิก "เปิด (vuln)" ของไฟล์นั้น — สคริปต์จะรันในโดเมนนี้
          <pre>${escapeHtml(sampleHtml)}</pre>
        </li>
        <li><b>Path traversal:</b> อัปโหลดไฟล์ที่ "ชื่อ" เป็น <code>../pwned.txt</code>
            (ใน DevTools เปลี่ยน filename หรือใช้ curl) → ไฟล์จะถูกเขียน <b>นอก</b> โฟลเดอร์ uploads
            <br><small>เทียบกับโหมด safe ที่ตั้งชื่อใหม่เองเสมอ จึงเขียนออกนอกโฟลเดอร์ไม่ได้</small>
        </li>
        <li>ลองอัปโหลดไฟล์เดียวกันในหน้า <a href="/safe">แก้แล้ว</a> จะเห็นว่าถ้าไม่ใช่รูปจริงจะถูกปฏิเสธ
            และต่อให้เป็นรูป เวลาเปิดก็ถูกบังคับให้ดาวน์โหลด ไม่รันเป็นสคริปต์
        </li>
      </ol>
      <p class="muted">ตัวอย่างอัปโหลดชื่อไฟล์อันตรายด้วย curl (รันจากโฟลเดอร์แล็บ):</p>
      <pre>curl -F "file=@evil.html;filename=../pwned.html" http://localhost:${PORT}/upload</pre>
    </details>

    <p class="switch">${safe
      ? 'ดูแบบมีช่องโหว่: <a href="/">/</a>'
      : 'ดูแบบแก้แล้ว: <a href="/safe">/safe</a>'}</p>
  `, safe ? 'safe' : 'vuln');
}

// =====================================================================
// จัดการการอัปโหลด
// =====================================================================
async function handleUpload(req, res, safe) {
  const ct = req.headers['content-type'] || '';
  const bMatch = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(ct);
  if (!ct.startsWith('multipart/form-data') || !bMatch) {
    return send(res, 400, uploadPage(safe, { ok: false, html: 'รูปแบบคำขอไม่ถูกต้อง (ต้องเป็น multipart/form-data)' }), { safe });
  }
  const boundary = (bMatch[1] || bMatch[2]).trim();

  let body;
  try {
    body = await readBody(req, safe ? SAFE_MAX : VULN_MAX);
  } catch (e) {
    if (e.message === 'TOO_LARGE') {
      return send(res, 413, uploadPage(safe, {
        ok: false,
        html: safe ? 'ไฟล์ใหญ่เกิน 1 MB — โหมดปลอดภัยปฏิเสธ' : 'ไฟล์ใหญ่เกินเพดานกันเครื่องพังของแล็บ (30 MB)',
      }), { safe });
    }
    throw e;
  }

  const { file } = parseMultipart(body, boundary);
  if (!file || !file.filename) {
    return send(res, 400, uploadPage(safe, { ok: false, html: 'ไม่พบไฟล์ในคำขอ' }), { safe });
  }

  if (safe) return saveSafe(res, file);
  return saveVuln(res, file);
}

// ❌ โหมดมีช่องโหว่: เชื่อทุกอย่างจากผู้ใช้ ใช้ชื่อไฟล์เดิมตรงๆ
function saveVuln(res, file) {
  const original = file.filename;
  // path.join กับชื่อที่มี ../ ได้ → ไฟล์หลุดออกนอก UPLOAD_DIR (นี่คือช่องโหว่)
  const dest = path.join(UPLOAD_DIR, original);
  const resolved = path.resolve(dest);

  const traversed = !resolved.startsWith(path.resolve(UPLOAD_DIR) + path.sep);
  try {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, file.data);
  } catch (e) {
    return send(res, 500, uploadPage(false, { ok: false, html: 'เขียนไฟล์ไม่สำเร็จ: ' + escapeHtml(e.message) }), { safe: false });
  }

  if (traversed) {
    console.log(`\x1b[31m[UPLOAD][PATH-TRAVERSAL] ชื่อ "${original}" ถูกเขียนออกนอก uploads/ -> ${resolved}\x1b[0m`);
  }
  if (isDangerousExt(original)) {
    console.log(`\x1b[31m[UPLOAD][XSS-RISK] อัปโหลดไฟล์ที่รันเป็นสคริปต์ได้: ${original} -> เปิด /uploads/${original} เพื่อรันในโดเมนนี้\x1b[0m`);
  }

  const warn = isDangerousExt(original)
    ? `<br>⚠ นามสกุลนี้เบราว์เซอร์จะตีความเป็น markup/script — <a href="/uploads/${encodeURIComponent(original)}" target="_blank">เปิดดู</a> แล้วสังเกตว่าสคริปต์รันในโดเมนนี้`
    : '';
  const tnote = traversed
    ? `<br>🚨 ชื่อไฟล์มี path traversal — ไฟล์ถูกเขียนออกนอกโฟลเดอร์ uploads ที่ <code>${escapeHtml(resolved)}</code>`
    : '';

  return send(res, 200, uploadPage(false, {
    ok: true,
    html: `อัปโหลดสำเร็จ (โหมดมีช่องโหว่): <code>${escapeHtml(original)}</code>${warn}${tnote}`,
  }), { safe: false });
}

// ✅ โหมดปลอดภัย: ตรวจ magic bytes, allowlist รูป, ตั้งชื่อใหม่ด้วยค่าสุ่ม
function saveSafe(res, file) {
  const sig = IMAGE_SIGNATURES.find((s) =>
    s.magic.every((b, i) => file.data[i] === b)
  );
  if (!sig) {
    console.log(`\x1b[33m[UPLOAD][SAFE] ปฏิเสธไฟล์ "${file.filename}" (ไม่ใช่รูป PNG/JPEG/GIF จริง)\x1b[0m`);
    return send(res, 400, uploadPage(true, {
      ok: false,
      html: `ปฏิเสธ: ไฟล์นี้ไม่ใช่รูป PNG / JPEG / GIF จริง (ตรวจจาก magic bytes ไม่ใช่นามสกุล) — ชื่อที่ส่งมา: <code>${escapeHtml(file.filename)}</code>`,
    }), { safe: true });
  }

  // ตั้งชื่อใหม่เองทั้งหมด ไม่เอาชื่อหรือนามสกุลจากผู้ใช้มาเลย
  const safeName = crypto.randomBytes(16).toString('hex') + '.' + sig.ext;
  try {
    fs.writeFileSync(path.join(UPLOAD_DIR, safeName), file.data);
  } catch (e) {
    return send(res, 500, uploadPage(true, { ok: false, html: 'เขียนไฟล์ไม่สำเร็จ: ' + escapeHtml(e.message) }), { safe: true });
  }

  return send(res, 200, uploadPage(true, {
    ok: true,
    html: `อัปโหลดสำเร็จ (โหมดปลอดภัย): เป็นรูป <b>${sig.type}</b> จริง · บันทึกด้วยชื่อสุ่ม <code>${escapeHtml(safeName)}</code> (ชื่อเดิม <code>${escapeHtml(file.filename)}</code> ถูกทิ้ง)`,
  }), { safe: true });
}

// =====================================================================
// เสิร์ฟไฟล์ที่อัปโหลด
// =====================================================================

// ❌ โหมดมีช่องโหว่: เอาชื่อจาก URL มาต่อ path ตรงๆ + ตั้ง Content-Type ตามนามสกุล
function serveVuln(res, rawName) {
  const name = decodeURIComponent(rawName); // อาจมี ../ ที่ถูก %-encode มา
  const full = path.join(UPLOAD_DIR, name);  // ❌ ไม่กัน traversal
  fs.readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('ไม่พบไฟล์');
    }
    const type = mimeByExt(name);
    if (isDangerousExt(name)) {
      console.log(`\x1b[31m[SERVE][XSS] เสิร์ฟ ${name} เป็น ${type} — สคริปต์ในไฟล์จะรันในโดเมนนี้\x1b[0m`);
    }
    // ❌ ตั้ง Content-Type ตามนามสกุล ไม่มี nosniff ไม่มี attachment
    res.writeHead(200, { 'Content-Type': type });
    res.end(data);
  });
}

// ✅ โหมดปลอดภัย: ใช้แค่ basename (ตัด ../), บังคับดาวน์โหลด, nosniff
function serveSafe(res, rawName) {
  const name = path.basename(decodeURIComponent(rawName)); // ✅ ตัดส่วน path ทิ้ง กัน traversal
  const full = path.join(UPLOAD_DIR, name);
  const resolved = path.resolve(full);
  if (!resolved.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('ชื่อไฟล์ไม่ถูกต้อง');
  }
  fs.readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('ไม่พบไฟล์');
    }
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',               // ✅ ไม่บอกชนิดจริง เบราว์เซอร์ไม่ตีความ
      'Content-Disposition': `attachment; filename="${name.replace(/"/g, '')}"`, // ✅ บังคับดาวน์โหลด
      'X-Content-Type-Options': 'nosniff',                      // ✅ ห้ามเบราว์เซอร์เดาชนิดไฟล์
    });
    res.end(data);
  });
}

// =====================================================================
// Router
// =====================================================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;

  try {
    if (req.method === 'GET' && STATIC[p]) {
      res.writeHead(200, { 'Content-Type': STATIC[p][1] });
      return res.end(STYLE);
    }

    if (req.method === 'GET') {
      // เสิร์ฟไฟล์ที่อัปโหลด — ต้องเช็ก /safe/uploads/ ก่อน /uploads/
      if (p.startsWith('/safe/uploads/')) return serveSafe(res, p.slice('/safe/uploads/'.length));
      if (p.startsWith('/uploads/')) return serveVuln(res, p.slice('/uploads/'.length));

      switch (p) {
        case '/': return send(res, 200, uploadPage(false));
        case '/safe': return send(res, 200, uploadPage(true), { safe: true });
      }
    }

    if (req.method === 'POST') {
      if (p === '/upload') return handleUpload(req, res, false);
      if (p === '/safe/upload') return handleUpload(req, res, true);
      if (p === '/reset') {
        const body = await readBody(req, 10_000);
        const form = new URLSearchParams(body.toString('utf8'));
        let n = 0;
        for (const f of listUploads()) {
          try { fs.unlinkSync(path.join(UPLOAD_DIR, f.name)); n++; } catch (_) {}
        }
        console.log(`\x1b[33m[RESET] ลบไฟล์ที่อัปโหลด ${n} ไฟล์\x1b[0m`);
        return redirect(res, form.get('back') === '/safe' ? '/safe' : '/');
      }
    }

    send(res, 404, page('ไม่พบหน้า', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับหน้าแรก</a></p>', null), {});
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', '<h1>500</h1><p>เกิดข้อผิดพลาด</p>', null));
  }
});

// =====================================================================
// CSS ฝังในโค้ด (ไม่ต้องมีไฟล์แยก)
// =====================================================================
const STYLE = `
:root{--bg:#eef1f5;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#2563eb;--red:#c62828;--red-bg:#fdecec;--green:#1e7d3a;--green-bg:#e7f5eb;--amber:#9a6a00;--amber-bg:#fff5e0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.6}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;color:var(--text);text-decoration:none}
.who{margin-left:auto;font-size:14px;color:var(--muted)}
main{max-width:820px;margin:0 auto;padding:24px 16px 48px}
footer{text-align:center;color:var(--muted);font-size:12.5px;padding:18px 16px;line-height:1.7}
a{color:var(--accent)}
h1{margin-top:0}
h2{font-size:19px;margin:18px 0 8px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--red-bg);color:var(--red)}
.badge.safe{background:var(--green-bg);color:var(--green)}
.stack{display:flex;flex-direction:column;gap:10px;margin:16px 0;max-width:420px}
input[type=file]{font:inherit;padding:10px;border:1px dashed var(--line);border-radius:8px;background:#fafbfc}
button{font:inherit;padding:10px 18px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600;align-self:flex-start}
button.secondary{background:#6b7280}
.card,.result{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:14px 0}
.result.ok{background:var(--green-bg);border-color:#bfe3c9}
.result.err{background:var(--red-bg);border-color:#f3c9c9}
.card ul{margin:6px 0 0;padding-left:20px}
.card li{margin:4px 0}
table{width:100%;border-collapse:collapse;background:var(--card);margin-top:8px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top;font-size:14px}
th{background:#f1f4f8}
code{font-family:Consolas,"Courier New",monospace;background:#e7ebf1;padding:1px 6px;border-radius:4px;font-size:13px;word-break:break-all}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:10px;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-word}
.muted{color:var(--muted);font-size:14px}
.switch{margin-top:24px;color:var(--muted)}
.tag{display:inline-block;background:var(--amber-bg);color:var(--amber);font-size:11px;font-weight:700;padding:1px 7px;border-radius:999px}
details{margin:14px 0}
summary{cursor:pointer;font-weight:600}
ol{padding-left:22px}ol li{margin:8px 0}
`;

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m⚠  File Upload Lab — เว็บนี้ตั้งใจให้มีช่องโหว่ ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  ลองอัปโหลดไฟล์ .html ที่มี <script> ในหน้า / แล้วกด "เปิด (vuln)"');
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
