// =====================================================================
//  Dependencies Lab — แดชบอร์ดจำลองเรื่อง "Dependency เก่า/มีช่องโหว่"
//  OWASP A06:2021 — Vulnerable and Outdated Components
//  ⚠ แล็บนี้เน้น "ความเข้าใจ + กระบวนการ" ไม่ได้เจาะระบบจริง
//  ⚠ ห้ามเอาไปรันบนเซิร์ฟเวอร์จริง / ห้ามเปิดให้คนอื่นเข้าถึง
//    รันแค่บนเครื่องตัวเอง (127.0.0.1) เท่านั้น
//
//  ไม่ต้องติดตั้งอะไรเพิ่ม ใช้แค่ Node.js:  node server.js
//  (ข้อมูลช่องโหว่ทั้งหมดเป็นข้อความอธิบายเชิงการศึกษาที่ฝังไว้ในโค้ด
//   ไม่มีการเชื่อมต่ออินเทอร์เน็ต ไม่มีการ npm install ใด ๆ ทั้งสิ้น)
// =====================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');

const HOST = '127.0.0.1'; // ฟังเฉพาะเครื่องตัวเอง คนอื่นในเน็ตเวิร์กเข้าไม่ได้
const PORT = Number(process.env.PORT) || 4700;

// ไฟล์ package.json "ตัวอย่าง" ที่แดชบอร์ดจะอ่านมาวิเคราะห์
const EXAMPLE_PKG = path.join(__dirname, 'vulnerable-example', 'package.json');

// ---------------------------------------------------------------------
// ✅ ฐานข้อมูลช่องโหว่ (จำลอง) — เลียนแบบสิ่งที่ `npm audit` ไปดึงมาจาก
//    GitHub Advisory Database / npm registry
//    ในโลกจริงข้อมูลนี้มาจากออนไลน์ แต่ในแล็บเราฝังไว้เพื่อการศึกษา
//    ข้อมูลอ้างอิงจากช่องโหว่ที่เป็นข่าว/ความรู้ทั่วไป (ไม่ใช่ข้อมูลสด)
// ---------------------------------------------------------------------
const ADVISORIES = {
  lodash: {
    vulnerable: '<4.17.12',
    patched: '4.17.21',
    severity: 'high',
    title: 'Prototype Pollution',
    cve: 'CVE-2019-10744',
    advisory: 'GHSA-jf85-cpcp-j695',
    cwe: 'CWE-1321 (Prototype Pollution)',
    desc:
      'ฟังก์ชัน defaultsDeep ของ lodash เวอร์ชันเก่าถูกหลอกให้เขียนทับ Object.prototype ได้ ' +
      'ทำให้แฮกเกอร์ยัดคุณสมบัติลงไปในทุก object ของโปรแกรม (prototype pollution) ' +
      'นำไปสู่การข้ามการตรวจสอบสิทธิ์หรือรันโค้ดได้ในบางกรณี — lodash เป็นไลบรารียอดฮิตมาก จึงกระทบวงกว้าง',
  },
  minimist: {
    vulnerable: '<1.2.6',
    patched: '1.2.8',
    severity: 'critical',
    title: 'Prototype Pollution',
    cve: 'CVE-2020-7598',
    advisory: 'GHSA-vh95-rmgr-6w4m',
    cwe: 'CWE-1321 (Prototype Pollution)',
    desc:
      'ตัวแยก argument บรรทัดคำสั่งยอดนิยม เวอร์ชันเก่ายอมให้ argument แบบ --__proto__.x ' +
      'ไปแก้ prototype ของทุก object ได้ มักเป็น transitive dependency (ไลบรารีอื่นลากมาให้อีกที) ' +
      'จึงแอบอยู่ในโปรเจกต์โดยที่เราไม่ได้ติดตั้งเองตรง ๆ',
  },
  'event-stream': {
    vulnerable: '>=3.3.6 <4.0.0',
    patched: '4.0.1',
    severity: 'critical',
    title: 'Malicious Code (Supply Chain Attack)',
    cve: 'CVE-2018-16487-เทียบเคียง',
    advisory: 'GHSA-mh6f-8j2x-4483',
    cwe: 'CWE-506 (Embedded Malicious Code)',
    desc:
      'เคสระดับตำนานปี 2018: ผู้ดูแลเดิมมอบสิทธิ์ให้คนแปลกหน้า คนนั้นแอบฝัง dependency ' +
      'ชื่อ flatmap-stream ที่มีโค้ดขโมย wallet คริปโต นี่คือ "supply chain attack" — ' +
      'โค้ดร้ายไม่ได้อยู่ในโปรเจกต์เราแต่ซ่อนอยู่ใน dependency ที่เราเชื่อใจ',
  },
  marked: {
    vulnerable: '<0.3.9',
    patched: '4.0.10',
    severity: 'high',
    title: 'Regular Expression Denial of Service (ReDoS)',
    cve: 'CVE-2017-1000427',
    advisory: 'GHSA-fqmf-w4xh-33rh',
    cwe: 'CWE-400 (Uncontrolled Resource Consumption)',
    desc:
      'ตัวแปลง Markdown เวอร์ชันเก่ามี regex ที่ทำงานช้าแบบ exponential เมื่อเจอ input ที่จัดวางมาเฉพาะ ' +
      'ส่งข้อความสั้น ๆ แต่ทำให้ CPU ค้างได้ (ReDoS) กลายเป็นช่องทาง Denial of Service',
  },
  jquery: {
    vulnerable: '<3.0.0',
    patched: '3.7.1',
    severity: 'moderate',
    title: 'Cross-Site Scripting (XSS)',
    cve: 'CVE-2015-9251',
    advisory: 'GHSA-rmxg-73gg-4mjj',
    cwe: 'CWE-79 (Cross-site Scripting)',
    desc:
      'jQuery รุ่นเก่าจัดการ response แบบ cross-domain ที่เป็น JavaScript โดยเอาไปรันทันที ' +
      'เปิดช่อง XSS หลายเว็บเก่า ๆ ยังค้าง jQuery 1.x อยู่ ทั้งที่ควรอัปเป็น 3.x นานแล้ว',
  },
  moment: {
    vulnerable: '<2.19.3',
    patched: '2.29.4',
    severity: 'high',
    title: 'Regular Expression Denial of Service (ReDoS)',
    cve: 'CVE-2017-18214',
    advisory: 'GHSA-446m-mv8f-q348',
    cwe: 'CWE-400 (Uncontrolled Resource Consumption)',
    desc:
      'ฟังก์ชันแปลงสตริงเป็นวันที่ของ moment เก่า เจอ input ยาว ๆ แล้ว regex ทำงานช้ามาก (ReDoS) ' +
      'หมายเหตุ: ปัจจุบัน moment อยู่ในสถานะ "legacy/maintenance" ทีมพัฒนาแนะนำให้ย้ายไปใช้ตัวใหม่ เช่น date-fns / Luxon / Day.js',
  },
  handlebars: {
    vulnerable: '<4.0.14',
    patched: '4.7.8',
    severity: 'critical',
    title: 'Prototype Pollution → Remote Code Execution',
    cve: 'CVE-2019-19919',
    advisory: 'GHSA-w457-6q6x-cgp9',
    cwe: 'CWE-1321 (Prototype Pollution)',
    desc:
      'เทมเพลตเอนจิน Handlebars เวอร์ชันเก่าถูก prototype pollution จนนำไปสู่การรันโค้ดจากระยะไกล (RCE) ได้ ' +
      'ร้ายแรงเพราะ handlebars มักถูกใช้ render หน้าเว็บจาก input ของผู้ใช้',
  },
  axios: {
    vulnerable: '<0.21.1',
    patched: '1.7.4',
    severity: 'high',
    title: 'Server-Side Request Forgery (SSRF)',
    cve: 'CVE-2020-28168',
    advisory: 'GHSA-4w2v-q235-vp99',
    cwe: 'CWE-918 (Server-Side Request Forgery)',
    desc:
      'ไลบรารี HTTP client ยอดนิยม เวอร์ชันเก่าตามไป redirect แม้เป็นที่อยู่ภายใน (เช่น 169.254.x.x) ' +
      'เปิดช่องให้ bypass proxy และยิง request ไปยังเครือข่ายภายใน (SSRF)',
  },
  debug: {
    vulnerable: '<2.6.9',
    patched: '4.3.4',
    severity: 'moderate',
    title: 'Regular Expression Denial of Service (ReDoS)',
    cve: 'CVE-2017-16137',
    advisory: 'GHSA-gxpj-cx7g-858c',
    cwe: 'CWE-400 (Uncontrolled Resource Consumption)',
    desc:
      'ไลบรารี debug (devDependency ที่พบได้แทบทุกโปรเจกต์ Node) เวอร์ชันเก่ามี regex ReDoS ' +
      'ตัวอย่างที่ดีของ "dependency เล็ก ๆ ที่เราแทบลืมว่ามี" แต่ก็ยังมีช่องโหว่ได้',
  },
  'node-sass': {
    vulnerable: '<4.13.1',
    patched: '7.0.3 (หรือย้ายไปใช้ dart-sass)',
    severity: 'moderate',
    title: 'Denial of Service / โค้ด native ที่เลิกดูแล',
    cve: 'หลายรายการ',
    advisory: 'GHSA-r8f7-9pfq-mjmv',
    cwe: 'CWE-400 / dependency ที่ deprecated',
    desc:
      'node-sass พึ่งพาโค้ด native (LibSass) ที่ปัจจุบัน deprecated แล้ว การ build ต้องคอมไพล์ native ' +
      'ทำให้ติดตั้งยากและมีช่องโหว่ค้าง ชุมชนแนะนำให้ย้ายไปใช้ sass (dart-sass) แทน — ' +
      'ตัวอย่างของ "dependency ที่ถูกทิ้งร้าง (unmaintained)" ซึ่งเป็นความเสี่ยงอีกแบบของ A06',
  },
};

// สถานะของแล็บ (เก็บในหน่วยความจำ; กด "npm audit fix จำลอง" แล้วจะถือว่าแพตช์แล้ว)
let patched = false;

// ---------------------------------------------------------------------
// ยูทิลิตี้
// ---------------------------------------------------------------------
function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// อ่าน package.json ตัวอย่าง แล้วรวม dependencies + devDependencies เป็นรายการเดียว
function loadDependencies() {
  const raw = fs.readFileSync(EXAMPLE_PKG, 'utf8');
  const pkg = JSON.parse(raw);
  const list = [];
  for (const [name, version] of Object.entries(pkg.dependencies || {})) {
    list.push({ name, version, dev: false });
  }
  for (const [name, version] of Object.entries(pkg.devDependencies || {})) {
    list.push({ name, version, dev: true });
  }
  return { pkg, list };
}

// ประเมินสถานะของ dependency แต่ละตัว (จำลองผลจาก npm audit)
function assess(dep) {
  const adv = ADVISORIES[dep.name];
  if (!adv) return { status: 'ok', dep };
  if (patched) return { status: 'patched', dep, adv };
  return { status: 'vuln', dep, adv };
}

const SEV = {
  critical: { label: 'Critical', cls: 'crit' },
  high: { label: 'High', cls: 'high' },
  moderate: { label: 'Moderate', cls: 'mod' },
  low: { label: 'Low', cls: 'low' },
};

// ---------------------------------------------------------------------
// CSS ฝังในโค้ด (ไม่ต้องมีไฟล์แยก)
// ---------------------------------------------------------------------
const STYLE = `
:root{--bg:#f3f5f8;--card:#fff;--text:#1d232b;--muted:#5d6673;--line:#dde1e6;--accent:#8b1a1a;
--crit:#7f1d1d;--crit-bg:#fee2e2;--high:#b91c1c;--high-bg:#fef2f2;--mod:#b45309;--mod-bg:#fff7ed;
--low:#3f6212;--low-bg:#f0fdf4;--ok:#166534;--ok-bg:#dcfce7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Sarabun","Leelawadee UI","Tahoma",system-ui,sans-serif;line-height:1.65}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 20px;background:#1a1626;color:#eee;border-bottom:3px solid var(--accent)}
.logo{font-weight:700;font-size:18px;color:#fff;text-decoration:none}
header nav{margin-left:auto;display:flex;gap:14px}
header nav a{color:#c4b5fd;text-decoration:none;font-size:14px}
main{max-width:900px;margin:0 auto;padding:24px 16px 56px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:18px}
a{color:var(--accent)}
h1{margin-top:0}
h2{margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
.pill{border-radius:999px;padding:6px 16px;font-weight:700;font-size:14px}
.pill.crit{background:var(--crit-bg);color:var(--crit)}
.pill.high{background:var(--high-bg);color:var(--high)}
.pill.mod{background:var(--mod-bg);color:var(--mod)}
.pill.low{background:var(--low-bg);color:var(--low)}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.total{background:#e5e7eb;color:#374151}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:14.5px;margin:8px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f1f4f8}
code{font-family:Consolas,"Courier New",monospace;background:#eef1f6;padding:1px 6px;border-radius:4px;font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:6px;font-size:12px;font-weight:700;white-space:nowrap}
.badge.crit{background:var(--crit-bg);color:var(--crit)}
.badge.high{background:var(--high-bg);color:var(--high)}
.badge.mod{background:var(--mod-bg);color:var(--mod)}
.badge.low{background:var(--low-bg);color:var(--low)}
.badge.ok{background:var(--ok-bg);color:var(--ok)}
.badge.dev{background:#e0e7ff;color:#3730a3}
.muted{color:var(--muted)}
.desc{color:var(--muted);font-size:13.5px;margin-top:4px}
pre{background:#0d1117;color:#c9d1d9;padding:16px;border-radius:10px;overflow:auto;font-size:13px;line-height:1.5}
pre .c-red{color:#ff7b72}pre .c-yel{color:#e3b341}pre .c-grn{color:#7ee787}pre .c-blu{color:#79c0ff}pre .c-dim{color:#8b949e}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
button{font:inherit;padding:10px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.secondary{background:#4b5563}
.note{background:#fffbeb;border:1px solid #fcd34d;border-radius:10px;padding:12px 16px;margin:14px 0;font-size:14px}
.ok-box{background:var(--ok-bg);border:1px solid #86efac;border-radius:10px;padding:12px 16px;margin:14px 0}
`;

// ---------------------------------------------------------------------
// โครงหน้าเว็บ
// ---------------------------------------------------------------------
function page(title, body) {
  return `<!doctype html>
<html lang="th"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Dependencies Lab</title>
  <style>${STYLE}</style>
</head><body>
  <header>
    <a href="/" class="logo">📦 Dependencies Lab</a>
    <nav>
      <a href="/">แดชบอร์ด</a>
      <a href="/audit">npm audit (จำลอง)</a>
      <a href="/pkg">ดู package.json</a>
    </nav>
  </header>
  <main>${body}</main>
  <footer>เพื่อการศึกษาการป้องกัน ใช้บนเครื่องตัวเองเท่านั้น · OWASP A06:2021 · Anti-hacking matters</footer>
</body></html>`;
}

// =====================================================================
// หน้าแดชบอร์ด: อ่าน package.json ตัวอย่าง แล้วแสดงสถานะ dependency
// =====================================================================
function dashboardPage() {
  const { list } = loadDependencies();
  const results = list.map(assess);

  // นับจำนวนตามความรุนแรง
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  let vulnCount = 0;
  for (const r of results) {
    if (r.status === 'vuln') {
      vulnCount++;
      counts[r.adv.severity] = (counts[r.adv.severity] || 0) + 1;
    }
  }

  const summary = patched
    ? `<div class="ok-box">✔ <b>แพตช์แล้ว (จำลอง)</b> — ทุก dependency ถูกอัปเดตเป็นเวอร์ชันที่ปลอดภัยแล้ว
         พบ <b>0</b> ช่องโหว่ · ลองกด "รีเซ็ตแล็บ" เพื่อย้อนกลับไปสถานะเริ่มต้นที่ยังมีช่องโหว่</div>`
    : `<div class="summary">
         <span class="pill total">${list.length} dependencies</span>
         <span class="pill crit">${counts.critical} critical</span>
         <span class="pill high">${counts.high} high</span>
         <span class="pill mod">${counts.moderate} moderate</span>
         <span class="pill ok">${list.length - vulnCount} ปลอดภัย</span>
       </div>`;

  const rows = results.map((r) => {
    const d = r.dep;
    const devTag = d.dev ? ' <span class="badge dev">dev</span>' : '';
    if (r.status === 'ok') {
      return `<tr>
        <td><code>${escapeHtml(d.name)}</code>${devTag}</td>
        <td><code>${escapeHtml(d.version)}</code></td>
        <td><span class="badge ok">ไม่พบช่องโหว่</span></td>
        <td class="muted">—</td>
      </tr>`;
    }
    if (r.status === 'patched') {
      return `<tr>
        <td><code>${escapeHtml(d.name)}</code>${devTag}</td>
        <td><code>${escapeHtml(r.adv.patched)}</code></td>
        <td><span class="badge ok">แพตช์แล้ว</span></td>
        <td class="muted">อัปจาก ${escapeHtml(d.version)} → ${escapeHtml(r.adv.patched)}</td>
      </tr>`;
    }
    const sev = SEV[r.adv.severity] || SEV.low;
    return `<tr>
      <td><code>${escapeHtml(d.name)}</code>${devTag}</td>
      <td><code>${escapeHtml(d.version)}</code></td>
      <td><span class="badge ${sev.cls}">${sev.label}</span></td>
      <td>
        <b>${escapeHtml(r.adv.title)}</b>
        · <code>${escapeHtml(r.adv.cve)}</code>
        <div class="desc">${escapeHtml(r.adv.desc)}</div>
        <div class="desc">ช่วงที่มีช่องโหว่: <code>${escapeHtml(r.adv.vulnerable)}</code>
          · ควรอัปเป็น <code>${escapeHtml(r.adv.patched)}</code>
          · <span class="muted">${escapeHtml(r.adv.advisory)}</span></div>
      </td>
    </tr>`;
  }).join('');

  return page('แดชบอร์ด', `
    <h1>📦 แดชบอร์ดตรวจ Dependency</h1>
    <p>หน้านี้อ่านไฟล์ <code>vulnerable-example/package.json</code> แล้วเทียบแต่ละ dependency
       กับฐานข้อมูลช่องโหว่ (จำลอง) เพื่อให้เห็นว่าเครื่องมืออย่าง <code>npm audit</code> ทำงานอย่างไร<br>
       <span class="muted">A06:2021 — Vulnerable and Outdated Components</span></p>

    <div class="note">⚠ ตัวเลข/คำอธิบายช่องโหว่ทั้งหมดเป็น <b>ข้อมูลเชิงการศึกษาที่ฝังไว้ในโค้ด</b>
       ไม่ได้ดึงออนไลน์ และ <b>ไม่มีการ npm install จริง</b> ไฟล์ตัวอย่างมีไว้ให้อ่านเท่านั้น</div>

    ${summary}

    <table>
      <tr><th>แพ็กเกจ</th><th>เวอร์ชันที่ใช้</th><th>สถานะ</th><th>รายละเอียด</th></tr>
      ${rows}
    </table>

    <div class="actions">
      ${patched
        ? `<form method="post" action="/reset"><button class="secondary">↺ รีเซ็ตแล็บ (กลับไปสถานะมีช่องโหว่)</button></form>`
        : `<form method="post" action="/fix"><button>🔧 จำลอง "npm audit fix" (อัปเกรดทุกตัว)</button></form>`}
      <a href="/audit"><button type="button" class="secondary">ดูตัวอย่างผลลัพธ์ npm audit</button></a>
    </div>

    <h2>อ่านตารางนี้อย่างไร</h2>
    <ul>
      <li><b>เวอร์ชันที่ใช้</b> คือเวอร์ชันที่ pin ไว้ใน package.json — ยิ่งห่างจากเวอร์ชันล่าสุดมาก ยิ่งเสี่ยง</li>
      <li><b>ความรุนแรง (severity)</b> มาจากผลกระทบของช่องโหว่: Critical &gt; High &gt; Moderate &gt; Low</li>
      <li><b>dev</b> = เป็น devDependency (ใช้ตอนพัฒนา/บิลด์) ยังมีความเสี่ยงได้ โดยเฉพาะในขั้นตอน CI/CD</li>
      <li>ช่องโหว่หลายตัวเป็น <b>transitive dependency</b> — ไลบรารีที่ dependency ของเราลากมาให้อีกที
          เราไม่ได้ติดตั้งเองตรง ๆ แต่ก็ได้รับผลกระทบ</li>
    </ul>
  `);
}

// =====================================================================
// หน้า "ตัวอย่างผลลัพธ์ npm audit (จำลอง)"
// =====================================================================
function auditPage() {
  if (patched) {
    return page('npm audit (จำลอง)', `
      <h1>ตัวอย่างผลลัพธ์ <code>npm audit</code> (จำลอง)</h1>
      <p>หลังจากกด "npm audit fix จำลอง" แล้ว รายงานจะหน้าตาแบบนี้:</p>
      <pre><span class="c-grn">found 0 vulnerabilities</span></pre>
      <p class="muted">คำว่า <code>found 0 vulnerabilities</code> คือเป้าหมายที่เราอยากเห็น
         <a href="/">กลับไปแดชบอร์ด</a> แล้วกดรีเซ็ตเพื่อดูสถานะก่อนแก้อีกครั้ง</p>
    `);
  }

  const { list } = loadDependencies();
  const results = list.map(assess).filter((r) => r.status === 'vuln');
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const r of results) counts[r.adv.severity] = (counts[r.adv.severity] || 0) + 1;

  // สร้างบล็อกรายงานต่อช่องโหว่ เลียนแบบหน้าตาของ `npm audit`
  const blocks = results.map((r) => {
    const d = r.dep;
    const sev = (SEV[r.adv.severity] || SEV.low).label;
    const sevColor = r.adv.severity === 'critical' || r.adv.severity === 'high' ? 'c-red' : 'c-yel';
    return (
`<span class="${sevColor}">${escapeHtml(d.name)}</span>  <span class="${sevColor}">${sev}</span>
<span class="c-dim">Severity: ${escapeHtml(r.adv.severity)}</span>
${escapeHtml(r.adv.title)} - <span class="c-blu">https://github.com/advisories/${escapeHtml(r.adv.advisory)}</span>
<span class="c-dim">${escapeHtml(r.adv.cwe)}</span>
<span class="c-dim">vulnerable: ${escapeHtml(r.adv.vulnerable)}  (ติดตั้งอยู่: ${escapeHtml(d.version)})</span>
<span class="c-grn">fix available via \`npm audit fix --force\`</span>
<span class="c-dim">Will upgrade ${escapeHtml(d.name)} to ${escapeHtml(r.adv.patched)}</span>`
    );
  }).join('\n\n');

  const total = results.length;
  const sevLine = `<span class="c-red">${counts.critical} critical</span>, <span class="c-red">${counts.high} high</span>, <span class="c-yel">${counts.moderate} moderate</span>`;

  return page('npm audit (จำลอง)', `
    <h1>ตัวอย่างผลลัพธ์ <code>npm audit</code> (จำลอง)</h1>
    <p>นี่คือหน้าตาของรายงานที่คุณจะเห็นบน terminal จริงเมื่อรัน <code>npm audit</code>
       ในโปรเจกต์ที่ใช้ dependency เวอร์ชันเหล่านี้ — ฝึกอ่านว่าแต่ละบรรทัดบอกอะไร</p>

    <pre><span class="c-dim">$ npm audit</span>

<span class="c-dim"># npm audit report</span>

${blocks}

<span class="c-dim">${total} vulnerabilities (</span>${sevLine}<span class="c-dim">)</span>

<span class="c-dim">To address all issues (including breaking changes), run:</span>
  <span class="c-grn">npm audit fix --force</span></pre>

    <h2>วิธีอ่านรายงาน npm audit</h2>
    <ul>
      <li><b>ชื่อแพ็กเกจ + ระดับความรุนแรง</b> อยู่บรรทัดแรกของแต่ละบล็อก (critical/high/moderate/low)</li>
      <li><b>ลิงก์ advisory</b> (GHSA-...) กดเข้าไปอ่านรายละเอียด CVE/CWE และตัวอย่างการโจมตีได้</li>
      <li><b>vulnerable</b> บอกช่วงเวอร์ชันที่มีปัญหา เทียบกับเวอร์ชันที่เราติดตั้งอยู่</li>
      <li><b>fix available</b> บอกว่าแก้ได้ด้วย <code>npm audit fix</code> หรือไม่ ถ้ามี
          <code>--force</code> แปลว่าการอัปอาจเป็น breaking change ต้องทดสอบก่อน</li>
      <li><b>บรรทัดสรุปท้ายสุด</b> รวมจำนวนช่องโหว่ทั้งหมดแยกตามความรุนแรง</li>
    </ul>

    <div class="note">หมายเหตุ: <code>npm audit</code> ตัวจริงจะไล่รวม <b>transitive dependency</b> ทั้งต้นไม้ด้วย
      ดังนั้นจำนวนช่องโหว่จริงมักมากกว่าจำนวน dependency ที่เราเขียนไว้เองใน package.json</div>

    <p><a href="/">← กลับไปแดชบอร์ด</a></p>
  `);
}

// =====================================================================
// หน้าแสดงเนื้อไฟล์ package.json ตัวอย่าง
// =====================================================================
function pkgPage() {
  const raw = fs.readFileSync(EXAMPLE_PKG, 'utf8');
  return page('package.json ตัวอย่าง', `
    <h1>ไฟล์ <code>vulnerable-example/package.json</code></h1>
    <p>นี่คือไฟล์ตัวอย่าง (สมมติว่าเป็นของโปรเจกต์หนึ่ง) ที่แดชบอร์ดอ่านมาวิเคราะห์
       ทุกเวอร์ชันถูกเลือกมาเพราะเป็นเวอร์ชันเก่าที่รู้กันว่ามีช่องโหว่</p>
    <pre>${escapeHtml(raw)}</pre>
    <p class="muted">⚠ ห้าม <code>npm install</code> ไฟล์นี้จริง — มีไว้อ่านและวิเคราะห์เท่านั้น</p>
    <p><a href="/">← กลับไปแดชบอร์ด</a></p>
  `);
}

// =====================================================================
// Router
// =====================================================================
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 10_000) req.destroy(); });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(''));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  const p = url.pathname;

  try {
    if (req.method === 'GET') {
      switch (p) {
        case '/':
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(dashboardPage());
        case '/audit':
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(auditPage());
        case '/pkg':
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(pkgPage());
      }
    }

    if (req.method === 'POST') {
      await readBody(req);
      switch (p) {
        case '/fix':
          patched = true;
          console.log('\x1b[32m[แล็บ] จำลอง "npm audit fix" — ถือว่าอัปเกรด dependency ทุกตัวแล้ว\x1b[0m');
          res.writeHead(303, { Location: '/' });
          return res.end();
        case '/reset':
          patched = false;
          console.log('\x1b[33m[แล็บ] รีเซ็ต — กลับไปสถานะที่ยังมีช่องโหว่\x1b[0m');
          res.writeHead(303, { Location: '/' });
          return res.end();
      }
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page('404', '<h1>404</h1><p>ไม่พบหน้านี้ <a href="/">กลับแดชบอร์ด</a></p>'));
  } catch (err) {
    console.error(err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(page('500', '<h1>500</h1><p>เกิดข้อผิดพลาด (อ่านไฟล์ตัวอย่างไม่ได้?)</p>'));
    }
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  \x1b[33m📦 Dependencies Lab — OWASP A06:2021 Vulnerable & Outdated Components\x1b[0m');
  console.log('  \x1b[33m   เพื่อการศึกษาการป้องกัน ใช้บนเครื่องตัวเองเท่านั้น (ไม่มีการ npm install จริง)\x1b[0m');
  console.log(`  เปิดเบราว์เซอร์ไปที่:  \x1b[36mhttp://localhost:${PORT}\x1b[0m`);
  console.log('  กด Ctrl+C เพื่อปิด');
  console.log('');
});
