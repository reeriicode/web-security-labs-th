// =====================================================================
//  ตัวรันรวม — เปิดแล็บทั้ง 10 ตัวพร้อมกันในโปรเซสเดียว
//  ใช้:  node run-all.js
//  กด Ctrl+C ครั้งเดียวเพื่อปิดทุกแล็บ
//  (แต่ละแล็บฟังคนละพอร์ต ดูรายการด้านล่าง)
//
//  ⚠ ทุกแล็บตั้งใจให้มีช่องโหว่ ใช้บนเครื่องตัวเองเท่านั้น ห้าม deploy
// =====================================================================

const path = require('path');

const LABS = [
  ['XSS',                   3000],
  ['CSRF',                  4000],
  ['Broken-Access-Control', 4100],
  ['SQL-Injection',         4200],
  ['Authentication',        4300],
  ['CORS',                  4400],
  ['File-Upload',           4500],
  ['Secrets',               4600],
  ['Dependencies',          4700],
  ['Error-Handling',        4800],
];

console.log('\n  \x1b[33m⚠  ชุดแล็บความปลอดภัยเว็บ — ตั้งใจให้มีช่องโหว่ ใช้บนเครื่องตัวเองเท่านั้น\x1b[0m\n');

let ok = 0;
for (const [folder, port] of LABS) {
  try {
    // แต่ละ server.js จะ listen พอร์ตของตัวเองทันทีที่ require
    require(path.join(__dirname, folder, 'server.js'));
    ok++;
  } catch (err) {
    console.error(`  \x1b[31m✗ เปิด ${folder} ไม่สำเร็จ:\x1b[0m ${err.message}`);
  }
}

// สรุปรายการลิงก์ให้กดง่ายๆ (พิมพ์หลัง event loop ตั้งต้นเสร็จ)
setTimeout(() => {
  console.log(`\n  \x1b[32mเปิดแล็บสำเร็จ ${ok}/${LABS.length} ตัว\x1b[0m  — เปิดเบราว์เซอร์ไปที่:`);
  for (const [folder, port] of LABS) {
    console.log(`    \x1b[36mhttp://localhost:${port}\x1b[0m  ${folder}`);
  }
  console.log('\n  กด \x1b[33mCtrl+C\x1b[0m เพื่อปิดทุกแล็บ\n');
}, 300);
