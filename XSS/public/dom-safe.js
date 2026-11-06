// Lab 3 — DOM-based XSS (แบบแก้แล้ว)

function render() {
  let name;
  try {
    name = decodeURIComponent(location.hash.slice(1));
  } catch {
    name = location.hash.slice(1);
  }
  name = name || 'ผู้มาเยือน';

  // ✅ ใช้ textContent แทน innerHTML
  //    textContent ใส่ข้อมูลเป็น "ข้อความ" เสมอ ไม่ว่าจะมี < > อยู่ข้างในก็ไม่กลายเป็นแท็ก
  document.getElementById('greeting').textContent = 'สวัสดีครับคุณ ' + name;
}

window.addEventListener('hashchange', render);
render();
