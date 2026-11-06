// Lab 3 — DOM-based XSS (แบบมีช่องโหว่)
// อ่านชื่อจากส่วนหลัง # ใน URL แล้วแสดงคำทักทาย

function render() {
  let name;
  try {
    name = decodeURIComponent(location.hash.slice(1)); // SOURCE: ข้อมูลที่ผู้ใช้ควบคุมได้
  } catch {
    name = location.hash.slice(1);
  }
  name = name || 'ผู้มาเยือน';

  // ❌ SINK อันตราย: innerHTML จะตีความข้อความเป็น HTML
  //    ถ้า name เป็น <img src=x onerror=...> เบราว์เซอร์จะสร้างแท็กและรันโค้ดใน onerror
  document.getElementById('greeting').innerHTML = 'สวัสดีครับคุณ ' + name;
}

window.addEventListener('hashchange', render);
render();
