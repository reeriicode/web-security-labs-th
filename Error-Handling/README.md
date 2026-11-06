# Error-Handling Lab — แล็บฝึกเรื่องการจัดการ Error อย่างปลอดภัย

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง ห้าม deploy และห้ามเอาเทคนิคไปลองกับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

หัวข้อ: **Improper Error Handling / Information Disclosure** — การเผยรายละเอียด error มากเกินไปจนกลายเป็นเบาะแสให้ผู้โจมตี

---

## 1. ปัญหานี้คืออะไร

เวลาเว็บเกิดข้อผิดพลาด (error) มันต้องตอบอะไรบางอย่างกลับไปให้ผู้ใช้ คำถามคือ **ตอบมากแค่ไหน**

หลายเว็บ (โดยเฉพาะตอนเปิด debug mode ค้างไว้) เลือกตอบ **ทุกอย่าง** กลับไปเลย ได้แก่

- **Stack trace เต็ม** — บอกว่าโค้ดพังที่ไฟล์ไหน บรรทัดไหน ฟังก์ชันอะไรเรียกอะไรต่อ
- **error ของฐานข้อมูล** — ชื่อตาราง ชื่อคอลัมน์ หน้าตา SQL query ชนิดฐานข้อมูลและเวอร์ชัน
- **path ของไฟล์บนเซิร์ฟเวอร์** — เช่น `/var/www/bank-app/...` หรือ `C:\inetpub\...`
- **เวอร์ชันของภาษา/เฟรมเวิร์ก/ไลบรารี** — Node 20.x, Express 4.x, pg 8.11.3 ฯลฯ

สิ่งเหล่านี้ไม่ได้ทำให้เว็บพังในตัวมันเอง แต่มันคือ **แผนที่ให้ผู้โจมตี**

> ต้นเหตุมีข้อเดียว: **เว็บเอา error ภายในระบบ (ที่มีไว้ให้ dev อ่าน) ส่งตรงกลับไปให้ผู้ใช้/ผู้โจมตีเห็น**

### ทำไมถึงอันตราย (information disclosure นำไปสู่การโจมตีอื่น)

ตัว error ที่หลุดออกมาเป็น "ข้อมูลข่าวกรอง" ให้ผู้โจมตีย่นเวลาขั้น reconnaissance ไปมาก เช่น

- เห็นว่าใช้ PostgreSQL + เห็น query `SELECT ... FROM app_users WHERE id = '...'`
  → รู้ว่ามีตาราง `app_users` คอลัมน์ `password_hash` และจุดนี้น่าจะมีช่องโหว่ **SQL Injection** ให้ลองต่อ
- เห็น path เต็ม `/var/www/bank-app/db/users.js`
  → รู้โครงสร้างไดเรกทอรี เดา endpoint/ไฟล์สำรอง (`.bak`, `.git`, config) ได้
- เห็นเวอร์ชันไลบรารีที่ล้าสมัย
  → ไปเปิด CVE หา exploit สำเร็จรูปที่ตรงเวอร์ชันนั้นได้ทันที
- เห็น error message ต่างกันระหว่าง "ผู้ใช้ไม่มี" กับ "รหัสผ่านผิด"
  → ทำ **user enumeration** ไล่เดาว่ามีบัญชีไหนอยู่จริง

พูดง่ายๆ: error ที่ละเอียดเกินไป = ยื่นพิมพ์เขียวของระบบให้คนที่กำลังจะโจมตีคุณ

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง npm install อะไรเลย** (ใช้ built-in module ล้วน)

```bash
node server.js
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:4800>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้

### โครงสร้างไฟล์

```
Error-Handling/
├── server.js             ← เซิร์ฟเวอร์ทั้งหมด (CSS ฝังในโค้ด ไม่มีไฟล์แยก)
├── package.json
├── .claude/launch.json   ← ตั้งค่ารัน preview (name: error-lab, port: 4800)
└── README.md             ← ไฟล์นี้
```

---

## 3. endpoint ในแล็บ

ทุก endpoint มี 2 โหมด: โหมดปกติ (มีช่องโหว่) ขึ้นต้นด้วย `/` ส่วนโหมดปลอดภัยขึ้นต้นด้วย `/safe`

| Endpoint | ทำอะไร | อินพุตปกติ | อินพุตที่ทำให้ error |
|---|---|---|---|
| `/user?id=` | ค้นผู้ใช้จาก id (จำลอง query ไป PostgreSQL) | `/user?id=1` | `/user?id=abc` (ผิดชนิด), `/user?id=999` (ไม่มีจริง) |
| `/parse?data=` | `JSON.parse()` ข้อมูลที่ส่งมา | `/parse?data={"a":1}` | `/parse?data={bad` (JSON พัง) |
| `/divide?a=&b=` | หารเลขด้วย "เครื่องคิดเลขของระบบ" | `/divide?a=10&b=2` | `/divide?a=10&b=0` (หารศูนย์), `/divide?a=x&b=2` (ไม่ใช่ตัวเลข) |
| `/config` | อ่านไฟล์ตั้งค่า (ไฟล์ตั้งใจไม่มี → `ENOENT`) | — | `/config` (เผย path เต็ม) |
| `/logs` | ดู log ฝั่งเซิร์ฟเวอร์ (จำลองว่าเฉพาะ dev เห็น) | — | — |
| `/reset` | ล้าง log และข้อมูลในหน่วยความจำ | — | — |

---

## 4. ลองโจมตี (โหมดมีช่องโหว่)

### 4.1 ดึงข้อมูลฐานข้อมูลจาก error — `/user?id=abc`

1. เปิด <http://localhost:4800/user?id=abc>
2. หน้าเว็บจะคายรายละเอียดออกมาทั้งหมด ลองสังเกต

   - **ชนิด:** `DatabaseError` · **code:** `22P02` (รหัส error จริงของ PostgreSQL = ชนิดข้อมูลผิด)
   - **ข้อความ:** เผย query เต็ม
     `SELECT id, username, email, password_hash, role FROM app_users WHERE id = 'abc' LIMIT 1`
     พร้อมชื่อ schema (`public`), ตาราง (`app_users`), ชื่อ db/host (`corp_prod@db-01.internal:5432`), เวอร์ชัน driver (`pg@8.11.3`)
   - **Stack trace:** บอก path ไฟล์จริงบนเครื่อง (เช่น `...\Error-Handling\server.js:...`)
   - **ข้อมูลระบบ:** เวอร์ชัน Node.js, OS, path ของแอป

3. แค่จากหน้าเดียวนี้ ผู้โจมตีรู้แล้วว่า: ใช้ PostgreSQL, มีตาราง `app_users` ที่มีคอลัมน์ `password_hash`, จุดนี้รับ `id` ไปต่อ query ตรงๆ (น่าลอง SQL Injection), เวอร์ชัน `pg` เท่านี้

### 4.2 เบาะแสจากการ parse — `/parse?data={bad`

เปิด <http://localhost:4800/parse?data=%7Bbad> จะเห็น `SyntaxError` ของ JSON พร้อม stack trace ชี้เข้าไปถึง internals ของ Node

### 4.3 path ไฟล์หลุดจาก error ของระบบไฟล์ — `/config`

เปิด <http://localhost:4800/config> โค้ดพยายามอ่านไฟล์ `config/database.secret.json` ที่ไม่มีอยู่จริง
→ เกิด `ENOENT` ที่ **มี path เต็มติดมาด้วย** บอกโครงสร้างไดเรกทอรีของเซิร์ฟเวอร์

### 4.4 หารด้วยศูนย์ — `/divide?a=10&b=0`

เปิด <http://localhost:4800/divide?a=10&b=0> เห็น `RangeError` (code `E_DIV_ZERO`) พร้อม stack trace

> ข้อสังเกต: ทุกหน้าในโหมดนี้ **ตอบ HTTP 500 พร้อมโยนทุกอย่างกลับไปที่เบราว์เซอร์** ซึ่งเป็นสิ่งที่ไม่ควรทำ

---

## 5. ลองแบบที่แก้แล้ว (โหมดปลอดภัย)

เติม `/safe` นำหน้า endpoint เดิม แล้วเทียบ

1. เปิด <http://localhost:4800/safe/user?id=abc>
2. คราวนี้ผู้ใช้เห็นแค่

   > ขออภัย เกิดข้อผิดพลาดบางอย่าง — กรุณาแจ้งรหัสอ้างอิง **error id: `9f3a1c7b2e`**

   - **ไม่มี** stack trace, **ไม่มี** path ไฟล์, **ไม่มี** ชื่อตาราง/คอลัมน์, **ไม่มี** เวอร์ชัน
   - ยังตอบ **HTTP 500** ตามจริง (ไม่ใช่แกล้งตอบ 200)

3. แล้วรายละเอียดจริงหายไปไหน? → ถูก **log ไว้ฝั่งเซิร์ฟเวอร์** ด้วย error id เดียวกัน
   เปิด <http://localhost:4800/logs> หรือดูใน terminal ที่รันเซิร์ฟเวอร์ จะเห็น stack trace เต็มผูกกับ `error id: 9f3a1c7b2e`

4. เมื่อผู้ใช้โทรแจ้ง "เจอ error id 9f3a1c7b2e" → dev ค้น log เจอ stack เต็มทันที **ตามสืบได้โดยไม่ต้องเปิดเผยอะไรต่อผู้ใช้เลย**

ลองโหมด safe ของหน้าอื่นได้เหมือนกัน:
<http://localhost:4800/safe/parse?data=%7Bbad> ·
<http://localhost:4800/safe/divide?a=10&b=0> ·
<http://localhost:4800/safe/config>

### โค้ดเทียบกัน (`server.js`)

```js
// ❌ โหมดมีช่องโหว่: โยน stack + error ของ DB กลับไปแสดงบนหน้าเว็บ
function renderErrorVuln(res, err, context) {
  // ... ส่ง err.message, err.code, err.stack, เวอร์ชัน Node, path ของแอป กลับไปทั้งหมด
}

// ✅ โหมดปลอดภัย: ผู้ใช้เห็นแค่ข้อความทั่วไป + error id, รายละเอียดจริง log ไว้ที่ server
function renderErrorSafe(res, err, context) {
  const errorId = newErrorId();          // สุ่ม id
  logServerSide(errorId, err, context);  // stack เต็ม → log ฝั่ง server เท่านั้น
  // ตอบผู้ใช้: "เกิดข้อผิดพลาด (error id: <errorId>)" + HTTP 500
}
```

---

## 6. วิธีป้องกันที่ถูกต้อง

### ✅ 1. แยก "ข้อความสำหรับผู้ใช้" ออกจาก "รายละเอียดสำหรับ dev"
ผู้ใช้เห็นแค่ข้อความทั่วไป + รหัสอ้างอิง (error id) ส่วน stack trace/รายละเอียดจริงเก็บไว้ฝั่งเซิร์ฟเวอร์

### ✅ 2. Server-side logging + error id (correlation id)
สุ่ม id ต่อ error หนึ่งครั้ง แล้ว

- **ตอบผู้ใช้**: "เกิดข้อผิดพลาด (error id: `xxxx`)"
- **log ฝั่ง server**: id เดียวกัน + stack trace เต็ม + context

→ dev ตามสืบจาก id ได้ 100% โดยผู้ใช้/ผู้โจมตีไม่เห็นอะไรเลย (ดูฟังก์ชัน `logServerSide` ในโค้ด)

### ✅ 3. ส่ง HTTP status code ที่ถูกต้อง
error ของเซิร์ฟเวอร์ = `500`, ไม่พบ = `404`, ไม่มีสิทธิ์ = `403` ฯลฯ
แต่ **เนื้อหา** ต้องเป็นข้อความทั่วไป ไม่ใช่ตอบ 200 แกล้งว่าไม่มีอะไรเกิดขึ้น

### ✅ 4. ปิด debug mode บน production
กรอบส่วนใหญ่เปิด error page ละเอียดไว้ให้ตอน dev ต้อง **ปิด** ก่อนขึ้นจริง เช่น

- Express: `app.get('env')` ไม่ให้เป็น `development`, อย่าส่ง `err.stack` ใน response
- Django: `DEBUG = False` (และตั้ง `ALLOWED_HOSTS`)
- PHP: `display_errors = Off` + `log_errors = On`
- Flask: อย่ารันด้วย `debug=True`
- ASP.NET: `<customErrors mode="On">` / `<deployment retail="true">`

### ✅ 5. มี error handler กลาง (catch-all) และ custom error page
ดัก error ทุกตัวที่จุดเดียว แปลงเป็น response ที่ปลอดภัยเสมอ และทำหน้า 404/500 ของตัวเอง
(อย่าให้ error page เริ่มต้นของเฟรมเวิร์กซึ่งมักโชว์เวอร์ชัน/stack โผล่)

### ✅ 6. ให้ error message เป็นกลางเสมอ (กัน enumeration)
"ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" (ข้อความเดียว) ดีกว่าแยกเป็น "ไม่มีผู้ใช้นี้" กับ "รหัสผ่านผิด"

---

## 7. สิ่งที่ "ไม่ควรทำ"

| สิ่งที่ทำผิด | ทำไมถึงไม่ดี |
|---|---|
| ส่ง `err.stack` กลับไปใน response | เผย path ไฟล์ โครงสร้างโค้ด internals ของเฟรมเวิร์ก |
| โชว์ error ดิบของ DB ให้ผู้ใช้ | เผยชื่อตาราง/คอลัมน์/query → นำไปสู่ SQL Injection |
| ปล่อย debug mode ไว้บน production | หน้าตั้งต้นของเฟรมเวิร์กคายทุกอย่างให้อัตโนมัติ |
| กลืน error เงียบๆ แล้วตอบ 200 | ผู้ใช้/ระบบ monitoring ไม่รู้ว่าพลาด แถม dev ก็ตามไม่เจอ |
| log รายละเอียดแล้ว**ไม่**ให้ error id ผู้ใช้ | ผู้ใช้แจ้งปัญหา แต่ dev หาใน log ไม่เจอว่าอันไหน |
| ใส่ข้อมูลลับ (คีย์/รหัส/ข้อมูลส่วนตัว) ลงใน log | log เองก็กลายเป็นเป้าหมายข้อมูลรั่ว ต้อง redact ก่อน |
| error message ต่างกันระหว่าง "ไม่มีผู้ใช้" กับ "รหัสผิด" | เปิดทางให้ไล่เดาบัญชีที่มีอยู่จริง (user enumeration) |

---

## 8. สรุปสั้นๆ (จำไว้ข้อเดียวก็ได้)

> **ผู้ใช้เห็น "ขออภัย เกิดข้อผิดพลาด + error id" พอ — รายละเอียดจริงเก็บไว้ใน log ฝั่งเซิร์ฟเวอร์**

Checklist ก่อนขึ้น production:

- [ ] ปิด debug mode ทุกที่ (เฟรมเวิร์ก, ภาษา, DB driver)
- [ ] ผู้ใช้ไม่เคยเห็น stack trace / path ไฟล์ / error ดิบของ DB
- [ ] มี error handler กลาง + custom 404/500 page
- [ ] ทุก error มี error id และ log รายละเอียดฝั่ง server ด้วย id เดียวกัน
- [ ] ส่ง HTTP status code ให้ตรงความจริง (500/404/403)
- [ ] error message เป็นกลาง ไม่ช่วยไล่เดาข้อมูล (enumeration)
- [ ] log ไม่เก็บความลับ (รหัสผ่าน/โทเคน/ข้อมูลส่วนตัว) แบบไม่ปิดบัง

---

## 9. รีเซ็ตแล็บ

อยากล้าง log เริ่มใหม่ เข้า <http://localhost:4800/reset> (หรือปิดแล้วเปิดเซิร์ฟเวอร์ใหม่)

---

## อ้างอิง

- OWASP — Improper Error Handling: <https://owasp.org/www-community/Improper_Error_Handling>
- OWASP — Error Handling Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html>
- OWASP — Logging Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- OWASP Top 10 (A05:2021 — Security Misconfiguration): <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
- MDN — HTTP 500 Internal Server Error: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500>
- MDN — HTTP response status codes: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status>
