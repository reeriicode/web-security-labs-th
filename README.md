# Anti-hacking matters — ชุดแล็บความปลอดภัยเว็บ (ภาษาไทย)

ชุดแล็บสำหรับเรียนรู้ช่องโหว่เว็บยอดฮิตและวิธีป้องกัน แต่ละหัวข้อเป็นโปรเจกต์แยกกัน
มีทั้งหน้าที่ **มีช่องโหว่ (VULNERABLE)** ให้ลองโจมตี และหน้าที่ **แก้แล้ว (SAFE)** ให้เทียบกัน
พร้อมไฟล์ `README.md` อธิบายภาษาไทยในทุกโฟลเดอร์

> ⚠️ **คำเตือน / ข้อกฎหมาย**
> ทุกแล็บในชุดนี้ "ตั้งใจเขียนให้มีช่องโหว่" เพื่อการศึกษาเท่านั้น
> - รันบนเครื่องตัวเอง (`localhost` / `127.0.0.1`) เท่านั้น **ห้ามนำขึ้นเซิร์ฟเวอร์จริงหรือเปิดให้คนอื่นเข้าถึง**
> - เทคนิคในที่นี้ใช้ทดสอบได้เฉพาะระบบของตัวเอง หรือระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น
> - การเจาะระบบของผู้อื่นโดยไม่ได้รับอนุญาตผิดกฎหมาย (พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ฯ)

---

## วิธีใช้งาน

ทุกแล็บใช้แค่ [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้องติดตั้งแพ็กเกจเพิ่มเลย** (`npm install` ก็ไม่ต้อง)

เข้าไปในโฟลเดอร์ของแล็บที่ต้องการ แล้วสั่ง:

```bash
node server.js
```

จากนั้นเปิดเบราว์เซอร์ไปที่พอร์ตของแล็บนั้น (ดูตารางด้านล่าง) และอ่าน `README.md` ในโฟลเดอร์เพื่อทำตามทีละขั้น

เปิด **ทุกแล็บพร้อมกัน** ด้วยคำสั่งเดียว (แต่ละตัวใช้คนละพอร์ต):

```bash
node run-all.js
```

> 📋 ดูคำสั่งโจมตี/payload ของทุกแล็บแบบคัดลอกได้ที่ [COMMANDS.md](COMMANDS.md) — เหมาะสำหรับใช้สอน/อบรม

---

## รายการแล็บ

| # | หัวข้อ | โฟลเดอร์ | พอร์ต | สรุปย่อ |
|---|---|---|---|---|
| 1 | **XSS** (Cross-Site Scripting) | [`XSS/`](XSS/README.md) | 3000 | แทรกสคริปต์ผ่านช่องกรอกข้อมูล → รันในเบราว์เซอร์คนอื่น + ขโมย session |
| 2 | **CSRF** (Cross-Site Request Forgery) | [`CSRF/`](CSRF/README.md) | 4000 | เว็บอื่นหลอกให้เบราว์เซอร์เหยื่อส่งคำสั่ง (เช่น โอนเงิน) ไปพร้อมคุกกี้ |
| 3 | **Broken Access Control** (IDOR) | [`Broken-Access-Control/`](Broken-Access-Control/README.md) | 4100 | แก้ URL ดูข้อมูลของคนอื่น / เข้าหน้า admin ได้ทั้งที่ไม่ใช่แอดมิน |
| 4 | **SQL Injection** | [`SQL-Injection/`](SQL-Injection/README.md) | 4200 | แทรกคำสั่ง SQL ผ่าน input → ล็อกอินข้ามรหัส / ดึงข้อมูลทั้งตาราง |
| 5 | **Authentication** | [`Authentication/`](Authentication/README.md) | 4300 | เก็บรหัสผ่านไม่ปลอดภัย, ไม่จำกัดการเดารหัส, token อ่อน |
| 6 | **CORS misconfiguration** | [`CORS/`](CORS/README.md) | 4400 | ตั้งค่า CORS ผิด → เว็บแฮกเกอร์อ่านข้อมูลลับของผู้ใช้ได้ |
| 7 | **File Upload** | [`File-Upload/`](File-Upload/README.md) | 4500 | อัปโหลดไฟล์อันตราย / ชื่อไฟล์หลอก → โค้ดรันบนเว็บ |
| 8 | **Secrets exposure** | [`Secrets/`](Secrets/README.md) | 4600 | API key หลุดใน frontend, ไฟล์ `.env` ถูกเปิดอ่านได้ |
| 9 | **Error handling** | [`Error-Handling/`](Error-Handling/README.md) | 4800 | เผย stack trace / error ของ DB ให้ผู้ใช้เห็น (information disclosure) |
| 10 | **Dependencies** | [`Dependencies/`](Dependencies/README.md) | 4700 | แพ็กเกจเก่าที่มีช่องโหว่ + วิธีตรวจด้วย `npm audit` |

---

## เทียบกับ OWASP Top 10 / รายการที่ควรรู้

| เรื่องที่พบบ่อย | อยู่ในแล็บ |
|---|---|
| **Broken Access Control** (เจอบ่อยที่สุด) — เช็กทุก API ว่าข้อมูลเป็นของผู้ใช้จริง ไม่ใช่เช็กแค่ล็อกอิน | แล็บ 3 |
| **Injection** (XSS, SQL) | แล็บ 1, 4 |
| **CSRF** — ใช้ `SameSite` และไม่ใช้ `GET` กับคำสั่งที่เปลี่ยนข้อมูล | แล็บ 2 |
| **Authentication** — bcrypt/argon2, rate limit, token อายุสั้น | แล็บ 5 |
| **Secrets** — ไม่ commit `.env`, ไม่ใส่ secret ใน frontend | แล็บ 8 |
| **CORS** — คุมว่าเว็บไหนเรียก API ได้ (แต่ไม่ได้กัน curl/Postman → ต้องมี auth ด้วย) | แล็บ 6 |
| **File upload** — ตรวจชนิด/ขนาด, ตั้งชื่อใหม่, ไม่ให้ไฟล์ถูกรันเป็นโค้ด | แล็บ 7 |
| **Dependencies** — `npm audit` สม่ำเสมอ + อัปเดต | แล็บ 10 |
| **Error message** — ไม่ส่ง stack trace/DB error ให้ผู้ใช้ เก็บใน log ฝั่งเซิร์ฟเวอร์ | แล็บ 9 |

> หมายเหตุเรื่อง **SQL Injection**: ORM อย่าง Prisma ป้องกันให้โดยปริยาย ยกเว้นตอนใช้ `$queryRawUnsafe`
> แล้วเอา string มาต่อกันเอง — ดูรายละเอียดในแล็บ 4

---

## แหล่งเรียนต่อ

- **OWASP Top 10** และ **OWASP Cheat Sheet Series** — รายการช่องโหว่และวิธีป้องกันแต่ละเรื่อง
  <https://owasp.org/www-project-top-ten/> · <https://cheatsheetseries.owasp.org/>
- **PortSwigger Web Security Academy** — แล็บฝึกเจาะช่องโหว่ฟรีและถูกกฎหมาย
  <https://portswigger.net/web-security>
- **MDN Web Docs** — อ่านเรื่อง HTTP, Cookie, CORS ละเอียดและถูกต้อง
  <https://developer.mozilla.org/>
