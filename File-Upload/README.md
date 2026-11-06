# File Upload Lab — แล็บฝึกทำความเข้าใจ Insecure File Upload

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง ห้าม deploy และห้ามเอาเทคนิคไปลองกับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 1. Insecure File Upload คืออะไร

ช่องโหว่ **การอัปโหลดไฟล์ที่ไม่ปลอดภัย** เกิดเมื่อเว็บยอมให้ผู้ใช้อัปโหลดไฟล์ โดย

> **เชื่อไฟล์ที่ผู้ใช้ส่งมา "ตามที่มันบอก"** — เชื่อนามสกุล เชื่อชื่อไฟล์ เชื่อ Content-Type ที่ผู้ใช้ส่งมา
> แล้วเอาไปเก็บ/เอาไปเสิร์ฟต่อโดยไม่ตรวจสอบของจริง

ปัญหาหลักมี 3 จุด และแล็บนี้สาธิตครบทั้งสาม

| จุดพลาด | ผลที่ตามมา |
|---|---|
| ไม่ตรวจว่าไฟล์เป็น "ชนิดอะไรจริงๆ" | อัปโหลดไฟล์อันตราย (เช่น `.html`, `.svg`, สคริปต์ฝั่ง server) ปนเข้ามาได้ |
| ใช้ "ชื่อไฟล์เดิมจากผู้ใช้" ตรงๆ | ชื่อที่มี `../` ทำให้ไฟล์หลุดออกนอกโฟลเดอร์ (path traversal) ทับไฟล์สำคัญได้ |
| เสิร์ฟไฟล์กลับโดยตั้ง Content-Type ตามนามสกุล | เบราว์เซอร์ "ตีความและรัน" ไฟล์ของแฮกเกอร์ในโดเมนของเรา |

### แฮกเกอร์เอาไปทำอะไรได้

- อัปโหลดไฟล์ **`.html` / `.svg` ที่มี `<script>`** แล้วหลอกให้เหยื่อเปิด → สคริปต์รันในโดเมนของเว็บเรา
  = **Stored XSS** (ขโมยคุกกี้/เซสชัน, ปลอมหน้า, ทำแทนผู้ใช้ได้ทุกอย่าง)
- ถ้าเซิร์ฟเวอร์ "เผลอรัน" ไฟล์ที่อัปโหลด (เช่น `.php`, `.jsp`, `.aspx` หรือ `.js` ที่ถูก `require`/execute ฝั่ง server)
  จะกลายเป็น **RCE (Remote Code Execution)** — ยึดเครื่องได้เลย ซึ่งรุนแรงที่สุด
  > แล็บนี้ **ไม่** รันไฟล์ฝั่ง server (เสิร์ฟเป็นไฟล์เฉยๆ) จึงสาธิตแค่ฝั่ง Stored XSS ที่เห็นภาพชัดและปลอดภัยต่อเครื่องผู้เรียน
  > แต่หลักการเดียวกัน: ถ้า runtime ของเซิร์ฟเวอร์ตีความไฟล์ที่อัปโหลดเมื่อไร = RCE ทันที
- เขียนไฟล์ทับของเดิมผ่าน path traversal (เช่นชื่อ `../server.js`, `../.htaccess`, `../config`)

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง npm install อะไรเลย**
ใช้เฉพาะโมดูลที่มากับ Node.js: `http`, `crypto`, `fs`, `path`, `url`

```bash
node server.js
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:4500>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้
โฟลเดอร์ `uploads/` **โค้ดสร้างให้เองตอนรัน** (ไม่ต้องสร้างไว้ก่อน)

### โครงสร้างไฟล์

```
File-Upload/
├── server.js          ← เซิร์ฟเวอร์ทั้งหมด (CSS ฝังในโค้ด, parser multipart เขียนเอง)
├── package.json
├── .claude/
│   └── launch.json
├── uploads/           ← โค้ดสร้างเองตอนรัน เก็บไฟล์ที่อัปโหลด
└── README.md          ← ไฟล์นี้
```

### หน้าในแล็บ

| โหมด | URL | พฤติกรรม |
|---|---|---|
| มีช่องโหว่ | `/` | รับทุกไฟล์ ใช้ชื่อเดิม เสิร์ฟตามนามสกุล |
| แก้แล้ว | `/safe` | ตรวจ magic bytes, รับเฉพาะรูป, ตั้งชื่อสุ่ม, บังคับดาวน์โหลด |

หน้าเดียวมีทั้ง **ฟอร์มอัปโหลด** และ **รายการไฟล์ที่อัปโหลด** (ลิงก์เปิด/ดาวน์โหลด) ให้เทียบโหมด vuln/safe

---

## 3. วิธีรับไฟล์ในแล็บนี้ (สำคัญ)

แล็บนี้ **เขียน parser `multipart/form-data` เองในโค้ด** (ฟังก์ชัน `parseMultipart` ใน `server.js`)
ไม่ได้ใช้ไลบรารีภายนอก และ**ไม่ได้ fallback เป็นฟอร์มข้อความ** — เป็นการอัปโหลดไฟล์จริงผ่าน `<input type="file">`

หลักการของ parser:

1. อ่านค่า `boundary` จาก header `Content-Type: multipart/form-data; boundary=...`
2. อ่าน body ทั้งก้อนเป็น **Buffer (ไบต์ดิบ)** ไม่แปลงเป็น string เพื่อไม่ให้ไบต์ของไฟล์ไบนารี (รูปภาพ) เพี้ยน
3. ตัด body ด้วย delimiter `--<boundary>` แยกเป็นส่วนๆ (parts)
4. แต่ละ part = `headers` + `\r\n\r\n` + `เนื้อหา` → อ่าน `name`, `filename`, `Content-Type` จาก header แล้วเก็บเนื้อหาเป็น Buffer

ทดสอบแล้วว่าแยกทั้งไฟล์ข้อความ (`.html`) และไฟล์ไบนารี (PNG ที่มีไบต์ `\r\n`, `0xFF`, `--` ปนอยู่) ได้ถูกต้องแบบ byte-exact

---

## 4. โหมดมีช่องโหว่ (`/`) — ลองโจมตี

### 4.1 Stored XSS ด้วยไฟล์ `.html`

1. สร้างไฟล์ชื่อ `evil.html` เนื้อหา:

   ```html
   <html><body><h1>hacked</h1>
   <script>alert('Stored XSS จากไฟล์ที่อัปโหลด: '+document.domain)</script>
   <script>new Image().src='/uploads/__steal?c='+encodeURIComponent(document.cookie)</script>
   </body></html>
   ```

2. อัปโหลดในหน้า `/`
3. ในตารางรายการไฟล์ คลิก **"เปิด (vuln)"** ของ `evil.html`
4. เบราว์เซอร์เปิด `/uploads/evil.html` โดยเซิร์ฟเวอร์ตั้ง `Content-Type: text/html` → **สคริปต์รันในโดเมน `localhost:4500`**
   - `alert` เด้งขึ้น และใน terminal ที่รันเซิร์ฟเวอร์จะขึ้นข้อความสีแดง `[SERVE][XSS] ...`

**ทำไมถึงรันได้:** ไฟล์ถูกเสิร์ฟจาก origin เดียวกับเว็บจริง เบราว์เซอร์จึงถือว่าสคริปต์นี้ "เป็นของเว็บนี้"
อ่าน `document.cookie` ของเว็บนี้ได้ ยิง request ในชื่อผู้ใช้ได้ = Stored XSS เต็มรูปแบบ
(`.svg` ก็ทำแบบเดียวกันได้ เพราะ SVG ฝัง `<script>` ได้ และถูกเสิร์ฟเป็น `image/svg+xml`)

### 4.2 Path Traversal ด้วยชื่อไฟล์

โหมด vuln บันทึกด้วย `path.join(UPLOAD_DIR, ชื่อไฟล์เดิม)` ตรงๆ ถ้าชื่อไฟล์เป็น `../pwned.html`
ไฟล์จะถูกเขียน **นอก** โฟลเดอร์ `uploads/` (ขึ้นไปที่โฟลเดอร์แล็บ)

เบราว์เซอร์ปกติจะแก้ชื่อไฟล์ให้ จึงต้องยิงด้วย `curl` (รันจากโฟลเดอร์แล็บ):

```bash
curl -F "file=@evil.html;filename=../pwned.html" http://localhost:4500/upload
```

หน้าเว็บจะแจ้ง 🚨 พร้อม path จริงที่ไฟล์ไปโผล่ และ terminal ขึ้น `[UPLOAD][PATH-TRAVERSAL] ...` สีแดง

> ⚠ ระวัง: อย่าตั้งชื่อทับไฟล์สำคัญ เช่น `../server.js` เพราะมันจะเขียนทับจริง (นี่คือความอันตรายของช่องโหว่นี้)
> ถ้าเผลอทับ ให้ใช้ไฟล์ `server.js` จากที่อื่นมาคืน

### โค้ดที่มีปัญหา (`server.js` ฟังก์ชัน `saveVuln` / `serveVuln`)

```js
// บันทึก: ใช้ชื่อเดิมตรงๆ → traversal ได้
const dest = path.join(UPLOAD_DIR, file.filename);
fs.writeFileSync(dest, file.data);

// เสิร์ฟ: ตั้ง Content-Type ตามนามสกุล ไม่มี nosniff ไม่มี attachment
res.writeHead(200, { 'Content-Type': mimeByExt(name) });
res.end(data);
```

---

## 5. โหมดแก้แล้ว (`/safe`) — ดูความต่าง

ลองอัปโหลด `evil.html` เดิมในหน้า `/safe` → **ถูกปฏิเสธ** เพราะไม่ใช่รูปจริง
ลองอัปโหลดรูป `.png`/`.jpg`/`.gif` จริง → ผ่าน แต่ถูกตั้งชื่อใหม่เป็นค่าสุ่ม และเวลาเปิดจะ **ดาวน์โหลด** ไม่รัน

โหมด safe ทำ 4 อย่าง:

### 5.1 ตรวจชนิดไฟล์จริงจาก magic bytes (ไม่เชื่อนามสกุล)

อ่านไบต์ต้นไฟล์เทียบกับลายเซ็นไฟล์จริง รับเฉพาะรูปใน allowlist

| ชนิด | magic bytes (hex) |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| GIF | `47 49 46 38` (`GIF8`) |

```js
const sig = IMAGE_SIGNATURES.find((s) => s.magic.every((b, i) => file.data[i] === b));
if (!sig) return reject('ไม่ใช่รูปจริง');   // ตั้งชื่อ .png แต่ข้างในเป็น html ก็ไม่ผ่าน
```

### 5.2 จำกัดขนาด 1 MB

อ่าน body โดยนับไบต์ ถ้าเกิน `1 MB` ตัดการเชื่อมต่อแล้วปฏิเสธ (โหมด vuln ไม่จำกัด — ในแล็บตั้งเพดานหลวมๆ 30 MB ไว้แค่กันเครื่องพัง)

### 5.3 ตั้งชื่อไฟล์ใหม่เองด้วยค่าสุ่ม (กัน path traversal)

```js
const safeName = crypto.randomBytes(16).toString('hex') + '.' + sig.ext;  // ชื่อ+นามสกุลจากฝั่งเราเท่านั้น
fs.writeFileSync(path.join(UPLOAD_DIR, safeName), file.data);             // ชื่อเดิมจากผู้ใช้ถูกทิ้งทั้งหมด
```

ชื่อจากผู้ใช้ไม่ถูกนำมาใช้เลย จึงไม่มีทางมี `../` หลุดเข้าไป

### 5.4 เสิร์ฟแบบบังคับดาวน์โหลด ไม่ให้เบราว์เซอร์ตีความ

```js
res.writeHead(200, {
  'Content-Type': 'application/octet-stream',                 // ไม่บอกชนิดจริง
  'Content-Disposition': 'attachment; filename="..."',        // บังคับดาวน์โหลด
  'X-Content-Type-Options': 'nosniff',                        // ห้ามเบราว์เซอร์เดาชนิดไฟล์เอง
});
```

และตัดชื่อด้วย `path.basename(...)` ก่อนเสมอ (`serveSafe`) เพื่อกัน `../` ตอนอ่านไฟล์กลับ

---

## 6. วิธีป้องกัน (สรุป)

### ✅ ตรวจสอบตอนรับไฟล์
- **ตรวจชนิดจริง** จาก magic bytes / content ไม่ใช่แค่นามสกุลหรือ `Content-Type` ที่ผู้ใช้ส่งมา
- ใช้ **allowlist** (อนุญาตเฉพาะชนิดที่ต้องการ) ไม่ใช่ blacklist (ไล่แบนทีละอย่าง มีช่องเลี่ยงเสมอ เช่น `file.pHp`, `file.php.`, double extension `img.jpg.php`)
- **จำกัดขนาด** กัน DoS จากไฟล์ยักษ์

### ✅ จัดการตอนเก็บไฟล์
- **ตั้งชื่อใหม่เอง** ด้วยค่าสุ่ม ไม่ใช้ชื่อ/นามสกุลจากผู้ใช้ → กัน path traversal และ overwrite
- เก็บไฟล์**นอก webroot** หรือใน storage แยก (เช่น object storage) ไม่ให้เซิร์ฟเวอร์เผลอรัน

### ✅ จัดการตอนเสิร์ฟไฟล์
- เสิร์ฟด้วย `Content-Type: application/octet-stream` + `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`
- ปิดการรันสคริปต์ฝั่ง server ในโฟลเดอร์อัปโหลด
- รูปที่รับมาควร re-encode ใหม่ (decode แล้ว encode ใหม่) เพื่อล้าง payload ที่ซ่อนในไฟล์

### ⚠ ที่ "ไม่พอ"

| วิธี | ทำไมไม่พอ |
|---|---|
| เช็กแค่ `Content-Type` ที่ผู้ใช้ส่งมา | ผู้ใช้ปลอมค่านี้ได้ตามใจ |
| เช็กแค่นามสกุล | `evil.php.jpg`, `evil.jpg` (ข้างในเป็น html), `evil.sVg` เลี่ยงได้ |
| blacklist นามสกุลอันตราย | มีนามสกุล/ลูกเล่นให้เลี่ยงเยอะมาก ใช้ allowlist ดีกว่า |
| เช็กฝั่ง JavaScript หน้าเว็บอย่างเดียว | แฮกเกอร์ยิง request ตรงไปเซิร์ฟเวอร์ได้ (เช่น curl) ข้ามหน้าเว็บ |

---

## 7. สรุปสั้นๆ (จำไว้ข้อเดียวก็ได้)

> **อย่าเชื่อไฟล์ที่ผู้ใช้ส่งมา: ตรวจชนิดจริง ตั้งชื่อเอง เก็บแยก และเสิร์ฟแบบไม่ให้เบราว์เซอร์รัน**

Checklist ก่อนปล่อยเว็บที่มีอัปโหลดไฟล์:

- [ ] ตรวจชนิดไฟล์จริง (magic bytes) + allowlist
- [ ] จำกัดขนาดไฟล์
- [ ] ตั้งชื่อไฟล์ใหม่เองด้วยค่าสุ่ม ไม่ใช้ชื่อจากผู้ใช้
- [ ] เก็บไฟล์นอก webroot / ปิดการรันสคริปต์ในโฟลเดอร์อัปโหลด
- [ ] เสิร์ฟด้วย `octet-stream` + `attachment` + `nosniff`
- [ ] (รูป) re-encode ใหม่เพื่อล้าง payload

---

## 8. รีเซ็ตแล็บ

ลบไฟล์ที่อัปโหลดทั้งหมด: กดปุ่ม **"ล้างไฟล์ที่อัปโหลดทั้งหมด"** ในหน้าเว็บ (เรียก `POST /reset`)
หรือลบเนื้อในโฟลเดอร์ `uploads/` เอง

> หมายเหตุ: `/reset` ลบเฉพาะไฟล์ในโฟลเดอร์ `uploads/` ถ้าเคยทดสอบ path traversal จนมีไฟล์หลุดออกไปข้างนอก (เช่น `../pwned.html`) ต้องไปลบไฟล์นั้นเองในโฟลเดอร์แล็บ

---

## อ้างอิง

- OWASP — File Upload Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- OWASP — Unrestricted File Upload: <https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>
- PortSwigger Web Security Academy — File upload vulnerabilities (แล็บฝึกฟรี): <https://portswigger.net/web-security/file-upload>
- MDN — X-Content-Type-Options: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>
- MDN — Content-Disposition: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition>
