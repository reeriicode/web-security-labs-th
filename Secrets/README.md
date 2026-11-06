# Secrets Lab — แล็บฝึกทำความเข้าใจ Secrets Exposure (ความลับรั่วไหล)

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง ห้าม deploy และห้ามเอาเทคนิคไปลองกับระบบที่ไม่ได้รับอนุญาต
> การเข้าถึง/ทดสอบระบบของผู้อื่นโดยไม่ได้รับอนุญาตผิด **พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ฯ**

> 🔒 **ค่า secret ทุกตัวในแล็บนี้เป็นค่าปลอม (placeholder)** ที่เห็นชัดว่าไม่ใช่ของจริง เช่น
> `sk_test_FAKE_not_a_real_key_0000`, `DEMO_FAKE_DB_PASSWORD_change_me` — ห้ามนำไปใช้จริง และไม่ใช่รูปแบบ key ของผู้ให้บริการใด

---

## 1. Secrets Exposure คืออะไร

**Secret** คือข้อมูลลับที่ใช้ยืนยันตัวตนหรือเข้าถึงทรัพยากร เช่น API key, รหัสผ่านฐานข้อมูล,
token, private key, connection string

**Secrets Exposure** คือการที่ความลับเหล่านี้ **หลุดไปอยู่ในที่ที่คนอื่นเข้าถึงได้** โดยไม่ตั้งใจ
เมื่อรั่วแล้ว ใครได้ไปก็ใช้สวมรอยเป็นแอปของเรา เรียก API ด้วยโควตา/ค่าใช้จ่ายของเรา
หรือเข้าฐานข้อมูลของเราได้ทันที

จุดที่ความลับมักรั่ว:

- ฝังไว้ใน **โค้ดฝั่ง frontend** (HTML/JavaScript ที่ส่งไปเบราว์เซอร์)
- ไฟล์ตั้งค่า เช่น **`.env`** ถูกเสิร์ฟให้ดาวน์โหลดได้ หรือถูก commit ขึ้น git
- หลุดใน **git history** (เคย commit แล้วลบ แต่ยังอยู่ในประวัติ)
- โผล่ใน log, error message, URL, หรือหน้า debug

แล็บนี้โฟกัส 2 ข้อแรกซึ่งพบบ่อยและเห็นภาพชัดที่สุด

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง `npm install` อะไรเลย** (ใช้ built-in module ล้วน)

```bash
node server.js
```

หรือ

```bash
npm start
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:4600>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้

### โครงสร้างไฟล์

```
Secrets/
├── server.js          ← เซิร์ฟเวอร์ทั้งหมด (Lab 1, 2 + ผู้ให้บริการจำลอง)
├── package.json
├── README.md          ← ไฟล์นี้
├── .env.example       ← ตัวอย่างไฟล์ตั้งค่าลับ (ค่า dummy) ใช้คัดลอกเป็น .env
├── .gitignore         ← กัน .env และ node_modules หลุดขึ้น git
└── .claude/
    └── launch.json    ← ตั้งค่ารัน preview (name: secrets-lab, port 4600)
```

> หมายเหตุ: แล็บนี้ **ไม่มีไฟล์ `.env` จริง** มาให้ ถ้าไม่ตั้ง environment variable เซิร์ฟเวอร์จะใช้ค่าปลอมในตัวโดยอัตโนมัติ
> ส่วนไฟล์ `.env` ที่ "รั่ว" ใน Lab 2 เป็นเนื้อหาปลอมที่สร้างขึ้นในหน่วยความจำเพื่อสาธิตเท่านั้น

### หัวข้อในแล็บ

| Lab | หัวข้อ | มีช่องโหว่ | แก้แล้ว |
|---|---|---|---|
| 1 | Secret ฝังใน frontend | `/frontend` | `/safe/frontend` |
| 2 | ไฟล์ `.env` ถูกเสิร์ฟ | `/envleak` | `/safe/envleak` |

รีเซ็ตตัวนับสถิติ: <http://localhost:4600/reset>

---

## 3. Lab 1 — Secret ฝังใน frontend (`/frontend`)

### สถานการณ์
แอปแปลภาษาเรียกใช้บริการแปลภายนอก (third-party API) ที่ต้องใช้ API key
นักพัฒนาเขียน JavaScript ฝั่งเบราว์เซอร์ให้ยิงไปหาผู้ให้บริการตรงๆ จึงต้องมี key อยู่ในโค้ดฝั่ง client

### โค้ดที่มีปัญหา (`/static/app-vuln.js`)

```js
const API_KEY = "sk_test_FAKE_not_a_real_key_0000";   // ← ความลับอยู่ในไฟล์ที่ส่งไปเบราว์เซอร์!
const url = '/thirdparty/translate?apikey=' + encodeURIComponent(API_KEY) + '&text=' + ...;
fetch(url);
```

### ลองดูของจริง
1. เปิด <http://localhost:4600/frontend>
2. ดู key ได้หลายวิธี:
   - คลิกขวา → **View Page Source** แล้วตามไปเปิดไฟล์ <http://localhost:4600/static/app-vuln.js>
   - เปิด DevTools (F12) → แท็บ **Sources** → ไฟล์ `app-vuln.js` → เห็นบรรทัด `const API_KEY = ...`
   - เปิด DevTools → แท็บ **Network** แล้วกดปุ่ม "แปล" → เห็น key ถูกส่งไปใน URL ของ request `/thirdparty/translate?apikey=...`
3. ใน terminal ที่รันเซิร์ฟเวอร์จะขึ้นข้อความสีแดง `[EXPOSED] ... ถูกเรียกพร้อม key ที่มองเห็นได้จากเบราว์เซอร์`

**ประเด็นสำคัญ:** ไม่ว่าจะซ่อน key ด้วยเทคนิคใดในฝั่ง client (ตั้งชื่อตัวแปรหลอก, minify, base64)
สุดท้ายโค้ดต้องรันในเบราว์เซอร์ ผู้ใช้จึงแกะกลับมาเห็นได้เสมอ
> **อะไรก็ตามที่ส่งไปถึงเบราว์เซอร์ = เปิดเผยทั้งหมด**

### โค้ดที่แก้แล้ว (`/static/app-safe.js` + backend proxy)

ฝั่ง client ไม่มี key เลย เรียก backend ของเราเองแทน:

```js
// app-safe.js — ไม่มี API key อยู่ในไฟล์นี้
fetch('/api/translate?text=' + encodeURIComponent(text));   // ไม่มี key ใน URL
```

ฝั่งเซิร์ฟเวอร์ (backend proxy) เป็นคนแนบ key ให้ผู้ให้บริการ:

```js
// server.js — key อยู่ฝั่งเซิร์ฟเวอร์เท่านั้น (อ่านจาก environment variable)
if (p === '/api/translate') {
  const result = callProvider(CONFIG.TRANSLATE_API_KEY, text);  // เซิร์ฟเวอร์แนบ key เอง
  return sendJson(res, 200, result);                            // ส่งกลับแค่ "ผลลัพธ์" ไม่ส่ง key
}
```

เปิด <http://localhost:4600/safe/frontend> แล้วลองหา key ในไฟล์ `app-safe.js` หรือในแท็บ Network — จะไม่เจอ

---

## 4. Lab 2 — ไฟล์ .env ถูกเสิร์ฟโดยไม่ตั้งใจ (`/envleak`)

### สถานการณ์
เว็บมีโฟลเดอร์ static สำหรับเสิร์ฟไฟล์สาธารณะ (`index.html`, `app.js`, รูปภาพ ฯลฯ)
แต่มีคนเผลอวางไฟล์ `.env` (ที่เก็บความลับ) ไว้ในโฟลเดอร์เดียวกัน หรือตั้ง web root เป็นโฟลเดอร์โปรเจกต์ทั้งก้อน
ถ้า static server ไม่บล็อก ใครเดา URL `/.env` ถูกก็โหลดความลับทั้งไฟล์ไปได้

### โค้ดที่มีปัญหา (`server.js` — static server ไม่บล็อก dotfiles)

```js
// ❌ vuln: ขอไฟล์อะไรก็เสิร์ฟหมด รวมถึง .env
if (p.startsWith('/raw/')) {
  return serveFromWebroot(res, p.slice(5), { blockDotfiles: false });
}
```

### ลองดูของจริง
1. เปิด <http://localhost:4600/envleak>
2. กดลิงก์ "เปิด /.env" (หรือเข้า <http://localhost:4600/raw/.env> ตรงๆ) → เห็นเนื้อหาไฟล์ลับทั้งไฟล์
3. ใน terminal จะขึ้น `[LEAK] ไฟล์ .env ถูกเสิร์ฟออกไป!`
4. ไฟล์สาธารณะอย่าง `index.html`, `app.js` ก็ยังโหลดได้ปกติ (ช่องโหว่คือ "เสิร์ฟมากเกินไป")

**แนวโจมตีจริง:** แฮกเกอร์มักยิงเดา URL อัตโนมัติ เช่น `/.env`, `/.git/config`, `/config.php.bak`,
`/.env.backup`, `/.aws/credentials` กับเว็บเป้าหมายจำนวนมาก ถ้าเซิร์ฟเวอร์ตัวไหนเผลอเสิร์ฟให้ ก็ได้ความลับไปฟรีๆ

### โค้ดที่แก้แล้ว (บล็อก dotfiles + กัน path traversal)

```js
// ✅ safe: บล็อกไฟล์ที่ขึ้นต้นด้วยจุด และกัน ../
if (blockDotfiles && name.startsWith('.')) {
  return sendText(res, 403, '403 Forbidden');   // .env, .git ฯลฯ เข้าไม่ได้
}
if (name.includes('..') || name.includes('/')) {
  return sendText(res, 400, 'คำขอไม่ถูกต้อง');    // กันหลุดออกนอกเว็บรูท
}
```

เปิด <http://localhost:4600/safe/envleak> แล้วกดลิงก์ `.env` → ได้ **403 Forbidden** ส่วนไฟล์สาธารณะยังโหลดได้

**แต่ทางแก้ที่แท้จริงคือ:** `.env` **ต้องไม่อยู่ใน web root ตั้งแต่แรก** และต้องอยู่ใน `.gitignore`
การบล็อกที่ static server เป็นแค่ชั้นกันพลาดเสริม ไม่ใช่เหตุผลให้วางไฟล์ลับไว้ผิดที่

---

## 5. หลักปฏิบัติการจัดการ Secret (Secrets Management)

### ✅ 1. อย่าใส่ secret ใน frontend เด็ดขาด
ทุกอย่างที่ส่งไปเบราว์เซอร์ถือว่าเปิดเผย ถ้าต้องเรียก third-party API ที่ใช้ key
ให้เรียกผ่าน **backend proxy** ของเราเอง แล้วให้เซิร์ฟเวอร์เป็นคนแนบ key (แบบ `/api/translate` ในแล็บ)

### ✅ 2. เก็บ secret ใน environment variable หรือ secret manager ฝั่งเซิร์ฟเวอร์
- เล็กๆ / dev: ใช้ไฟล์ `.env` (อ่านผ่าน `process.env`) ที่ **อยู่นอก web root** และอยู่ใน `.gitignore`
- production: ใช้ secret manager เช่น AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault,
  Azure Key Vault หรือ environment variable ของแพลตฟอร์ม (เช่น ใน container/CI)

### ✅ 3. อย่า commit `.env` ขึ้น git
- ใส่ `.env` และ `.env.*` ใน `.gitignore` (ยกเว้น `.env.example`)
- แจก `.env.example` ที่มีแต่ **ชื่อ key กับค่า dummy** ให้ทีมรู้ว่าต้องตั้งค่าอะไรบ้าง (ดูไฟล์ `.env.example` ในแล็บนี้)

### ✅ 4. อย่าให้ไฟล์ลับอยู่ใน web root / เสิร์ฟได้
- เก็บไฟล์ตั้งค่าไว้นอกโฟลเดอร์ที่ static server เปิดให้โหลด
- ตั้ง static server ให้บล็อก dotfiles และกัน path traversal (`..`)

### ✅ 5. rotate key ทันทีเมื่อสงสัยว่ารั่ว
ถ้า key หลุด (เช่น เผลอ push ขึ้น git, แชร์ผิดช่อง) ให้ถือว่า **ใช้ไม่ได้แล้ว**
ต้อง **สร้าง key ใหม่และยกเลิก (revoke) key เดิมทันที** การแค่ลบไฟล์หรือลบ commit ไม่พอ เพราะอาจมีคนเห็นไปแล้ว

### ✅ 6. ระวัง secret หลุดใน git history
การลบ `.env` ออกจาก repo ใน commit ใหม่ **ไม่ได้ลบมันออกจากประวัติ** — ใครก็ยัง `git log`/`git checkout`
commit เก่าไปดูได้ ถ้าเคย commit secret ไปแล้ว ต้อง rotate key นั้นเสมอ (การล้าง history ด้วย
`git filter-repo`/BFG ช่วยได้ แต่ถ้าเคย push ขึ้นที่สาธารณะก็ถือว่ารั่วไปแล้ว)

### ⚠ สิ่งที่ "ไม่พอ" หรือเข้าใจผิดบ่อย

| ความเข้าใจผิด | ทำไมไม่พอ |
|---|---|
| "ซ่อน/minify/base64 key ในโค้ด frontend ก็พอ" | แกะกลับมาเห็นได้เสมอ ไม่ใช่การเข้ารหัส |
| "ลบ `.env` ออกจาก repo แล้วปลอดภัย" | ยังอยู่ใน git history ต้อง rotate key |
| "ไฟล์ขึ้นต้นด้วยจุดเบราว์เซอร์คงไม่โหลดเอง" | ขอ URL ตรงๆ ได้ สแกนเนอร์ยิงเดาอัตโนมัติ |
| "repo เป็น private ก็ใส่ secret ได้" | private วันนี้อาจ public วันหน้า + คนในทีม/ผู้รับเหมาเห็นหมด |

---

## 6. สรุปสั้นๆ (จำไว้ข้อเดียวก็ได้)

> **ความลับต้องอยู่ฝั่งเซิร์ฟเวอร์เท่านั้น ไม่อยู่ใน frontend ไม่อยู่ใน web root ไม่อยู่ใน git**
> **และเมื่อสงสัยว่ารั่ว ให้ rotate ทันที**

Checklist ก่อนปล่อยเว็บ:

- [ ] ไม่มี API key / token / รหัสผ่าน อยู่ในโค้ดหรือไฟล์ที่ส่งไป frontend
- [ ] third-party API ที่ใช้ key เรียกผ่าน backend proxy
- [ ] secret อ่านจาก environment variable / secret manager
- [ ] `.env` อยู่ใน `.gitignore` และอยู่นอก web root
- [ ] มี `.env.example` (ค่า dummy) ให้ทีม
- [ ] static server บล็อก dotfiles + กัน path traversal
- [ ] มีแผน rotate key เมื่อรั่ว และรู้ว่า git history เก็บทุกอย่าง

---

## 7. แบบฝึกหัดต่อยอด

1. เปิด DevTools → Network ที่หน้า `/frontend` กับ `/safe/frontend` เทียบดูว่า request ต่างกันอย่างไร (หน้าไหนมี `apikey=` ใน URL)
2. ลองค้นหาคำว่า `KEY` ในไฟล์ `/static/app-vuln.js` และ `/static/app-safe.js` ดูว่าเจอกี่ที่
3. ใน `server.js` ลองเพิ่มไฟล์ `.env.backup` เข้าไปใน `WEBROOT` แล้วดูว่าโหมด vuln เสิร์ฟให้ไหม และโหมด safe บล็อกไหม
4. ลองตั้ง environment variable จริงก่อนรัน (เช่น `TRANSLATE_API_KEY`) แล้วดูว่าค่าใน Lab 1 โหมด vuln เปลี่ยนตามไหม — เพื่อเข้าใจว่า key มาจากฝั่งเซิร์ฟเวอร์

---

## อ้างอิง

- OWASP — Secrets Management Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- OWASP — Top 10 (A05:2021 Security Misconfiguration): <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
- MDN — Environment variables / process.env (Node.js): <https://nodejs.org/api/process.html#processenv>
- MDN — Same-origin policy: <https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy>
- PortSwigger Web Security Academy — Information disclosure: <https://portswigger.net/web-security/information-disclosure>
