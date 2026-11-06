# CORS Lab — แล็บฝึกทำความเข้าใจ CORS Misconfiguration

> ⚠ **เว็บนี้ตั้งใจเขียนให้ตั้งค่า CORS ผิด** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง ห้าม deploy และห้ามเอาเทคนิคไปลองกับเว็บที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 1. CORS คืออะไร (และ *ไม่ใช่* อะไร)

เบราว์เซอร์มีกฎพื้นฐานชื่อ **Same-Origin Policy (SOP)**:

> JavaScript ของเว็บ origin หนึ่ง จะ **อ่าน response** ของอีก origin หนึ่ง **ไม่ได้**

**CORS (Cross-Origin Resource Sharing)** คือกลไกที่เซิร์ฟเวอร์ใช้ "ผ่อนกฎ SOP"
โดยส่ง HTTP header กลับมาบอกเบราว์เซอร์ว่า **"เว็บต้นทาง (origin) ไหนบ้าง ที่ฉันอนุญาตให้อ่าน response ของฉันได้"**

ประโยคสำคัญที่ต้องเข้าใจให้ถูก:

> **CORS คุมว่า "origin ไหนอ่าน response ของ API เราผ่านเบราว์เซอร์ได้บ้าง" เท่านั้น**

สิ่งที่ CORS **ไม่ได้** ทำ:

- ❌ CORS **ไม่ได้กัน** การยิง API ตรง ๆ ด้วย `curl` / Postman / สคริปต์ฝั่งเซิร์ฟเวอร์
  (เครื่องมือพวกนี้ไม่สนใจ CORS header เลย เพราะ CORS เป็นกฎที่ **เบราว์เซอร์** บังคับ)
- ❌ CORS **ไม่ใช่** การตรวจสิทธิ์ (authentication/authorization) — การกันไม่ให้คนอ่านข้อมูลลับ
  เป็นเรื่องของ **auth** (ต้องมี token/เซสชัน + ตรวจสิทธิ์) ต่างหาก

ในแล็บนี้จะเห็นชัดว่า เซิร์ฟเวอร์ **ส่งข้อมูลออกมาเสมอ** (curl เห็นเสมอ)
แต่ **เบราว์เซอร์** ของ origin ที่ไม่ได้รับอนุญาตจะ **ถูกบล็อกไม่ให้อ่าน**

### CORS misconfiguration คือช่องโหว่ยังไง

ถ้าตั้งค่า CORS ผิด เช่น

- **สะท้อน (reflect) ค่า `Origin` ที่ร้องขอกลับมาแบบไม่กรอง** ใน `Access-Control-Allow-Origin`
  **พร้อมกับ** `Access-Control-Allow-Credentials: true` → เว็บของแฮกเกอร์ **อ่านข้อมูลลับของเหยื่อได้**
- หรือใช้ `Access-Control-Allow-Origin: *` กับ API ที่คืน **ข้อมูลลับ** → ทุกเว็บอ่านได้

ผลคือ เว็บของแฮกเกอร์ที่เหยื่อหลงเข้าไป สามารถสั่งให้เบราว์เซอร์ของเหยื่อ
ยิงคำขอไปที่ API (พร้อมเซสชันของเหยื่อ) **แล้วอ่านคำตอบกลับมาได้** → ข้อมูลลับรั่ว

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง npm install อะไรเลย** (ใช้ built-in module ล้วน)

```bash
node server.js
```

เซิร์ฟเวอร์ฟังที่ `127.0.0.1` พอร์ต `4400` เปิดได้ 2 ทาง (สองนี้คือ "คนละ origin" กัน):

| บทบาท | เปิดที่ | origin |
|---|---|---|
| 🏦 ธนาคาร / เหยื่อ (มี API ข้อมูลลับ) | <http://localhost:4400> | `http://localhost:4400` (อยู่ใน allowlist) |
| 😈 เว็บของแฮกเกอร์ | <http://127.0.0.1:4400/evil> | `http://127.0.0.1:4400` (ไม่อยู่ใน allowlist) |

> **หมายเหตุ:** เครื่องส่วนใหญ่ `localhost` ชี้มาที่ `127.0.0.1` อยู่แล้ว ทั้งสอง URL จึงเข้าได้
> ถ้าเปิด `http://localhost:4400` ไม่ติด (บางเครื่อง localhost ไปทาง IPv6 `::1`) ให้ลองสลับ:
> เปิดธนาคารที่ `http://127.0.0.1:4400` และเว็บแฮกเกอร์ที่ `http://localhost:4400/evil` แทน
> (แล็บยังทำงานเหมือนเดิม เพราะสองชื่อนี้เป็นคนละ origin ไม่ว่าจะสลับทางไหน
> แต่ต้องแก้ allowlist/ลิงก์ให้ตรงด้วย — ดูตัวแปร `BANK_ORIGIN`/`EVIL_ORIGIN` ใน `server.js`)

### โครงสร้างไฟล์

```
CORS/
├── server.js            ← เซิร์ฟเวอร์ธนาคาร + API + หน้าแฮกเกอร์ทั้งหมด (CSS ฝังในไฟล์)
├── package.json
├── .claude/launch.json  ← สำหรับปุ่มรันในเครื่องมือ (name: cors-lab, port 4400)
└── README.md            ← ไฟล์นี้
```

### บัญชีทดสอบ

| บัญชี | รหัสผ่าน | บทบาท |
|---|---|---|
| `somsri` | `somsri123` | เหยื่อ (มีข้อมูลลับ: อีเมล ยอดเงิน เลขบัญชี OTP) |

---

## 3. ทำไม `127.0.0.1` กับ `localhost` ถึงเป็น "คนละ origin"

**origin = scheme + host + port** และต้องตรงกัน **ทั้งสามส่วนแบบตัวต่อตัว**

```
http :// localhost : 4400     ← origin A
http :// 127.0.0.1 : 4400     ← origin B
         ^^^^^^^^^   host คนละค่า (เทียบแบบ "ตัวอักษร" ไม่ได้ resolve DNS ก่อน)
```

ถึงแม้ `localhost` กับ `127.0.0.1` จะชี้ไปเครื่อง (และเซิร์ฟเวอร์) เดียวกัน
แต่เบราว์เซอร์เทียบ origin จาก **ข้อความของ host** ไม่ได้แปลงเป็น IP ก่อน
ดังนั้นมันจึงถือเป็น **2 origin** → การ fetch ระหว่างสองชื่อนี้คือ **cross-origin จริง**
ทำให้เราสาธิต CORS ได้ครบวงจรบนเครื่องเดียว โดยไม่ต้องมี 2 โดเมน/2 เครื่อง

(เกร็ด: `http` กับ `https`, หรือพอร์ต `4400` กับ `4401` ก็เป็นคนละ origin เช่นกัน)

---

## 4. ลองโจมตี (ฝั่งมีช่องโหว่)

1. เปิด <http://localhost:4400> แล้วล็อกอินเป็น **somsri** (`somsri123`)
   → เห็นหน้าธนาคารพร้อมข้อมูลลับ และกล่องทดสอบจะขึ้น ✅ ว่า origin นี้อ่าน `/api/safe/me` ได้
   (เพราะ `http://localhost:4400` อยู่ใน allowlist) — **นี่คือพฤติกรรมปกติที่ถูกต้อง**
2. **อย่าออกจากระบบ** (จำลองคนที่เปิดเว็บธนาคารค้างไว้)
3. เปิดเว็บของแฮกเกอร์ที่ **คนละ origin**: <http://127.0.0.1:4400/evil>
   - หน้านี้จะ **โจมตีอัตโนมัติทันทีที่โหลด** (ปุ่ม ①): สั่งเบราว์เซอร์ fetch ไปที่
     `http://localhost:4400/api/me` ซึ่งเป็น **คนละ origin**
   - ช่อง "ผลล่าสุด" จะขึ้น **✅ อ่านข้อมูลลับได้สำเร็จ** พร้อม JSON ข้อมูลของ somsri
   - ตาราง "ข้อมูลที่เว็บนี้อ่าน (ขโมย) ไปได้แล้ว" จะมีรายการเพิ่ม (รีเฟรชหน้าเพื่อเห็น)
   - ใน terminal ที่รันเซิร์ฟเวอร์จะขึ้นข้อความ **สีแดง** `[CORS ATTACK] เว็บแฮกเกอร์ (...) อ่านข้อมูลลับ...`

เหยื่อไม่ได้ทำอะไรเลย แค่เปิดหน้าเว็บผิดหน้าเดียว ข้อมูลลับก็ถูกเว็บอื่นอ่านไปแล้ว

### โค้ดที่ตั้งผิด (`server.js` ฟังก์ชัน `applyCors` โหมด `vuln`)

```js
// ❌ สะท้อน Origin ที่ร้องขอกลับมาแบบไม่กรองเลย + อนุญาต credentials
if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

ปัญหา: เซิร์ฟเวอร์ "เชื่อ" ค่า `Origin` ที่เบราว์เซอร์ของเหยื่อส่งมา แล้วสะท้อนกลับไปดื้อ ๆ
เท่ากับประกาศว่า **"ทุก origin อ่านฉันได้"** — เว็บแฮกเกอร์จึงได้รับอนุญาต

---

## 5. ดูให้เห็นด้วยตา: เปิด DevTools

เปิด DevTools (กด **F12**) บนหน้า <http://127.0.0.1:4400/evil> แล้วดู 2 แท็บนี้

### แท็บ Network
- จะเห็นคำขอ **`OPTIONS /api/me`** (preflight) มาก่อน แล้วตามด้วย **`GET /api/me`**
  (preflight เกิดเพราะ fetch ในแล็บแนบ header `X-Demo` ทำให้ไม่ใช่ "simple request")
- คลิกที่ `GET /api/me` → ดู **Response Headers** จะเห็น
  `Access-Control-Allow-Origin: http://127.0.0.1:4400` และ `Access-Control-Allow-Credentials: true`
  → นี่คือใบอนุญาตที่ทำให้เบราว์เซอร์ยอมให้ JS อ่าน response

### แท็บ Console
- ตอนกดปุ่ม ② (หน้า SAFE) และ ④ (wildcard + credential) จะเห็น error สีแดงประมาณว่า
  `Access to fetch at 'http://localhost:4400/...' from origin 'http://127.0.0.1:4400' has been blocked by CORS policy`
  → **นี่คือ CORS ทำงานถูกต้อง** เบราว์เซอร์บล็อกไม่ให้ origin ที่ไม่ได้รับอนุญาตอ่าน response

---

## 6. ลองฝั่งที่แก้แล้ว (ปลอดภัย)

บนหน้าเว็บแฮกเกอร์ (<http://127.0.0.1:4400/evil>) กดปุ่ม **②: อ่าน `/api/safe/me`**

- ช่อง "ผลล่าสุด" จะขึ้น **❌ อ่านไม่ได้ — ถูกเบราว์เซอร์บล็อกด้วย CORS policy**
- เปิด Console (F12) จะเห็น error CORS สีแดง
- ตารางข้อมูลที่ขโมยได้ **ไม่เพิ่ม** และ terminal **ไม่มี** log สีแดง

### โค้ดที่แก้แล้ว (`server.js` ฟังก์ชัน `applyCors` โหมด `safe`)

```js
// ✅ ส่ง ACAO เฉพาะเมื่อ origin อยู่ใน allowlist เท่านั้น
const ALLOWLIST = new Set(['http://localhost:4400']);
if (origin && ALLOWLIST.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
// origin อื่น (เช่น http://127.0.0.1:4400) จะไม่ได้ header ACAO
// → เบราว์เซอร์จึงบล็อกไม่ให้มันอ่าน response
```

**ทำไมถึงกันได้:** เซิร์ฟเวอร์อนุญาต (ส่ง `Access-Control-Allow-Origin`) ให้เฉพาะ
`http://localhost:4400` ซึ่งเป็น origin ของธนาคารเองเท่านั้น
พอเว็บแฮกเกอร์ (`http://127.0.0.1:4400`) ขอมา เซิร์ฟเวอร์ไม่ส่ง ACAO ที่ตรงกับมัน
เบราว์เซอร์จึงไม่ยอมให้ JS ของเว็บแฮกเกอร์อ่านคำตอบ

> **เทียบให้ชัด:** หน้าธนาคารเอง (origin `http://localhost:4400`) อ่าน `/api/safe/me` ได้ปกติ
> (ดูกล่องทดสอบในหน้าแดชบอร์ด) — allowlist จึงไม่ได้พังการใช้งานจริง แค่กัน origin แปลกปลอม

---

## 7. กับดักยอดฮิต: `Access-Control-Allow-Origin: *`

กดปุ่ม **③** และ **④** บนหน้าเว็บแฮกเกอร์ เพื่อเทียบพฤติกรรมของ `ACAO: *`

| ปุ่ม | คำขอ | ผล | บทเรียน |
|---|---|---|---|
| ③ | `/api/wildcard/me` **ไม่ส่ง** credential | ✅ **อ่านได้** | `*` = ทุก origin อ่าน response ได้ → ถ้า API นี้คืน **ข้อมูลลับ** ก็รั่วให้ทุกเว็บทันที |
| ④ | `/api/wildcard/me` **ส่ง** credential (`credentials: include`) | ❌ **ถูกบล็อก** | เบราว์เซอร์ห้ามใช้ `ACAO: *` คู่กับคำขอที่มี credential — ต้องระบุ origin เจาะจง + `Allow-Credentials: true` |

**สรุปกฎสำคัญของ credentialed request:**

> ถ้าคำขอเป็นแบบ **มี credential** (คุกกี้/`Authorization`): เบราว์เซอร์จะยอมให้อ่าน response
> **ก็ต่อเมื่อ** `Access-Control-Allow-Origin` เป็น **ค่า origin เจาะจง (ไม่ใช่ `*`)**
> **และ** มี `Access-Control-Allow-Credentials: true`

นี่คือเหตุผลที่นักพัฒนาหลายคน "แก้ผิดทาง": อยากให้คำขอแบบมีคุกกี้ทำงาน เลยเปลี่ยนจาก `*`
ไปเป็น "สะท้อน origin กลับ + credentials true" โดยไม่มี allowlist → กลายเป็นช่องโหว่ข้อ 4 ทันที

---

## 8. พิสูจน์ว่า CORS ≠ การตรวจสิทธิ์ (สำคัญมาก)

ลองยิง API ตรง ๆ ด้วย `curl` (ไม่ผ่านเบราว์เซอร์) — **ต้องล็อกอิน somsri ค้างไว้ก่อน**
เพราะ API อิงเซสชันจำลองในหน่วยความจำ:

```bash
# ยิงหน้า "ปลอดภัย" ตรง ๆ ก็ยังได้ข้อมูลลับกลับมาเต็ม ๆ
curl -s http://localhost:4400/api/safe/me

# แกล้งปลอม Origin เป็นเว็บแฮกเกอร์ ก็ยังได้ข้อมูล
curl -s -H "Origin: http://evil.example" http://localhost:4400/api/safe/me
```

จะเห็นว่า **ข้อมูลลับถูกส่งกลับมาเสมอ** เพราะ:

- CORS header เป็นแค่ "คำสั่งถึงเบราว์เซอร์" — `curl` ไม่สนใจและไม่บังคับตัวเอง
- การบล็อกของ CORS เกิดใน **เบราว์เซอร์ของเหยื่อ** เท่านั้น

> **บทเรียน:** CORS ป้องกันแค่ "เว็บ origin อื่นอ่านข้อมูลผ่านเบราว์เซอร์ของผู้ใช้"
> มันไม่ได้ทำให้ API ปลอดภัยจากการเข้าถึงโดยตรง การกันข้อมูลลับต้องใช้ **auth จริง**
> (ตรวจ token/เซสชัน + สิทธิ์ทุกคำขอที่ฝั่งเซิร์ฟเวอร์) เสมอ

---

## 9. วิธีป้องกัน CORS misconfiguration

### ✅ 1. ใช้ allowlist เจาะจง อย่าสะท้อน Origin ดื้อ ๆ
อนุญาตเฉพาะ origin ที่รู้จักจริง ๆ (เก็บเป็นลิสต์) แล้วเทียบแบบ **ตรงทั้งสตริง**

```js
const ALLOWLIST = new Set(['https://app.example.com']);
if (ALLOWLIST.has(req.headers.origin)) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Vary', 'Origin'); // อย่าลืม เพื่อความถูกต้องของ cache
}
```

### ✅ 2. ระวังการเทียบ origin แบบหละหลวม
อย่าใช้ "ลงท้ายด้วย `example.com`" หรือ regex หลวม ๆ เพราะโดนหลอกได้ เช่น
`evil-example.com`, `example.com.evil.com`, หรือ subdomain ที่ถูกยึด → เทียบแบบ **เท่ากันเป๊ะ** เท่านั้น

### ✅ 3. อย่าใช้ `ACAO: *` กับข้อมูลลับ
`*` เหมาะกับ **ทรัพยากรสาธารณะที่ไม่มีความลับ** เท่านั้น (เช่น CDN, ฟอนต์, API เปิดสาธารณะ)
ถ้า endpoint คืนข้อมูลผู้ใช้/ข้อมูลลับ ห้ามใช้ `*`

### ✅ 4. `Allow-Credentials: true` ต้องมาคู่กับ origin เจาะจงเท่านั้น
ห้ามจับคู่ `Allow-Credentials: true` กับการสะท้อน origin แบบไม่มี allowlist (เบราว์เซอร์ยอม แต่มันคือช่องโหว่)
และห้ามใช้คู่กับ `*` (เบราว์เซอร์ไม่ยอมอยู่แล้ว)

### ✅ 5. ตั้งคุกกี้ให้ปลอดภัย + จำกัดการส่งข้าม origin
`HttpOnly` + `Secure` + `SameSite=Lax/Strict` ช่วยลดการที่คุกกี้ถูกแนบไปกับคำขอข้ามเว็บ
(เป็นชั้นป้องกันเสริมที่ทำงานร่วมกับ CORS)

### ✅ 6. CORS ไม่ใช่ auth — ต้องมี auth จริงเสมอ
ตรวจสิทธิ์ทุกคำขอที่ฝั่งเซิร์ฟเวอร์ (token/เซสชัน + ตรวจว่าผู้ใช้มีสิทธิ์เห็นข้อมูลนั้น)
อย่าพึ่ง CORS เป็นด่านกันข้อมูลลับ

### ⚠ สิ่งที่ "ไม่ช่วย" หรือเข้าใจผิดบ่อย
- **คิดว่า CORS กันแฮกเกอร์ยิง API** — ไม่จริง curl/Postman ข้าม CORS ได้หมด
- **เอา `*` ใส่ทุก endpoint เพื่อความสะดวก** — ถ้ามีข้อมูลลับคือรั่ว
- **สะท้อน Origin กลับเพื่อให้ "ใช้งานได้"** — เท่ากับเปิดให้ทุกเว็บอ่าน

---

## 10. สรุปสั้น ๆ (จำข้อเดียวก็ได้)

> **CORS บอกแค่ว่า "เบราว์เซอร์จะให้ origin ไหนอ่าน response ของเราได้บ้าง"**
> ดังนั้นจง **allowlist เจาะจง**, อย่าสะท้อน Origin ดื้อ ๆ, อย่าใช้ `*` กับข้อมูลลับ
> และ **อย่าใช้ CORS แทน auth** — การกันข้อมูลลับต้องตรวจสิทธิ์จริงที่เซิร์ฟเวอร์

Checklist ก่อนปล่อยเว็บ:

- [ ] `Access-Control-Allow-Origin` มาจาก **allowlist เจาะจง** (ไม่สะท้อน Origin ดิบ ๆ)
- [ ] ไม่ใช้ `ACAO: *` กับ endpoint ที่คืนข้อมูลลับ
- [ ] `Allow-Credentials: true` ใช้คู่กับ origin เจาะจงเท่านั้น (ห้ามคู่กับ `*`/reflect แบบไม่มี allowlist)
- [ ] มีการตรวจสิทธิ์ (auth) จริงทุก endpoint — ไม่พึ่ง CORS
- [ ] คุกกี้เซสชันตั้ง `HttpOnly; Secure; SameSite`
- [ ] ใส่ `Vary: Origin` เมื่อ ACAO เปลี่ยนตาม origin

---

## 11. หมายเหตุเรื่อง credentials / คุกกี้ ในแล็บนี้ (อ่านเพื่อความเข้าใจที่ถูกต้อง)

ในโลกจริง การโจมตี CORS ที่อันตรายคือ **credentialed request**: เบราว์เซอร์ของเหยื่อ
**แนบคุกกี้ session ของเว็บเป้าหมายไปให้อัตโนมัติ** (เมื่อ fetch ด้วย `credentials: 'include'`)
แล้วถ้า CORS header ยอม เว็บแฮกเกอร์ก็อ่านคำตอบที่ผูกกับเซสชันของเหยื่อได้

**ข้อจำกัดบน localhost (เล่าตรง ๆ):** คุกกี้ถูกผูกกับ **host** คุกกี้ที่ตั้งบน `localhost`
จะไม่ถูกส่งไปที่ `127.0.0.1` (คนละ host = คนละ cookie jar) และคุกกี้ `SameSite=Lax/None`
บน `http` ยังมีข้อจำกัดของเบราว์เซอร์อีก ทำให้เดโมคุกกี้ข้าม origin บนเครื่องเดียว **ไม่เสถียร**

แล็บนี้จึงเลือกวิธีที่ **รันได้จริงอย่างเชื่อถือได้**: ใช้ **เซสชันจำลองในหน่วยความจำ**
(เซิร์ฟเวอร์จำว่า "เหยื่อ somsri ล็อกอินค้างอยู่") เป็นตัวแทนของ "credential ของเหยื่อ"
ส่วนฝั่ง JavaScript ยัง fetch ด้วย `credentials: 'include'` จริง เพื่อให้
**เบราว์เซอร์บังคับกฎ CORS ของ credentialed request เหมือนจริงทุกประการ** กล่าวคือ:

- กฎ "ACAO ต้องเป็น origin เจาะจง + `Allow-Credentials: true`" ที่เห็นในปุ่ม ④ → ทำงานจริง
- การบล็อก/อนุญาตการอ่าน response ตาม origin → ทำงานจริง

สิ่งที่ถูก "จำลอง" คือ **ที่มาของตัว credential** เท่านั้น (ใช้เซสชันในหน่วยความจำแทนคุกกี้ที่แนบข้าม host)
ซึ่งไม่กระทบบทเรียนหลักเรื่องการตั้งค่า CORS header เลย

---

## 12. รีเซ็ตแล็บ

ล้างรายการที่ขโมยได้และออกจากระบบ: เข้า <http://localhost:4400/reset> (หรือปิดแล้วเปิดเซิร์ฟเวอร์ใหม่)

---

## อ้างอิง

- OWASP — CORS OriginHeaderScrutiny / Testing Cross Origin Resource Sharing:
  <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing>
- OWASP — HTML5 Security Cheat Sheet (หัวข้อ CORS):
  <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing>
- PortSwigger Web Security Academy — CORS (แล็บฝึกฟรี): <https://portswigger.net/web-security/cors>
- MDN — Cross-Origin Resource Sharing (CORS): <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>
- MDN — Same-origin policy: <https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy>
- MDN — Access-Control-Allow-Credentials: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials>
