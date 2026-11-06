# Authentication Lab — แล็บฝึกทำความเข้าใจการยืนยันตัวตนที่ไม่ปลอดภัย

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง และห้ามเอาเทคนิคไปลองกับระบบที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 1. "การยืนยันตัวตนที่ไม่ปลอดภัย" คืออะไร

**Authentication** คือการพิสูจน์ว่า "คุณเป็นใคร" (ล็อกอินด้วยรหัสผ่าน แล้วได้ session/token มาถือไว้)
ถ้าทำพลาด แฮกเกอร์จะเข้าบัญชีคนอื่นได้โดยไม่ต้องเป็นเจ้าของตัวจริง อยู่ในอันดับต้นๆ ของ
**OWASP Top 10** (A07:2021 – Identification and Authentication Failures)

แล็บนี้แยกให้เห็น 3 จุดพลาดที่เจอบ่อยที่สุด แต่ละจุดมีฝั่ง **VULNERABLE** (ผิด) กับ **SAFE** (แก้แล้ว) ให้เทียบ

| เดโม | เรื่อง | ช่องโหว่ฝั่ง vuln | วิธีที่ถูกฝั่ง safe |
|---|---|---|---|
| 1 | การเก็บรหัสผ่าน | เก็บเป็น **plain text** — DB หลุด = เห็นรหัสจริงทันที | เก็บเป็น **scrypt hash + salt** |
| 2 | Brute force | ล็อกอินผิดได้ **ไม่จำกัด** → เดารหัสได้ไม่อั้น | **rate limit / lockout** |
| 3 | Session token | token **เดาได้** (base64 ของชื่อ) + **ไม่หมดอายุ** | token **สุ่ม** ด้วย `crypto.randomBytes` + **หมดอายุ** |

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) (เวอร์ชัน 18 ขึ้นไป) **ไม่ต้อง `npm install` อะไรเลย**
ใช้เฉพาะโมดูลที่มากับ Node.js (`http`, `crypto`, `url`) และแฮชรหัสผ่านด้วย `crypto.scryptSync` ที่เป็น built-in

```bash
node server.js
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:4300>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้
ข้อมูลทั้งหมดอยู่ในหน่วยความจำ ปิดเซิร์ฟเวอร์หรือกด <http://localhost:4300/reset> แล้วรีเซ็ตใหม่หมด

### โครงสร้างไฟล์

```
Authentication/
├── server.js            ← เซิร์ฟเวอร์ทั้งหมด (ทั้ง 3 เดโม + CSS ฝังในโค้ด)
├── package.json
├── README.md            ← ไฟล์นี้
└── .claude/
    └── launch.json      ← ตั้งค่าให้รันชื่อ "auth-lab" พอร์ต 4300
```

### บัญชีทดสอบ

| บัญชี | รหัสผ่าน | สิทธิ์ | หมายเหตุ |
|---|---|---|---|
| `user` | `123456` | สมาชิกทั่วไป | **รหัสอ่อนมาก** อยู่ในลิสต์รหัสยอดฮิต → เครื่องมือเดารหัสเจอแน่ |
| `admin` | `Tr0ub4dor&3xK` | ผู้ดูแลระบบ | รหัสแข็งกว่า ไม่อยู่ใน wordlist → เดาด้วยลิสต์สั้นๆ ไม่เจอ |

> รหัสของ `user` คือ `123456` ถูกวางไว้ลำดับที่ 8 ใน wordlist ของเครื่องมือเดารหัสโดยตั้งใจ
> เพื่อให้เห็นว่าหน้า safe **ล็อกบัญชีได้ก่อน** (หลังผิด 5 ครั้ง) จะเดาไปถึงรหัสจริงในครั้งที่ 8

### route สำคัญ

| หน้า | ทำอะไร |
|---|---|
| `/` | หน้าแรก รวมลิงก์ทุกเดโม |
| `/leak` · `/safe/leak` | เดโม 1: ฐานข้อมูลรั่ว (plain text vs hash) |
| `/login` · `/safe/login` | เดโม 2: ฟอร์มล็อกอิน (ไม่จำกัด vs rate limit) |
| `/guess` · `/safe/guess` | เดโม 2: เครื่องมือเดารหัส (จำลอง) |
| `/account` · `/safe/account` | หน้าบัญชี (ดูว่า token ตัดสินว่าเราเป็นใคร) |
| `/token` · `/safe/token` | เดโม 3: session token (เดาได้ vs สุ่ม+หมดอายุ) |
| `/forge?user=admin` | สวมรอยด้วย token ที่เดาได้ (ฝั่ง vuln) |
| `/logout` · `/safe/logout` | ออกจากระบบ |
| `/reset` | รีเซ็ตข้อมูลทั้งหมด |

เวลาโจมตีสำเร็จ ให้ดู **terminal** ที่รันเซิร์ฟเวอร์ จะมีข้อความ **สีแดง** ขึ้น เช่น
`[BRUTE FORCE] เดารหัสของ "user" สำเร็จ: 123456`

---

## 3. เดโม 1 — การเก็บรหัสผ่าน (`/leak`)

### สถานการณ์
ไม่มีระบบไหนรับประกันว่าฐานข้อมูลจะไม่หลุด (SQL injection, backup ตั้งค่าผิด, พนักงานในองค์กร ฯลฯ)
คำถามจริงคือ **"วันที่ DB หลุด แฮกเกอร์จะได้อะไรไป"**

### ลองดู
1. เปิด <http://localhost:4300/leak> → เห็นตาราง users ที่ column รหัสผ่านเป็น **ตัวหนังสือจริง** อ่านออกทั้งหมด
   (ใน terminal จะขึ้นสีแดง `[DB LEAK] ...`) — เอารหัสนี้ไปล็อกอินได้เลยทันที
2. เปิด <http://localhost:4300/safe/leak> → ข้อมูลชุดเดียวกัน แต่ column รหัสผ่านเป็นค่า hash ยาวๆ เช่น
   `scrypt$<salt>$<hash>` เอาไปล็อกอินตรงๆ ไม่ได้

### โค้ดที่ผิด ❌ และที่ถูก ✅ (`server.js`)

```js
// ❌ เก็บรหัสผ่านเป็น plain text
vulnUsers['user'] = { password: '123456' };

// ✅ เก็บเป็น scrypt hash + salt (ไม่มีรหัสจริงอยู่ในฐานข้อมูลเลย)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');     // salt สุ่มต่อผู้ใช้
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
// ตอนล็อกอินไม่ต้องถอด hash กลับ แต่เอารหัสที่กรอกมา hash ใหม่แล้วเทียบ
function verifyPassword(password, stored) {
  const [, salt, hash] = stored.split('$');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(test,'hex'));
}
```

### ทำไม hash + salt ถึงช่วย
- **hash เป็นทางเดียว** (one-way) ถอดกลับเป็นรหัสจริงไม่ได้ — ต้องเดาแล้ว hash เทียบเท่านั้น
- **scrypt จงใจช้าและกินแรม** → ต่อให้เดา ก็เดาได้ช้ามาก (ต่างจาก MD5/SHA-256 ที่เร็วจนเดาเป็นล้านรหัสต่อวินาที)
- **salt สุ่มต่อผู้ใช้** → สองคนตั้งรหัสเดียวกัน ค่า hash ก็ต่างกัน ใช้ **rainbow table** (ตารางสำเร็จรูป) ไม่ได้

> **ของจริงใน production ใช้อะไร:** นิยม **bcrypt** หรือ **argon2** (argon2id เป็นตัวที่แนะนำล่าสุด)
> เพราะออกแบบมาเพื่อแฮชรหัสผ่านโดยเฉพาะ ปรับ "ต้นทุน" (work factor) ตามฮาร์ดแวร์ได้ และผ่านการตรวจสอบอย่างกว้างขวาง
> แล็บนี้ใช้ `scrypt` เพราะมากับ Node.js ไม่ต้องลง npm — แต่แนวคิดเหมือนกันทุกอย่าง: **เก็บ hash ไม่เก็บรหัสจริง**

---

## 4. เดโม 2 — Brute force / Rate limiting (`/login`, `/guess`)

### สถานการณ์
ถ้าเว็บให้กรอกรหัสผิดกี่ครั้งก็ได้ แฮกเกอร์ก็เขียนสคริปต์ไล่ลองรหัสยอดฮิต (dictionary attack)
หรือลองทุกความเป็นไปได้ (brute force) จนกว่าจะเจอ โดยเฉพาะบัญชีที่ตั้งรหัสอ่อน

### ลองโจมตี (ฝั่ง vuln)
1. เปิด <http://localhost:4300/guess> (เครื่องมือเดารหัสจำลอง)
2. ช่องชื่อผู้ใช้ใส่ `user` แล้วกด **"เริ่มเดารหัส"**
3. เครื่องมือจะไล่ยิงรหัสยอดฮิตทีละตัวไปที่ `/login` — ไม่มีอะไรมาหยุด — จนเจอ `123456` ในครั้งที่ 8
   แล้วขึ้น `✅ สำเร็จ! รหัสคือ '123456'` (ใน terminal ขึ้นสีแดง `[BRUTE FORCE] ...`)
4. ลองเปลี่ยนเป็น `admin` แล้วกดใหม่ → ไล่จนหมดลิสต์ก็ไม่เจอ (รหัส admin แข็งและไม่อยู่ในลิสต์)

### ลองแบบที่แก้แล้ว (ฝั่ง safe)
1. เปิด <http://localhost:4300/safe/guess> (เครื่องมือเดารหัสตัวเดิม แต่ยิงไปที่ `/safe/login`)
2. ใส่ `user` แล้วกดเดารหัส
3. คราวนี้พอผิดครบ **5 ครั้ง** บัญชีจะ **ถูกล็อกชั่วคราว** ขึ้น `🔒 บัญชีถูกล็อกชั่วคราว! เครื่องมือยิงต่อไม่ได้`
   → เครื่องมือยิงไปไม่ถึงครั้งที่ 8 ที่เป็นรหัสจริง **การโจมตีถูกบล็อกก่อนเดาเจอ**

### โค้ดที่ผิด ❌ และที่ถูก ✅ (`server.js`)

```js
// ❌ /login : ไม่นับ ไม่จำกัด ยิงกี่ครั้งก็ได้
if (p === '/login') {
  const u = db.vulnUsers[username];
  if (u && password === u.password) { /* ... ล็อกอินผ่าน ... */ }
  // ผิดก็แค่ตอบ error แล้วจบ ไม่มีการจำว่าผิดมากี่ครั้ง
}

// ✅ /safe/login : จำกัดจำนวนครั้งต่อบัญชี (lockout)
if (p === '/safe/login') {
  if (lockState(key).locked) return /* ปฏิเสธ: ถูกล็อกชั่วคราว */;
  if (u && verifyPassword(password, u.hash)) { recordSuccess(key); /* ผ่าน + รีเซ็ตตัวนับ */ }
  else { recordFail(key); /* ผิดครบ MAX_FAILS -> ล็อก LOCK_MS วินาที */ }
}
```

```js
function recordFail(key) {
  const rec = db.loginAttempts.get(key) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= MAX_FAILS) { rec.lockedUntil = Date.now() + LOCK_MS; rec.fails = 0; }
  db.loginAttempts.set(key, rec);
}
```

### วิธีกัน brute force ในงานจริง (ใช้หลายชั้นรวมกัน)
- **Rate limiting / lockout:** จำกัดจำนวนครั้งต่อบัญชีและต่อ IP + หน่วงเวลา (exponential backoff) แบบในแล็บนี้
- **MFA / 2FA:** ต่อให้เดารหัสถูก ก็ยังต้องมี OTP/แอป authenticator อีกชั้น (กันได้ดีที่สุด)
- **บังคับรหัสผ่านที่แข็งแรง** และเช็กกับรายการรหัสที่เคยรั่ว (เช่น Have I Been Pwned) ไม่ให้ตั้งรหัสยอดฮิต
- **CAPTCHA** เมื่อเริ่มน่าสงสัย (ใช้เสริม ไม่ใช่ตัวหลัก)
- **ตรวจจับ/แจ้งเตือน** การล็อกอินผิดถี่ผิดปกติ

> **ข้อควรระวังของ lockout:** ถ้าออกแบบไม่ดี แฮกเกอร์อาจจงใจกรอกผิดเพื่อ **ล็อกบัญชีคนอื่น** (account lockout DoS)
> ทางแก้คือใช้การหน่วงเวลา + ล็อกชั่วคราว (ไม่ถาวร) + ดูร่วมกับ IP/อุปกรณ์ แทนการล็อกถาวรจากการผิดอย่างเดียว

---

## 5. เดโม 3 — Session token ที่เดาได้ / ไม่หมดอายุ (`/token`)

### สถานการณ์
หลังล็อกอิน เซิร์ฟเวอร์จะออก "ตั๋ว" (session id / token) ให้เบราว์เซอร์ถือไว้ในคุกกี้
หน้าถัดๆ ไปจะเชื่อตั๋วใบนี้ว่า "คุณเป็นใคร" ถ้าตั๋วนี้ **เดาได้** หรือ **ไม่มีวันหมดอายุ** ก็อันตราย

### ลองโจมตี (ฝั่ง vuln)
1. เปิด <http://localhost:4300/token> → จะเห็นว่า token ของหน้า vuln คือ `base64(ชื่อผู้ใช้)` เช่น
   `admin` → `YWRtaW4=` (ใครก็คำนวณได้ ไม่ต้องรู้รหัสผ่าน)
2. กดลิงก์ **"สวมรอยเป็น admin"** (`/forge?user=admin`) → เซิร์ฟเวอร์ตั้งคุกกี้ `auth=YWRtaW4=` ให้
   แล้วพาไป `/account` ซึ่งขึ้นว่าคุณคือ **admin** ทันที **โดยไม่ต้องกรอกรหัสผ่านเลย**
   (ใน terminal ขึ้นสีแดง `[TOKEN FORGE] ...`)
3. ลองเปิด DevTools (F12) → Application → Cookies จะเห็นคุกกี้ `auth` ที่เดาค่าได้ง่ายๆ

### ลองแบบที่แก้แล้ว (ฝั่ง safe)
1. เปิด <http://localhost:4300/safe/login> ล็อกอินเป็น `user`/`123456`
2. ไป <http://localhost:4300/safe/account> → token เป็นค่าสุ่มยาวๆ เช่น `9f3c1a...` และมี **countdown เวลาหมดอายุ**
   (ตั้งไว้ 60 วินาทีในแล็บเพื่อให้เห็นชัด)
3. รอจน countdown หมด แล้วรีเฟรช → ระบบเด้งออก ต้องล็อกอินใหม่ — token เดิมใช้ต่อไม่ได้แล้ว

### โค้ดที่ผิด ❌ และที่ถูก ✅ (`server.js`)

```js
// ❌ token = base64 ของชื่อผู้ใช้ ไม่มีวันหมดอายุ ไม่ได้เก็บที่เซิร์ฟเวอร์
function vulnTokenFor(username) { return Buffer.from(username).toString('base64'); }
// ตัดสินว่าเป็นใครด้วยการถอด base64 กลับ -> เดา/ปลอมได้ทันที

// ✅ token สุ่ม 128 บิต เก็บที่เซิร์ฟเวอร์พร้อมเวลาหมดอายุ
const tok = crypto.randomBytes(16).toString('hex');
db.safeTokens.set(tok, { user: username, expires: Date.now() + TOKEN_TTL });
// ตัดสินว่าเป็นใครด้วยการ "ค้นหา" ใน Map + เช็กว่ายังไม่หมดอายุ
function currentSafeUser(req) {
  const rec = db.safeTokens.get(cookie.safe_auth);
  if (!rec || rec.expires < Date.now()) return null;  // ไม่มี/หมดอายุ = ไม่ผ่าน
  return rec.user;
}
```

### token ที่ดีต้องมีคุณสมบัติอะไร
- **เดาไม่ได้:** สุ่มจาก CSPRNG อย่าง `crypto.randomBytes` อย่างน้อย 128 บิต — ห้ามอิงจากชื่อผู้ใช้/เลขเรียง/เวลา
- **หมดอายุได้:** มีทั้ง idle timeout (ไม่ใช้งานนานแล้วหมด) และ absolute timeout (อายุรวมสูงสุด)
- **ถอน (revoke) ได้:** เก็บ session ที่ฝั่งเซิร์ฟเวอร์ (หรือถ้าใช้ JWT ต้องมี blocklist/เวอร์ชัน) → logout แล้วตัดได้จริง
- **ออกใหม่หลังล็อกอิน (session regeneration):** กัน session fixation
- **ส่งผ่านคุกกี้ที่ตั้งค่าแน่นหนา:** `HttpOnly` (JS อ่านไม่ได้ กัน XSS ขโมย) + `Secure` + `SameSite`

> สังเกตในแล็บ: คุกกี้ฝั่ง safe ตั้งเป็น `HttpOnly` ส่วนฝั่ง vuln ไม่ได้ตั้ง — ลองพิมพ์ `document.cookie` ใน Console เทียบดู

---

## 6. ⚠ สิ่งที่ "ไม่ช่วย" หรือเข้าใจผิดบ่อย

| ความเชื่อ | ความจริง |
|---|---|
| เข้ารหัส (encrypt) รหัสผ่านไว้ก็พอ | **ผิด** — encrypt ถอดกลับได้ ถ้ากุญแจหลุดก็เห็นรหัสจริง ต้องใช้ **hash** (ทางเดียว) |
| ใช้ MD5 / SHA-256 แฮชรหัสผ่าน | **ไม่พอ** — เร็วเกินไป เดาได้เป็นล้านต่อวินาที ต้องใช้ bcrypt/argon2/scrypt ที่จงใจช้า + มี salt |
| แค่ซ่อน/ไม่โชว์รหัสในหน้าเว็บก็ปลอดภัย | **ผิด** — ประเด็นอยู่ที่ "เก็บยังไงในฐานข้อมูล" ไม่ใช่การแสดงผล |
| token เป็น base64 แล้ว "เข้ารหัส" แล้ว | **ผิด** — base64 แค่เปลี่ยนรูปแบบ ใครก็ถอดกลับได้ ไม่ใช่การเข้ารหัส |
| ล็อกอินอยู่แล้วก็ถือว่าปลอดภัย | **ผิด** — ถ้า token เดา/ปลอมได้ หรือไม่หมดอายุ การล็อกอินนั้นก็ไม่ปลอดภัย |
| ใส่ CAPTCHA อย่างเดียวกัน brute force ได้ | **ไม่พอ** — เป็นชั้นเสริม ควรมี rate limit + MFA ร่วมด้วย |

---

## 7. สรุปสั้นๆ (จำไว้ 3 ข้อ)

> 1. **อย่าเก็บรหัสผ่านจริง** — เก็บเป็น hash (bcrypt/argon2/scrypt) + salt เสมอ
> 2. **อย่าให้เดาไม่อั้น** — จำกัดจำนวนครั้ง + MFA
> 3. **อย่าใช้ token ที่เดาได้/ไม่หมดอายุ** — สุ่มด้วย CSPRNG, ตั้งวันหมดอายุ, ถอนได้

### Checklist ก่อนปล่อยระบบ

- [ ] รหัสผ่านเก็บเป็น hash ด้วย bcrypt / argon2 / scrypt + salt (ไม่ใช่ plain text / MD5 / SHA เปล่าๆ / encrypt)
- [ ] มี rate limiting / lockout ต่อบัญชีและต่อ IP + หน่วงเวลา
- [ ] รองรับ MFA / 2FA อย่างน้อยสำหรับบัญชีสำคัญ
- [ ] บังคับรหัสผ่านแข็งแรง + เช็กกับรายการรหัสที่เคยรั่ว
- [ ] session token สุ่มจาก CSPRNG ≥ 128 บิต
- [ ] token มีวันหมดอายุ (idle + absolute) และ revoke ได้จริง
- [ ] ออก session ใหม่หลังล็อกอิน (กัน session fixation)
- [ ] คุกกี้ session ตั้ง `HttpOnly; Secure; SameSite`
- [ ] ข้อความ error ตอนล็อกอินไม่บอกว่า "ผิดที่ชื่อผู้ใช้" หรือ "ผิดที่รหัส" (กัน user enumeration)

---

## 8. แบบฝึกหัดต่อยอด

1. ใน `server.js` ลองเพิ่มบัญชีใหม่ที่ตั้งรหัสเป็น `password` แล้วรันเครื่องมือเดารหัสดูว่าเจอในครั้งที่เท่าไร
2. ลองลด `MAX_FAILS` เหลือ 3 หรือเพิ่ม `LOCK_MS` แล้วดูผลที่ `/safe/guess`
3. เปิด DevTools → Application → Cookies เทียบคุกกี้ `auth` (vuln) กับ `safe_auth` (safe) — ตัวไหนเดาค่าได้ ตัวไหน `HttpOnly`
4. ลองแก้ฝั่ง vuln ให้ token เป็นเลขเรียง (1, 2, 3, ...) แทน base64 แล้วคิดว่าทำไมยังอันตรายเหมือนเดิม
5. ลองทำให้ข้อความ error ของ `/safe/login` เหมือนกันทั้งกรณีชื่อผิดและรหัสผิด เพื่อกัน user enumeration

---

## อ้างอิง

- OWASP — Authentication Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- OWASP — Password Storage Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- OWASP — Session Management Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
- OWASP Top 10 — A07:2021 Identification and Authentication Failures: <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
- PortSwigger Web Security Academy — Authentication (แล็บฝึกฟรี): <https://portswigger.net/web-security/authentication>
- MDN — Set-Cookie (HttpOnly, Secure, SameSite): <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- Node.js — `crypto.scryptSync`: <https://nodejs.org/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options>
