# SQL Injection Lab — แล็บฝึกทำความเข้าใจ SQL Injection

> ⚠ **เว็บนี้ตั้งใจเขียนให้มีช่องโหว่** ใช้เรียนรู้บนเครื่องตัวเองเท่านั้น
> ห้ามเอาขึ้นเซิร์ฟเวอร์จริง และห้ามเอา payload ไปลองกับเว็บที่ไม่ได้รับอนุญาต (ผิด พ.ร.บ. คอมพิวเตอร์ฯ)

---

## 1. SQL Injection คืออะไร

**SQL Injection (SQLi)** คือช่องโหว่ที่ทำให้แฮกเกอร์ **แอบเขียนคำสั่ง SQL ของตัวเองเข้าไปในคำสั่งของเว็บ**
ผ่านช่องกรอกข้อมูลธรรมดา เช่น ช่อง login หรือช่องค้นหา

ต้นเหตุมีข้อเดียว เหมือนกับ XSS เป๊ะ:

> **เว็บเอาข้อมูลที่ผู้ใช้ส่งมา ไปต่อเป็น "คำสั่ง SQL" ตรง ๆ โดยไม่แยกระหว่าง "ข้อมูล" กับ "คำสั่ง"**

ตัวอย่างหน้า login ที่เขียนแบบมีช่องโหว่:

```js
const sql = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'";
```

ถ้าผู้ใช้กรอก `somchai` / `somchai2024` ก็ได้คำสั่งปกติ:

```sql
SELECT * FROM users WHERE username='somchai' AND password='somchai2024'
```

แต่ถ้าผู้ใช้กรอก username เป็น `admin' --` จะได้:

```sql
SELECT * FROM users WHERE username='admin' --' AND password='...'
```

เครื่องหมาย `--` ใน SQL คือ **คอมเมนต์** ทุกอย่างหลังจากนั้นถูกตัดทิ้ง
คำสั่งจึงเหลือแค่ `WHERE username='admin'` → ล็อกอินเป็น admin **ได้โดยไม่ต้องรู้รหัสผ่าน**

ฐานข้อมูลแยกไม่ออกว่าส่วนไหนคือ "ข้อมูลที่ผู้ใช้พิมพ์" ส่วนไหนคือ "คำสั่งของโปรแกรมเมอร์" — มันเห็นเป็นข้อความ SQL ก้อนเดียว แล้วรันทั้งหมด

### แฮกเกอร์เอาไปทำอะไรได้

- ข้ามการล็อกอิน (authentication bypass) เข้าบัญชีใครก็ได้
- ดึงข้อมูลทั้งตารางออกมา เช่น รหัสผ่าน อีเมล ข้อมูลบัตร (data exfiltration / UNION-based)
- อ่านข้อมูลจากตารางอื่น หรือ metadata ของฐานข้อมูล
- ในกรณีร้ายแรง: แก้ไข/ลบข้อมูล หรือรันคำสั่งบนเครื่องเซิร์ฟเวอร์

SQLi เป็นหนึ่งในช่องโหว่ที่เก่าแก่และร้ายแรงที่สุด อยู่ในหมวด **A03:2021 – Injection** ของ OWASP Top 10

---

## 2. วิธีรัน

ต้องมี [Node.js](https://nodejs.org) — แล็บนี้ทดสอบบน **Node v24.16.0** บน Windows **ไม่ต้อง npm install อะไรเลย**

```bash
node server.js
```

แล้วเปิดเบราว์เซอร์ไปที่ <http://localhost:4200>

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` คนอื่นในวง LAN เข้าไม่ได้

### เอนจินฐานข้อมูล (สำคัญ)

แล็บนี้พยายามใช้ **ฐานข้อมูล SQLite จริง** ผ่านโมดูล built-in `node:sqlite` (มากับ Node 24+) ก่อนเสมอ

- ถ้าใช้ได้ → จะเห็น `DB: node:sqlite — ฐานข้อมูล SQLite จริง` ที่มุมขวาบน และ **สาธิต `UNION SELECT` / `sqlite_version()` ได้จริง**
- ถ้าเครื่องไหน `node:sqlite` ใช้ไม่ได้ → โค้ดจะ `try/catch` แล้ว **fallback ไปใช้ "เอนจินจำลอง" (mock) ในหน่วยความจำ**
  ที่ตีความ SQL เองและยังสาธิต login bypass, `' OR '1'='1' --` และ UNION ได้เหมือนกัน

ทั้งสองเอนจินรับ SQL ก้อนเดียวกันที่โค้ดต่อ string ขึ้นมา จึงถูก inject ได้จริงทั้งคู่ (ไม่ใช่การแกล้งทำผลลัพธ์)

### โครงสร้างไฟล์

```
SQL-Injection/
├── server.js            ← เซิร์ฟเวอร์ + เอนจิน SQLite จริง + เอนจินจำลอง (ทั้งหมดอยู่ไฟล์เดียว)
├── package.json
├── .claude/
│   └── launch.json      ← ตั้งค่าไว้รันชื่อ "sqli-lab" พอร์ต 4200
└── README.md            ← ไฟล์นี้
```

### ข้อมูลทดสอบ (ตาราง `users`)

คอลัมน์: `id, username, password, email, role` — เป้าหมายของแฮกเกอร์คือดึงคอลัมน์ `password` ออกมา

| id | username | password | email | role |
|---|---|---|---|---|
| 1 | `admin` | `S3cr3t_@dm1n!` | admin@siamsecure.test | admin |
| 2 | `somchai` | `somchai2024` | somchai@mail.test | user |
| 3 | `nida` | `nida!rak99` | nida@mail.test | user |
| 4 | `guest` | `guest` | guest@mail.test | user |
| 5 | `support` | `help-desk-01` | support@siamsecure.test | staff |

ข้อมูลเป็น **in-memory** รีสตาร์ทเซิร์ฟเวอร์ หรือกด <http://localhost:4200/reset> แล้วกลับมาเหมือนเดิม

### เส้นทางในแล็บ

| Lab | หัวข้อ | มีช่องโหว่ | แก้แล้ว |
|---|---|---|---|
| 1 | Login bypass | `/login` | `/safe/login` |
| 2 | ดึงข้อมูลผ่านช่องค้นหา (UNION) | `/search` | `/safe/search` |
| – | รีเซ็ตฐานข้อมูล | `/reset` | |

> **จุดเด่นเพื่อการสอน:** ทุกหน้าจะ **แสดง SQL ที่ถูกสร้างขึ้นจริง** (escape แล้ว) ให้ดู
> ส่วนที่เป็นสีแดงในกล่อง SQL คือสิ่งที่ผู้ใช้พิมพ์เข้าไป จะเห็นชัดว่า input ทำให้โครงสร้างคำสั่งเปลี่ยนไปอย่างไร
> ส่วนหน้า `/safe/*` จะโชว์ว่า SQL คงที่ (มี `?`) และค่าถูกส่ง "แยก" เป็นพารามิเตอร์ต่างหาก

---

## 3. Lab 1 — Login Bypass (`/login`)

### สถานการณ์
หน้า login ตรวจสอบรหัสผ่านด้วยการต่อ string:

```sql
SELECT * FROM users WHERE username='<input>' AND password='<input>'
```

### โค้ดที่มีปัญหา (`server.js` ฟังก์ชัน `runLogin`)

```js
// ❌ เอา u, p มาต่อใส่ SQL ตรง ๆ
const sql = `SELECT id, username, password, email, role
             FROM users WHERE username = '${u}' AND password = '${p}'`;
const rows = ENGINE.all(sql);     // params ว่าง → ทุกอย่างคือ "คำสั่ง"
```

### ลองโจมตีทีละขั้น

1. เปิด <http://localhost:4200/login>
2. กรอก **username** = `admin' --` ส่วน **password** พิมพ์อะไรก็ได้ แล้วกดเข้าสู่ระบบ
   (หรือกดปุ่ม "ลอง" ในหน้าเว็บได้เลย)
3. ดูกล่อง "SQL ที่ถูกสร้างขึ้นจริง" จะเห็นว่าคำสั่งกลายเป็น:

   ```sql
   SELECT ... FROM users WHERE username = 'admin' --' AND password = 'xxx'
   ```

   ส่วน `--' AND password = 'xxx'` ถูกคอมเมนต์ทิ้ง → เหลือแค่ `WHERE username = 'admin'`
4. ผลคือ **ล็อกอินสำเร็จเป็น admin** ทั้งที่ไม่รู้รหัส และใน terminal จะขึ้นข้อความสีแดง `[SQLi] Login bypass สำเร็จ!`

### payload อื่นที่ได้ผล

| payload (ช่อง username) | ทำงานยังไง |
|---|---|
| `admin' --` | คอมเมนต์ทิ้งเงื่อนไข password → เข้าเป็น admin |
| `' OR '1'='1' -- ` | `'1'='1'` จริงเสมอ + `--` ตัดส่วนที่เหลือ → ได้ผู้ใช้คนแรก (admin) |
| `' OR 1=1 -- ` | แบบเดียวกันแต่ใช้ตัวเลข |
| `' UNION SELECT 1,'x','y','z','w' -- ` | แทรกแถวปลอมที่ควบคุมค่าเองได้ |

> **ข้อสังเกตเชิงลึก (ดีมากสำหรับสอน):** ถ้ากรอก `' OR '1'='1` โดย **ไม่มี** `--` ปิดท้าย มักจะ **ไม่ผ่าน**
> เพราะคำสั่งจะเป็น `username='' OR '1'='1' AND password='xxx'` และ `AND` มีลำดับความสำคัญสูงกว่า `OR`
> ทำให้ตีความเป็น `username='' OR ('1'='1' AND password='xxx')` ซึ่งต้องรหัสผ่านถูกอยู่ดี
> จึงต้องใช้ `--` คอมเมนต์ช่วง `AND password` ทิ้งไป การโจมตีถึงจะสำเร็จ

### แบบที่แก้แล้ว (`/safe/login`)
กรอก payload ชุดเดิม จะเห็นว่า **เข้าไม่ได้** และกล่อง SQL แสดงว่าคำสั่งเป็น
`WHERE username = ? AND password = ?` โดยค่าที่พิมพ์ถูกส่งแยกเป็นพารามิเตอร์ `admin' --` กลายเป็นแค่ "ชื่อผู้ใช้ที่หาไม่เจอ"

---

## 4. Lab 2 — ดึงข้อมูลผ่านช่องค้นหา / UNION (`/search`)

### สถานการณ์
ช่องค้นหาผู้ใช้จากชื่อ ใช้ `LIKE` ต่อ string:

```sql
SELECT id, username, email, role FROM users WHERE username LIKE '%<input>%'
```

### ลองโจมตีทีละขั้น

**ก. ดึงทุกแถวด้วย `OR '1'='1'`**

1. เปิด <http://localhost:4200/search>
2. ค้นด้วย `' OR '1'='1' -- ` → SQL กลายเป็น
   `... WHERE username LIKE '%' OR '1'='1' -- %'`
3. เงื่อนไขเป็นจริงทุกแถว → ได้ผู้ใช้ **ทั้งตาราง** (ทั้งที่ควรค้นได้ทีละชื่อ)

**ข. ดึง password ด้วย `UNION SELECT` (หัวใจของ data exfiltration)**

1. ค้นด้วย:

   ```sql
   ' UNION SELECT id, username, password, role FROM users --
   ```

2. SQL จะกลายเป็น:

   ```sql
   SELECT id, username, email, role FROM users WHERE username LIKE '%'
   UNION SELECT id, username, password, role FROM users -- %'
   ```

3. คำสั่งที่สองดึงคอลัมน์ `password` มาวางในตำแหน่งเดียวกับ `email`
   → **รหัสผ่านของทุกคนโผล่มาในช่อง email ของผลลัพธ์** เช่น `S3cr3t_@dm1n!`

   > เคล็ดลับของ UNION: จำนวนคอลัมน์ของทั้งสอง SELECT ต้อง **เท่ากัน** (ที่นี่คือ 4 คอลัมน์)
   > ถ้าไม่เท่าฐานข้อมูลจะ error — แฮกเกอร์จึงมักลองเดาจำนวนคอลัมน์ก่อน (`ORDER BY n`, `UNION SELECT NULL,NULL,...`)

**ค. ดึง metadata ของฐานข้อมูล** (ได้ผลเมื่อใช้ SQLite จริง)

```sql
zzz' UNION SELECT 1, sqlite_version(), 'db-version', 'x' --
```

จะได้เลขเวอร์ชันของ SQLite กลับมา แสดงว่าดึงข้อมูลนอกตาราง `users` ออกมาได้ด้วย

### โค้ดที่มีปัญหา / โค้ดที่แก้ (`server.js` ฟังก์ชัน `runSearch`)

```js
// ❌ ต่อ string → inject ได้
const sql = `SELECT id, username, email, role
             FROM users WHERE username LIKE '%${q}%'`;
const rows = ENGINE.all(sql);

// ✅ prepared statement → wildcard อยู่ใน parameter ค่าที่พิมพ์ไม่มีทางเป็นคำสั่ง
const sql = `SELECT id, username, email, role
             FROM users WHERE username LIKE ?`;
const rows = ENGINE.all(sql, ['%' + q + '%']);
```

ลองยิง payload ชุดเดิมที่ `/safe/search` จะเห็นว่าดึงข้อมูลไม่ออก

---

## 5. วิธีป้องกัน SQL Injection

### ✅ 1. Parameterized Query / Prepared Statement — วิธีหลักและสำคัญที่สุด

แยก "คำสั่ง" ออกจาก "ข้อมูล" ให้เด็ดขาด ใช้ `?` (หรือ named parameter) แทนค่าทุกครั้ง
ฐานข้อมูลจะ compile โครง SQL ก่อน แล้วค่อยเอาค่ามาใส่ในฐานะ "ข้อมูลล้วน ๆ" ไม่มีทางกลายเป็นคำสั่ง

```js
// ❌ อันตราย
db.exec("SELECT * FROM users WHERE username='" + u + "'");

// ✅ ปลอดภัย (node:sqlite / better-sqlite3)
db.prepare("SELECT * FROM users WHERE username = ?").get(u);

// ✅ ปลอดภัย (mysql2)
conn.execute("SELECT * FROM users WHERE username = ?", [u]);

// ✅ ปลอดภัย (pg)
client.query("SELECT * FROM users WHERE username = $1", [u]);
```

### ✅ 2. ใช้ ORM / Query Builder อย่างถูกวิธี

ORM ส่วนใหญ่สร้าง parameterized query ให้อัตโนมัติ จึงปลอดภัยโดยปริยาย — **แต่จะกลับมาอันตรายทันทีเมื่อใช้ raw query แล้วเอา string มาต่อเอง**

ตัวอย่าง **Prisma** (ประเด็นที่หลายคนเข้าใจผิด):

```js
// ✅ ปลอดภัย: query ปกติของ Prisma — parameterized ให้อัตโนมัติ
await prisma.user.findMany({ where: { username: input } });

// ✅ ปลอดภัย: $queryRaw แบบ tagged template → ค่าใน ${} กลายเป็น parameter เสมอ
await prisma.$queryRaw`SELECT * FROM users WHERE username = ${input}`;

// ❌ อันตราย: $queryRawUnsafe + ต่อ string เอง → inject ได้เต็ม ๆ
await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE username = '${input}'`
);

// ✅ ถ้าจำเป็นต้องใช้ $queryRawUnsafe จริง ๆ ให้ส่งค่าเป็น parameter แยก
await prisma.$queryRawUnsafe(
  "SELECT * FROM users WHERE username = $1", input
);
```

จุดสำคัญ: `` $queryRaw`...` `` (tagged template) ปลอดภัย แต่ `$queryRawUnsafe("..." + input)` ไม่ปลอดภัย
หลักเดียวกันนี้ใช้กับ ORM อื่น เช่น Sequelize (`sequelize.query(sql, { replacements })` ปลอดภัย แต่ต่อ string เองไม่ปลอดภัย),
TypeORM (`createQueryBuilder().where("x = :v", { v })` ปลอดภัย แต่ `.where("x = '" + v + "'")` ไม่ปลอดภัย),
Knex (`.where('x', v)` ปลอดภัย แต่ `knex.raw("... " + v)` ไม่ปลอดภัย)

### ✅ 3. หลักการเสริม (ไม่ใช้แทนข้อ 1)

- **Least privilege:** บัญชีฐานข้อมูลที่เว็บใช้ ควรมีสิทธิ์เท่าที่จำเป็น (เช่นอ่านอย่างเดียว) จำกัดความเสียหายเมื่อโดนเจาะ
- **Allowlist สำหรับส่วนที่เป็น identifier:** ชื่อคอลัมน์/ตาราง/ทิศทาง `ORDER BY` ที่ผูกกับ parameter ไม่ได้ ให้เทียบกับรายการที่อนุญาตไว้ล่วงหน้า ห้ามรับค่าดิบ
- **ไม่โชว์ error ของฐานข้อมูลให้ผู้ใช้เห็น:** ปิด error-based SQLi (ในแล็บนี้จงใจโชว์ error ให้ดูว่ามันช่วยแฮกเกอร์อย่างไร)
- **Validation ตามชนิดข้อมูล:** ช่องที่ควรเป็นตัวเลขก็บังคับให้เป็นตัวเลข ช่วยลดพื้นที่โจมตี (แต่ยังไม่พอ ต้อง parameterize อยู่ดี)

---

## 6. สิ่งที่ "ไม่ช่วย" หรือ "ไม่พอ"

| วิธี | ทำไมไม่พอ |
|---|---|
| escape เครื่องหมาย `'` เอง (เติม `\` หรือ `''`) | พลาดง่าย มี encoding/charset พิสดารที่เลี่ยงได้ และใช้ไม่ได้กับ identifier — ใช้ prepared statement ดีกว่า |
| blacklist คำว่า `UNION`, `SELECT`, `--` | เลี่ยงได้สารพัด เช่น `UNunionION`, คอมเมนต์คั่น `UN/**/ION`, เปลี่ยน case, encode |
| ตรวจแค่ฝั่งหน้าเว็บ (JavaScript) | แฮกเกอร์ยิง request ตรงไป API ได้ ข้ามหน้าเว็บไปเลย |
| จำกัดความยาว input | login bypass สั้นมาก (`admin'--`) จำกัดความยาวไม่ช่วย |
| ซ่อน error message อย่างเดียว | กัน error-based ได้ แต่ยัง bypass/union/blind SQLi ได้อยู่ |
| ใช้ stored procedure | ช่วยเฉพาะเมื่อข้างในใช้ parameter ถ้าข้างในยังต่อ string ก็ inject ได้เหมือนเดิม |

---

## 7. สรุปสั้น ๆ (จำข้อเดียวก็ได้)

> **อย่าเอา input ของผู้ใช้ไปต่อเป็นคำสั่ง SQL — ใช้ parameterized query เสมอ ให้ฐานข้อมูลแยก "คำสั่ง" ออกจาก "ข้อมูล" ให้**

### Checklist ก่อนปล่อยเว็บ

- [ ] ทุกคิวรีที่มีค่าจากผู้ใช้ ใช้ `?` / `$1` / named parameter ไม่มีการต่อ string เข้ากับ SQL
- [ ] ใช้ ORM แบบปลอดภัย ไม่มี `$queryRawUnsafe` / `raw()` ที่ต่อ string เอง
- [ ] ส่วนที่เป็น identifier (ชื่อคอลัมน์, `ORDER BY`) ตรวจด้วย allowlist
- [ ] บัญชีฐานข้อมูลของแอปใช้สิทธิ์เท่าที่จำเป็น (least privilege)
- [ ] ไม่ส่ง error ดิบของฐานข้อมูลออกไปให้ผู้ใช้
- [ ] มี input validation ตามชนิดข้อมูล (เป็นชั้นเสริม)

---

## 8. แบบฝึกหัดต่อยอด

1. ในหน้า `/search` ลองหาจำนวนคอลัมน์ที่ถูกต้องด้วย `' ORDER BY 5 -- ` (ดูว่า error ที่คอลัมน์ไหน)
2. ลองใช้ `' UNION SELECT 1, name, sql, 'x' FROM sqlite_master -- ` เพื่อดูโครงสร้างตารางทั้งฐานข้อมูล (เมื่อใช้ SQLite จริง)
3. เปิด `server.js` ฟังก์ชัน `runSearch` แล้วเปลี่ยนฝั่ง safe ให้ต่อ string ดู ว่า payload กลับมาทำงานไหม
4. ลองคิดว่าถ้า `password` ถูกเก็บเป็น hash (bcrypt) แทน plain text การ `UNION` ดึง password ออกมายังอันตรายอยู่ไหม เพราะอะไร

---

## อ้างอิง

- OWASP — SQL Injection Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- OWASP — SQL Injection (คำอธิบายช่องโหว่): <https://owasp.org/www-community/attacks/SQL_Injection>
- PortSwigger Web Security Academy — SQL injection (แล็บฝึกฟรี): <https://portswigger.net/web-security/sql-injection>
- PortSwigger — SQL injection UNION attacks: <https://portswigger.net/web-security/sql-injection/union-attacks>
- Prisma Docs — Raw queries ($queryRaw / $queryRawUnsafe): <https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries>
- MDN — SQL injection (ภาพรวม): <https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/SQL_injection>
