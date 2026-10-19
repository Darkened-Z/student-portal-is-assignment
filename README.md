# Student Portal — IS Assignment 2 Part 2

A full-stack web application demonstrating common web vulnerabilities and their fixes.

**Student:** Tayyaba Riaz | FA24-BST-080 | COMSATS University Islamabad  
**Course:** Information Security (Practical)

---

## Use Case

An academic student portal where students log in, view enrolled courses, search the course catalog, and post comments on course pages. The application is built twice — once deliberately insecure, once hardened.

## Tech Stack

- **Backend:** Node.js + Express.js
- **Database:** SQLite (via better-sqlite3)
- **Frontend:** Server-rendered HTML + vanilla CSS
- **Sessions:** express-session (cookie-based)

## Quick Start

```bash
npm install
node server.js
# open http://localhost:3000
```

## Test Credentials

| Username | Password  | Role    |
|----------|-----------|---------|
| admin    | admin123  | admin   |
| tayyaba  | pass@123  | student |
| zeeshan  | zeeshan99 | student |

---

## Versions

| Route prefix   | Version    |
|----------------|------------|
| `/vulnerable/` | Insecure — all attacks work |
| `/secure/`     | Hardened — all attacks blocked |

---

## Implemented Vulnerabilities & Fixes

### 1. Reflected XSS
- **Where:** `/vulnerable/courses?q=<payload>`
- **Payload:** `<script>alert('Reflected XSS')</script>`
- **Root cause:** search term `q` is interpolated raw into the HTML response
- **Fix:** `escapeHtml(q)` encodes `<` `>` `"` as HTML entities before insertion

### 2. Stored XSS
- **Where:** Comment form on `/vulnerable/comments/:id`
- **Payload:** `<script>alert('Stored XSS')</script>`
- **Root cause:** comment content saved raw to DB and rendered with `${content}` in template
- **Fix:** `escapeHtml(c.content)` applied at render time

### 3. DOM-based XSS
- **Where:** URL hash on `/vulnerable/comments/:id#<payload>`
- **Payload:** `#<img src=x onerror=alert('DOM XSS')>`
- **Root cause:** `document.getElementById(...).innerHTML = location.hash` executes injected HTML
- **Fix:** Use `textContent` instead of `innerHTML`

### 4. CSRF
- **Where:** POST `/vulnerable/profile/update-email`
- **Attack:** Visit `/vulnerable/csrf-demo` — a forged form auto-submits and changes the victim's email
- **Root cause:** no CSRF token; browser attaches session cookie automatically
- **Fix:** cryptographically random token in hidden form field, validated server-side before processing

### 5. SQL Injection — Easy (login bypass)
- **Where:** POST `/vulnerable/login`
- **Payload:** username `admin' OR '1'='1' --`, any password
- **Root cause:** `SELECT * FROM users WHERE username='${u}' AND password='${p}'`
- **Fix:** parameterized query `db.prepare('...WHERE username=? AND password=?').get(u, p)`

### 6. SQL Injection — Intermediate (error/blind-based)
- **Where:** `/vulnerable/courses?q=<payload>`
- **Payload:** `%' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a' --`
- **Root cause:** search query concatenated directly, error message leaked to response
- **Fix:** parameterized LIKE query `db.prepare("...WHERE name LIKE ?").all('%' + q + '%')`

### 7. SQL Injection — Advanced (UNION-based multi-step)
- **Where:** `/vulnerable/courses/filter?cat=<payload>`
- **Attack chain:**
  1. `CS' ORDER BY 5--` → confirm 5 columns
  2. `CS' UNION SELECT null,name,null,null,null FROM sqlite_master WHERE type='table'--` → list tables
  3. `CS' UNION SELECT null,sql,null,null,null FROM sqlite_master WHERE name='users'--` → get schema
  4. `CS' UNION SELECT null,username,password,null,null FROM users--` → dump credentials
- **Fix:** parameterized query `db.prepare('...WHERE category=?').all(cat)`

---

## Project Structure

```
part2_webapp/
├── server.js          main Express app
├── db/
│   ├── setup.js       DB init helper
│   ├── schema.sql     table definitions
│   └── seed.sql       sample data
├── routes/
│   ├── vulnerable.js  all insecure endpoints
│   └── secure.js      all hardened endpoints
└── public/
    └── css/style.css  shared stylesheet
```
