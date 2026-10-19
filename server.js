const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { initDb } = require('./db/setup');

const app = express();

// initialise DB on startup
initDb();

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'is-assignment2-secret-do-not-use-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ─── routes ────────────────────────────────────────────────────────────
app.use('/vulnerable', require('./routes/vulnerable'));
app.use('/secure',     require('./routes/secure'));

// Landing page
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Student Portal — IS Assignment 2</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<header style="background:#1a1a2e;color:#fff;padding:20px 40px;display:flex;align-items:center;gap:20px;">
  <span style="font-size:2rem;">🎓</span>
  <div>
    <h1 style="margin:0">Student Portal</h1>
    <p style="margin:0;opacity:.7">Information Security Assignment 2 — Part 2</p>
  </div>
</header>
<main style="max-width:700px;margin:40px auto;padding:0 20px;">
  <p style="color:#555">This project demonstrates common web vulnerabilities and their fixes.
  Choose a version to explore:</p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:24px;">
    <div class="card" style="border-top:4px solid #e74c3c;">
      <h2 style="color:#e74c3c">⚠️ Vulnerable Version</h2>
      <p>All attacks work end-to-end. Try the payloads shown on each page.</p>
      <ul>
        <li>Reflected XSS (search)</li>
        <li>Stored XSS (comments)</li>
        <li>DOM-based XSS (URL hash)</li>
        <li>CSRF (email change)</li>
        <li>SQLi Easy (login)</li>
        <li>SQLi Intermediate (search)</li>
        <li>SQLi Advanced (UNION)</li>
      </ul>
      <a href="/vulnerable/login" class="btn btn-danger">Enter Vulnerable Version →</a>
    </div>
    <div class="card" style="border-top:4px solid #27ae60;">
      <h2 style="color:#27ae60">✅ Secure Version</h2>
      <p>All attacks are blocked. Each page shows the specific fix applied.</p>
      <ul>
        <li>Output encoding (escapeHtml)</li>
        <li>textContent instead of innerHTML</li>
        <li>CSRF tokens on all forms</li>
        <li>Parameterized queries</li>
        <li>Input validation</li>
      </ul>
      <a href="/secure/login" class="btn btn-safe">Enter Secure Version →</a>
    </div>
  </div>
  <div class="card" style="margin-top:24px;background:#f8f9fa;">
    <h3>Test Credentials</h3>
    <table style="width:100%">
      <tr><th>Username</th><th>Password</th><th>Role</th></tr>
      <tr><td>admin</td><td>admin123</td><td>admin</td></tr>
      <tr><td>tayyaba</td><td>pass@123</td><td>student</td></tr>
      <tr><td>zeeshan</td><td>zeeshan99</td><td>student</td></tr>
    </table>
  </div>
</main>
<footer>Student: Tayyaba Riaz &nbsp;|&nbsp; Reg: FA24-BST-080 &nbsp;|&nbsp; COMSATS University Islamabad</footer>
</body>
</html>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[server] Student Portal running at http://localhost:${PORT}`);
    console.log(`[server] Vulnerable: http://localhost:${PORT}/vulnerable/login`);
    console.log(`[server]    Secure: http://localhost:${PORT}/secure/login`);
});
