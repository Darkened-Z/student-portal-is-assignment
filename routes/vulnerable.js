const express = require('express');
const router = express.Router();
const { getDb } = require('../db/setup');
const crypto = require('crypto');

// ─── helpers ───────────────────────────────────────────────────────────
function html(title, body, req) {
    const user = req.session.user;
    const nav = user
        ? `<a href="/vulnerable/dashboard">Dashboard</a>
           <a href="/vulnerable/courses">Courses</a>
           <a href="/vulnerable/profile">Profile</a>
           <a href="/vulnerable/logout">Logout (${user.username})</a>`
        : `<a href="/vulnerable/login">Login</a>`;
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${title} — Vulnerable Portal</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<header class="vuln-header">
  <div class="brand">🎓 Student Portal <span class="badge badge-vuln">VULNERABLE</span></div>
  <nav>${nav}</nav>
</header>
<main>${body}</main>
<footer>Information Security Assignment 2 — Tayyaba Riaz FA24-BST-080</footer>
</body>
</html>`;
}

function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/vulnerable/login');
    next();
}

// ─── auth ──────────────────────────────────────────────────────────────

router.get('/login', (req, res) => {
    res.send(html('Login', `
    <div class="card">
      <h2>Login</h2>
      ${req.query.error ? `<p class="error">${req.query.error}</p>` : ''}
      <form method="POST" action="/vulnerable/login">
        <label>Username</label>
        <input name="username" placeholder="e.g. admin">
        <label>Password</label>
        <input type="password" name="password">
        <button type="submit">Login</button>
      </form>
      <p class="hint">💉 SQLi Easy: username <code>admin' OR '1'='1' --</code>, any password</p>
    </div>`, req));
});

// VULNERABILITY: SQL INJECTION — EASY (login bypass)
// Plain string interpolation into SQL query; no parameterization.
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const db = getDb();
    // VULN: direct interpolation allows ' OR '1'='1' -- to bypass auth
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    console.log('[vuln][sql-easy] query:', query);
    let user;
    try {
        user = db.prepare(query).get();
    } catch (e) {
        db.close();
        return res.redirect('/vulnerable/login?error=' + encodeURIComponent('SQL Error: ' + e.message));
    }
    db.close();
    if (!user) return res.redirect('/vulnerable/login?error=Invalid+credentials');
    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/vulnerable/dashboard');
});

router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/vulnerable/login');
});

// ─── dashboard ─────────────────────────────────────────────────────────

router.get('/dashboard', requireLogin, (req, res) => {
    const db = getDb();
    const courses = db.prepare(
        'SELECT c.* FROM courses c JOIN enrollments e ON c.id=e.course_id WHERE e.user_id=?'
    ).all(req.session.user.id);
    db.close();
    const rows = courses.map(c => `<tr><td>${c.name}</td><td>${c.category}</td><td>${c.instructor}</td>
        <td><a href="/vulnerable/comments/${c.id}">Comments</a></td></tr>`).join('');
    res.send(html('Dashboard', `
    <div class="card">
      <h2>Welcome, ${req.session.user.username}</h2>
      <h3>Your Enrolled Courses</h3>
      <table><thead><tr><th>Course</th><th>Category</th><th>Instructor</th><th>Actions</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">No enrollments yet.</td></tr>'}</tbody></table>
    </div>`, req));
});

// ─── search — REFLECTED XSS ────────────────────────────────────────────

router.get('/courses', requireLogin, (req, res) => {
    const db = getDb();
    const q = req.query.q || '';
    let courses = [];
    if (q) {
        // VULNERABILITY: SQL INJECTION — INTERMEDIATE (blind/error-based on search)
        // ALSO: REFLECTED XSS — q is printed directly into HTML without encoding
        const query = `SELECT * FROM courses WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
        console.log('[vuln][sql-intermediate] query:', query);
        try {
            courses = db.prepare(query).all();
        } catch (e) {
            const errMsg = e.message;
            db.close();
            // REFLECTED XSS: q injected directly into response HTML
            return res.send(html('Courses', `
            <div class="card">
              <h2>Search Courses</h2>
              <form method="GET">
                <input name="q" value="${q}" placeholder="Search...">
                <button type="submit">Search</button>
              </form>
              <p class="error">DB Error (query logged server-side): ${errMsg}</p>
              <p>Search term: ${q}</p>
            </div>`, req));
        }
    } else {
        courses = db.prepare('SELECT * FROM courses').all();
    }
    db.close();
    const rows = courses.map(c =>
        `<tr><td>${c.name}</td><td>${c.category}</td><td>${c.instructor}</td></tr>`
    ).join('');
    // REFLECTED XSS: q printed raw into HTML — payload: ?q=<script>alert('XSS')</script>
    res.send(html('Courses', `
    <div class="card">
      <h2>Search Courses</h2>
      <form method="GET">
        <input name="q" value="${q}" placeholder="Search by name or category...">
        <button type="submit">Search</button>
      </form>
      ${q ? `<p>Results for: ${q}</p>` : ''}
      <table><thead><tr><th>Name</th><th>Category</th><th>Instructor</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="3">No results.</td></tr>'}</tbody></table>
      <hr>
      <h3>Advanced SQLi — Category Filter</h3>
      <form method="GET" action="/vulnerable/courses/filter">
        <input name="cat" placeholder="Category (e.g. CS)">
        <button type="submit">Filter</button>
      </form>
      <p class="hint">💉 Try: <code>CS' UNION SELECT null,username,password,null,null FROM users--</code></p>
    </div>`, req));
});

// VULNERABILITY: SQL INJECTION — ADVANCED (UNION-based, multi-step)
router.get('/courses/filter', requireLogin, (req, res) => {
    const cat = req.query.cat || '';
    const db = getDb();
    // VULN: direct interpolation — attacker can do UNION SELECT to dump any table
    const query = `SELECT id, name, category, instructor, description FROM courses WHERE category='${cat}'`;
    console.log('[vuln][sql-advanced] query:', query);
    let rows = [];
    let err = null;
    try {
        rows = db.prepare(query).all();
    } catch (e) {
        err = e.message;
    }
    db.close();
    const trs = rows.map(r =>
        `<tr><td>${r.id}</td><td>${r.name}</td><td>${r.category}</td><td>${r.instructor}</td><td>${r.description||''}</td></tr>`
    ).join('');
    res.send(html('Filter', `
    <div class="card">
      <h2>Filter by Category</h2>
      <form method="GET">
        <input name="cat" value="${cat}" placeholder="Category">
        <button>Filter</button>
      </form>
      <p class="hint">Step 1: <code>CS' ORDER BY 5--</code> → find column count<br>
      Step 2: <code>CS' UNION SELECT null,name,null,null,null FROM sqlite_master WHERE type='table'--</code><br>
      Step 3: <code>CS' UNION SELECT null,sql,null,null,null FROM sqlite_master WHERE name='users'--</code><br>
      Step 4: <code>CS' UNION SELECT null,username,password,null,null FROM users--</code></p>
      ${err ? `<p class="error">Error: ${err}</p>` : ''}
      <p>Query: <code>${query.replace(/</g,'&lt;')}</code></p>
      <table><thead><tr><th>ID</th><th>Name/Data</th><th>Category</th><th>Instructor</th><th>Desc</th></tr></thead>
      <tbody>${trs || '<tr><td colspan="5">No results.</td></tr>'}</tbody></table>
    </div>`, req));
});

// ─── comments — STORED XSS ─────────────────────────────────────────────

router.get('/comments/:id', requireLogin, (req, res) => {
    const db = getDb();
    const course = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
    const comments = db.prepare(
        'SELECT c.content, u.username, c.created_at FROM comments c JOIN users u ON c.user_id=u.id WHERE c.course_id=? ORDER BY c.created_at DESC'
    ).all(req.params.id);
    db.close();
    if (!course) return res.status(404).send('Not found');
    // STORED XSS: content rendered with innerHTML in the template below
    const commentHtml = comments.map(c =>
        `<div class="comment"><strong>${c.username}</strong>: <span class="comment-body">${c.content}</span>
         <small>${c.created_at}</small></div>`
    ).join('') || '<p>No comments yet.</p>';
    res.send(html(course.name, `
    <div class="card">
      <h2>${course.name} — Comments</h2>
      <div id="comments">${commentHtml}</div>
      <hr>
      <h3>Post a Comment</h3>
      <form method="POST" action="/vulnerable/comments/${req.params.id}">
        <textarea name="content" placeholder="Your comment... try: <script>alert('Stored XSS')<\/script>"></textarea>
        <button type="submit">Post</button>
      </form>
      <p class="hint">💉 Stored XSS payload: <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></p>
      <hr>
      <!-- DOM-based XSS demo section -->
      <h3>Share Link (DOM-based XSS)</h3>
      <p>Append a hash to the URL to show a welcome message:</p>
      <code>http://localhost:3000/vulnerable/comments/${req.params.id}#Hello%20World</code>
      <div id="dom-msg" style="color:green;font-weight:bold;margin-top:8px;"></div>
      <script>
        // VULNERABILITY: DOM-BASED XSS
        // Reads location.hash and writes to innerHTML without sanitization.
        // Payload: #<img src=x onerror=alert('DOM XSS')>
        var hash = decodeURIComponent(location.hash.substring(1));
        if (hash) {
            document.getElementById('dom-msg').innerHTML = 'Welcome note: ' + hash;
        }
      <\/script>
      <p class="hint">💉 DOM XSS URL: <code>#&lt;img src=x onerror=alert('DOM XSS')&gt;</code></p>
    </div>`, req));
});

router.post('/comments/:id', requireLogin, (req, res) => {
    const { content } = req.body;
    const db = getDb();
    // STORED XSS: content saved raw to DB — no sanitization
    db.prepare('INSERT INTO comments (user_id, course_id, content) VALUES (?, ?, ?)').run(
        req.session.user.id, req.params.id, content
    );
    db.close();
    res.redirect(`/vulnerable/comments/${req.params.id}`);
});

// ─── profile — CSRF vulnerability ──────────────────────────────────────

router.get('/profile', requireLogin, (req, res) => {
    res.send(html('Profile', `
    <div class="card">
      <h2>Profile</h2>
      <p><strong>Username:</strong> ${req.session.user.username}</p>
      <p><strong>Email:</strong> ${req.session.user.email}</p>
      <hr>
      <h3>Change Email</h3>
      <!-- NO CSRF TOKEN — form is vulnerable -->
      <form method="POST" action="/vulnerable/profile/update-email">
        <label>New Email</label>
        <input type="email" name="email" placeholder="new@email.com">
        <button type="submit">Update Email</button>
      </form>
      <p class="hint">💉 CSRF: submit this form from <a href="/vulnerable/csrf-demo" target="_blank">the attacker page</a></p>
    </div>`, req));
});

// VULNERABILITY: CSRF — no token, no origin check, state-changing action
router.post('/profile/update-email', requireLogin, (req, res) => {
    const { email } = req.body;
    const db = getDb();
    db.prepare('UPDATE users SET email=? WHERE id=?').run(email, req.session.user.id);
    db.close();
    req.session.user.email = email;
    res.redirect('/vulnerable/profile?msg=Email+updated');
});

// Attacker page for CSRF demo (hosted same-origin — assignment allows this)
router.get('/csrf-demo', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head><title>Attacker Page — CSRF Demo</title>
<link rel="stylesheet" href="/css/style.css"></head>
<body>
<header class="vuln-header">
  <div class="brand">⚠️ Attacker's Page — CSRF Demo</div>
</header>
<main>
<div class="card">
  <h2>CSRF Attack Demo</h2>
  <p>This page simulates an attacker's site. When the victim (logged-in user) visits
     this page and clicks the button, their email is silently changed.</p>
  <p>Because the vulnerable endpoint has no CSRF token, the browser sends the request
     with the victim's session cookie automatically.</p>
  <form method="POST" action="/vulnerable/profile/update-email">
    <input type="hidden" name="email" value="hacked@attacker.com">
    <button type="submit" class="btn-danger">Click me to win a prize!</button>
  </form>
  <p class="hint">After clicking, check <a href="/vulnerable/profile">your profile</a> — the email changed without your consent.</p>
</div>
</main>
</body>
</html>`);
});

module.exports = router;
