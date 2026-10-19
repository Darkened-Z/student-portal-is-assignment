const express = require('express');
const router = express.Router();
const { getDb } = require('../db/setup');
const crypto = require('crypto');

// ─── helpers ───────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function csrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

function verifyCsrf(req, res, next) {
    const token = req.body._csrf;
    if (!token || token !== req.session.csrfToken) {
        return res.status(403).send(html('Error',
            '<div class="card"><h2>403 — CSRF Token Invalid</h2><p>This request was blocked because it did not include a valid CSRF token. This is exactly how CSRF attacks are prevented.</p></div>', req));
    }
    // Rotate token after use
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    next();
}

function html(title, body, req) {
    const user = req.session.secureUser;
    const nav = user
        ? `<a href="/secure/dashboard">Dashboard</a>
           <a href="/secure/courses">Courses</a>
           <a href="/secure/profile">Profile</a>
           <a href="/secure/logout">Logout (${escapeHtml(user.username)})</a>`
        : `<a href="/secure/login">Login</a>`;
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)} — Secure Portal</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<header class="secure-header">
  <div class="brand">🎓 Student Portal <span class="badge badge-safe">SECURE</span></div>
  <nav>${nav}</nav>
</header>
<main>${body}</main>
<footer>Information Security Assignment 2 — Tayyaba Riaz FA24-BST-080</footer>
</body>
</html>`;
}

function requireLogin(req, res, next) {
    if (!req.session.secureUser) return res.redirect('/secure/login');
    next();
}

// ─── auth ──────────────────────────────────────────────────────────────

router.get('/login', (req, res) => {
    const tok = csrfToken(req);
    res.send(html('Login', `
    <div class="card">
      <h2>Login</h2>
      ${req.query.error ? `<p class="error">${escapeHtml(req.query.error)}</p>` : ''}
      <form method="POST" action="/secure/login">
        <input type="hidden" name="_csrf" value="${tok}">
        <label>Username</label>
        <input name="username" placeholder="Username">
        <label>Password</label>
        <input type="password" name="password">
        <button type="submit">Login</button>
      </form>
      <p class="fix">FIX: Parameterized query — no interpolation. CSRF token on form.</p>
    </div>`, req));
});

// FIX: parameterized query — SQL injection impossible
router.post('/login', verifyCsrf, (req, res) => {
    const { username, password } = req.body;
    const db = getDb();
    // SECURE: uses ? placeholder — the DB driver treats username/password as data, not SQL
    const user = db.prepare('SELECT * FROM users WHERE username=? AND password=?').get(username, password);
    db.close();
    if (!user) return res.redirect('/secure/login?error=Invalid+credentials');
    req.session.secureUser = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/secure/dashboard');
});

router.get('/logout', (req, res) => {
    delete req.session.secureUser;
    res.redirect('/secure/login');
});

// ─── dashboard ─────────────────────────────────────────────────────────

router.get('/dashboard', requireLogin, (req, res) => {
    const db = getDb();
    const courses = db.prepare(
        'SELECT c.* FROM courses c JOIN enrollments e ON c.id=e.course_id WHERE e.user_id=?'
    ).all(req.session.secureUser.id);
    db.close();
    const rows = courses.map(c =>
        `<tr><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.category)}</td><td>${escapeHtml(c.instructor)}</td>
         <td><a href="/secure/comments/${c.id}">Comments</a></td></tr>`
    ).join('');
    res.send(html('Dashboard', `
    <div class="card">
      <h2>Welcome, ${escapeHtml(req.session.secureUser.username)}</h2>
      <h3>Your Enrolled Courses</h3>
      <table><thead><tr><th>Course</th><th>Category</th><th>Instructor</th><th>Actions</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">No enrollments yet.</td></tr>'}</tbody></table>
    </div>`, req));
});

// ─── search — REFLECTED XSS fix ────────────────────────────────────────

router.get('/courses', requireLogin, (req, res) => {
    const db = getDb();
    const q = req.query.q || '';
    let courses = [];
    if (q) {
        // FIX: parameterized query — no SQLi
        courses = db.prepare("SELECT * FROM courses WHERE name LIKE ? OR category LIKE ?").all(`%${q}%`, `%${q}%`);
    } else {
        courses = db.prepare('SELECT * FROM courses').all();
    }
    db.close();
    const rows = courses.map(c =>
        `<tr><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.category)}</td><td>${escapeHtml(c.instructor)}</td></tr>`
    ).join('');
    // FIX: escapeHtml(q) — any <script> tag in q is rendered as text, not executed
    res.send(html('Courses', `
    <div class="card">
      <h2>Search Courses</h2>
      <form method="GET">
        <input name="q" value="${escapeHtml(q)}" placeholder="Search by name or category...">
        <button type="submit">Search</button>
      </form>
      ${q ? `<p>Results for: ${escapeHtml(q)}</p>` : ''}
      <table><thead><tr><th>Name</th><th>Category</th><th>Instructor</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="3">No results.</td></tr>'}</tbody></table>
      <p class="fix">FIX: escapeHtml() encodes &lt;script&gt; to text. Parameterized queries prevent SQLi.</p>
      <hr>
      <h3>Category Filter (SQLi Advanced — Fixed)</h3>
      <form method="GET" action="/secure/courses/filter">
        <input name="cat" placeholder="Category (e.g. CS)">
        <button type="submit">Filter</button>
      </form>
    </div>`, req));
});

// FIX: parameterized query for UNION-based SQLi
router.get('/courses/filter', requireLogin, (req, res) => {
    const cat = req.query.cat || '';
    const db = getDb();
    // SECURE: ? placeholder makes UNION injection impossible
    const rows = db.prepare(
        'SELECT id, name, category, instructor, description FROM courses WHERE category=?'
    ).all(cat);
    db.close();
    const trs = rows.map(r =>
        `<tr><td>${escapeHtml(String(r.id))}</td><td>${escapeHtml(r.name)}</td>
         <td>${escapeHtml(r.category)}</td><td>${escapeHtml(r.instructor)}</td>
         <td>${escapeHtml(r.description||'')}</td></tr>`
    ).join('');
    res.send(html('Filter', `
    <div class="card">
      <h2>Filter by Category</h2>
      <form method="GET"><input name="cat" value="${escapeHtml(cat)}"><button>Filter</button></form>
      <p class="fix">FIX: Parameterized query — UNION injection returns zero rows.</p>
      <table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Instructor</th><th>Desc</th></tr></thead>
      <tbody>${trs || '<tr><td colspan="5">No results.</td></tr>'}</tbody></table>
    </div>`, req));
});

// ─── comments — STORED XSS & DOM XSS fix ───────────────────────────────

router.get('/comments/:id', requireLogin, (req, res) => {
    const db = getDb();
    const course = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
    const comments = db.prepare(
        'SELECT c.content, u.username, c.created_at FROM comments c JOIN users u ON c.user_id=u.id WHERE c.course_id=? ORDER BY c.created_at DESC'
    ).all(req.params.id);
    db.close();
    if (!course) return res.status(404).send('Not found');
    // FIX: escapeHtml() on content — <script> is rendered as text
    const commentHtml = comments.map(c =>
        `<div class="comment"><strong>${escapeHtml(c.username)}</strong>: ${escapeHtml(c.content)}
         <small>${escapeHtml(c.created_at)}</small></div>`
    ).join('') || '<p>No comments yet.</p>';
    const tok = csrfToken(req);
    res.send(html(course.name, `
    <div class="card">
      <h2>${escapeHtml(course.name)} — Comments</h2>
      <p class="fix">FIX: All output escaped with escapeHtml() — stored scripts render as text.</p>
      <div id="comments">${commentHtml}</div>
      <hr>
      <h3>Post a Comment</h3>
      <form method="POST" action="/secure/comments/${req.params.id}">
        <input type="hidden" name="_csrf" value="${tok}">
        <textarea name="content" placeholder="Your comment..."></textarea>
        <button type="submit">Post</button>
      </form>
      <hr>
      <!-- DOM-based XSS — FIXED -->
      <h3>Share Link (DOM XSS — Fixed)</h3>
      <div id="dom-msg" style="color:green;font-weight:bold;margin-top:8px;"></div>
      <script>
        // FIX: textContent instead of innerHTML — browser renders text, not HTML/JS
        var hash = decodeURIComponent(location.hash.substring(1));
        if (hash) {
            var el = document.getElementById('dom-msg');
            el.textContent = 'Welcome note: ' + hash;  // safe: textContent never executes scripts
        }
      <\/script>
      <p class="fix">FIX: textContent instead of innerHTML — hash payload is displayed as literal text, not executed.</p>
    </div>`, req));
});

router.post('/comments/:id', requireLogin, verifyCsrf, (req, res) => {
    const { content } = req.body;
    const db = getDb();
    db.prepare('INSERT INTO comments (user_id, course_id, content) VALUES (?, ?, ?)').run(
        req.session.secureUser.id, req.params.id, content
    );
    db.close();
    res.redirect(`/secure/comments/${req.params.id}`);
});

// ─── profile — CSRF fix ────────────────────────────────────────────────

router.get('/profile', requireLogin, (req, res) => {
    const tok = csrfToken(req);
    res.send(html('Profile', `
    <div class="card">
      <h2>Profile</h2>
      <p><strong>Username:</strong> ${escapeHtml(req.session.secureUser.username)}</p>
      <p><strong>Email:</strong> ${escapeHtml(req.session.secureUser.email)}</p>
      <hr>
      <h3>Change Email</h3>
      <!-- FIX: hidden CSRF token in every form -->
      <form method="POST" action="/secure/profile/update-email">
        <input type="hidden" name="_csrf" value="${tok}">
        <label>New Email</label>
        <input type="email" name="email" placeholder="new@email.com">
        <button type="submit">Update Email</button>
      </form>
      <p class="fix">FIX: CSRF token in form. The attacker page cannot know the token, so the forged request is rejected with 403.</p>
    </div>`, req));
});

// FIX: CSRF token verified before processing state-changing action
router.post('/profile/update-email', requireLogin, verifyCsrf, (req, res) => {
    const { email } = req.body;
    const db = getDb();
    db.prepare('UPDATE users SET email=? WHERE id=?').run(email, req.session.secureUser.id);
    db.close();
    req.session.secureUser.email = email;
    res.redirect('/secure/profile?msg=Email+updated');
});

// CSRF attacker demo — will FAIL on secure version (no valid token)
router.get('/csrf-demo', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head><title>Attacker Page — CSRF Demo (Secure)</title>
<link rel="stylesheet" href="/css/style.css"></head>
<body>
<header class="secure-header">
  <div class="brand">⚠️ Attacker's Page — CSRF Demo (Secure)</div>
</header>
<main>
<div class="card">
  <h2>CSRF Attack — Blocked in Secure Version</h2>
  <p>Clicking this button sends a POST to <code>/secure/profile/update-email</code> without a valid CSRF token.</p>
  <form method="POST" action="/secure/profile/update-email">
    <input type="hidden" name="email" value="hacked@attacker.com">
    <button type="submit" class="btn-danger">Attempt CSRF Attack</button>
  </form>
  <p class="fix">Expected result: 403 Forbidden — CSRF token missing or invalid.</p>
</div>
</main>
</body>
</html>`);
});

module.exports = router;
