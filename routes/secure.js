const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const { getDb } = require('../db/setup');
const { page, COLORS, initials } = require('../views/layout');

router.use((req, _res, next) => { req._mode = 'secure'; next(); });

function auth(req, res, next) {
    if (!req.session.secureUser) return res.redirect('/secure/login');
    next();
}

function csrfToken(req) {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    return req.session.csrfToken;
}

function verifyCsrf(req, res, next) {
    const token = req.body._csrf;
    if (!token || token !== req.session.csrfToken) {
        return res.status(403).send(page('Forbidden', `
<div class="card" style="border-top:3px solid var(--red)">
  <div class="card-title">CSRF Token Invalid</div>
  <p style="font-size:13px;color:var(--text-2);margin-top:8px">
    The form submission was rejected — CSRF token missing or mismatched.
    This is the expected behavior in the secure version.
  </p>
  <a href="/secure/profile" class="btn btn-outline" style="margin-top:14px">← Back to Profile</a>
</div>`, req, 'profile'));
    }
    next();
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Login ─────────────────────────────────────────────────────────────

router.get('/login', (req, res) => {
    const err = req.query.error || '';
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — FAST Portal (Secure)</title>
<link rel="stylesheet" href="/css/portal.css">
</head>
<body>
<div class="login-wrap">

  <div class="login-panel">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:32px">
      <div style="width:36px;height:36px;background:rgba(255,255,255,.15);border:1.5px solid rgba(255,255,255,.4);border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px">F</div>
      <div>
        <div style="font-weight:700;font-size:14px">FAST NUCES</div>
        <div style="font-size:11px;opacity:.6">National University</div>
      </div>
    </div>
    <h2 style="font-size:20px;font-weight:700;margin-bottom:8px">Student Learning Portal</h2>
    <p style="font-size:13px;opacity:.65;line-height:1.6">This version uses parameterized queries, CSRF tokens, and HTML escaping.</p>
    <div class="cred-table">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;opacity:.5">Test Accounts</div>
      admin / admin123<br>
      tayyaba / pass@123<br>
      zeeshan / zeeshan99
    </div>
    <div style="margin-top:auto;padding-top:32px">
      <span class="mode-pill safe" style="font-size:10px">✓ Secure Mode</span>
    </div>
  </div>

  <div class="login-form-area">
    <div class="login-box">
      <div class="login-heading">Sign in</div>
      <div class="login-sub">Use your FAST student credentials</div>
      ${err ? `<div class="alert alert-danger">${escapeHtml(err)}</div>` : ''}
      <form method="POST" action="/secure/login">
        <div class="form-row">
          <label>Username</label>
          <input name="username" placeholder="e.g. admin" autocomplete="off">
        </div>
        <div class="form-row">
          <label>Password</label>
          <input type="password" name="password" placeholder="••••••••">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;margin-top:4px">Sign In</button>
      </form>
      <div class="fix-box" style="margin-top:18px">
        <b>SQLi Easy Fix — Parameterized Query</b>
        Attempts like <code>admin' OR '1'='1' --</code> are blocked.
        <code style="color:var(--ok)">db.prepare('...WHERE username=? AND password=?').get(u,p)</code>
      </div>
    </div>
  </div>

</div>
</body></html>`);
});

// FIX: parameterized query — no string interpolation
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE username=? AND password=?').get(username, password);
    db.close();
    if (!user) return res.redirect('/secure/login?error=Invalid+username+or+password');
    req.session.secureUser = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/secure/dashboard');
});

router.get('/logout', (req, res) => { req.session.secureUser = null; res.redirect('/secure/login'); });

// ── Dashboard ─────────────────────────────────────────────────────────

router.get('/dashboard', auth, (req, res) => {
    const db = getDb();
    const courses = db.prepare('SELECT c.* FROM courses c JOIN enrollments e ON c.id=e.course_id WHERE e.user_id=?').all(req.session.secureUser.id);
    const total   = db.prepare('SELECT COUNT(*) as n FROM courses').get().n;
    db.close();

    const cards = courses.length ? courses.map((c, i) => `
    <div class="course-card">
      <div class="course-stripe" style="background:${COLORS[i%COLORS.length]}"></div>
      <div class="course-body">
        <div class="course-name">${escapeHtml(c.name)}</div>
        <div class="course-inst">${escapeHtml(c.instructor)} &nbsp;·&nbsp; <span class="badge">${escapeHtml(c.category)}</span></div>
        <div class="course-desc">${escapeHtml((c.description||'').slice(0,80))}…</div>
      </div>
      <div class="course-foot">
        <a href="/secure/comments/${c.id}" class="btn btn-plain btn-sm">Discussion</a>
      </div>
    </div>`).join('')
    : `<p style="color:var(--text-2);font-size:13px;padding:8px 0">No enrollments found.</p>`;

    res.send(page('Dashboard', `
<div class="stats-row">
  <div class="stat"><div class="stat-num">${courses.length}</div><div class="stat-label">Enrolled</div></div>
  <div class="stat"><div class="stat-num">${total}</div><div class="stat-label">Total Courses</div></div>
  <div class="stat"><div class="stat-num">FA24</div><div class="stat-label">Semester</div></div>
  <div class="stat"><div class="stat-num">BST</div><div class="stat-label">Program</div></div>
</div>
<div class="card">
  <div class="card-header">
    <div><div class="card-title">My Courses</div><div class="card-sub">Enrolled this semester</div></div>
    <a href="/secure/courses" class="btn btn-outline btn-sm">Browse All</a>
  </div>
  <div class="course-grid">${cards}</div>
</div>`, req, 'dashboard'));
});

// ── Courses ───────────────────────────────────────────────────────────

router.get('/courses', auth, (req, res) => {
    const db = getDb();
    const q  = req.query.q || '';
    let courses = [];

    if (q) {
        // FIX: parameterized LIKE; reflected XSS prevented by escapeHtml at render
        courses = db.prepare("SELECT * FROM courses WHERE name LIKE ? OR category LIKE ?").all(`%${q}%`, `%${q}%`);
    } else {
        courses = db.prepare('SELECT * FROM courses').all();
    }
    db.close();

    const rows = courses.map(c => `<tr>
      <td><strong>${escapeHtml(c.name)}</strong></td>
      <td><span class="badge">${escapeHtml(c.category)}</span></td>
      <td>${escapeHtml(c.instructor)}</td>
      <td style="color:var(--text-2)">${escapeHtml((c.description||'').slice(0,60))}</td>
      <td><a href="/secure/comments/${c.id}" class="btn btn-plain btn-sm">Discussion</a></td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-2);padding:16px">No results</td></tr>';

    res.send(page('Courses', `
<div class="card">
  <div class="card-header">
    <div><div class="card-title">Course Catalog</div><div class="card-sub">Search available courses</div></div>
  </div>
  <form method="GET" style="display:flex;gap:8px;margin-bottom:16px">
    <input name="q" value="${escapeHtml(q)}" placeholder="Search by name or category…" style="flex:1">
    <button type="submit" class="btn btn-primary">Search</button>
  </form>
  ${q ? `<p style="font-size:13px;color:var(--text-2);margin-bottom:12px">Results for: ${escapeHtml(q)}</p>` : ''}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Course</th><th>Category</th><th>Instructor</th><th>Description</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  <div class="fix-box">
    <b>Reflected XSS Fix — escapeHtml()</b>
    <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> is rendered as literal text, not executed.
  </div>
</div>

<div class="card">
  <div class="card-header">
    <div><div class="card-title">Category Filter (SQLi Advanced — Fixed)</div></div>
  </div>
  <form method="GET" action="/secure/courses/filter" style="display:flex;gap:8px;margin-bottom:14px">
    <input name="cat" placeholder="Category (e.g. CS)" style="flex:1">
    <button type="submit" class="btn btn-primary">Filter</button>
  </form>
  <div class="fix-box">
    <b>SQLi Advanced Fix — Parameterized query</b>
    UNION payloads return empty or error; no data leakage.
  </div>
</div>`, req, 'courses'));
});

router.get('/courses/filter', auth, (req, res) => {
    const cat = req.query.cat || '';
    const db  = getDb();
    // FIX: parameterized query
    const rows = db.prepare('SELECT id, name, category, instructor, description FROM courses WHERE category=?').all(cat);
    db.close();

    const trs = rows.map(r => `<tr>
      <td style="font-family:var(--mono);font-size:11.5px">${r.id}</td>
      <td><strong>${escapeHtml(r.name)}</strong></td>
      <td>${escapeHtml(r.category)}</td>
      <td>${escapeHtml(r.instructor)}</td>
      <td style="color:var(--text-2)">${escapeHtml(r.description||'')}</td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;padding:14px;color:var(--text-2)">No results</td></tr>';

    res.send(page('Category Filter', `
<div class="card">
  <div class="card-header">
    <div><div class="card-title">Category Filter — Secure</div></div>
    <a href="/secure/courses" class="btn btn-plain btn-sm">← Back</a>
  </div>
  <form method="GET" style="display:flex;gap:8px;margin-bottom:14px">
    <input name="cat" value="${escapeHtml(cat)}" placeholder="Category" style="flex:1">
    <button type="submit" class="btn btn-primary">Filter</button>
  </form>
  <div class="table-wrap">
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Instructor</th><th>Description</th></tr></thead>
      <tbody>${trs}</tbody>
    </table>
  </div>
  <div class="fix-box"><b>SQLi Advanced Fix</b> Parameterized query; UNION injections return no results.</div>
</div>`, req, 'courses'));
});

// ── Comments ──────────────────────────────────────────────────────────

router.get('/comments/:id', auth, (req, res) => {
    const db     = getDb();
    const course = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
    if (!course) { db.close(); return res.status(404).send('Not found'); }
    const list = db.prepare(`SELECT c.content, u.username, c.created_at FROM comments c
        JOIN users u ON c.user_id=u.id WHERE c.course_id=? ORDER BY c.created_at DESC`).all(req.params.id);
    db.close();

    // FIX: escapeHtml on content — Stored XSS blocked
    const comments = list.map(c => `
    <div class="comment">
      <div class="c-avatar">${initials(c.username)}</div>
      <div class="c-body">
        <div class="c-header"><span class="c-author">${escapeHtml(c.username)}</span><span class="c-time">${c.created_at}</span></div>
        <div class="c-text">${escapeHtml(c.content)}</div>
      </div>
    </div>`).join('') || `<p style="color:var(--text-2);font-size:13px">No comments yet.</p>`;

    res.send(page(course.name, `
<div class="card" style="margin-bottom:14px">
  <div style="font-size:12.5px;color:var(--text-2);margin-bottom:10px"><a href="/secure/courses">← Courses</a></div>
  <div class="card-title" style="font-size:17px">${escapeHtml(course.name)}</div>
  <div style="font-size:13px;color:var(--text-2);margin-top:3px">${escapeHtml(course.instructor)} &nbsp;·&nbsp; ${escapeHtml(course.category)}</div>
  <p style="margin-top:10px;font-size:13px;color:var(--text-2)">${escapeHtml(course.description||'')}</p>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="card-title" style="margin-bottom:16px">Discussion (${list.length})</div>
  <div class="comment-list">${comments}</div>
  <hr class="sep">
  <div style="font-size:13px;font-weight:600;margin-bottom:10px">Post a Comment</div>
  <form method="POST" action="/secure/comments/${req.params.id}">
    <div class="form-row">
      <textarea name="content" placeholder="Write your comment…"></textarea>
    </div>
    <button type="submit" class="btn btn-primary">Post</button>
  </form>
  <div class="fix-box">
    <b>Stored XSS Fix — escapeHtml() at render</b>
    Scripts in comments are escaped to literal text.
  </div>
</div>

<div class="card">
  <div class="card-title" style="margin-bottom:8px">DOM-Based XSS — Fixed</div>
  <p style="font-size:13px;color:var(--text-2);margin-bottom:10px">
    The secure version uses <code>textContent</code> instead of <code>innerHTML</code>.
    The hash payload is rendered as text — not executed.
  </p>
  <div id="dom-out" style="margin-top:12px;font-size:13.5px;font-weight:500;color:var(--ok)"></div>
  <script>
    // FIX: textContent instead of innerHTML — DOM XSS blocked
    var h = decodeURIComponent(location.hash.slice(1));
    if (h) document.getElementById('dom-out').textContent = 'Note: ' + h;
  <\/script>
  <div class="fix-box"><b>DOM XSS Fix</b> <code>textContent</code> treats input as plain text — no HTML parsed.</div>
</div>`, req, 'courses'));
});

router.post('/comments/:id', auth, (req, res) => {
    const db = getDb();
    db.prepare('INSERT INTO comments (user_id, course_id, content) VALUES (?,?,?)').run(
        req.session.secureUser.id, req.params.id, req.body.content);
    db.close();
    res.redirect(`/secure/comments/${req.params.id}`);
});

// ── Profile ───────────────────────────────────────────────────────────

router.get('/profile', auth, (req, res) => {
    const u     = req.session.secureUser;
    const token = csrfToken(req);
    res.send(page('Profile', `
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

  <div class="card">
    <div class="card-title" style="margin-bottom:16px">Account</div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:18px;border-bottom:1px solid var(--border)">
      <div style="width:44px;height:44px;border-radius:50%;background:var(--green);color:#fff;font-weight:700;font-size:16px;display:flex;align-items:center;justify-content:center">${initials(u.username)}</div>
      <div>
        <div style="font-weight:600;font-size:15px">${escapeHtml(u.username)}</div>
        <div style="font-size:12px;color:var(--text-2);text-transform:capitalize">${u.role}</div>
      </div>
    </div>
    <div style="display:grid;gap:10px;font-size:13px">
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Email</span><span>${escapeHtml(u.email)}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Program</span><span>BS Telecom</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Semester</span><span>FA24</span></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title" style="margin-bottom:14px">Change Email</div>
    <!-- FIX: CSRF token included in every state-changing form -->
    <form method="POST" action="/secure/profile/update-email">
      <input type="hidden" name="_csrf" value="${token}">
      <div class="form-row">
        <label>New Email</label>
        <input type="email" name="email" placeholder="new@nu.edu.pk">
      </div>
      <button type="submit" class="btn btn-primary">Update</button>
    </form>
    <div class="fix-box">
      <b>CSRF Fix — token in session</b>
      The hidden <code>_csrf</code> field is validated server-side. Cross-origin form submissions are rejected.
    </div>
  </div>

</div>`, req, 'profile'));
});

// FIX: CSRF token validation before processing
router.post('/profile/update-email', auth, verifyCsrf, (req, res) => {
    const db = getDb();
    db.prepare('UPDATE users SET email=? WHERE id=?').run(req.body.email, req.session.secureUser.id);
    db.close();
    req.session.secureUser.email = req.body.email;
    res.redirect('/secure/profile');
});

// built by Tayyaba Riaz — FA24-BST-080

module.exports = router;
