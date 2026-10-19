const COLORS = ['#006838','#1a6b9c','#7c3aed','#c2410c','#0f766e','#b45309'];

function initials(name) {
    return (name||'U').split(/\s+/).map(w=>w[0]).join('').toUpperCase().slice(0,2);
}

function navbar({ user, mode, active }) {
    const base = `/${mode}`;
    const isVuln = mode === 'vulnerable';
    const modePill = isVuln
        ? `<span class="mode-pill vuln">⚠ Vulnerable</span>`
        : `<span class="mode-pill safe">✓ Secure</span>`;
    const switchBtn = isVuln
        ? `<a href="/secure/login" class="switch-btn">→ Secure</a>`
        : `<a href="/vulnerable/login" class="switch-btn">→ Vulnerable</a>`;

    const links = user ? [
        ['Dashboard', `${base}/dashboard`, 'dashboard'],
        ['Courses',   `${base}/courses`,   'courses'],
        ['Profile',   `${base}/profile`,   'profile'],
        ['Logout',    `${base}/logout`,    ''],
    ] : [];

    const navLinks = links.map(([label, href, key]) =>
        `<a href="${href}" class="nav-link${active===key?' active':''}">${label}</a>`
    ).join('');

    return `<nav class="navbar">
    <a href="${base}/${user?'dashboard':'login'}" class="nav-brand">
        <div class="nav-logo">F</div>
        <div>
            <div class="nav-brand-text">FAST NUCES</div>
            <div class="nav-brand-sub">Student Portal</div>
        </div>
    </a>
    <div class="nav-links">${navLinks}</div>
    <div class="nav-right">
        ${modePill}
        ${switchBtn}
        ${user ? `<span class="nav-user">${user.username}</span><div class="nav-avatar">${initials(user.username)}</div>` : ''}
    </div>
</nav>`;
}

function page(title, body, req, active) {
    const mode = req._mode || 'vulnerable';
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — FAST Portal</title>
<link rel="stylesheet" href="/css/portal.css">
</head>
<body>
${navbar({ user: req.session[mode==='vulnerable'?'user':'secureUser'], mode, active })}
<div class="page-wrap">
${body}
</div>
<footer>FAST NUCES Student Portal — Information Security Assignment 2 — Zeeshan Khan 23F-0553</footer>
</body>
</html>`;
}

module.exports = { page, COLORS, initials };
