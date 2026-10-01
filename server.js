/*
 * VulnLab DAST demo
 * -----------------
 * App con formulario de login y varios modulos protegidos por sesion.
 * UI construida con Bootstrap 5 + tema Bootswatch "Brite" (enlazado por CDN),
 * con el color primario ajustado a verde.
 *
 * Incluye, de forma deliberada, DEBILIDADES DE CONFIGURACION suaves para que
 * un escaner DAST (p. ej. Aikido Security) tenga hallazgos que reportar:
 *   - Sin cabeceras de seguridad (CSP, HSTS, X-Frame-Options, etc.)
 *   - Cabecera X-Powered-By expuesta
 *   - Cookie de sesion sin HttpOnly / Secure / SameSite
 *   - Credenciales demo debiles y documentadas
 *
 * USO EXCLUSIVO en entornos de prueba autorizados. No pongas datos reales.
 * Cada punto esta marcado con "WEAK:" para que puedas endurecerlo despues.
 */
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');

const PORT = process.env.PORT || 3000;
const app = express();

app.use(helmet());

// WEAK: no se desactiva x-powered-by, asi el DAST detecta el framework/version.
// Para endurecer: app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false }));

// WEAK: cookie de sesion sin HttpOnly, sin Secure y sin SameSite.
// Endurecer: cookie: { httpOnly: true, secure: true, sameSite: 'lax' }
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'demo-secret-cambia-esto',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: false, secure: false, maxAge: 1000 * 60 * 60 * 4 },
}));

// WEAK: no se aplican cabeceras de seguridad (no helmet/CSP/HSTS...).
// Endurecer: usar `helmet()` y una Content-Security-Policy.

// ---- Usuarios demo (en memoria). Credenciales debiles a proposito. ----
const USERS = {
  admin: { password: 'Admin123!', role: 'admin', name: 'Ana Admin' },
  demo: { password: 'demo1234', role: 'user', name: 'Usuario Demo' },
};

// ---- Datos demo (en memoria) para poblar los modulos ----
const REPOS = [
  { name: 'core-api', lang: 'Node.js', branch: 'main', crit: 1, high: 3, med: 5, low: 2, ignored: 4, scan: 'hace 2 h', status: 'danger' },
  { name: 'web-frontend', lang: 'Vue, JS', branch: 'main', crit: 0, high: 2, med: 8, low: 6, ignored: 12, scan: 'hace 5 h', status: 'warn' },
  { name: 'payments-service', lang: 'Python', branch: 'main', crit: 2, high: 4, med: 3, low: 1, ignored: 7, scan: 'hace 17 h', status: 'danger' },
  { name: 'infra-terraform', lang: 'HCL', branch: 'prod', crit: 0, high: 0, med: 2, low: 3, ignored: 1, scan: 'hace 1 d', status: 'ok' },
  { name: 'mobile-app', lang: 'Kotlin', branch: 'dev', crit: 0, high: 1, med: 4, low: 5, ignored: 9, scan: 'hace 2 d', status: 'warn' },
];
const ALERTS = [
  { id: 'ALK-1042', title: 'Cabecera Content-Security-Policy ausente', sev: 'high', repo: 'web-frontend', status: 'open', date: '2026-09-29' },
  { id: 'ALK-1041', title: 'Cookie de sesion sin flag Secure', sev: 'high', repo: 'core-api', status: 'open', date: '2026-09-29' },
  { id: 'ALK-1038', title: 'Dependencia con CVE conocido (lodash)', sev: 'crit', repo: 'payments-service', status: 'open', date: '2026-09-28' },
  { id: 'ALK-1035', title: 'Divulgacion de version del servidor (X-Powered-By)', sev: 'med', repo: 'core-api', status: 'triage', date: '2026-09-28' },
  { id: 'ALK-1030', title: 'HSTS no habilitado', sev: 'med', repo: 'web-frontend', status: 'open', date: '2026-09-27' },
  { id: 'ALK-1022', title: 'Autocompletado activo en campo sensible', sev: 'low', repo: 'mobile-app', status: 'resolved', date: '2026-09-25' },
];
const TEAM = [
  { user: 'admin', name: 'Ana Admin', role: 'admin', email: 'ana@vulnlab.test', last: 'hace 2 min', state: 'ok' },
  { user: 'demo', name: 'Usuario Demo', role: 'user', email: 'demo@vulnlab.test', last: 'hace 3 h', state: 'ok' },
  { user: 'carlos', name: 'Carlos Ruiz', role: 'user', email: 'carlos@vulnlab.test', last: 'hace 1 d', state: 'warn' },
  { user: 'sofia', name: 'Sofia Lopez', role: 'auditor', email: 'sofia@vulnlab.test', last: 'hace 4 d', state: 'off' },
];

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ---- Helpers de badges (Bootstrap) ----
function sevPills(r) {
  const cell = (n, cls) => `<span class="badge sev ${n === 0 ? 'sev-zero' : cls} rounded-pill">${n}</span>`;
  return `<span class="d-inline-flex gap-1">${cell(r.crit, 'sev-crit')}${cell(r.high, 'sev-high')}${cell(r.med, 'sev-med')}${cell(r.low, 'sev-low')}</span>`;
}
function sevBadge(sev) {
  const map = { crit: ['sev-crit', 'Critica'], high: ['sev-high', 'Alta'], med: ['sev-med', 'Media'], low: ['sev-low', 'Baja'] };
  const [cls, label] = map[sev] || ['sev-zero', sev];
  return `<span class="badge sev ${cls} rounded-pill">${label}</span>`;
}
function statusBadge(st) {
  const map = {
    open: ['text-bg-danger', 'Abierta'], triage: ['text-bg-warning', 'En triage'], resolved: ['text-bg-success', 'Resuelta'],
    ok: ['text-bg-success', 'OK'], warn: ['text-bg-warning', 'Atencion'], danger: ['text-bg-danger', 'Critico'],
    off: ['text-bg-secondary', 'Inactivo'],
  };
  const [cls, label] = map[st] || ['text-bg-secondary', st];
  return `<span class="badge ${cls} rounded-pill">${label}</span>`;
}

// ---- Plantilla base (Bootstrap 5 + Bootswatch Brite en verde) ----
function page(title, body, opts = {}) {
  const { chrome = true } = opts;
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · VulnLab</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootswatch@5.3.7/dist/brite/bootstrap.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.11.3/font/bootstrap-icons.min.css">
<style>
  /* Ajuste del tema Brite a VERDE */
  :root {
    --bs-primary:#2f9e44; --bs-primary-rgb:47,158,68;
    --brand-dark:#1e7a34; --brand-darker:#155724; --brand-soft:#e9f7ec;
  }
  body { background:#f4f8f1; }
  a { color:var(--brand-dark); }
  .btn-primary { --bs-btn-bg:#2f9e44; --bs-btn-border-color:#2f9e44;
    --bs-btn-hover-bg:#278239; --bs-btn-hover-border-color:#278239;
    --bs-btn-active-bg:#1e7a34; --bs-btn-active-border-color:#1e7a34;
    --bs-btn-disabled-bg:#2f9e44; --bs-btn-disabled-border-color:#2f9e44;
    --bs-btn-color:#fff; --bs-btn-hover-color:#fff; --bs-btn-active-color:#fff; }
  .bg-primary { background-color:#2f9e44 !important; }
  .text-primary { color:#2f9e44 !important; }
  .navbar { box-shadow:0 1px 0 rgba(0,0,0,.06); }
  .navbar-brand { font-weight:800; letter-spacing:.4px; display:flex; align-items:center; gap:.5rem; }
  .navbar-brand .logo { width:26px; height:26px; border-radius:8px;
    background:linear-gradient(135deg,#a2e436,#1e7a34); display:inline-block; }
  .card { border:1px solid #e3ebd8; border-radius:1rem; box-shadow:0 8px 24px rgba(44,71,24,.05); }
  .kpi .display-6 { color:#1e7a34; font-weight:800; }
  .table thead th { text-transform:uppercase; font-size:.72rem; letter-spacing:.4px;
    color:#4a5d23; background:#eef4e5; }
  .table > :not(caption) > * > * { padding:.85rem 1rem; }
  .table-hover tbody tr:hover { background:#f0f6e6; }
  /* Pills de severidad tipo panel de seguridad */
  .badge.sev { min-width:30px; font-weight:700; border:1px solid transparent; }
  .sev-crit { background:#fdecec; color:#c0392b; border-color:#f7c9c4; }
  .sev-high { background:#fef1e0; color:#c9740b; border-color:#f6d8ac; }
  .sev-med  { background:#e8f1fc; color:#2f6fb0; border-color:#c8def5; }
  .sev-low  { background:#e9f7ec; color:#2e8b40; border-color:#c6e9cb; }
  .sev-zero { background:#f2f4ee; color:#9aa88a; border-color:#e3ebd8; }
  .tag { font-size:.68rem; text-transform:uppercase; letter-spacing:.3px; }
  .module-card { text-decoration:none; color:inherit; height:100%; transition:.15s; }
  .module-card:hover { transform:translateY(-3px); border-color:#2f9e44; }
  .module-card .bi { font-size:1.6rem; color:#2f9e44; }
  .login-wrap { min-height:100vh; display:flex; align-items:center; }
</style></head><body>
${chrome ? '' : ''}${body}
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
</body></html>`;
}

const MODULES = [
  ['/dashboard', 'Dashboard', 'bi-speedometer2'],
  ['/repos', 'Repositorios', 'bi-folder2-open'],
  ['/alerts', 'Alertas', 'bi-shield-exclamation'],
  ['/team', 'Usuarios', 'bi-people'],
  ['/profile', 'Perfil', 'bi-person-circle'],
];

function nav(user, active) {
  const links = MODULES.map(([href, label, icon]) =>
    `<li class="nav-item"><a class="nav-link${active === href ? ' active fw-semibold' : ''}" href="${href}">
      <i class="bi ${icon} me-1"></i>${label}</a></li>`).join('');
  return `
<nav class="navbar navbar-expand-lg bg-white sticky-top">
  <div class="container-xl">
    <a class="navbar-brand text-success" href="/dashboard"><span class="logo"></span>VulnLab</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navmenu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navmenu">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        ${links}
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
            <i class="bi bi-grid-3x3-gap me-1"></i>Mas modulos</a>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="/repos"><i class="bi bi-clipboard-data me-2"></i>Reportes</a></li>
            <li><a class="dropdown-item" href="/alerts"><i class="bi bi-bell me-2"></i>Notificaciones</a></li>
            <li><a class="dropdown-item" href="/team"><i class="bi bi-gear me-2"></i>Ajustes</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="/profile"><i class="bi bi-question-circle me-2"></i>Ayuda</a></li>
          </ul>
        </li>
      </ul>
      <span class="navbar-text me-3 d-none d-lg-inline"><i class="bi bi-person-circle me-1"></i>${esc(user.name)}</span>
      <form method="POST" action="/logout" class="d-flex m-0">
        <button class="btn btn-outline-success btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Salir</button>
      </form>
    </div>
  </div>
</nav>`;
}

function shell(user, active, inner) {
  const found = MODULES.find(([href]) => href === active);
  const title = found ? found[1] : 'Panel';
  return page(title, `${nav(user, active)}
<div class="container-xl py-4">
  <div class="alert alert-warning d-flex align-items-center py-2 mb-4" role="alert">
    <i class="bi bi-exclamation-triangle-fill me-2"></i>
    <small class="mb-0">Entorno de PRUEBAS deliberadamente vulnerable. No usar datos reales.</small>
  </div>
  ${inner}
</div>`);
}

// ---------- Rutas ----------
app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

app.get('/healthz', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.get('/login', (req, res) => {
  const err = req.query.error ? '<div class="alert alert-danger py-2"><i class="bi bi-x-circle me-1"></i>Credenciales invalidas.</div>' : '';
  res.send(page('Login', `
  <div class="login-wrap">
    <div class="container" style="max-width:440px">
      <div class="text-center mb-4">
        <span class="d-inline-block" style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#a2e436,#1e7a34)"></span>
        <h3 class="mt-3 fw-bold text-success">VulnLab</h3>
        <p class="text-muted small">Panel de seguridad · demo DAST</p>
      </div>
      <div class="card">
        <div class="card-body p-4">
          <h5 class="card-title mb-3">Iniciar sesion</h5>
          ${err}
          <form method="POST" action="/login">
            <div class="mb-3">
              <label class="form-label" for="username">Usuario</label>
              <input class="form-control" id="username" name="username" autocomplete="username" required>
            </div>
            <div class="mb-3">
              <label class="form-label" for="password">Contrase&ntilde;a</label>
              <input class="form-control" id="password" name="password" type="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right me-1"></i>Entrar</button>
          </form>
          <div class="alert alert-light border mt-3 mb-0 small">
            <b>Credenciales demo:</b> <code>admin / Admin123!</code> o <code>demo / demo1234</code>
          </div>
        </div>
      </div>
    </div>
  </div>`, { chrome: false }));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = USERS[username];
  if (u && u.password === password) {
    req.session.user = { username, role: u.role, name: u.name };
    return res.redirect('/dashboard');
  }
  return res.redirect('/login?error=1');
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  const totals = REPOS.reduce((a, r) => ({
    crit: a.crit + r.crit, high: a.high + r.high, med: a.med + r.med, low: a.low + r.low,
  }), { crit: 0, high: 0, med: 0, low: 0 });
  const kpi = (icon, val, label, cls) => `
    <div class="col-6 col-lg-3">
      <div class="card h-100 kpi"><div class="card-body">
        <div class="d-flex align-items-center justify-content-between">
          <span class="display-6">${val}</span><i class="bi ${icon} fs-3 text-${cls}"></i>
        </div><div class="text-muted small mt-1">${label}</div>
      </div></div>
    </div>`;
  const repoRows = REPOS.map(r => `
    <tr>
      <td><span class="fw-semibold text-success">${esc(r.name)}</span>
        <span class="badge text-bg-light tag ms-1">${esc(r.branch)}</span></td>
      <td class="text-muted small">${esc(r.lang)}</td>
      <td>${sevPills(r)}</td>
      <td class="text-center">${r.ignored}</td>
      <td>${statusBadge(r.status)}</td>
      <td class="text-muted small">${esc(r.scan)}</td>
    </tr>`).join('');
  res.send(shell(user, '/dashboard', `
  <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
    <div>
      <h4 class="mb-0">Hola, ${esc(user.name)} 👋</h4>
      <span class="text-muted small">Sesion iniciada con rol <span class="badge text-bg-success rounded-pill">${esc(user.role)}</span></span>
    </div>
    <a href="/repos" class="btn btn-primary btn-sm"><i class="bi bi-plus-lg me-1"></i>Nuevo escaneo</a>
  </div>

  <div class="row g-3 mb-2">
    ${kpi('bi-x-octagon', totals.crit, 'Criticas', 'danger')}
    ${kpi('bi-exclamation-triangle', totals.high, 'Altas', 'warning')}
    ${kpi('bi-info-circle', totals.med, 'Medias', 'primary')}
    ${kpi('bi-check2-circle', totals.low, 'Bajas', 'success')}
  </div>

  <h5 class="mb-3">Modulos</h5>
  <div class="row g-3 mb-4">
    ${MODULES.map(([href, label, icon]) => `
    <div class="col-6 col-md-4 col-lg">
      <a href="${href}" class="card module-card"><div class="card-body text-center">
        <i class="bi ${icon}"></i>
        <div class="fw-semibold mt-2 text-success">${label}</div>
      </div></a>
    </div>`).join('')}
  </div>

  <div class="card">
    <div class="card-header bg-white d-flex align-items-center justify-content-between">
      <span class="fw-semibold"><i class="bi bi-folder2-open me-2 text-success"></i>Repositorios monitoreados</span>
      <span class="text-muted small">crit / alta / media / baja</span>
    </div>
    <div class="table-responsive">
      <table class="table table-hover align-middle mb-0">
        <thead><tr><th>Repositorio</th><th>Lenguaje</th><th>Hallazgos</th>
          <th class="text-center">Ignorados</th><th>Estado</th><th>Ultimo escaneo</th></tr></thead>
        <tbody>${repoRows}</tbody>
      </table>
    </div>
  </div>`));
});

app.get('/repos', requireAuth, (req, res) => {
  const user = req.session.user;
  const rows = REPOS.map(r => `
    <tr>
      <td><span class="fw-semibold text-success">${esc(r.name)}</span>
        <span class="badge text-bg-light tag ms-1">${esc(r.branch)}</span></td>
      <td class="text-muted small">${esc(r.lang)}</td>
      <td>${sevBadge('crit')} <span class="ms-1">${r.crit}</span></td>
      <td>${sevPills(r)}</td>
      <td class="text-center">${r.ignored}</td>
      <td>${statusBadge(r.status)}</td>
      <td class="text-muted small">${esc(r.scan)}</td>
    </tr>`).join('');
  res.send(shell(user, '/repos', `
  <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
    <h4 class="mb-0"><i class="bi bi-folder2-open me-2 text-success"></i>Repositorios</h4>
    <div class="input-group input-group-sm" style="max-width:280px">
      <span class="input-group-text bg-white"><i class="bi bi-search"></i></span>
      <input class="form-control" placeholder="Buscar repositorio...">
    </div>
  </div>
  <div class="card"><div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead><tr><th>Repositorio</th><th>Lenguaje</th><th>Severidad top</th>
        <th>Hallazgos</th><th class="text-center">Ignorados</th><th>Estado</th><th>Ultimo escaneo</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div></div>`));
});

app.get('/alerts', requireAuth, (req, res) => {
  const user = req.session.user;
  const rows = ALERTS.map(a => `
    <tr>
      <td class="text-muted small">${esc(a.id)}</td>
      <td class="fw-semibold">${esc(a.title)}</td>
      <td>${sevBadge(a.sev)}</td>
      <td><span class="badge text-bg-light tag">${esc(a.repo)}</span></td>
      <td>${statusBadge(a.status)}</td>
      <td class="text-muted small">${esc(a.date)}</td>
    </tr>`).join('');
  res.send(shell(user, '/alerts', `
  <h4 class="mb-3"><i class="bi bi-shield-exclamation me-2 text-success"></i>Alertas de seguridad</h4>
  <div class="card"><div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead><tr><th>ID</th><th>Hallazgo</th><th>Severidad</th><th>Repositorio</th><th>Estado</th><th>Fecha</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div></div>`));
});

app.get('/team', requireAuth, (req, res) => {
  const user = req.session.user;
  const rows = TEAM.map(t => `
    <tr>
      <td>
        <div class="d-flex align-items-center gap-2">
          <span class="rounded-circle d-inline-flex align-items-center justify-content-center text-white fw-bold"
            style="width:34px;height:34px;background:linear-gradient(135deg,#a2e436,#1e7a34)">${esc(t.name[0])}</span>
          <div><div class="fw-semibold">${esc(t.name)}</div><div class="text-muted small">@${esc(t.user)}</div></div>
        </div>
      </td>
      <td><span class="badge text-bg-secondary rounded-pill">${esc(t.role)}</span></td>
      <td class="text-muted small">${esc(t.email)}</td>
      <td class="text-muted small">${esc(t.last)}</td>
      <td>${statusBadge(t.state)}</td>
    </tr>`).join('');
  res.send(shell(user, '/team', `
  <h4 class="mb-3"><i class="bi bi-people me-2 text-success"></i>Usuarios del equipo</h4>
  <div class="card"><div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead><tr><th>Usuario</th><th>Rol</th><th>Correo</th><th>Ultima actividad</th><th>Estado</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div></div>`));
});

app.get('/profile', requireAuth, (req, res) => {
  const user = req.session.user;
  res.send(shell(user, '/profile', `
  <h4 class="mb-3"><i class="bi bi-person-circle me-2 text-success"></i>Mi perfil</h4>
  <div class="row g-3">
    <div class="col-lg-4">
      <div class="card"><div class="card-body text-center">
        <span class="rounded-circle d-inline-flex align-items-center justify-content-center text-white fw-bold mb-2"
          style="width:72px;height:72px;font-size:1.8rem;background:linear-gradient(135deg,#a2e436,#1e7a34)">${esc(user.name[0])}</span>
        <h5 class="mb-0">${esc(user.name)}</h5>
        <div class="text-muted small">@${esc(user.username)}</div>
        <span class="badge text-bg-success rounded-pill mt-2">${esc(user.role)}</span>
      </div></div>
    </div>
    <div class="col-lg-8">
      <div class="card"><div class="card-body">
        <h6 class="text-muted text-uppercase small mb-3">Datos de la cuenta</h6>
        <table class="table mb-0">
          <tbody>
            <tr><th style="width:160px" class="text-muted">Usuario</th><td>${esc(user.username)}</td></tr>
            <tr><th class="text-muted">Nombre</th><td>${esc(user.name)}</td></tr>
            <tr><th class="text-muted">Rol</th><td><span class="badge text-bg-success rounded-pill">${esc(user.role)}</span></td></tr>
            <tr><th class="text-muted">Estado</th><td>${statusBadge('ok')}</td></tr>
          </tbody>
        </table>
      </div></div>
    </div>
  </div>`));
});

app.listen(PORT, () => console.log(`VulnLab escuchando en puerto ${PORT}`));
