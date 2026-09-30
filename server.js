/*
 * VulnLab DAST demo
 * -----------------
 * App minima con formulario de login y un dashboard protegido por sesion.
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

const PORT = process.env.PORT || 3000;
const app = express();

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

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function page(title, body) {
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · VulnLab</title>
<style>
  :root {
    --green-500:#7cb342; --green-600:#5f9a2e; --green-700:#4a7c26;
    --green-800:#3a5f1e; --green-900:#2c4718;
    --lime:#9ccc3c; --olive:#4a5d23;
    --bg:#f4f7f0; --surface:#ffffff; --ink:#26331a; --muted:#6b7a5a;
    --line:#e3ebd8; --line-strong:#cddcbb;
    --danger:#b45309; --danger-bg:#fef6e7; --danger-line:#f5d9a8;
    --shadow:0 1px 2px rgba(44,71,24,.06), 0 8px 24px rgba(44,71,24,.06);
  }
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin:0;
    background:var(--bg); color:var(--ink); line-height:1.5; }
  header { background:var(--surface); border-bottom:1px solid var(--line);
    padding:0 24px; height:60px; display:flex; gap:22px; align-items:center;
    box-shadow:var(--shadow); position:sticky; top:0; z-index:5; }
  header .brand { font-weight:800; letter-spacing:.5px; margin-right:auto;
    display:flex; align-items:center; gap:10px; font-size:18px; color:var(--green-800); }
  header .brand::before { content:""; width:22px; height:22px; border-radius:6px;
    background:linear-gradient(135deg,var(--lime),var(--green-700)); display:inline-block; }
  header a { color:var(--olive); text-decoration:none; font-size:14px; font-weight:600;
    padding:6px 4px; border-bottom:2px solid transparent; transition:.15s; }
  header a:hover { color:var(--green-700); border-bottom-color:var(--green-500); }
  main { max-width:900px; margin:34px auto; padding:0 24px; }
  .card { background:var(--surface); border:1px solid var(--line); border-radius:14px;
    padding:26px; margin-bottom:22px; box-shadow:var(--shadow); }
  h1 { font-size:22px; margin:0 0 6px; color:var(--green-900); }
  p { color:var(--muted); }
  label { display:block; font-size:13px; font-weight:600; margin:14px 0 6px; color:var(--olive); }
  input { width:100%; padding:11px 12px; border-radius:9px; border:1px solid var(--line-strong);
    background:#fbfdf8; color:var(--ink); font-size:15px; transition:.15s; }
  input:focus { outline:none; border-color:var(--green-500);
    box-shadow:0 0 0 3px rgba(124,179,66,.18); background:#fff; }
  button { margin-top:20px; padding:11px 22px; border:0; border-radius:9px;
    background:linear-gradient(135deg,var(--green-500),var(--green-700)); color:#fff;
    font-weight:700; font-size:14px; cursor:pointer; box-shadow:0 2px 8px rgba(74,124,38,.28); transition:.15s; }
  button:hover { filter:brightness(1.06); transform:translateY(-1px); }
  .logout-btn { margin:0; padding:7px 14px; font-size:13px;
    background:#eef4e5; color:var(--green-800); box-shadow:none; border:1px solid var(--line-strong); }
  .logout-btn:hover { background:#e3edd4; transform:none; }
  .banner { background:var(--danger-bg); border:1px solid var(--danger-line); color:var(--danger);
    padding:11px 16px; border-radius:10px; font-size:13px; font-weight:500; margin-bottom:22px;
    display:flex; align-items:center; gap:8px; }
  .banner::before { content:"\\26A0"; font-size:15px; }
  .kpi { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-top:18px; }
  .kpi div { background:linear-gradient(160deg,#fbfdf8,#f0f6e6); border:1px solid var(--line);
    border-radius:12px; padding:18px 20px; position:relative; overflow:hidden; }
  .kpi div::after { content:""; position:absolute; left:0; top:0; bottom:0; width:4px;
    background:linear-gradient(var(--lime),var(--green-700)); }
  .kpi b { font-size:26px; display:block; color:var(--green-800); font-weight:800; }
  .kpi span { font-size:13px; color:var(--muted); }
  table { width:100%; border-collapse:separate; border-spacing:0; font-size:14px;
    border:1px solid var(--line); border-radius:12px; overflow:hidden; }
  thead th { background:#eef4e5; color:var(--green-800); font-weight:700; font-size:12px;
    text-transform:uppercase; letter-spacing:.4px; }
  th, td { text-align:left; padding:12px 16px; }
  tbody tr { border-top:1px solid var(--line); }
  tbody tr:nth-child(even) { background:#fafcf6; }
  tbody tr:hover { background:#f0f6e6; }
  .profile-table th { width:140px; color:var(--olive); background:#fafcf6; }
  .badge { display:inline-block; padding:3px 11px; border-radius:999px; font-size:12px;
    font-weight:700; background:#e3edd4; color:var(--green-800); border:1px solid var(--line-strong); }
  .err { color:var(--danger); font-size:14px; font-weight:600; margin:4px 0 0; }
  code { background:#eef4e5; color:var(--green-800); padding:2px 7px; border-radius:5px;
    font-size:12px; font-weight:600; }
  .hint { font-size:12px; color:var(--muted); margin-top:16px; }
</style></head><body>
${body}
</body></html>`;
}

// ---- Rutas ----
app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

// Endpoint de salud para Render / DAST
app.get('/healthz', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.get('/login', (req, res) => {
  const err = req.query.error ? '<p class="err">Credenciales invalidas.</p>' : '';
  res.send(page('Login', `
  <main>
    <div class="banner">Entorno de PRUEBAS deliberadamente vulnerable. No usar datos reales.</div>
    <div class="card">
      <h1>Iniciar sesion</h1>
      ${err}
      <form method="POST" action="/login">
        <label for="username">Usuario</label>
        <input id="username" name="username" autocomplete="username" required>
        <label for="password">Contrase&ntilde;a</label>
        <input id="password" name="password" type="password" required>
        <button type="submit">Entrar</button>
      </form>
      <p class="hint">
        Credenciales demo: <code>admin / Admin123!</code> o <code>demo / demo1234</code>
      </p>
    </div>
  </main>`));
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

function nav(user) {
  return `<header>
    <span class="brand">VulnLab</span>
    <a href="/dashboard">Dashboard</a>
    <a href="/profile">Perfil</a>
    <form method="POST" action="/logout" style="margin:0"><button class="logout-btn">Salir (${esc(user.username)})</button></form>
  </header>`;
}

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  res.send(page('Dashboard', `
  ${nav(user)}
  <main>
    <div class="card">
      <h1>Hola, ${esc(user.name)} 👋</h1>
      <p>Sesion iniciada correctamente con rol <span class="badge">${esc(user.role)}</span>. Esta pagina solo es accesible autenticado.</p>
      <div class="kpi">
        <div><b>128</b><span>Usuarios</span></div>
        <div><b>$ 42.9k</b><span>Ingresos</span></div>
        <div><b>7</b><span>Alertas</span></div>
      </div>
    </div>
    <div class="card">
      <h1>Actividad reciente</h1>
      <table>
        <thead><tr><th>Fecha</th><th>Evento</th><th>Origen</th></tr></thead>
        <tbody>
          <tr><td>2026-09-29</td><td>Inicio de sesion</td><td>${esc(user.username)}</td></tr>
          <tr><td>2026-09-28</td><td>Actualizacion de perfil</td><td>demo</td></tr>
          <tr><td>2026-09-27</td><td>Exportacion de reporte</td><td>admin</td></tr>
        </tbody>
      </table>
    </div>
  </main>`));
});

app.get('/profile', requireAuth, (req, res) => {
  const user = req.session.user;
  res.send(page('Perfil', `
  ${nav(user)}
  <main>
    <div class="card">
      <h1>Mi perfil</h1>
      <table class="profile-table">
        <tbody>
          <tr><th>Usuario</th><td>${esc(user.username)}</td></tr>
          <tr><th>Nombre</th><td>${esc(user.name)}</td></tr>
          <tr><th>Rol</th><td><span class="badge">${esc(user.role)}</span></td></tr>
        </tbody>
      </table>
    </div>
  </main>`));
});

app.listen(PORT, () => console.log(`VulnLab escuchando en puerto ${PORT}`));
