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
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0; }
  header { background:#1e293b; padding:14px 20px; display:flex; gap:16px; align-items:center; }
  header a { color:#93c5fd; text-decoration:none; font-size:14px; }
  header .brand { font-weight:700; color:#fff; margin-right:auto; }
  main { max-width:820px; margin:32px auto; padding:0 20px; }
  .card { background:#1e293b; border:1px solid #334155; border-radius:12px; padding:24px; margin-bottom:20px; }
  h1 { font-size:22px; margin-top:0; }
  label { display:block; font-size:13px; margin:12px 0 4px; }
  input { width:100%; padding:10px; border-radius:8px; border:1px solid #475569; background:#0f172a; color:#e2e8f0; }
  button { margin-top:18px; padding:10px 18px; border:0; border-radius:8px; background:#2563eb; color:#fff; font-weight:600; cursor:pointer; }
  .banner { background:#7c2d12; border:1px solid #ea580c; color:#fed7aa; padding:10px 14px; border-radius:8px; font-size:13px; margin-bottom:20px; }
  .kpi { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
  .kpi div { background:#0f172a; border:1px solid #334155; border-radius:10px; padding:16px; }
  .kpi b { font-size:24px; display:block; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  td, th { text-align:left; padding:8px; border-bottom:1px solid #334155; }
  .err { color:#fca5a5; font-size:14px; }
  code { background:#0f172a; padding:2px 6px; border-radius:4px; }
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
      <p style="font-size:12px;color:#94a3b8;margin-top:16px">
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
    <form method="POST" action="/logout" style="margin:0"><button style="margin:0;padding:6px 12px;background:#334155">Salir (${esc(user.username)})</button></form>
  </header>`;
}

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  res.send(page('Dashboard', `
  ${nav(user)}
  <main>
    <div class="card">
      <h1>Hola, ${esc(user.name)} 👋</h1>
      <p>Sesion iniciada correctamente como <b>${esc(user.role)}</b>. Esta pagina solo es accesible autenticado.</p>
      <div class="kpi">
        <div><b>128</b>Usuarios</div>
        <div><b>$ 42.9k</b>Ingresos</div>
        <div><b>7</b>Alertas</div>
      </div>
    </div>
    <div class="card">
      <h1>Actividad reciente</h1>
      <table>
        <tr><th>Fecha</th><th>Evento</th><th>Origen</th></tr>
        <tr><td>2026-09-29</td><td>Inicio de sesion</td><td>${esc(user.username)}</td></tr>
        <tr><td>2026-09-28</td><td>Actualizacion de perfil</td><td>demo</td></tr>
        <tr><td>2026-09-27</td><td>Exportacion de reporte</td><td>admin</td></tr>
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
      <table>
        <tr><th>Usuario</th><td>${esc(user.username)}</td></tr>
        <tr><th>Nombre</th><td>${esc(user.name)}</td></tr>
        <tr><th>Rol</th><td>${esc(user.role)}</td></tr>
      </table>
    </div>
  </main>`));
});

app.listen(PORT, () => console.log(`VulnLab escuchando en puerto ${PORT}`));
