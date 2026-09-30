# VulnLab · App de prueba para DAST autenticado (Aikido Security)

App mínima con **formulario de login** y un **dashboard protegido por sesión**, pensada
para practicar un escaneo **DAST autenticado** con Aikido Security. Incluye, a propósito,
varias **debilidades de configuración** suaves para que el escáner tenga hallazgos.

> ⚠️ **Solo entornos de prueba autorizados.** No pongas datos reales, no la dejes
> publicada más tiempo del necesario y bórrala cuando termines.

## Credenciales demo

| Usuario | Contraseña   | Rol   |
|---------|--------------|-------|
| `admin` | `Admin123!`  | admin |
| `demo`  | `demo1234`   | user  |

## Rutas

- `GET /login` — formulario de login
- `POST /login` — autentica y crea la sesión
- `GET /dashboard` — panel protegido (redirige a `/login` sin sesión)
- `GET /profile` — perfil protegido
- `POST /logout` — cierra sesión
- `GET /healthz` — health check (para Render y para verificar disponibilidad)

## Debilidades incluidas (marcadas con `WEAK:` en `server.js`)

- Sin cabeceras de seguridad (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
- Cabecera `X-Powered-By` expuesta (revela framework).
- Cookie de sesión **sin** `HttpOnly`, `Secure` ni `SameSite`.
- Credenciales demo débiles y públicas.

---

## 1) Herramientas donde registrarte

| Para qué | Herramienta | Notas |
|---|---|---|
| Escáner DAST | **Aikido Security** — https://app.aikido.dev | Regístrate; la función DAST se usa en trial/plan de pago. |
| Dominio público | **Render.com** — https://render.com | Plan free, HTTPS automático, sin tarjeta. |
| Código | **GitHub** | Para conectar Render a despliegue automático. |

## 2) Probar en local

```bash
npm install
npm start
# abre http://localhost:3000/login
```

## 3) Subir a GitHub

```bash
git init
git add .
git commit -m "VulnLab: app de prueba para DAST autenticado"
git branch -M main
git remote add origin https://github.com/<tu-usuario>/vulnlab-dast.git
git push -u origin main
```

## 4) Desplegar en Render

Opción A — **Blueprint (recomendada)**: el repo ya trae `render.yaml`.
1. En Render → **New** → **Blueprint** → conecta tu repo.
2. Render lee `render.yaml`, crea el servicio web y genera `SESSION_SECRET`.
3. Espera al deploy. Tu URL pública será `https://vulnlab-dast.onrender.com` (o similar).

Opción B — **Web Service manual**:
1. **New** → **Web Service** → conecta el repo.
2. Runtime: Node. Build: `npm install`. Start: `npm start`. Health check: `/healthz`.

Verifica: abre `https://<tu-app>.onrender.com/login` y entra con `admin / Admin123!`.

## 5) Escaneo DAST autenticado en Aikido

1. En Aikido → módulo **DAST / Surface Monitoring** → añade el dominio
   `https://<tu-app>.onrender.com`.
2. Configura la **autenticación** para que el escáner llegue al dashboard:
   - **Login por formulario / grabación (agente):** indica la URL `.../login`,
     el campo usuario (`#username`), el campo contraseña (`#password`) y el botón
     de envío; usuario `admin`, contraseña `Admin123!`.
   - Aikido navegará el login, obtendrá la cookie de sesión y escaneará las rutas
     autenticadas (`/dashboard`, `/profile`).
3. Lanza el escaneo y revisa los hallazgos (cabeceras faltantes, cookie insegura,
   divulgación de versión, etc.).

## 6) Al terminar

- Suspende o borra el servicio en Render.
- Si quieres endurecer la app, sigue los comentarios `WEAK:` en `server.js`
  (añade `helmet`, `app.disable('x-powered-by')` y flags seguras de cookie).
