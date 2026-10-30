# Aljibe

Un panel que junta varias cuentas de Google Drive en una sola. Subís un archivo y Aljibe elige en qué cuenta guardarlo; si no entra entero en ninguna, lo parte y reparte los trozos entre varias. Al descargar los vuelve a unir en streaming.

Pensado para un **grupo chico de gente conocida**: cada persona entra **solo con su cuenta de Google** (sin contraseñas propias) y conecta *sus propias* cuentas de Drive. El administrador reparte invitaciones.

**Stack:** un solo `public/index.html` + una Pages Function (`functions/api/[[path]].js`) + D1 (SQLite) en Cloudflare. Sin servidor propio.

## Qué hace

- Archivos grandes **repartidos en varias cuentas**, con descarga transparente y soporte de `Range` (sirve para ver videos y retomar descargas).
- Subida **reanudable** por bloques de 8 MB, con reintentos si se corta la conexión.
- Permiso mínimo de Google (`drive.file`): Aljibe solo ve lo que ella misma creó, no el resto de tu Drive.
- **Reindexar**: cada parte guarda en Drive los datos para reconstruirla. Si se pierde la base D1, un botón recupera archivos y carpetas virtuales leyendo los Drives (con el nombre y la carpeta que tenían **al subirse**; los cambios hechos después con Renombrar/Mover solo viven en D1).
- **Varios usuarios con invitación.** Datos completamente separados: nadie ve ni toca los archivos, carpetas o cuentas de otro. Una cuenta de Google solo puede estar conectada a un usuario.
- **Compartir por enlace:** cada archivo (también los partidos en varias cuentas) puede tener un enlace público con vencimiento (1 a 90 días) que se puede desactivar. Hay un solo enlace por archivo: crear otro anula el anterior.
- **Equilibrar:** reparte lo ya guardado entre las cuentas para que queden parejas (mueve partes de la cuenta con menos espacio libre a la que más tiene). Copia por bloques de 8 MB, es reanudable y solo borra la original cuando la copia está completa.
- **Todo bajo Google:** se entra con «Continuar con Google». La cuenta con la que entrás queda conectada como primer almacenamiento; después sumás más con «+ Conectar cuenta». No hay contraseñas de Aljibe que recordar ni que robar.
- Panel de administración: crear invitaciones (de un solo uso, vencen a los 7 días), ver usuarios y su uso, quitar usuarios.
- El inicio de sesión va atado al navegador (cookie temporal + `state` firmado) y la sesión dura 30 días.
- Los tokens de Google se guardan **cifrados** (AES-GCM).

## Estructura

```
aljibe/
├─ public/index.html            ← toda la interfaz
├─ functions/api/[[path]].js    ← toda la API
├─ schema.sql                   ← tablas de D1
└─ README.md
```

## Puesta en marcha

### 1. Subir el proyecto a GitHub
Subí estos archivos a un repositorio, **en la raíz** (que queden `public/`, `functions/api/[[path]].js`, `schema.sql`). Cuidá que el archivo de la API conserve los corchetes en el nombre.

### 2. Crear la base D1
Cloudflare → **Workers & Pages → D1 → Create database** (nombre: `aljibe`).
Abrí la pestaña **Console**, pegá el contenido de `schema.sql` y ejecutalo. Si no acepta todo junto, pegá las sentencias de a una (cada `CREATE TABLE` / `CREATE INDEX` es una).
Comprobá con `SELECT name FROM sqlite_master WHERE type='table';`: tienen que aparecer `users`, `invites`, `accounts`, `files`, `parts`, `folders`, `shares` y `moves`.

**Si venís de una versión anterior (v0.2/v0.3):** alcanza con crear las dos tablas nuevas. Pegá estas dos líneas en la consola de D1 (de a una si hace falta):
```sql
CREATE TABLE IF NOT EXISTS shares ( token TEXT PRIMARY KEY, file_id TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL );
CREATE TABLE IF NOT EXISTS moves ( file_id TEXT NOT NULL, idx INTEGER NOT NULL, to_account INTEGER NOT NULL, session_url TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (file_id, idx) );
```

### 3. Crear el proyecto en Pages
Cloudflare → **Workers & Pages → Create → Pages → Connect to Git** → elegí el repo.
- Framework preset: *None*
- Build command: *(vacío)*
- Build output directory: `public`

Al terminar te da una URL del estilo `https://aljibe-xxx.pages.dev`. Anotala.

### 4. Credenciales de Google
En [Google Cloud Console](https://console.cloud.google.com/):
1. Creá un proyecto nuevo.
2. **APIs y servicios → Biblioteca** → habilitá **Google Drive API**.
3. **Pantalla de consentimiento de OAuth** → tipo *Externo*. Completá nombre de la app y email de contacto. En **Permisos** agregá `.../auth/drive.file`.
4. **Credenciales → Crear credenciales → ID de cliente de OAuth** → tipo *Aplicación web*.
   En **URI de redireccionamiento autorizados** poné exactamente:
   `https://TU-URL.pages.dev/api/google/callback`
5. Copiá el *Client ID* y el *Client secret*.
6. **Importante:** en la pantalla de consentimiento pasá el estado de *Testing* a ***En producción*** ("Publicar app"). Si queda en *Testing*, Google vence los tokens a los 7 días y solo deja entrar a los usuarios de prueba que cargues a mano (hasta 100).

Sobre la verificación de Google: según su documentación, `drive.file` es un permiso **no sensible**, que solo requiere la verificación básica de la app. Para un grupo chico podés dejar la app sin verificar; es posible que cada persona vea el aviso "Google no verificó esta app" al conectar su cuenta (*Avanzado → Ir a Aljibe*). Si más adelante querés quitar ese aviso, hay que hacer la verificación básica (pide página de inicio, política de privacidad y dominio propio).

Si usás un dominio propio, agregá también su URI de redirección.

### 5. Variables y base en Pages
En tu proyecto de Pages → **Settings**:

**Bindings → Add → D1 database**
- Variable name: `DB` → elegí la base `aljibe` (en Production y en Preview).

**Variables and Secrets** (tipo *Secret*):

| Nombre | Valor |
|---|---|
| `ADMIN_CODE` | un código largo y aleatorio (20+ caracteres). Sirve **una sola vez**, para crear al administrador |
| `SESSION_SECRET` | una cadena larga y aleatoria (mínimo 16 caracteres, mejor 40+) |
| `GOOGLE_CLIENT_ID` | el Client ID |
| `GOOGLE_CLIENT_SECRET` | el Client secret |

Después hacé un **nuevo deploy** (Deployments → Retry deployment) para que tome las variables.

> ⚠️ No cambies `SESSION_SECRET` después de que haya gente conectada: con él se cifran los tokens de Google y habría que reconectar todas las cuentas.

### 6. Crear al administrador y empezar
1. Entrá a `https://TU-URL.pages.dev/?invite=TU_ADMIN_CODE` (con tu `ADMIN_CODE` como código) y tocá **Continuar con Google**. La cuenta de Google con la que entres queda como administradora y conectada como primer almacenamiento. Solo funciona mientras no haya administrador.
2. Sumá más cuentas tuyas con **+ Conectar cuenta**.
3. Para sumar gente: en **Usuarios e invitaciones** tocá **+ Crear invitación** y mandá el enlace. La persona lo abre, toca *Continuar con Google* y listo. Cada vez que vuelva, entra con el mismo botón (sin invitación).

## Cómo funciona por dentro

- En cada Drive se crea una carpeta `Aljibe`. Los archivos van ahí (los que se parten se llaman `nombre.part001`, `.part002`…).
- Las carpetas que ves en la app son **virtuales** (viven en D1), no existen en Drive.
- Para subir, el navegador manda bloques de 8 MB a `/api/upload/block`; la función los reenvía a una sesión de subida reanudable de Google. Los archivos nunca se guardan en Cloudflare.
- Para elegir cuenta usa la que más espacio libre tenga (dejando 16 MB de margen), **solo entre las cuentas del propio usuario**. Si el archivo no entra en una sola, lo reparte de mayor a menor espacio libre.

## Privacidad: qué puede ver quien administra

Si invitás gente, conviene que lo sepan:
- El panel de administración muestra emails y totales (cuentas, cantidad de archivos, tamaño). No muestra nombres ni contenido.
- Pero quien administra el despliegue (acceso a Cloudflare y a sus secretos) técnicamente puede leer la base —que incluye nombres de archivos— y descifrar los tokens de Google, que dan acceso a la carpeta `Aljibe` de cada persona (solo a lo que Aljibe creó).
- El contenido de los archivos **no está cifrado** en Drive.

Quitar a un usuario revoca el acceso de Aljibe a sus cuentas de Google y borra sus datos de la base. **Sus archivos siguen en sus propios Drives** (carpeta `Aljibe`).

## Recuperar el acceso de administrador

No hay contraseñas que olvidar: el administrador entra con su cuenta de Google. Si perdiera el acceso a esa cuenta de Google, en la consola de D1 se puede cambiar el email del administrador por otra cuenta de Google tuya (reemplazá los emails):

```sql
UPDATE users SET email='nueva@gmail.com' WHERE is_admin=1;
```
La próxima vez que entres con `nueva@gmail.com` serás el administrador y se conectará esa cuenta. Si querés empezar de cero como administrador: `DELETE FROM users WHERE is_admin=1;` y volvé a usar el enlace con `ADMIN_CODE` (los archivos de ese usuario dejan de estar asociados).

## Límites a tener presentes

- **Enlaces para compartir:** la descarga pasa por Cloudflare y cuenta para el límite diario de peticiones del plan gratis (cada bloque de descarga es una petición). Sirve para compartir con pocas personas, no para repartir a mucha gente. Quien tenga el enlace puede descargar; no se puede restringir por persona.
- **Equilibrar** es lento con archivos grandes (todo pasa por Cloudflare, bloque a bloque) y hay que dejar la pestaña abierta; si se corta, se vuelve a tocar el botón y retoma. No equilibra el espacio que usan Gmail o Fotos, solo lo que guardó Aljibe.

- **Plan gratis de Cloudflare:** según su documentación, cada petición tiene **10 ms de CPU**, hay un tope de **100.000 peticiones por día** y **50 subpeticiones** por invocación. Cada bloque de 8 MB es una petición: subir 100 GB son unas 12.800.
- **Sin hash de contraseñas:** al no haber contraseñas propias, desaparece lo más pesado en CPU.
- **Cuota de Drive:** los 15 GB de cada cuenta se comparten con Gmail y Fotos. Aljibe lee la cuota real, así que ya lo descuenta.
- **Descarga/subida pasan por Cloudflare**, así que dependen de su ancho de banda y no son tan rápidas como hablar directo con Google.
- **Sin papelera:** borrar un archivo lo elimina de Drive de forma definitiva.
- **Cuentas inactivas:** Google puede borrar cuentas sin uso por 2 años.
- Las reglas de Google sobre crear cuentas solo para juntar espacio no son claras; usalo con cuentas propias.

## Ideas para la próxima versión
Cifrado en el cliente, redundancia (copia en dos cuentas), sincronización automática con un cron, subida de carpetas completas, cuotas por usuario y enlaces con contraseña.
