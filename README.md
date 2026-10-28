# Aljibe

Un panel personal que junta varias cuentas de Google Drive en una sola. Subís un archivo y Aljibe elige en qué cuenta guardarlo; si no entra entero en ninguna, lo parte y reparte los trozos entre varias. Al descargar los vuelve a unir en streaming.

**Stack:** un solo `public/index.html` + una Pages Function (`functions/api/[[path]].js`) + D1 (SQLite) en Cloudflare. Sin servidor propio.

## Qué hace distinto de 9drive

- Archivos grandes **repartidos en varias cuentas** (chunking), con descarga transparente y soporte de `Range` (sirve para ver videos y retomar descargas).
- Subida **reanudable** por bloques de 8 MB: si se corta, reintenta desde donde quedó.
- Permiso mínimo de Google (`drive.file`): Aljibe solo ve lo que ella misma creó, no el resto de tu Drive.
- **Reindexar**: cada parte guarda en Drive (campo `description`) los datos para reconstruirla. Si perdés la base D1, un botón recupera archivos, carpetas virtuales y nombres leyendo los Drives (con el nombre y la carpeta que tenían **al subirse**: los cambios hechos después con Renombrar/Mover solo viven en D1).
- Los refresh tokens se guardan **cifrados** (AES-GCM).
- Sin registro de usuarios: una sola contraseña, pensada para uso personal.

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
Creá un repositorio nuevo (puede ser privado) y subí estos archivos tal cual, respetando las carpetas.

### 2. Crear la base D1
Cloudflare → **Workers & Pages → D1 → Create database** (nombre: `aljibe`).
Abrí la pestaña **Console**, pegá el contenido de `schema.sql` y ejecutalo.

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
3. **Pantalla de consentimiento de OAuth** → tipo *Externo*. Completá nombre y email. En **Permisos** agregá `.../auth/drive.file`.
4. **Credenciales → Crear credenciales → ID de cliente de OAuth** → tipo *Aplicación web*.
   En **URI de redireccionamiento autorizados** poné exactamente:
   `https://TU-URL.pages.dev/api/google/callback`
5. Copiá el *Client ID* y el *Client secret*.
6. **Importante:** en la pantalla de consentimiento pasá el estado de *Testing* a ***En producción*** (botón "Publicar app"). Si queda en Testing, Google vence los tokens a los 7 días y tenés que reconectar todo. Al ser solo para vos, no hace falta verificación: al conectar cada cuenta aparece el aviso "Google no verificó esta app" → *Avanzado → Ir a Aljibe*.

Si usás un dominio propio, agregá también su URI de redirección.

### 5. Variables y base en Pages
En tu proyecto de Pages → **Settings**:

**Bindings → Add → D1 database**
- Variable name: `DB` → elegí la base `aljibe` (en Production y en Preview).

**Variables and Secrets** (tipo *Secret*):

| Nombre | Valor |
|---|---|
| `APP_PASSWORD` | la contraseña con la que vas a entrar |
| `SESSION_SECRET` | una cadena larga y aleatoria (mínimo 16 caracteres, mejor 40+) |
| `GOOGLE_CLIENT_ID` | el Client ID |
| `GOOGLE_CLIENT_SECRET` | el Client secret |

Después hacé un **nuevo deploy** (Deployments → Retry deployment) para que tome las variables.

> ⚠️ No cambies `SESSION_SECRET` después de conectar cuentas: con él se cifran los tokens y habría que reconectarlas.

### 6. Usarlo
Entrá a tu URL, ingresá la contraseña y tocá **+ Conectar cuenta** por cada cuenta de Google. Listo.

## Cómo funciona por dentro

- En cada Drive se crea una carpeta `Aljibe`. Los archivos van ahí (los que se parten se llaman `nombre.part001`, `.part002`…).
- Las carpetas que ves en la app son **virtuales** (viven en D1), no existen en Drive.
- Para subir, el navegador manda bloques de 8 MB a `/api/upload/block`; la función los reenvía a una sesión de subida reanudable de Google. Los archivos nunca se guardan en Cloudflare.
- Para elegir cuenta: usa la que más espacio libre tenga (dejando 16 MB de margen). Si el archivo no entra en una sola, lo reparte de mayor a menor espacio libre.

## Límites a tener presentes

- **Plan gratis de Cloudflare:** las funciones tienen tope de CPU y de subpeticiones por invocación. Con bloques de 8 MB y archivos repartidos en pocas cuentas está dentro de lo normal; si ves errores 1102 o 1015, avisame.
- **Cuota de Drive:** los 15 GB de cada cuenta se comparten con Gmail y Fotos. Aljibe lee la cuota real, así que ya lo descuenta.
- **Descarga/subida pasan por Cloudflare**, así que dependen de su ancho de banda y no son tan rápidas como hablar directo con Google.
- **Sin papelera:** borrar un archivo lo elimina de Drive de forma definitiva.
- **Cuentas inactivas:** Google puede borrar cuentas sin uso por 2 años. Conviene entrar de vez en cuando.
- **Cifrado de archivos:** esta versión **no** cifra el contenido. Quien tenga acceso a tus Drives ve los archivos (las partes de un archivo grande no se pueden abrir sueltas, pero no están cifradas).
- Las reglas de Google sobre crear cuentas solo para juntar espacio no son claras; usalo con tus propias cuentas y para uso personal.

## Ideas para la próxima versión
Cifrado en el cliente, redundancia (copia en dos cuentas), sincronización automática con un cron, y subida de carpetas completas.
