// Aljibe v0.4 — API multiusuario (Cloudflare Pages Function, atiende todo /api/*)
// Bindings / variables necesarias: DB (D1), ADMIN_CODE, SESSION_SECRET,
// GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET.

const BLOCK = 8 * 1024 * 1024;       // tamaño de bloque de subida (múltiplo de 256 KiB)
const MARGIN = 16 * 1024 * 1024;     // espacio que se deja libre en cada cuenta
const SESSION_DAYS = 30;
const SCOPES = 'openid email https://www.googleapis.com/auth/drive.file';
const DRIVE = 'https://www.googleapis.com/drive/v3';
const UPLOAD = 'https://www.googleapis.com/upload/drive/v3/files';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const now = () => Math.floor(Date.now() / 1000);
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });

// ───────────── utilidades de criptografía ─────────────
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
};
const hmacKey = (env) =>
  crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const sign = async (env, text) => b64u.enc(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(text)));
async function verifySig(env, text, sig) {
  try { return await crypto.subtle.verify('HMAC', await hmacKey(env), b64u.dec(sig), enc.encode(text)); }
  catch { return false; }
}
async function aesKey(env) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode('aes:' + env.SESSION_SECRET));
  return crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), enc.encode(text)));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return b64u.enc(out);
}
async function decrypt(env, s) {
  const raw = b64u.dec(s);
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, await aesKey(env), raw.slice(12)));
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
async function sha(text) { return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(text ?? '')))); }
const codeEq = async (a, b) => sameBytes(await sha(a), await sha(b));

// ───────────── sesión ─────────────
function readCookies(req) {
  const o = {};
  for (const p of (req.headers.get('Cookie') || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return o;
}
async function sessionCookie(env, user) {
  const exp = now() + SESSION_DAYS * 86400;
  const sig = await sign(env, `s:${user.id}.${exp}`);
  return `aljibe=${user.id}.${exp}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}
async function getUser(req, env) {
  const c = readCookies(req).aljibe;
  if (!c) return null;
  const [uid, exp, sig] = c.split('.');
  if (!uid || !exp || !sig || Number(exp) < now()) return null;
  const user = await env.DB.prepare('SELECT id, email, is_admin FROM users WHERE id=?').bind(Number(uid)).first();
  if (!user) return null;
  if (!(await verifySig(env, `s:${user.id}.${exp}`, sig))) return null;
  return user;
}
const publicUser = (u) => ({ id: u.id, email: u.email, is_admin: !!u.is_admin });
const normEmail = (e) => String(e ?? '').trim().toLowerCase();
// ───────────── administración ─────────────
function needAdmin(user) { if (!user.is_admin) throw new HttpError(403, 'Solo el administrador puede hacer esto'); }

async function adminUsers(env) {
  const rows = (await env.DB.prepare(
    `SELECT u.id, u.email, u.is_admin, u.created_at,
       (SELECT COUNT(*) FROM accounts a WHERE a.user_id=u.id) AS naccounts,
       (SELECT COUNT(*) FROM files f WHERE f.user_id=u.id) AS nfiles,
       (SELECT COALESCE(SUM(size),0) FROM files f WHERE f.user_id=u.id) AS bytes
     FROM users u ORDER BY u.id`).all()).results;
  return json({ users: rows.map((r) => ({ ...r, is_admin: !!r.is_admin })) });
}

async function adminDeleteUser(env, me, id) {
  if (id === me.id) throw new HttpError(400, 'No podés quitarte a vos mismo');
  const u = await env.DB.prepare('SELECT id FROM users WHERE id=?').bind(id).first();
  if (!u) throw new HttpError(404, 'El usuario no existe');
  const accs = (await env.DB.prepare('SELECT refresh_token FROM accounts WHERE user_id=?').bind(id).all()).results;
  for (const a of accs) {
    try { await fetch('https://oauth2.googleapis.com/revoke', { method: 'POST', body: new URLSearchParams({ token: await decrypt(env, a.refresh_token) }) }); }
    catch { /* si falla la revocación igual se quita */ }
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM shares WHERE user_id=?').bind(id),
    env.DB.prepare('DELETE FROM moves WHERE file_id IN (SELECT id FROM files WHERE user_id=?)').bind(id),
    env.DB.prepare('DELETE FROM parts WHERE file_id IN (SELECT id FROM files WHERE user_id=?)').bind(id),
    env.DB.prepare('DELETE FROM files WHERE user_id=?').bind(id),
    env.DB.prepare('DELETE FROM folders WHERE user_id=?').bind(id),
    env.DB.prepare('DELETE FROM accounts WHERE user_id=?').bind(id),
    env.DB.prepare('DELETE FROM users WHERE id=?').bind(id),
  ]);
  tokenCache.clear();
  return json({ ok: true });
}

async function adminCreateInvite(env, me, body) {
  const days = Math.min(30, Math.max(1, Math.floor(Number(body.days) || 7)));
  const code = b64u.enc(crypto.getRandomValues(new Uint8Array(16)));
  await env.DB.prepare('INSERT INTO invites (code, created_by, created_at, expires_at) VALUES (?,?,?,?)')
    .bind(code, me.id, now(), now() + days * 86400).run();
  return json({ ok: true, code, days });
}

async function adminInvites(env) {
  const rows = (await env.DB.prepare(
    `SELECT i.code, i.created_at, i.expires_at, i.used_at, u.email AS used_by_email
     FROM invites i LEFT JOIN users u ON u.id=i.used_by ORDER BY i.created_at DESC LIMIT 100`).all()).results;
  return json({ invites: rows });
}

// ───────────── nombres y rutas virtuales ─────────────
function cleanName(n) {
  const s = String(n ?? '').replace(/[\u0000-\u001f\u007f\\/]/g, '').trim().slice(0, 200);
  return s === '.' || s === '..' ? '' : s;
}
const cleanPath = (p) => String(p || '').split('/').map(cleanName).filter(Boolean).slice(0, 8).join('/');
function folderStmts(env, userId, path) {
  const parts = path.split('/').filter(Boolean);
  return parts.map((_, i) =>
    env.DB.prepare('INSERT OR IGNORE INTO folders (user_id, path) VALUES (?,?)').bind(userId, parts.slice(0, i + 1).join('/')));
}
async function runBatch(env, stmts) {
  for (let i = 0; i < stmts.length; i += 80) await env.DB.batch(stmts.slice(i, i + 80));
}

// ───────────── Google: tokens y cuotas ─────────────
const tokenCache = new Map(); // account id -> { token, exp }

async function accessToken(env, acc) {
  const hit = tokenCache.get(acc.id);
  if (hit && hit.exp > Date.now() + 60000) return hit.token;
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET)
    throw new HttpError(500, 'Falta configurar GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET');
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: await decrypt(env, acc.refresh_token),
      grant_type: 'refresh_token',
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    tokenCache.delete(acc.id);
    throw new HttpError(502, j.error === 'invalid_grant'
      ? `El acceso de ${acc.email} venció o fue revocado: reconectá la cuenta`
      : `No se pudo renovar el acceso de ${acc.email}`);
  }
  tokenCache.set(acc.id, { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 });
  return j.access_token;
}

async function drive(env, acc, path, init = {}) {
  const token = await accessToken(env, acc);
  return fetch(path.startsWith('http') ? path : DRIVE + path, {
    ...init,
    headers: { Authorization: 'Bearer ' + token, ...(init.headers || {}) },
  });
}

async function refreshQuota(env, acc) {
  const r = await drive(env, acc, '/about?fields=storageQuota');
  if (!r.ok) throw new HttpError(502, `Drive respondió ${r.status} para ${acc.email}`);
  const q = (await r.json()).storageQuota || {};
  acc.quota_limit = q.limit ? Number(q.limit) : null;
  acc.quota_usage = Number(q.usage || 0);
  acc.quota_at = now();
  await env.DB.prepare('UPDATE accounts SET quota_limit=?, quota_usage=?, quota_at=? WHERE id=?')
    .bind(acc.quota_limit, acc.quota_usage, acc.quota_at, acc.id).run();
}

// maxAge (segundos): refresca la cuota si es más vieja que eso. null = no refrescar.
async function loadAccounts(env, userId, maxAge = null) {
  const rows = (await env.DB.prepare('SELECT * FROM accounts WHERE user_id=? ORDER BY id').bind(userId).all()).results;
  await Promise.all(rows.map(async (a) => {
    if (maxAge !== null && (!a.quota_at || now() - a.quota_at > maxAge)) {
      try { await refreshQuota(env, a); } catch (e) { a.error = e.message; }
    }
  }));
  for (const a of rows) {
    a.limit = a.quota_limit;
    a.usage = a.quota_usage || 0;
    a.free = a.limit == null ? 1e15 : Math.max(0, a.limit - a.usage);
  }
  return rows;
}

async function ensureRootFolder(token) {
  const q = new URLSearchParams({
    q: "name='Aljibe' and mimeType='application/vnd.google-apps.folder' and trashed=false",
    fields: 'files(id)',
  });
  const h = { Authorization: 'Bearer ' + token };
  const r = await fetch(`${DRIVE}/files?${q}`, { headers: h });
  if (r.ok) {
    const f = (await r.json()).files || [];
    if (f.length) return f[0].id;
  }
  const c = await fetch(`${DRIVE}/files?fields=id`, {
    method: 'POST',
    headers: { ...h, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Aljibe', mimeType: 'application/vnd.google-apps.folder' }),
  });
  if (!c.ok) throw new HttpError(502, 'No se pudo crear la carpeta Aljibe en Drive');
  return (await c.json()).id;
}

// ───────────── OAuth ─────────────
// Un solo flujo de Google para dos cosas:
//  · modo "l" (entrar): identifica a la persona por su email de Google. Si ya es usuaria, entra; si no, necesita
//    una invitación (o el ADMIN_CODE si todavía no hay administrador). Esa misma cuenta queda conectada como almacenamiento.
//  · modo "c" (conectar otra cuenta): suma una cuenta de Drive al usuario que ya tiene sesión.
// El "state" va firmado. En modo "c" queda atado al usuario; en modo "l" además se ata al navegador con una cookie
// temporal, para que nadie pueda hacer que otra persona termine entrando a una sesión ajena.
const redirectUri = (url) => url.origin + '/api/google/callback';
const stateCookie = (v, age) => `aljibe_st=${v}; Path=/api/google; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;

async function startOAuth(env, url, mode, extra) {
  if (!env.GOOGLE_CLIENT_ID) throw new HttpError(500, 'Falta configurar GOOGLE_CLIENT_ID');
  const nonce = b64u.enc(crypto.getRandomValues(new Uint8Array(12)));
  const exp = now() + 600;
  const sig = await sign(env, `${mode}:${nonce}.${exp}.${extra}`);
  const p = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri(url),
    response_type: 'code',
    scope: SCOPES,
    access_type: 'offline',
    prompt: 'consent select_account',
    state: `${mode}.${nonce}.${exp}.${extra}.${sig}`,
  });
  const headers = { Location: 'https://accounts.google.com/o/oauth2/v2/auth?' + p, 'Cache-Control': 'no-store' };
  if (mode === 'l') headers['Set-Cookie'] = stateCookie(nonce, 600);
  return new Response(null, { status: 302, headers });
}

async function googleLogin(env, url) {
  const invite = (url.searchParams.get('invite') || '').trim();
  if (!/^[A-Za-z0-9_-]{0,200}$/.test(invite)) throw new HttpError(400, 'La invitación no es válida');
  return startOAuth(env, url, 'l', invite || '-');
}
const googleConnect = (env, url, user) => startOAuth(env, url, 'c', String(user.id));

async function exchange(env, url) {
  const err = url.searchParams.get('error');
  if (err) throw new HttpError(400, err === 'access_denied' ? 'Cancelaste el acceso con Google.' : 'Google devolvió: ' + err);
  const code = url.searchParams.get('code');
  if (!code) throw new HttpError(400, 'Falta el código de Google');
  const tr = await fetch(TOKEN_URL, {
    method: 'POST',
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri(url),
      grant_type: 'authorization_code',
    }),
  });
  const t = await tr.json();
  if (!tr.ok) throw new HttpError(502, 'Google rechazó el código: ' + (t.error_description || t.error));
  if (!(t.scope || '').includes('drive.file'))
    throw new HttpError(400, 'Hay que aceptar el permiso de Drive para poder guardar archivos.');
  if (!t.refresh_token)
    throw new HttpError(400, 'Google no entregó refresh token. Quitá el acceso de Aljibe en myaccount.google.com/permissions y probá de nuevo.');
  const ui = await (await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: 'Bearer ' + t.access_token },
  })).json();
  const email = String(ui.email || '').toLowerCase();
  if (!email) throw new HttpError(502, 'No se pudo leer el email de la cuenta');
  if (ui.email_verified === false) throw new HttpError(400, 'Google no verificó ese email');
  return { t, email };
}

// Guarda (o actualiza) la cuenta de Drive de un usuario. Devuelve false si pertenece a otro usuario.
async function saveAccount(env, userId, email, t) {
  const other = await env.DB.prepare('SELECT user_id FROM accounts WHERE email=?').bind(email).first();
  if (other && other.user_id !== userId) return false;
  const root = await ensureRootFolder(t.access_token);
  await env.DB.prepare(
    `INSERT INTO accounts (user_id, email, refresh_token, root_folder_id, created_at) VALUES (?,?,?,?,?)
     ON CONFLICT(email) DO UPDATE SET refresh_token=excluded.refresh_token, root_folder_id=excluded.root_folder_id`
  ).bind(userId, email, await encrypt(env, t.refresh_token), root, now()).run();
  tokenCache.clear();
  return true;
}

async function googleCallback(env, url, req, user) {
  const to = (q, cookies = []) => {
    const h = new Headers({ Location: '/?' + q, 'Cache-Control': 'no-store' });
    for (const c of cookies) h.append('Set-Cookie', c);
    return new Response(null, { status: 302, headers: h });
  };
  let mode = '';
  try {
    const [m, nonce, exp, extra, sig] = (url.searchParams.get('state') || '').split('.');
    mode = m;
    if (!sig || (m !== 'l' && m !== 'c') || Number(exp) < now() || !(await verifySig(env, `${m}:${nonce}.${exp}.${extra}`, sig)))
      throw new HttpError(400, 'El acceso venció o no es válido. Probá de nuevo.');
    if (m === 'c') {
      if (!user) throw new HttpError(401, 'Tu sesión venció. Entrá de nuevo.');
      if (String(user.id) !== extra) throw new HttpError(400, 'El acceso no es válido. Probá de nuevo.');
      const { t, email } = await exchange(env, url);
      if (!(await saveAccount(env, user.id, email, t)))
        throw new HttpError(409, 'Esa cuenta de Google ya está conectada a otro usuario de Aljibe');
      return to('connected=' + encodeURIComponent(email));
    }
    // modo entrar
    if (readCookies(req).aljibe_st !== nonce) throw new HttpError(400, 'El acceso no es válido o se abrió en otro navegador. Probá de nuevo.');
    const { t, email } = await exchange(env, url);
    let u = await env.DB.prepare('SELECT id, email, is_admin FROM users WHERE email=?').bind(email).first();
    let welcome = false;
    if (!u) {
      const code = extra === '-' ? '' : extra;
      let isAdmin = 0, invite = null;
      if (env.ADMIN_CODE && code && (await codeEq(code, env.ADMIN_CODE))) {
        const a = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin=1').first();
        if (a.n > 0) throw new HttpError(403, 'Ya existe un administrador. Pedile una invitación.');
        isAdmin = 1;
      } else {
        invite = code ? await env.DB.prepare('SELECT * FROM invites WHERE code=?').bind(code).first() : null;
        if (!invite || invite.used_by || invite.expires_at < now())
          throw new HttpError(403, 'Esa cuenta de Google todavía no tiene acceso a Aljibe. Pedí una invitación a quien administra.');
      }
      const owner = await env.DB.prepare('SELECT user_id FROM accounts WHERE email=?').bind(email).first();
      if (owner) throw new HttpError(409, 'Esa cuenta de Google ya está conectada a otro usuario de Aljibe');
      let r;
      try {
        r = await env.DB.prepare("INSERT INTO users (email, pw, is_admin, created_at) VALUES (?,'google',?,?)").bind(email, isAdmin, now()).run();
      } catch { throw new HttpError(409, 'Ya existe un usuario con ese email'); }
      u = { id: r.meta.last_row_id, email, is_admin: isAdmin };
      if (invite) { // la invitación se consume de forma atómica
        const c = await env.DB.prepare('UPDATE invites SET used_by=?, used_at=? WHERE code=? AND used_by IS NULL').bind(u.id, now(), invite.code).run();
        if (c.meta.changes !== 1) {
          await env.DB.prepare('DELETE FROM users WHERE id=?').bind(u.id).run();
          throw new HttpError(403, 'La invitación ya fue usada');
        }
      }
      welcome = true;
    }
    await saveAccount(env, u.id, email, t); // si esa cuenta es de otro usuario, simplemente no se toca
    return to(welcome ? 'welcome=1' : '', [await sessionCookie(env, u), stateCookie('', 0)]);
  } catch (e) {
    return to('error=' + encodeURIComponent(e.message), mode === 'l' ? [stateCookie('', 0)] : []);
  }
}

// ───────────── cuentas ─────────────
async function listAccounts(env, user, url) {
  const accs = await loadAccounts(env, user.id, url.searchParams.get('refresh') ? 0 : 120);
  const stored = new Map((await env.DB.prepare(
    `SELECT p.account_id AS id, SUM(p.size) AS bytes, COUNT(*) AS n FROM parts p
     JOIN accounts a ON a.id=p.account_id WHERE a.user_id=? AND p.drive_id IS NOT NULL GROUP BY p.account_id`
  ).bind(user.id).all()).results.map((r) => [r.id, r]));
  return json({
    accounts: accs.map((a) => ({
      id: a.id, email: a.email, limit: a.limit, usage: a.usage, free: a.free,
      known: a.quota_at != null, error: a.error || null,
      stored: stored.get(a.id)?.bytes || 0, parts: stored.get(a.id)?.n || 0,
    })),
  });
}

async function deleteAccount(env, user, id) {
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id=? AND user_id=?').bind(id, user.id).first();
  if (!acc) throw new HttpError(404, 'La cuenta no existe');
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM parts WHERE account_id=?').bind(id).first();
  if (n.n > 0) throw new HttpError(409, 'Todavía hay archivos guardados en esa cuenta. Borralos o movelos antes de quitarla.');
  try {
    await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST', body: new URLSearchParams({ token: await decrypt(env, acc.refresh_token) }),
    });
  } catch { /* si falla la revocación igual la quitamos */ }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM moves WHERE to_account=?').bind(id),
    env.DB.prepare('DELETE FROM accounts WHERE id=?').bind(id),
  ]);
  tokenCache.delete(acc.id);
  return json({ ok: true });
}

// ───────────── árbol, carpetas y archivos ─────────────
async function tree(env, user) {
  const files = (await env.DB.prepare(
    `SELECT f.id, f.name, f.folder, f.size, f.mime, f.status, f.nparts, f.created_at,
            s.token AS share_token, s.expires_at AS share_exp
     FROM files f LEFT JOIN shares s ON s.file_id=f.id
     WHERE f.user_id=? ORDER BY f.name COLLATE NOCASE`
  ).bind(user.id).all()).results;
  const folders = (await env.DB.prepare('SELECT path FROM folders WHERE user_id=? ORDER BY path').bind(user.id).all()).results.map((r) => r.path);
  return json({ files, folders });
}

async function createFolder(env, user, body) {
  const path = cleanPath(body.path);
  if (!path) throw new HttpError(400, 'Nombre de carpeta inválido');
  await runBatch(env, folderStmts(env, user.id, path));
  return json({ ok: true, path });
}

async function deleteFolder(env, user, body) {
  const path = cleanPath(body.path);
  if (!path) throw new HttpError(400, 'Carpeta inválida');
  const pre = path + '/';
  const used = await env.DB.prepare('SELECT COUNT(*) AS n FROM files WHERE user_id=? AND (folder=? OR substr(folder,1,?)=?)')
    .bind(user.id, path, pre.length, pre).first();
  if (used.n > 0) throw new HttpError(409, 'La carpeta no está vacía');
  await env.DB.prepare('DELETE FROM folders WHERE user_id=? AND (path=? OR substr(path,1,?)=?)').bind(user.id, path, pre.length, pre).run();
  return json({ ok: true });
}

async function patchFile(env, user, id, body) {
  const f = await env.DB.prepare('SELECT * FROM files WHERE id=? AND user_id=?').bind(id, user.id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  const name = body.name !== undefined ? cleanName(body.name) : f.name;
  const folder = body.folder !== undefined ? cleanPath(body.folder) : f.folder;
  if (!name) throw new HttpError(400, 'Nombre inválido');
  await runBatch(env, [
    env.DB.prepare('UPDATE files SET name=?, folder=? WHERE id=?').bind(name, folder, id),
    ...folderStmts(env, user.id, folder),
  ]);
  return json({ ok: true });
}

async function deleteFile(env, user, id) {
  const f = await env.DB.prepare('SELECT id FROM files WHERE id=? AND user_id=?').bind(id, user.id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  const parts = (await env.DB.prepare(
    `SELECT p.drive_id, a.id, a.email, a.refresh_token FROM parts p JOIN accounts a ON a.id=p.account_id
     WHERE p.file_id=? AND p.drive_id IS NOT NULL`).bind(id).all()).results;
  const failed = [];
  for (const p of parts) {
    try {
      const r = await drive(env, { id: p.id, email: p.email, refresh_token: p.refresh_token }, `/files/${p.drive_id}`, { method: 'DELETE' });
      if (!r.ok && r.status !== 404) failed.push(`${p.email} (${r.status})`);
    } catch (e) { failed.push(`${p.email}: ${e.message}`); }
  }
  if (failed.length) throw new HttpError(502, 'No se pudo borrar de Drive en: ' + failed.join(', ') + '. El archivo sigue registrado.');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM shares WHERE file_id=?').bind(id),
    env.DB.prepare('DELETE FROM moves WHERE file_id=?').bind(id),
    env.DB.prepare('DELETE FROM parts WHERE file_id=?').bind(id),
    env.DB.prepare('DELETE FROM files WHERE id=?').bind(id),
  ]);
  return json({ ok: true });
}

// ───────────── descarga (con soporte de Range) ─────────────
async function download(ctx, user, id, inline) {
  const f = await ctx.env.DB.prepare('SELECT * FROM files WHERE id=? AND user_id=?').bind(id, user.id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  return streamFile(ctx, f, inline, 'private, max-age=0, must-revalidate');
}

async function streamFile(ctx, f, inline, cache) {
  const { env, request } = ctx;
  const id = f.id;
  if (f.status !== 'ready') throw new HttpError(409, f.status === 'uploading' ? 'El archivo todavía se está subiendo' : 'Al archivo le faltan partes en Drive (probá "Reindexar")');
  const parts = (await env.DB.prepare(
    `SELECT p.idx, p.size, p.drive_id, a.id AS aid, a.email, a.refresh_token
     FROM parts p JOIN accounts a ON a.id=p.account_id WHERE p.file_id=? ORDER BY p.idx`).bind(id).all()).results;

  let start = 0, end = f.size - 1, status = 200;
  const rh = request.headers.get('Range');
  if (rh) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rh.trim());
    if (m && (m[1] !== '' || m[2] !== '')) {
      if (m[1] === '') start = Math.max(0, f.size - Number(m[2]));
      else { start = Number(m[1]); if (m[2] !== '') end = Math.min(Number(m[2]), f.size - 1); }
      if (start > end || start >= f.size)
        return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${f.size}` } });
      status = 206;
    }
  }

  const segs = [];
  let off = 0;
  for (const p of parts) {
    const pS = off, pE = off + p.size;
    off = pE;
    const a = Math.max(start, pS), b = Math.min(end + 1, pE);
    if (a < b) segs.push({ p, from: a - pS, to: b - pS - 1 });
  }
  for (const s of segs) s.token = await accessToken(env, { id: s.p.aid, email: s.p.email, refresh_token: s.p.refresh_token });

  const len = end - start + 1;
  const { readable, writable } = typeof FixedLengthStream !== 'undefined' ? new FixedLengthStream(len) : new TransformStream();
  ctx.waitUntil((async () => {
    try {
      for (const s of segs) {
        const r = await fetch(`${DRIVE}/files/${s.p.drive_id}?alt=media`, {
          headers: { Authorization: 'Bearer ' + s.token, Range: `bytes=${s.from}-${s.to}` },
        });
        if (!r.ok) throw new Error('Drive respondió ' + r.status);
        await r.body.pipeTo(writable, { preventClose: true });
      }
      await writable.close();
    } catch (e) { try { await writable.abort(e); } catch { /* ya cerrado */ } }
  })());

  // Solo se muestra en el navegador lo que es seguro; el resto se descarga.
  const safeInline = /^(image|video|audio)\//.test(f.mime) || f.mime === 'application/pdf' || f.mime === 'text/plain';
  const asInline = inline && safeInline;
  const ascii = f.name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  const headers = {
    'Content-Type': f.mime,
    'Content-Disposition': `${asInline ? 'inline' : 'attachment'}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(f.name).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16))}`,
    'Accept-Ranges': 'bytes',
    'Cache-Control': cache,
    'X-Content-Type-Options': 'nosniff',
  };
  if (f.mime !== 'application/pdf') headers['Content-Security-Policy'] = "default-src 'none'; sandbox";
  if (status === 206) headers['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
  if (typeof FixedLengthStream === 'undefined') headers['Content-Length'] = String(len);
  return new Response(readable, { status, headers });
}

// ───────────── enlaces para compartir ─────────────
// Un enlace = un token largo e imposible de adivinar. Cualquiera que lo tenga descarga el archivo (sin cuenta)
// hasta que venza o se desactive. Hay un solo enlace por archivo: crear otro reemplaza (y anula) el anterior.
async function shareCreate(env, user, id, body) {
  const f = await env.DB.prepare('SELECT id, status FROM files WHERE id=? AND user_id=?').bind(id, user.id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  if (f.status !== 'ready') throw new HttpError(409, 'El archivo todavía no está listo para compartir');
  const days = Math.min(90, Math.max(1, Math.floor(Number(body.days) || 7)));
  const token = b64u.enc(crypto.getRandomValues(new Uint8Array(24)));
  const exp = now() + days * 86400;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM shares WHERE file_id=?').bind(id),
    env.DB.prepare('INSERT INTO shares (token, file_id, user_id, created_at, expires_at) VALUES (?,?,?,?,?)').bind(token, id, user.id, now(), exp),
  ]);
  return json({ ok: true, token, expires_at: exp });
}

async function shareDelete(env, user, id) {
  await env.DB.prepare('DELETE FROM shares WHERE file_id=? AND user_id=?').bind(id, user.id).run();
  return json({ ok: true });
}

async function shareDownload(ctx, token, inline) {
  const { env } = ctx;
  const bad = new HttpError(404, 'El enlace no existe o ya venció');
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) throw bad;
  const s = await env.DB.prepare('SELECT * FROM shares WHERE token=?').bind(token).first();
  if (!s) throw bad;
  if (s.expires_at < now()) { await env.DB.prepare('DELETE FROM shares WHERE token=?').bind(token).run(); throw bad; }
  const f = await env.DB.prepare('SELECT * FROM files WHERE id=? AND user_id=?').bind(s.file_id, s.user_id).first();
  if (!f) throw bad;
  const res = await streamFile(ctx, f, inline, 'private, no-store');
  res.headers.set('X-Robots-Tag', 'noindex, nofollow');
  res.headers.set('Referrer-Policy', 'no-referrer');
  return res;
}

// ───────────── equilibrar entre cuentas ─────────────
// Mueve partes de la cuenta con menos espacio libre a la que más tiene, hasta que queden parejas.
// Cada parte se copia por bloques de 8 MB (reanudable) y recién cuando está completa se cambia en la base y se borra la original.
const MIN_GAP = 128 * 1024 * 1024; // no se mueve nada si la diferencia de espacio libre es menor

async function rebalancePlan(env, user) {
  const accs = (await loadAccounts(env, user.id, 0)).filter((a) => !a.error && a.limit != null);
  if (accs.length < 2) throw new HttpError(400, 'Hacen falta al menos 2 cuentas conectadas y legibles para equilibrar.');
  const rows = (await env.DB.prepare(
    `SELECT p.file_id, p.idx, p.size, p.account_id, f.name FROM parts p JOIN files f ON f.id=p.file_id
     WHERE f.user_id=? AND f.status='ready' AND p.drive_id IS NOT NULL`).bind(user.id).all()).results;
  const free = new Map(accs.map((a) => [a.id, a.free]));
  const email = new Map(accs.map((a) => [a.id, a.email]));
  const held = new Map(accs.map((a) => [a.id, []]));
  for (const r of rows) held.get(r.account_id)?.push(r);
  for (const l of held.values()) l.sort((a, b) => b.size - a.size);

  const moves = [];
  for (let guard = 0; guard < 500; guard++) {
    const order = [...free.keys()].sort((a, b) => free.get(a) - free.get(b));
    const dst = order[order.length - 1];
    let done = false;
    for (const src of order) {
      if (src === dst) break;
      const gap = free.get(dst) - free.get(src);
      if (gap < MIN_GAP) break;
      const limit = Math.min(gap / 2, free.get(dst) - MARGIN);
      const list = held.get(src);
      const i = list.findIndex((p) => p.size <= limit);
      if (i < 0) continue;
      const [p] = list.splice(i, 1);
      free.set(src, free.get(src) + p.size); free.set(dst, free.get(dst) - p.size);
      held.get(dst).push(p); held.get(dst).sort((a, b) => b.size - a.size);
      moves.push({ file: p.file_id, idx: p.idx, name: p.name, size: p.size, from: email.get(src), to: dst, to_email: email.get(dst) });
      done = true; break;
    }
    if (!done) break;
  }
  return json({ moves, bytes: moves.reduce((n, m) => n + m.size, 0), accounts: accs.length });
}

async function moveFinish(env, user, part, mv, dst, newId) {
  // La parte solo cambia de cuenta si sigue siendo la misma que se copió (nadie la borró ni la movió mientras tanto).
  const u = await env.DB.prepare('UPDATE parts SET account_id=?, drive_id=? WHERE file_id=? AND idx=? AND drive_id=?')
    .bind(dst.id, newId, part.file_id, part.idx, part.drive_id).run();
  await env.DB.prepare('DELETE FROM moves WHERE file_id=? AND idx=?').bind(part.file_id, part.idx).run();
  if (u.meta.changes !== 1) {
    try { await drive(env, dst, `/files/${newId}`, { method: 'DELETE' }); } catch { /* queda como copia suelta */ }
    throw new HttpError(409, 'El archivo cambió mientras se movía. Probá de nuevo.');
  }
  let deleted = true;
  try {
    const src = await env.DB.prepare('SELECT * FROM accounts WHERE id=? AND user_id=?').bind(mv.from_account, user.id).first();
    const r = await drive(env, src, `/files/${part.drive_id}`, { method: 'DELETE' });
    deleted = r.ok || r.status === 404;
  } catch { deleted = false; }
  tokenCache.clear();
  return json({ done: true, deleted });
}

async function moveOwn(env, user, fileId, idx) {
  const part = await env.DB.prepare(
    `SELECT p.* FROM parts p JOIN files f ON f.id=p.file_id
     WHERE p.file_id=? AND p.idx=? AND f.user_id=? AND f.status='ready' AND p.drive_id IS NOT NULL`
  ).bind(String(fileId), Number(idx), user.id).first();
  if (!part) throw new HttpError(404, 'Parte no encontrada');
  return part;
}

async function moveStart(env, user, body) {
  const part = await moveOwn(env, user, body.file, body.idx);
  const dst = await env.DB.prepare('SELECT * FROM accounts WHERE id=? AND user_id=?').bind(Number(body.to), user.id).first();
  if (!dst) throw new HttpError(404, 'La cuenta de destino no existe');
  if (dst.id === part.account_id) throw new HttpError(400, 'La parte ya está en esa cuenta');
  const [d] = (await loadAccounts(env, user.id, 120)).filter((a) => a.id === dst.id);
  if (d.error || d.free < part.size + MARGIN) throw new HttpError(507, 'La cuenta de destino no tiene espacio suficiente');

  let mv = await env.DB.prepare('SELECT * FROM moves WHERE file_id=? AND idx=?').bind(part.file_id, part.idx).first();
  if (mv && mv.to_account === dst.id) { // reanudar: preguntar a Google hasta dónde llegó
    const r = await fetch(mv.session_url, { method: 'PUT', headers: { 'Content-Range': `bytes */${part.size}` } });
    if (r.status === 308) return json({ done: false, size: part.size, block: BLOCK, next: nextFromRange(r.headers.get('Range')) });
    if (r.ok) return moveFinish(env, user, part, { from_account: part.account_id }, dst, (await r.json()).id);
    // la sesión venció: se arranca una nueva
  }
  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?').bind(part.file_id).first();
  const loc = await initSession(env, dst, { id: f.id, name: f.name, folder: f.folder, mime: f.mime, idx: part.idx, total: f.nparts, size: f.size, partSize: part.size });
  await env.DB.prepare('INSERT OR REPLACE INTO moves (file_id, idx, to_account, session_url, created_at) VALUES (?,?,?,?,?)')
    .bind(part.file_id, part.idx, dst.id, loc, now()).run();
  return json({ done: false, size: part.size, block: BLOCK, next: 0 });
}

async function moveBlock(env, user, url) {
  const part = await moveOwn(env, user, url.searchParams.get('file'), url.searchParams.get('idx'));
  const start = Number(url.searchParams.get('start')), end = Number(url.searchParams.get('end')); // end exclusivo
  if (!(start >= 0 && end > start && end <= part.size && end - start <= BLOCK)) throw new HttpError(400, 'Rango inválido');
  const mv = await env.DB.prepare('SELECT * FROM moves WHERE file_id=? AND idx=?').bind(part.file_id, part.idx).first();
  if (!mv) throw new HttpError(409, 'No hay un movimiento en curso para esta parte');
  const dst = await env.DB.prepare('SELECT * FROM accounts WHERE id=? AND user_id=?').bind(mv.to_account, user.id).first();
  const src = await env.DB.prepare('SELECT * FROM accounts WHERE id=? AND user_id=?').bind(part.account_id, user.id).first();
  if (!dst || !src) throw new HttpError(404, 'La cuenta ya no existe');

  const g = await fetch(`${DRIVE}/files/${part.drive_id}?alt=media`, {
    headers: { Authorization: 'Bearer ' + (await accessToken(env, src)), Range: `bytes=${start}-${end - 1}` },
  });
  if (!g.ok) throw new HttpError(502, `Drive respondió ${g.status} al leer la parte original`);
  const data = await g.arrayBuffer();
  if (data.byteLength !== end - start) throw new HttpError(502, 'Drive devolvió un bloque incompleto');
  const r = await fetch(mv.session_url, { method: 'PUT', headers: { 'Content-Range': `bytes ${start}-${end - 1}/${part.size}` }, body: data });
  if (r.status === 308) return json({ done: false, next: nextFromRange(r.headers.get('Range')) });
  if (r.ok) return moveFinish(env, user, part, { from_account: src.id }, dst, (await r.json()).id);
  throw new HttpError(502, `Drive respondió ${r.status} al copiar el bloque`);
}

// ───────────── subida ─────────────
async function initSession(env, acc, m) {
  const token = await accessToken(env, acc);
  const single = m.total === 1;
  const meta = {
    name: single ? m.name : `${m.name}.part${String(m.idx + 1).padStart(3, '0')}`,
    parents: [acc.root_folder_id],
    mimeType: single ? m.mime : 'application/octet-stream',
    description: JSON.stringify({ v: 1, id: m.id, name: m.name, folder: m.folder, mime: m.mime, idx: m.idx, total: m.total, size: m.size }),
    appProperties: { aljibe: '1' },
  };
  const r = await fetch(`${UPLOAD}?uploadType=resumable&fields=id,size`, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + token,
      'Content-Type': 'application/json; charset=UTF-8',
      'X-Upload-Content-Type': meta.mimeType,
      'X-Upload-Content-Length': String(m.partSize),
    },
    body: JSON.stringify(meta),
  });
  const loc = r.headers.get('Location');
  if (!r.ok || !loc) throw new HttpError(502, `Drive no abrió la sesión de subida para ${acc.email} (${r.status})`);
  return loc;
}

async function uploadStart(env, user, body) {
  const name = cleanName(body.name);
  const size = Number(body.size);
  if (!name) throw new HttpError(400, 'Falta el nombre del archivo');
  if (!Number.isSafeInteger(size) || size <= 0) throw new HttpError(400, 'No se admiten archivos vacíos');
  const folder = cleanPath(body.folder);
  const mime = String(body.mime || 'application/octet-stream').slice(0, 100);

  const accs = (await loadAccounts(env, user.id, 30)).filter((a) => !a.error);
  if (!accs.length) throw new HttpError(409, 'Conectá al menos una cuenta de Google antes de subir');

  const reserved = new Map((await env.DB.prepare(
    `SELECT p.account_id AS id, SUM(p.size) AS s FROM parts p JOIN files f ON f.id=p.file_id
     WHERE f.status='uploading' AND p.drive_id IS NULL GROUP BY p.account_id`).all()).results.map((r) => [r.id, r.s]));
  const cand = accs
    .map((a) => ({ a, free: a.free - (reserved.get(a.id) || 0) - MARGIN }))
    .filter((c) => c.free > 0)
    .sort((x, y) => y.free - x.free);

  let plan = [];
  if (cand.length && cand[0].free >= size) plan = [{ acc: cand[0].a, size }];
  else {
    let left = size;
    for (const c of cand) {
      if (left <= 0) break;
      const take = Math.min(left, c.free);
      plan.push({ acc: c.a, size: take });
      left -= take;
    }
    if (left > 0) throw new HttpError(507, 'No hay espacio suficiente en las cuentas conectadas');
  }

  const id = crypto.randomUUID();
  const total = plan.length;
  const sessions = [];
  for (let i = 0; i < total; i++)
    sessions.push(await initSession(env, plan[i].acc, { id, name, folder, mime, size, idx: i, total, partSize: plan[i].size }));

  await runBatch(env, [
    env.DB.prepare('INSERT INTO files (id,user_id,name,folder,size,mime,nparts,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, user.id, name, folder, size, mime, total, 'uploading', now()),
    ...plan.map((p, i) =>
      env.DB.prepare('INSERT INTO parts (file_id,idx,account_id,size,session_url) VALUES (?,?,?,?,?)').bind(id, i, p.acc.id, p.size, sessions[i])),
    ...folderStmts(env, user.id, folder),
  ]);
  return json({ file_id: id, block: BLOCK, parts: plan.map((p, i) => ({ idx: i, size: p.size, account: p.acc.email })) });
}

const nextFromRange = (h) => {
  const m = /bytes=0-(\d+)/.exec(h || '');
  return m ? Number(m[1]) + 1 : 0;
};

// Devuelve la parte solo si el archivo es del usuario.
const ownPart = (env, user, fileId, idx) => env.DB.prepare(
  'SELECT p.* FROM parts p JOIN files f ON f.id=p.file_id WHERE p.file_id=? AND p.idx=? AND f.user_id=?'
).bind(String(fileId), Number(idx), user.id).first();

async function recordDone(env, fileId, idx, res) {
  const j = await res.json();
  await env.DB.prepare('UPDATE parts SET drive_id=?, session_url=NULL WHERE file_id=? AND idx=?').bind(j.id, fileId, idx).run();
  return json({ done: true, drive_id: j.id });
}

async function uploadBlock(request, env, user, url) {
  const fileId = url.searchParams.get('file');
  const idx = Number(url.searchParams.get('idx'));
  const start = Number(url.searchParams.get('start'));
  const end = Number(url.searchParams.get('end')); // exclusivo
  const part = await ownPart(env, user, fileId, idx);
  if (!part) throw new HttpError(404, 'Parte no encontrada');
  if (part.drive_id) return json({ done: true, drive_id: part.drive_id });
  if (!part.session_url) throw new HttpError(409, 'La sesión de subida ya no existe');
  if (!(start >= 0 && end > start && end <= part.size)) throw new HttpError(400, 'Rango inválido');

  const data = await request.arrayBuffer();
  if (data.byteLength !== end - start) throw new HttpError(400, 'El tamaño del bloque no coincide con el rango');
  const r = await fetch(part.session_url, {
    method: 'PUT',
    headers: { 'Content-Range': `bytes ${start}-${end - 1}/${part.size}` },
    body: data,
  });
  if (r.status === 308) return json({ done: false, next: nextFromRange(r.headers.get('Range')) });
  if (r.ok) return recordDone(env, fileId, idx, r);
  throw new HttpError(502, `Drive respondió ${r.status} al subir el bloque`);
}

async function uploadStatus(env, user, body) {
  const part = await ownPart(env, user, body.file, body.idx);
  if (!part) throw new HttpError(404, 'Parte no encontrada');
  if (part.drive_id) return json({ done: true, drive_id: part.drive_id });
  if (!part.session_url) throw new HttpError(409, 'La sesión de subida ya no existe');
  const r = await fetch(part.session_url, { method: 'PUT', headers: { 'Content-Range': `bytes */${part.size}` } });
  if (r.status === 308) return json({ done: false, next: nextFromRange(r.headers.get('Range')) });
  if (r.ok) return recordDone(env, part.file_id, part.idx, r);
  throw new HttpError(502, `Drive respondió ${r.status} al consultar la sesión`);
}

async function uploadFinish(env, user, body) {
  const f = await env.DB.prepare('SELECT nparts FROM files WHERE id=? AND user_id=?').bind(String(body.file), user.id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  const rows = (await env.DB.prepare('SELECT drive_id FROM parts WHERE file_id=?').bind(String(body.file)).all()).results;
  if (rows.length !== f.nparts || rows.some((r) => !r.drive_id)) throw new HttpError(409, 'Faltan partes por subir');
  await env.DB.prepare("UPDATE files SET status='ready' WHERE id=?").bind(String(body.file)).run();
  return json({ ok: true });
}

// ───────────── reindexar desde Drive (solo las cuentas del usuario) ─────────────
async function reindex(env, user) {
  const accs = (await env.DB.prepare('SELECT * FROM accounts WHERE user_id=?').bind(user.id).all()).results;
  const found = new Map(); // file id -> { meta, parts: Map(idx -> {account_id, drive_id, size}) }
  const seen = new Set();
  const okAcc = new Set();
  const errors = [];

  for (const acc of accs) {
    try {
      let pageToken = '';
      do {
        const q = new URLSearchParams({
          q: "appProperties has { key='aljibe' and value='1' } and trashed=false",
          fields: 'nextPageToken,files(id,size,description)',
          pageSize: '1000',
        });
        if (pageToken) q.set('pageToken', pageToken);
        const r = await drive(env, acc, `/files?${q}`);
        if (!r.ok) throw new Error('Drive respondió ' + r.status);
        const j = await r.json();
        for (const f of j.files || []) {
          let d;
          try { d = JSON.parse(f.description || ''); } catch { continue; }
          if (!d || d.v !== 1 || !d.id) continue;
          seen.add(f.id);
          if (!found.has(d.id)) found.set(d.id, { meta: d, parts: new Map() });
          found.get(d.id).parts.set(d.idx, { account_id: acc.id, drive_id: f.id, size: Number(f.size || 0) });
        }
        pageToken = j.nextPageToken || '';
      } while (pageToken);
      okAcc.add(acc.id);
    } catch (e) { errors.push(`${acc.email}: ${e.message}`); }
  }

  const owner = new Map((await env.DB.prepare('SELECT id, user_id FROM files').all()).results.map((r) => [r.id, r.user_id]));
  const stmts = [];
  let added = 0;
  for (const [fid, g] of found) {
    if (owner.has(fid) && owner.get(fid) !== user.id) continue; // el id pertenece a otro usuario: no se toca
    const d = g.meta;
    if (!owner.has(fid)) {
      added++;
      stmts.push(env.DB.prepare('INSERT INTO files (id,user_id,name,folder,size,mime,nparts,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(fid, user.id, cleanName(d.name) || 'sin-nombre', cleanPath(d.folder), Number(d.size) || 0, String(d.mime || 'application/octet-stream'), Number(d.total) || 1, 'incomplete', now()));
      stmts.push(...folderStmts(env, user.id, cleanPath(d.folder)));
    }
    for (const [idx, p] of g.parts)
      stmts.push(env.DB.prepare(
        `INSERT INTO parts (file_id,idx,account_id,size,drive_id) VALUES (?,?,?,?,?)
         ON CONFLICT(file_id,idx) DO UPDATE SET drive_id=excluded.drive_id, account_id=excluded.account_id, size=excluded.size`)
        .bind(fid, idx, p.account_id, p.size, p.drive_id));
  }
  await runBatch(env, stmts);

  // Recalcular estado de cada archivo del usuario según lo que realmente hay en Drive.
  const rows = (await env.DB.prepare(
    'SELECT f.id, f.status, f.nparts, p.idx, p.account_id, p.drive_id FROM files f LEFT JOIN parts p ON p.file_id=f.id WHERE f.user_id=?'
  ).bind(user.id).all()).results;
  const byFile = new Map();
  for (const r of rows) {
    if (!byFile.has(r.id)) byFile.set(r.id, { status: r.status, nparts: r.nparts, parts: [] });
    if (r.idx !== null) byFile.get(r.id).parts.push(r);
  }
  const upd = [];
  let incomplete = 0;
  for (const [id, f] of byFile) {
    if (f.parts.some((p) => !okAcc.has(p.account_id))) { if (f.status === 'incomplete') incomplete++; continue; }
    const complete = f.parts.length === f.nparts && f.parts.every((p) => p.drive_id && seen.has(p.drive_id));
    if (f.status === 'uploading' && !complete) continue;
    const next = complete ? 'ready' : 'incomplete';
    if (!complete) incomplete++;
    if (next !== f.status) upd.push(env.DB.prepare('UPDATE files SET status=? WHERE id=?').bind(next, id));
  }
  await runBatch(env, upd);
  return json({ found: found.size, added, incomplete, errors });
}

// ───────────── enrutador ─────────────
export async function onRequest(ctx) {
  try {
    return await route(ctx);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'Error interno: ' + e.message }, 500);
  }
}

async function route(ctx) {
  const { request, env } = ctx;
  for (const k of ['DB', 'ADMIN_CODE', 'SESSION_SECRET'])
    if (!env[k]) throw new HttpError(500, `Falta configurar ${k}`);
  if (env.SESSION_SECRET.length < 16) throw new HttpError(500, 'SESSION_SECRET es demasiado corto (mínimo 16 caracteres)');

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  const seg = path.split('/');
  const m = request.method;

  // Protección CSRF: toda petición que cambia estado debe traer este encabezado.
  if (m !== 'GET' && m !== 'HEAD' && request.headers.get('X-Requested-With') !== 'aljibe')
    throw new HttpError(403, 'Petición no permitida');

  const readBody = () => request.clone().json().catch(() => ({}));

  // Rutas públicas
  if (path === 'google/login' && m === 'GET') return googleLogin(env, url);
  if (path === 'logout' && m === 'POST')
    return json({ ok: true }, 200, { 'Set-Cookie': 'aljibe=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });

  if (seg[0] === 's' && seg[1] && seg.length === 2 && (m === 'GET' || m === 'HEAD')) return shareDownload(ctx, seg[1], url.searchParams.get('inline') === '1');

  const user = await getUser(request, env);
  if (path === 'google/callback' && m === 'GET') return googleCallback(env, url, request, user);
  if (!user) throw new HttpError(401, 'No autenticado');

  if (path === 'me' && m === 'GET') return json({ ok: true, user: publicUser(user) });
  if (path === 'google/connect' && m === 'GET') return googleConnect(env, url, user);

  if (path === 'accounts' && m === 'GET') return listAccounts(env, user, url);
  if (seg[0] === 'accounts' && seg[1] && m === 'DELETE') return deleteAccount(env, user, Number(seg[1]));

  if (path === 'tree' && m === 'GET') return tree(env, user);
  if (path === 'folders' && m === 'POST') return createFolder(env, user, await readBody());
  if (path === 'folders' && m === 'DELETE') return deleteFolder(env, user, await readBody());

  if (seg[0] === 'files' && seg[1]) {
    if (seg[2] === 'download' && m === 'GET') return download(ctx, user, seg[1], url.searchParams.get('inline') === '1');
    if (seg[2] === 'share' && m === 'POST') return shareCreate(env, user, seg[1], await readBody());
    if (seg[2] === 'share' && m === 'DELETE') return shareDelete(env, user, seg[1]);
    if (m === 'PATCH') return patchFile(env, user, seg[1], await readBody());
    if (m === 'DELETE') return deleteFile(env, user, seg[1]);
  }

  if (path === 'upload/start' && m === 'POST') return uploadStart(env, user, await readBody());
  if (path === 'upload/block' && m === 'PUT') return uploadBlock(request, env, user, url);
  if (path === 'upload/status' && m === 'POST') return uploadStatus(env, user, await readBody());
  if (path === 'upload/finish' && m === 'POST') return uploadFinish(env, user, await readBody());
  if (path === 'rebalance/plan' && m === 'POST') return rebalancePlan(env, user);
  if (path === 'move/start' && m === 'POST') return moveStart(env, user, await readBody());
  if (path === 'move/block' && m === 'PUT') return moveBlock(env, user, url);
  if (path === 'reindex' && m === 'POST') return reindex(env, user);

  // Administración
  if (seg[0] === 'admin') {
    needAdmin(user);
    if (path === 'admin/users' && m === 'GET') return adminUsers(env);
    if (seg[1] === 'users' && seg[2] && m === 'DELETE') return adminDeleteUser(env, user, Number(seg[2]));
    if (path === 'admin/invites' && m === 'GET') return adminInvites(env);
    if (path === 'admin/invites' && m === 'POST') return adminCreateInvite(env, user, await readBody());
    if (seg[1] === 'invites' && seg[2] && m === 'DELETE') {
      await env.DB.prepare('DELETE FROM invites WHERE code=? AND used_by IS NULL').bind(seg[2]).run();
      return json({ ok: true });
    }
  }

  throw new HttpError(404, 'Ruta no encontrada');
}
