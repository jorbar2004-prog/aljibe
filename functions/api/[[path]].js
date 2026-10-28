// Aljibe — API (Cloudflare Pages Function, atiende todo /api/*)
// Bindings / variables necesarias: DB (D1), APP_PASSWORD, SESSION_SECRET,
// GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

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
async function passwordOk(env, given) {
  const a = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(given ?? ''))));
  const b = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(env.APP_PASSWORD)));
  let d = 0;
  for (let i = 0; i < 32; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ───────────── sesión ─────────────
function readCookies(req) {
  const o = {};
  for (const p of (req.headers.get('Cookie') || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return o;
}
async function isAuthed(req, env) {
  const c = readCookies(req).aljibe;
  if (!c) return false;
  const [exp, sig] = c.split('.');
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  return verifySig(env, 's:' + exp, sig);
}
async function sessionCookie(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  return `aljibe=${exp}.${await sign(env, 's:' + exp)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

// ───────────── nombres y rutas virtuales ─────────────
function cleanName(n) {
  const s = String(n ?? '').replace(/[\u0000-\u001f\u007f\\/]/g, '').trim().slice(0, 200);
  return s === '.' || s === '..' ? '' : s;
}
const cleanPath = (p) => String(p || '').split('/').map(cleanName).filter(Boolean).slice(0, 8).join('/');
function folderStmts(env, path) {
  const parts = path.split('/').filter(Boolean);
  return parts.map((_, i) =>
    env.DB.prepare('INSERT OR IGNORE INTO folders (path) VALUES (?)').bind(parts.slice(0, i + 1).join('/')));
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
  acc.quota_at = Math.floor(Date.now() / 1000);
  await env.DB.prepare('UPDATE accounts SET quota_limit=?, quota_usage=?, quota_at=? WHERE id=?')
    .bind(acc.quota_limit, acc.quota_usage, acc.quota_at, acc.id).run();
}

// maxAge (segundos): refresca la cuota si es más vieja que eso. null = no refrescar.
async function loadAccounts(env, maxAge = null) {
  const rows = (await env.DB.prepare('SELECT * FROM accounts ORDER BY id').all()).results;
  const now = Math.floor(Date.now() / 1000);
  await Promise.all(rows.map(async (a) => {
    if (maxAge !== null && (!a.quota_at || now - a.quota_at > maxAge)) {
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
async function googleConnect(env, url) {
  if (!env.GOOGLE_CLIENT_ID) throw new HttpError(500, 'Falta configurar GOOGLE_CLIENT_ID');
  const nonce = b64u.enc(crypto.getRandomValues(new Uint8Array(12)));
  const exp = Math.floor(Date.now() / 1000) + 600;
  const sig = await sign(env, `o:${nonce}.${exp}`);
  const p = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: url.origin + '/api/google/callback',
    response_type: 'code',
    scope: SCOPES,
    access_type: 'offline',
    prompt: 'consent select_account',
    state: `${nonce}.${exp}.${sig}`,
  });
  return new Response(null, { status: 302, headers: { Location: 'https://accounts.google.com/o/oauth2/v2/auth?' + p, 'Cache-Control': 'no-store' } });
}

async function googleCallback(env, url) {
  const back = (q) => new Response(null, { status: 302, headers: { Location: '/?' + q, 'Cache-Control': 'no-store' } });
  try {
    const err = url.searchParams.get('error');
    if (err) throw new HttpError(400, 'Google devolvió: ' + err);
    const [nonce, exp, sig] = (url.searchParams.get('state') || '').split('.');
    if (!sig || Number(exp) < Date.now() / 1000 || !(await verifySig(env, `o:${nonce}.${exp}`, sig)))
      throw new HttpError(400, 'La conexión venció o no es válida. Probá de nuevo.');
    const code = url.searchParams.get('code');
    if (!code) throw new HttpError(400, 'Falta el código de Google');

    const tr = await fetch(TOKEN_URL, {
      method: 'POST',
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: url.origin + '/api/google/callback',
        grant_type: 'authorization_code',
      }),
    });
    const t = await tr.json();
    if (!tr.ok) throw new HttpError(502, 'Google rechazó el código: ' + (t.error_description || t.error));
    if (!(t.scope || '').includes('drive.file'))
      throw new HttpError(400, 'Hay que aceptar el permiso de Drive para poder guardar archivos.');
    if (!t.refresh_token)
      throw new HttpError(400, 'Google no entregó refresh token. Quitá el acceso de Aljibe en myaccount.google.com/permissions y reconectá.');

    const ui = await (await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: 'Bearer ' + t.access_token },
    })).json();
    const email = String(ui.email || '').toLowerCase();
    if (!email) throw new HttpError(502, 'No se pudo leer el email de la cuenta');

    const root = await ensureRootFolder(t.access_token);
    await env.DB.prepare(
      `INSERT INTO accounts (email, refresh_token, root_folder_id, created_at) VALUES (?,?,?,?)
       ON CONFLICT(email) DO UPDATE SET refresh_token=excluded.refresh_token, root_folder_id=excluded.root_folder_id`
    ).bind(email, await encrypt(env, t.refresh_token), root, Math.floor(Date.now() / 1000)).run();
    tokenCache.clear();
    return back('connected=' + encodeURIComponent(email));
  } catch (e) {
    return back('error=' + encodeURIComponent(e.message));
  }
}

// ───────────── cuentas ─────────────
async function listAccounts(env, url) {
  const accs = await loadAccounts(env, url.searchParams.get('refresh') ? 0 : 120);
  const stored = new Map((await env.DB.prepare(
    'SELECT account_id AS id, SUM(size) AS bytes, COUNT(*) AS n FROM parts WHERE drive_id IS NOT NULL GROUP BY account_id'
  ).all()).results.map((r) => [r.id, r]));
  return json({
    accounts: accs.map((a) => ({
      id: a.id, email: a.email, limit: a.limit, usage: a.usage, free: a.free,
      known: a.quota_at != null, error: a.error || null,
      stored: stored.get(a.id)?.bytes || 0, parts: stored.get(a.id)?.n || 0,
    })),
  });
}

async function deleteAccount(env, id) {
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id=?').bind(id).first();
  if (!acc) throw new HttpError(404, 'La cuenta no existe');
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM parts WHERE account_id=?').bind(id).first();
  if (n.n > 0) throw new HttpError(409, 'Todavía hay archivos guardados en esa cuenta. Borralos o movelos antes de quitarla.');
  try {
    await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST', body: new URLSearchParams({ token: await decrypt(env, acc.refresh_token) }),
    });
  } catch { /* si falla la revocación igual la quitamos */ }
  await env.DB.prepare('DELETE FROM accounts WHERE id=?').bind(id).run();
  tokenCache.delete(acc.id);
  return json({ ok: true });
}

// ───────────── árbol, carpetas y archivos ─────────────
async function tree(env) {
  const files = (await env.DB.prepare(
    'SELECT id, name, folder, size, mime, status, nparts, created_at FROM files ORDER BY name COLLATE NOCASE'
  ).all()).results;
  const folders = (await env.DB.prepare('SELECT path FROM folders ORDER BY path').all()).results.map((r) => r.path);
  return json({ files, folders });
}

async function createFolder(env, body) {
  const path = cleanPath(body.path);
  if (!path) throw new HttpError(400, 'Nombre de carpeta inválido');
  await runBatch(env, folderStmts(env, path));
  return json({ ok: true, path });
}

async function deleteFolder(env, body) {
  const path = cleanPath(body.path);
  if (!path) throw new HttpError(400, 'Carpeta inválida');
  const pre = path + '/';
  const used = await env.DB.prepare('SELECT COUNT(*) AS n FROM files WHERE folder=? OR substr(folder,1,?)=?')
    .bind(path, pre.length, pre).first();
  if (used.n > 0) throw new HttpError(409, 'La carpeta no está vacía');
  await env.DB.prepare('DELETE FROM folders WHERE path=? OR substr(path,1,?)=?').bind(path, pre.length, pre).run();
  return json({ ok: true });
}

async function patchFile(env, id, body) {
  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?').bind(id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  const name = body.name !== undefined ? cleanName(body.name) : f.name;
  const folder = body.folder !== undefined ? cleanPath(body.folder) : f.folder;
  if (!name) throw new HttpError(400, 'Nombre inválido');
  await runBatch(env, [
    env.DB.prepare('UPDATE files SET name=?, folder=? WHERE id=?').bind(name, folder, id),
    ...folderStmts(env, folder),
  ]);
  return json({ ok: true });
}

async function deleteFile(env, id) {
  const f = await env.DB.prepare('SELECT id FROM files WHERE id=?').bind(id).first();
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
    env.DB.prepare('DELETE FROM parts WHERE file_id=?').bind(id),
    env.DB.prepare('DELETE FROM files WHERE id=?').bind(id),
  ]);
  return json({ ok: true });
}

// ───────────── descarga (con soporte de Range) ─────────────
async function download(ctx, id, inline) {
  const { env, request } = ctx;
  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?').bind(id).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
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
    'Cache-Control': 'private, max-age=0, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
  };
  if (f.mime !== 'application/pdf') headers['Content-Security-Policy'] = "default-src 'none'; sandbox";
  if (status === 206) headers['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
  if (typeof FixedLengthStream === 'undefined') headers['Content-Length'] = String(len);
  return new Response(readable, { status, headers });
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

async function uploadStart(env, body) {
  const name = cleanName(body.name);
  const size = Number(body.size);
  if (!name) throw new HttpError(400, 'Falta el nombre del archivo');
  if (!Number.isSafeInteger(size) || size <= 0) throw new HttpError(400, 'No se admiten archivos vacíos');
  const folder = cleanPath(body.folder);
  const mime = String(body.mime || 'application/octet-stream').slice(0, 100);

  const accs = (await loadAccounts(env, 30)).filter((a) => !a.error);
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
    env.DB.prepare('INSERT INTO files (id,name,folder,size,mime,nparts,status,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .bind(id, name, folder, size, mime, total, 'uploading', Math.floor(Date.now() / 1000)),
    ...plan.map((p, i) =>
      env.DB.prepare('INSERT INTO parts (file_id,idx,account_id,size,session_url) VALUES (?,?,?,?,?)').bind(id, i, p.acc.id, p.size, sessions[i])),
    ...folderStmts(env, folder),
  ]);
  return json({ file_id: id, block: BLOCK, parts: plan.map((p, i) => ({ idx: i, size: p.size, account: p.acc.email })) });
}

const nextFromRange = (h) => {
  const m = /bytes=0-(\d+)/.exec(h || '');
  return m ? Number(m[1]) + 1 : 0;
};

async function recordDone(env, fileId, idx, res) {
  const j = await res.json();
  await env.DB.prepare('UPDATE parts SET drive_id=?, session_url=NULL WHERE file_id=? AND idx=?').bind(j.id, fileId, idx).run();
  return json({ done: true, drive_id: j.id });
}

async function uploadBlock(request, env, url) {
  const fileId = url.searchParams.get('file');
  const idx = Number(url.searchParams.get('idx'));
  const start = Number(url.searchParams.get('start'));
  const end = Number(url.searchParams.get('end')); // exclusivo
  const part = await env.DB.prepare('SELECT * FROM parts WHERE file_id=? AND idx=?').bind(fileId, idx).first();
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

async function uploadStatus(env, body) {
  const part = await env.DB.prepare('SELECT * FROM parts WHERE file_id=? AND idx=?').bind(body.file, Number(body.idx)).first();
  if (!part) throw new HttpError(404, 'Parte no encontrada');
  if (part.drive_id) return json({ done: true, drive_id: part.drive_id });
  if (!part.session_url) throw new HttpError(409, 'La sesión de subida ya no existe');
  const r = await fetch(part.session_url, { method: 'PUT', headers: { 'Content-Range': `bytes */${part.size}` } });
  if (r.status === 308) return json({ done: false, next: nextFromRange(r.headers.get('Range')) });
  if (r.ok) return recordDone(env, part.file_id, part.idx, r);
  throw new HttpError(502, `Drive respondió ${r.status} al consultar la sesión`);
}

async function uploadFinish(env, body) {
  const rows = (await env.DB.prepare('SELECT drive_id FROM parts WHERE file_id=?').bind(body.file).all()).results;
  const f = await env.DB.prepare('SELECT nparts FROM files WHERE id=?').bind(body.file).first();
  if (!f) throw new HttpError(404, 'El archivo no existe');
  if (rows.length !== f.nparts || rows.some((r) => !r.drive_id)) throw new HttpError(409, 'Faltan partes por subir');
  await env.DB.prepare("UPDATE files SET status='ready' WHERE id=?").bind(body.file).run();
  return json({ ok: true });
}

// ───────────── reindexar desde Drive ─────────────
async function reindex(env) {
  const accs = (await env.DB.prepare('SELECT * FROM accounts').all()).results;
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

  const existing = new Set((await env.DB.prepare('SELECT id FROM files').all()).results.map((r) => r.id));
  const stmts = [];
  let added = 0;
  for (const [fid, g] of found) {
    const d = g.meta;
    if (!existing.has(fid)) {
      added++;
      stmts.push(env.DB.prepare('INSERT INTO files (id,name,folder,size,mime,nparts,status,created_at) VALUES (?,?,?,?,?,?,?,?)')
        .bind(fid, cleanName(d.name) || 'sin-nombre', cleanPath(d.folder), Number(d.size) || 0, String(d.mime || 'application/octet-stream'), Number(d.total) || 1, 'incomplete', Math.floor(Date.now() / 1000)));
      stmts.push(...folderStmts(env, cleanPath(d.folder)));
    }
    for (const [idx, p] of g.parts)
      stmts.push(env.DB.prepare(
        `INSERT INTO parts (file_id,idx,account_id,size,drive_id) VALUES (?,?,?,?,?)
         ON CONFLICT(file_id,idx) DO UPDATE SET drive_id=excluded.drive_id, account_id=excluded.account_id, size=excluded.size`)
        .bind(fid, idx, p.account_id, p.size, p.drive_id));
  }
  await runBatch(env, stmts);

  // Recalcular estado de cada archivo según lo que realmente hay en Drive.
  const rows = (await env.DB.prepare(
    'SELECT f.id, f.status, f.nparts, p.idx, p.account_id, p.drive_id FROM files f LEFT JOIN parts p ON p.file_id=f.id').all()).results;
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
  {
    for (const k of ['DB', 'APP_PASSWORD', 'SESSION_SECRET'])
      if (!env[k]) throw new HttpError(500, `Falta configurar ${k}`);
    if (env.SESSION_SECRET.length < 16) throw new HttpError(500, 'SESSION_SECRET es demasiado corto (mínimo 16 caracteres)');

    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
    const seg = path.split('/');
    const m = request.method;

    // Protección CSRF: toda petición que cambia estado debe traer este encabezado.
    if (m !== 'GET' && m !== 'HEAD' && request.headers.get('X-Requested-With') !== 'aljibe')
      throw new HttpError(403, 'Petición no permitida');

    if (path === 'login' && m === 'POST') {
      const body = await request.json().catch(() => ({}));
      if (!(await passwordOk(env, body.password))) {
        await new Promise((r) => setTimeout(r, 600));
        throw new HttpError(401, 'Contraseña incorrecta');
      }
      return json({ ok: true }, 200, { 'Set-Cookie': await sessionCookie(env) });
    }
    if (path === 'logout' && m === 'POST')
      return json({ ok: true }, 200, { 'Set-Cookie': 'aljibe=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });

    if (!(await isAuthed(request, env))) throw new HttpError(401, 'No autenticado');

    if (path === 'me' && m === 'GET') return json({ ok: true });
    if (path === 'google/connect' && m === 'GET') return googleConnect(env, url);
    if (path === 'google/callback' && m === 'GET') return googleCallback(env, url);

    if (path === 'accounts' && m === 'GET') return listAccounts(env, url);
    if (seg[0] === 'accounts' && seg[1] && m === 'DELETE') return deleteAccount(env, Number(seg[1]));

    if (path === 'tree' && m === 'GET') return tree(env);
    const body = m === 'POST' || m === 'PATCH' || m === 'DELETE' ? await request.clone().json().catch(() => ({})) : {};
    if (path === 'folders' && m === 'POST') return createFolder(env, body);
    if (path === 'folders' && m === 'DELETE') return deleteFolder(env, body);

    if (seg[0] === 'files' && seg[1]) {
      if (seg[2] === 'download' && m === 'GET') return download(ctx, seg[1], url.searchParams.get('inline') === '1');
      if (m === 'PATCH') return patchFile(env, seg[1], body);
      if (m === 'DELETE') return deleteFile(env, seg[1]);
    }

    if (path === 'upload/start' && m === 'POST') return uploadStart(env, body);
    if (path === 'upload/block' && m === 'PUT') return uploadBlock(request, env, url);
    if (path === 'upload/status' && m === 'POST') return uploadStatus(env, body);
    if (path === 'upload/finish' && m === 'POST') return uploadFinish(env, body);
    if (path === 'reindex' && m === 'POST') return reindex(env);

    throw new HttpError(404, 'Ruta no encontrada');
  }
}
