-- Aljibe v0.2 — esquema D1 (SQLite), multiusuario con invitaciones
-- Ejecutalo UNA sola vez en la consola de D1 (Workers & Pages → D1 → tu base → Console).
-- Si la consola no acepta todo junto, pegá las sentencias de a una.

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  email        TEXT NOT NULL UNIQUE,
  pw           TEXT NOT NULL,            -- pbkdf2$iteraciones$sal$hash
  is_admin     INTEGER NOT NULL DEFAULT 0,
  fails        INTEGER NOT NULL DEFAULT 0,     -- intentos fallidos seguidos
  locked_until INTEGER NOT NULL DEFAULT 0,     -- epoch (s) hasta el que está bloqueado
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
  code       TEXT PRIMARY KEY,
  created_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_by    INTEGER,
  used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS accounts (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL,
  email          TEXT NOT NULL UNIQUE,   -- una cuenta de Google solo puede estar en un usuario
  refresh_token  TEXT NOT NULL,          -- cifrado con AES-GCM (clave derivada de SESSION_SECRET)
  root_folder_id TEXT,                   -- carpeta "Aljibe" dentro de ese Drive
  quota_limit    INTEGER,                -- bytes totales (NULL = sin límite informado)
  quota_usage    INTEGER,                -- bytes usados (Drive + Gmail + Fotos)
  quota_at       INTEGER,                -- epoch (s) de la última consulta de cuota
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id         TEXT PRIMARY KEY,           -- UUID
  user_id    INTEGER NOT NULL,
  name       TEXT NOT NULL,
  folder     TEXT NOT NULL DEFAULT '',   -- carpeta virtual, ej. "fotos/2024" ('' = raíz)
  size       INTEGER NOT NULL,
  mime       TEXT NOT NULL DEFAULT 'application/octet-stream',
  nparts     INTEGER NOT NULL DEFAULT 1,
  status     TEXT NOT NULL DEFAULT 'uploading',  -- uploading | ready | incomplete
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS parts (
  file_id     TEXT NOT NULL,
  idx         INTEGER NOT NULL,
  account_id  INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  drive_id    TEXT,                      -- NULL mientras la parte no terminó de subirse
  session_url TEXT,                      -- sesión de subida reanudable de Google
  PRIMARY KEY (file_id, idx)
);

CREATE TABLE IF NOT EXISTS folders (
  user_id INTEGER NOT NULL,
  path    TEXT NOT NULL,
  PRIMARY KEY (user_id, path)
);

CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id, folder);
CREATE INDEX IF NOT EXISTS idx_parts_account ON parts(account_id);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
