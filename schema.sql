-- Aljibe — esquema D1 (SQLite)
-- Ejecutalo una sola vez en la consola de D1 (Workers & Pages → D1 → tu base → Console).

CREATE TABLE IF NOT EXISTS accounts (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  email          TEXT NOT NULL UNIQUE,
  refresh_token  TEXT NOT NULL,          -- cifrado con AES-GCM (clave derivada de SESSION_SECRET)
  root_folder_id TEXT,                   -- carpeta "Aljibe" dentro de ese Drive
  quota_limit    INTEGER,                -- bytes totales (NULL = sin límite informado)
  quota_usage    INTEGER,                -- bytes usados (Drive + Gmail + Fotos)
  quota_at       INTEGER,                -- epoch (s) de la última consulta de cuota
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id         TEXT PRIMARY KEY,           -- UUID
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
  path TEXT PRIMARY KEY
);

CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder);
CREATE INDEX IF NOT EXISTS idx_parts_account ON parts(account_id);
