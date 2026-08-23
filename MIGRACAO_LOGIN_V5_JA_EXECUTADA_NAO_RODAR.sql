-- V5 — USUÁRIOS, SENHAS E SESSÕES
-- Execute UMA VEZ no Console do D1 antes de subir os arquivos da V5.

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','common')),
  employee_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (employee_id) REFERENCES employees(id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('MATHEUS.SALDANHA','f2c390575226b7b845e2e7c3cfd9a69a71c480cde783d8f7ef527494851d2045','619695cfb3f7a8170acd06b3e7efa5a5','common',(SELECT id FROM employees WHERE name='MATHEUS SALDANHA FERREIRA' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('CRYSLARA.ANJOS','587c296c9d7d749192e4e9983343a30b5e1706b492f6b2f0f37ea2adbf98e51a','bdedd2c2fb7c09e461ab216243f61c7a','common',(SELECT id FROM employees WHERE name='CRYSLARA RODRIGUES DOS ANJOS' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('KEVEN.OLIVEIRA','0ab07b0aea7c3e728ced15e571bdd52b586fc7d7b129b360d0b2d722e9b552a9','b4f8ab1bcc747346212925f4d014f3a7','common',(SELECT id FROM employees WHERE name='KEVEN WILLIAN REIS OLIVEIRA' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('EDINALDO.CABRAL','5ab494a8aa0d315e3011e763cd628335232f7bd874c793055796b7a9ff418dd3','2cb626ce9bfef443746122b042299a0d','common',(SELECT id FROM employees WHERE name='EDINALDO DE MOURA CABRAL' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('UBIRATAN.TELES','0b18c36b7907d80a37963772243e3725fc4248a16a7b85b303de6b9373fe55fb','eb2586f29a5742d10a051636584a3e3d','common',(SELECT id FROM employees WHERE name='UBIRATAN SILVA TELLES' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

INSERT INTO users (username,password_hash,salt,role,employee_id,active)
VALUES ('LARA.RODRIGUES','71f630e82f8a82cd9bc950f7691c052e7b4559c08ab29cc07ebe715e202fea41','2d452c577620ee636da5947d29e343d8','admin',(SELECT id FROM employees WHERE name='LARA CARVALHO RODRIGUES' LIMIT 1),1)
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt,role=excluded.role,employee_id=excluded.employee_id,active=1;

SELECT username, role, active FROM users ORDER BY role, username;
