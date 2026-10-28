PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  bio TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  website TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at TEXT,
  trashed_at TEXT
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, path)
);

CREATE TABLE IF NOT EXISTS project_folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, path)
);

CREATE TABLE IF NOT EXISTS commits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  snapshot TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT commits_id_project_id_unique UNIQUE(id, project_id)
);

CREATE TABLE IF NOT EXISTS deployments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  commit_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('BUILDING','LIVE','FAILED')),
  message TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  FOREIGN KEY (commit_id, project_id) REFERENCES commits(id, project_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS project_databases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'main',
  schema_name TEXT NOT NULL DEFAULT '',
  db_username TEXT NOT NULL DEFAULT '',
  db_password_cipher TEXT NOT NULL DEFAULT '',
  provisioned_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS database_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  database_id INTEGER NOT NULL REFERENCES project_databases(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  columns TEXT NOT NULL DEFAULT '[]',
  physical_ready INTEGER NOT NULL DEFAULT 0,
  public_read INTEGER NOT NULL DEFAULT 0,
  public_insert INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(database_id, name)
);

CREATE TABLE IF NOT EXISTS database_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  table_id INTEGER NOT NULL REFERENCES database_tables(id) ON DELETE CASCADE,
  data TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT 'Chave principal',
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL,
  key_type TEXT NOT NULL DEFAULT 'secret',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_trash ON projects(user_id, trashed_at);
CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id, path);
CREATE INDEX IF NOT EXISTS idx_commits_project ON commits(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployments_project ON deployments(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_db_tables_database ON database_tables(database_id, name);
CREATE INDEX IF NOT EXISTS idx_db_records_table ON database_records(table_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_project ON api_keys(project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_project_folders_project ON project_folders(project_id, path);

CREATE TABLE IF NOT EXISTS project_database_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'external', hostname TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 5432,
  database_name TEXT NOT NULL, username TEXT NOT NULL, password_cipher TEXT NOT NULL DEFAULT '',
  provider_project_id TEXT NOT NULL DEFAULT '',
  provider_branch_id TEXT NOT NULL DEFAULT '',
  connection_uri_cipher TEXT NOT NULL DEFAULT '',
  pooled_uri_cipher TEXT NOT NULL DEFAULT '',
  region_id TEXT NOT NULL DEFAULT '',
  pg_version INTEGER NOT NULL DEFAULT 16,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS project_env_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(project_id,name)
);
CREATE TABLE IF NOT EXISTS project_env_vars (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, group_id INTEGER REFERENCES project_env_groups(id) ON DELETE SET NULL,
  name TEXT NOT NULL, value_cipher TEXT NOT NULL DEFAULT '', is_secret INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(project_id,name)
);
CREATE INDEX IF NOT EXISTS idx_env_groups_project ON project_env_groups(project_id,name);
CREATE INDEX IF NOT EXISTS idx_env_vars_project ON project_env_vars(project_id,name);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  reset_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_reset_at ON auth_rate_limits(reset_at);

CREATE TABLE IF NOT EXISTS api_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  reset_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_rate_limits_reset_at ON api_rate_limits(reset_at);

-- Shared cooldowns prevent one webhook alert storm per serverless instance.
CREATE TABLE IF NOT EXISTS operational_alert_cooldowns (
  event_key TEXT PRIMARY KEY,
  last_sent_at BIGINT NOT NULL
);

-- Persistent reservations prevent concurrent requests from provisioning duplicate
-- provider resources and keep failed cleanup visible for operator reconciliation.
CREATE TABLE IF NOT EXISTS neon_provision_reservations (
  project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','failed','cleanup_required')),
  provider_project_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_neon_provision_reservations_user_state ON neon_provision_reservations(user_id, state);
CREATE INDEX IF NOT EXISTS idx_neon_provision_reservations_state ON neon_provision_reservations(state);


-- Durable project lifecycle operations. A Neon project is never removed from the
-- internal inventory until the provider confirms deletion; pending operations
-- block restore and duplicate deletion after timeouts or instance restarts.
CREATE TABLE IF NOT EXISTS project_lifecycle_operations (
  project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation TEXT NOT NULL DEFAULT 'delete_neon_project' CHECK (operation IN ('delete_neon_project')),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','cleanup_required')),
  provider_project_id TEXT NOT NULL DEFAULT '',
  last_error_code TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_lifecycle_operations_state ON project_lifecycle_operations(state, updated_at);

