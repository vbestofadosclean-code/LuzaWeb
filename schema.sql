CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  bio TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  website TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at TIMESTAMPTZ,
  trashed_at TIMESTAMPTZ
);

ALTER TABLE projects ADD COLUMN IF NOT EXISTS trashed_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS files (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, path)
);

CREATE TABLE IF NOT EXISTS project_folders (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, path)
);

CREATE TABLE IF NOT EXISTS commits (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  snapshot JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deployments (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  commit_id BIGINT NOT NULL REFERENCES commits(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('BUILDING','LIVE','FAILED')),
  message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS project_databases (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'main',
  schema_name TEXT NOT NULL DEFAULT '',
  db_username TEXT NOT NULL DEFAULT '',
  db_password_cipher TEXT NOT NULL DEFAULT '',
  provisioned_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS database_tables (
  id BIGSERIAL PRIMARY KEY,
  database_id BIGINT NOT NULL REFERENCES project_databases(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  columns JSONB NOT NULL DEFAULT '[]'::jsonb,
  physical_ready BOOLEAN NOT NULL DEFAULT FALSE,
  public_read BOOLEAN NOT NULL DEFAULT FALSE,
  public_insert BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(database_id, name)
);

CREATE TABLE IF NOT EXISTS database_records (
  id BIGSERIAL PRIMARY KEY,
  table_id BIGINT NOT NULL REFERENCES database_tables(id) ON DELETE CASCADE,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT 'Chave principal',
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL,
  key_type TEXT NOT NULL DEFAULT 'secret' CHECK (key_type IN ('secret','publishable')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
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
  id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'external', hostname TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 5432,
  database_name TEXT NOT NULL, username TEXT NOT NULL, password_cipher TEXT NOT NULL DEFAULT '',
  provider_project_id TEXT NOT NULL DEFAULT '',
  provider_branch_id TEXT NOT NULL DEFAULT '',
  connection_uri_cipher TEXT NOT NULL DEFAULT '',
  pooled_uri_cipher TEXT NOT NULL DEFAULT '',
  region_id TEXT NOT NULL DEFAULT '',
  pg_version INTEGER NOT NULL DEFAULT 16,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS project_env_groups (
  id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(project_id,name)
);
CREATE TABLE IF NOT EXISTS project_env_vars (
  id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, group_id BIGINT REFERENCES project_env_groups(id) ON DELETE SET NULL,
  name TEXT NOT NULL, value_cipher TEXT NOT NULL DEFAULT '', is_secret BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(project_id,name)
);
CREATE INDEX IF NOT EXISTS idx_env_groups_project ON project_env_groups(project_id,name);
CREATE INDEX IF NOT EXISTS idx_env_vars_project ON project_env_vars(project_id,name);
