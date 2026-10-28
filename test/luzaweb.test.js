import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { SQLitePool } from '../local-db.js';
import { validateSameOriginMutation } from '../request-security.js';
import { isPublicPostgresIp, normalizePostgresHostname, validatePostgresPort, resolvePublicPostgresTarget, buildPinnedPostgresClientConfig, consumePostgresConnectionTestLimit, isPostgresTargetSecurityError } from '../postgres-target-security.js';
import { normalizeApiErrorEnvelope } from '../api-errors.js';
import { getRequestClientIp, normalizeClientIp } from '../client-ip.js';
import { claimOperationalAlertCooldown, pruneOperationalAlertCooldowns } from '../operational-alerts.js';
import { validateSecretConfiguration } from '../secret-crypto.js';
import { hardenProjectDatabaseRoles } from '../postgres-role-hardening.js';
import { consumeResourceCreationLimit, parseNeonProjectCount, reserveNeonProvisionSlot, resourceQuotaLimits } from '../resource-limits.js';
import { classifyLifecycleDeleteOperation, lifecycleOperationBlocksRestore, NEON_DELETE_PENDING_STALE_MS } from '../project-lifecycle.js';
import { encryptBackupFile, decryptBackupFile, validateBackupPassphrase } from '../scripts/backup-crypto.mjs';
import { cleanChildEnv, parsePostgresConnectionUrl, pgClientEnv, safeBundleRelativePath } from '../scripts/backup-utils.mjs';

const root = new URL('..', import.meta.url);
const read = file => fs.readFile(new URL(file, root), 'utf8');

test('CSRF guard permits only exact same-origin browser mutations', () => {
  const makeReq = (method, headers = {}, protocol = 'https') => ({
    method,
    protocol,
    headers: { host: 'luzaweb.example', ...headers },
    get(name) { return this.headers[name.toLowerCase()]; }
  });
  assert.deepEqual(validateSameOriginMutation(makeReq('POST', { origin: 'https://luzaweb.example' })), { ok: true, reason: 'origin_match' });
  assert.deepEqual(validateSameOriginMutation(makeReq('PATCH', { origin: 'https://luzaweb.example:443', 'sec-fetch-site': 'same-origin' })), { ok: true, reason: 'origin_match' });
  assert.deepEqual(validateSameOriginMutation(makeReq('DELETE', { referer: 'https://luzaweb.example/account?tab=security' })), { ok: true, reason: 'referer_match' });
  assert.equal(validateSameOriginMutation(makeReq('POST', { origin: 'https://attacker.example' })).reason, 'origin_mismatch');
  assert.equal(validateSameOriginMutation(makeReq('POST', { origin: 'https://sub.luzaweb.example' })).reason, 'origin_mismatch');
  assert.equal(validateSameOriginMutation(makeReq('POST', { origin: 'null' })).reason, 'invalid_origin');
  assert.equal(validateSameOriginMutation(makeReq('POST', { origin: 'https://luzaweb.example', 'sec-fetch-site': 'cross-site' })).reason, 'fetch_metadata_cross_site');
  assert.equal(validateSameOriginMutation(makeReq('POST')).reason, 'origin_missing');
  assert.deepEqual(validateSameOriginMutation(makeReq('GET')), { ok: true, reason: 'safe_method' });
});

test('CSRF middleware covers every state-changing dashboard API route but not the public-key API', async () => {
  const server = await read('server.js');
  const guard = server.indexOf("app.use('/api', enforceSameOriginMutations)");
  const firstDashboardRoute = server.indexOf("app.post('/api/auth/register'");
  const publicApiMiddleware = server.indexOf("app.use('/v1'");
  assert.ok(guard > 0 && guard < firstDashboardRoute, 'guard must run before every dashboard API route');
  assert.ok(publicApiMiddleware > firstDashboardRoute, 'public /v1 API remains separately handled');
  assert.match(server, /code: 'CSRF_ORIGIN_REJECTED'/);
  assert.match(server, /method: req\.method/);
  assert.match(server, /reason: verdict\.reason/);
});

test('published project HTML stays sandboxed with an opaque origin separate from dashboard sessions', async () => {
  const server = await read('server.js');
  const published = server.slice(server.indexOf('async function servePublished'), server.indexOf("app.get('/sites/:slug/__luza_env.js'"));
  assert.match(published, /Content-Security-Policy', "sandbox allow-scripts allow-forms allow-popups/);
  assert.doesNotMatch(published, /sandbox[^\n]*allow-same-origin/);
  assert.doesNotMatch(published, /sandbox[^\n]*allow-top-navigation/);
  assert.match(server, /opaque origin and cannot pass this check/);
});

test('LUZAWEB interface keeps the requested navigation', async () => {
  const html = await read('public/index.html');
  for (const item of ['Dashboard', 'Projetos', 'Atividade', 'Editor', 'Lixeira', 'Conta']) {
    assert.match(html, new RegExp(item));
  }
  for (const section of ['landingView', 'authView', 'appView']) assert.match(html, new RegExp(`id=["']${section}["']`));
});

test('project workspace exposes Repository, Deploy, Database and API', async () => {
  const js = await read('public/app.js');
  for (const item of ['Repository', 'Deploy', 'Database', 'API']) assert.match(js, new RegExp(item));
  assert.match(js, /switchProjectSection/);
});

test('server defines persistent database and deployment tables', async () => {
  const schema = await read('schema.sql');
  for (const table of ['projects', 'deployments', 'project_databases', 'database_tables', 'database_records', 'api_keys']) {
    assert.match(schema, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  }
});

test('real publish route serves project snapshots', async () => {
  const server = await read('server.js');
  assert.match(server, /app\.post\('\/api\/projects\/:id\/deploy'/);
  assert.match(server, /app\.get\('\/sites\/:slug\//);
  assert.match(server, /status='LIVE'/);
  assert.equal((server.match(/await pruneProjectHistory\(client, project\.id, HISTORY_RETENTION\)/g) || []).length, 2, 'commits and deployments both apply history retention');
});

test('trash, account and API routes are present', async () => {
  const server = await read('server.js');
  for (const route of ['/api/trash', '/api/account', '/api/projects/:id/database', '/api/projects/:id/api-keys', '/v1/:slug/:table']) {
    assert.match(server, new RegExp(route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('project view removes the global topbar and adds a resizable project navigation', async () => {
  const js = await read('public/app.js');
  const css = await read('public/styles.css');
  assert.match(js, /projectNavResizer/);
  assert.match(js, /projectNavWidth/);
  assert.match(js, /applyProjectNavWidth/);
  assert.match(css, /app-view\.project-open \.topbar\{display:none\}/);
  assert.match(css, /project-nav-resizer/);
});

test('repository file picker and line-number gutter are wired correctly', async () => {
  const js = await read('public/app.js');
  const css = await read('public/styles.css');
  assert.match(js, /id=\"fileInput\" type=\"file\" class=\"visually-hidden\" multiple/);
  assert.doesNotMatch(js, /id=\"fileInput\"[^>]*webkitdirectory/);
  assert.match(js, /addEventListener\('change',e=>importFiles\(e\)\)/);
  assert.match(js, /wrap=\"off\"/);
  assert.match(css, /editor-wrap\{display:grid;grid-template-columns:52px minmax\(0,1fr\)/);
});


test('repository uses create-folder, folder-local import, recursive tree and drag-and-drop move', async () => {
  const js = await read('public/app.js');
  const server = await read('server.js');
  const schema = await read('schema.sql');
  assert.match(js, /id="fileInput" type="file" class="visually-hidden" multiple/);
  assert.match(js, /id="createFolderBtn" class="btn secondary">＋ Pasta/);
  assert.doesNotMatch(js, /Importar pasta|folderInput|importFolderBtn|webkitdirectory/);
  assert.match(js, /class="folder-import" data-folder-path/);
  assert.match(js, /function importPathForFile\(file, targetFolder = ''\)/);
  assert.match(js, /async function createRepositoryFolder\(\)/);
  assert.match(js, /async function moveRepositoryFile\(fileId,targetFolder=''\)/);
  assert.match(js, /draggable="true" class="file-tree-file/);
  assert.match(js, /function encodeBinaryContent\(mime, base64\)/);
  assert.match(js, /function parseBinaryContent\(content\)/);
  assert.match(js, /async function importFiles\(e\)/);
  assert.match(server, /app\.post\('\/api\/projects\/:id\/folders'/);
  assert.match(server, /app\.patch\('\/api\/projects\/:id\/files\/:fileId\/path'/);
  assert.match(server, /function storedContentBytes\(content\)/);
  assert.match(server, /Buffer\.from\(binary\.base64, 'base64'\)/);
  assert.match(server, /function isPrivatePublishedPath\(filePath\)/);
  assert.match(server, /if \(isPrivatePublishedPath\(requestedPath\)\)/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS project_folders/);
  assert.doesNotMatch(js, /ALLOWED_EXTENSIONS_CLIENT/);
});

test('the first active project of each user receives starter files', async () => {
  const js = await read('public/app.js');
  const server = await read('server.js');
  assert.match(js, /const isFirstProject=!db\.projects\.some\(p=>Number\(p\.user_id\)===Number\(user\.id\)\)/);
  assert.match(js, /if\(isFirstProject\)localSeedProject\(db,project\.id\)/);
  assert.match(server, /SELECT COUNT\(\*\)::int AS count FROM projects WHERE user_id=\$1/);
  assert.match(server, /SELECT COUNT\(\*\)::int AS count FROM projects WHERE user_id=\$1 AND trashed_at IS NULL/);
  assert.match(server, /if \(activePerUser === 0\) await seedProject/);
});

test('account profile has editable extended information with server validation', async () => {
  const js = await read('public/app.js');
  const server = await read('server.js');
  const schema = await read('schema.sql');
  for (const id of ['accountUsername','accountBio','accountLocation','accountWebsite','accountPhone']) assert.ok(js.includes(`id="${id}"`));
  assert.match(js, /profile-avatar-large/);
  assert.match(js, /profile-stats/);
  assert.match(server, /username = String\(req\.body\.username/);
  assert.match(server, /website = String\(req\.body\.website/);
  assert.match(schema, /username TEXT NOT NULL DEFAULT ''/);
  assert.match(schema, /bio TEXT NOT NULL DEFAULT ''/);
});

test('line-number toggle removes the gutter without shrinking the editor or editing its contents', async () => {
  const js = await read('public/app.js');
  const css = await read('public/styles.css');
  assert.match(js, /wrap\.classList\.toggle\('line-numbers-hidden',!state\.lineNumbers\)/);
  assert.match(js, /nums\.hidden=!state\.lineNumbers/);
  assert.match(css, /editor-wrap\.line-numbers-hidden\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(css, /editor-wrap\.line-numbers-hidden \.line-nos\{display:none\}/);
});


test('database connection settings and project environment variable management are available', async () => {
  const server = await read('server.js');
  const cryptoModule = await read('secret-crypto.js');
  const js = await read('public/app.js');
  const pgSchema = await read('schema.sql');
  const sqliteSchema = await read('schema.sqlite.sql');
  for (const route of ['/api/projects/:id/database/connection', '/api/projects/:id/database/connection/test', '/api/projects/:id/environment', '/api/projects/:id/environment/groups', '/api/projects/:id/environment/variables']) assert.ok(server.includes(route));
  for (const label of ['Hostname', 'Internal Database URL', 'External Database URL', 'PSQL Command', 'Variáveis do ambiente', 'Criar grupo']) assert.ok(js.includes(label));
  for (const table of ['project_database_connections', 'project_env_groups', 'project_env_vars']) { assert.ok(pgSchema.includes(`CREATE TABLE IF NOT EXISTS ${table}`)); assert.ok(sqliteSchema.includes(`CREATE TABLE IF NOT EXISTS ${table}`)); }
  assert.match(cryptoModule, /createCipheriv\('aes-256-gcm'/);
});

test('Netlify deployment routes the public frontend to the backend Function', async () => {
  const config = await read('netlify.toml');
  const fn = await read('netlify/functions/server.mjs');
  const server = await read('server.js');
  assert.match(config, /publish = "public"/);
  assert.match(config, /from = "\/api\/\*"[\s\S]*?to = "\/.netlify\/functions\/server\/api\/:splat"/);
  assert.match(config, /from = "\/v1\/\*"[\s\S]*?to = "\/.netlify\/functions\/server\/v1\/:splat"/);
  assert.match(config, /from = "\/sites\/\*"[\s\S]*?to = "\/.netlify\/functions\/server\/sites\/:splat"/);
  assert.match(fn, /initDb\(\)/);
  assert.match(fn, /normalizeRewritePath/);
  assert.match(fn, /request_id: requestId/);
  assert.match(fn, /code: 'SERVICE_UNAVAILABLE'/);
  assert.doesNotMatch(fn, /error\?\.message \|\| error/);
  assert.match(server, /process\.env\.NETLIFY && !databaseConfigured/);
  assert.match(server, /validateSecretConfiguration\(\{ \.\.\.process\.env, JWT_SECRET \}\)/);
});

test('deploy button is enabled and the public site routes serve the latest snapshot', async () => {
  const js = await read('public/app.js');
  const server = await read('server.js');
  const envRoute = server.indexOf("app.get('/sites/:slug/__luza_env.js'");
  const wildcardRoute = server.indexOf("app.get('/sites/:slug/*splat'");
  assert.match(js, /id="repoDeployBtn" class="btn primary"/);
  assert.match(js, /async function deployProject\(\)/);
  assert.match(js, /api\(`\/api\/projects\/\$\{project\.id\}\/deploy`/);
  assert.match(server, /app\.post\('\/api\/projects\/:id\/deploy'/);
  assert.ok(envRoute >= 0 && wildcardRoute > envRoute, 'public env route must precede the catch-all site route');
  assert.match(server, /window\.LUZA_ENV = Object\.freeze/);
  assert.match(server, /is_secret=FALSE/);
});

test('PostgreSQL-backed project tables use isolated schemas and support record CRUD', async () => {
  const server = await read('server.js');
  const js = await read('public/app.js');
  const schema = await read('schema.sql');
  assert.match(server, /function projectSchemaName\(projectId\)/);
  assert.match(server, /async function provisionProjectDbConnection/);
  assert.match(server, /CREATE ROLE .*NOCREATEDB NOCREATEROLE NOINHERIT/);
  assert.match(server, /async function createPhysicalTable/);
  assert.match(server, /app\.post\('\/api\/projects\/:id\/database\/tables'/);
  assert.match(server, /app\.get\('\/api\/projects\/:id\/database\/tables\/:tableId\/records'/);
  assert.match(server, /app\.post\('\/api\/projects\/:id\/database\/tables\/:tableId\/records'/);
  assert.match(server, /app\.put\('\/api\/projects\/:id\/database\/tables\/:tableId\/records\/:recordId'/);
  assert.match(server, /app\.delete\('\/api\/projects\/:id\/database\/tables\/:tableId\/records\/:recordId'/);
  assert.match(js, /function openRecordDialog\(table, record=null\)/);
  assert.match(js, /edit-record/);
  assert.match(schema, /physical_ready BOOLEAN NOT NULL DEFAULT FALSE/);
});

test('public API keys are permission-limited and private keys can update/delete records', async () => {
  const server = await read('server.js');
  const js = await read('public/app.js');
  const schema = await read('schema.sql');
  assert.match(server, /replace\(\/\^Bearer\\s\+\/i, ''\)/);
  assert.match(server, /key_type === 'publishable'.*public_read/s);
  assert.match(server, /key_type === 'publishable'.*public_insert/s);
  assert.match(server, /Uma chave pública não pode actualizar registos/);
  assert.match(server, /Uma chave pública não pode eliminar registos/);
  assert.match(server, /app\.put\('\/v1\/:slug\/:table\/:recordId'/);
  assert.match(js, /Chave pública limitada/);
  assert.match(schema, /key_type TEXT NOT NULL DEFAULT 'secret' CHECK \(key_type IN \('secret','publishable'\)\)/);
});

test('Netlify SPA fallback does not override existing JavaScript, CSS or image files', async () => {
  const config = await read('netlify.toml');
  const fallback = config.slice(config.lastIndexOf('[[redirects]]'));
  assert.match(fallback, /from = "\/\*"/);
  assert.match(fallback, /to = "\/index\.html"/);
  assert.doesNotMatch(fallback, /force = true/);
});


test('PostgreSQL string IDs are handled when selecting and saving repository files', async () => {
  const js = await read('public/app.js');
  assert.match(js, /files\.find\(f=>String\(f\.id\)===String\(state\.currentFile\)\)/);
  assert.match(js, /String\(file\.id\)===String\(state\.currentFile\)/);
  assert.match(js, /async function saveCurrentFile[\s\S]*?files\.find\(f=>String\(f\.id\)===String\(state\.currentFile\)\)/);
});

test('repository supports Ctrl+X and Ctrl+V file moves without intercepting editor text shortcuts', async () => {
  const js = await read('public/app.js');
  const css = await read('public/styles.css');
  assert.match(js, /cutFileId/);
  assert.match(js, /selectedFolderPath/);
  assert.match(js, /if\(key==='x'\)/);
  assert.match(js, /key==='v'&&state\.cutFileId!==null/);
  assert.match(js, /isTextEditingTarget\)return/);
  assert.match(css, /\.file-tree-file\.cut-pending/);
  assert.match(css, /\.folder-main\.selected-folder/);
});

test('credential-like environment variables are always protected from static publishing', async () => {
  const server = await read('server.js');
  const js = await read('public/app.js');
  assert.match(server, /function isSensitiveEnvName\(name\)/);
  assert.match(server, /Boolean\(row\.is_secret\) \|\| isSensitiveEnvName\(row\.name\)/);
  assert.match(server, /result\.rows\.filter\(row => !isSensitiveEnvName\(row\.name\)\)/);
  assert.match(server, /const isSecret=Boolean\(req\.body\.is_secret\) \|\| isSensitiveEnvName\(name\)/);
  assert.match(js, /function isSensitiveEnvName\(name\)/);
  assert.match(js, /secretInput\.disabled=forced/);
});

test('SQLite schema persists projects, files, database records, environment variables and API keys', async () => {
  const tempDir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'luzaweb-test-'));
  const filename = path.join(tempDir, 'luzaweb.sqlite');
  let pool = new SQLitePool(filename);
  try {
    pool.exec(await read('schema.sqlite.sql'));
    const user = await pool.query(
      'INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id',
      ['Teste', 'teste@example.invalid', 'hash']
    );
    const userId = user.rows[0].id;
    const project = await pool.query(
      'INSERT INTO projects(user_id,name,slug) VALUES($1,$2,$3) RETURNING id',
      [userId, 'Site de teste', 'site-de-teste']
    );
    const projectId = project.rows[0].id;
    await pool.query('INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4)', [projectId, 'index.html', '<h1>Teste</h1>', 14]);
    const db = await pool.query('INSERT INTO project_databases(project_id,name,schema_name) VALUES($1,$2,$3) RETURNING id', [projectId, 'main', `luza_project_${projectId}`]);
    const table = await pool.query('INSERT INTO database_tables(database_id,name,columns) VALUES($1,$2,$3) RETURNING id', [db.rows[0].id, 'clientes', JSON.stringify([{name:'nome',type:'text',required:true}])]);
    await pool.query('INSERT INTO database_records(table_id,data) VALUES($1,$2) RETURNING id', [table.rows[0].id, JSON.stringify({nome:'Ana'})]);
    await pool.query('INSERT INTO project_env_groups(project_id,name) VALUES($1,$2)', [projectId, 'Produção']);
    await pool.query('INSERT INTO project_env_vars(project_id,name,value_cipher,is_secret) VALUES($1,$2,$3,$4)', [projectId, 'DATABASE_URL', 'ciphertext', 1]);
    await pool.query('INSERT INTO api_keys(project_id,label,token_hash,token_hint,key_type) VALUES($1,$2,$3,$4,$5)', [projectId, 'Teste', 'hashed-token', '1234', 'secret']);
    await pool.end();
    pool = new SQLitePool(filename);
    const files = await pool.query('SELECT path,content FROM files WHERE project_id=$1', [projectId]);
    const records = await pool.query('SELECT data FROM database_records WHERE table_id=$1', [table.rows[0].id]);
    const env = await pool.query('SELECT name,is_secret FROM project_env_vars WHERE project_id=$1', [projectId]);
    const keys = await pool.query('SELECT label FROM api_keys WHERE project_id=$1', [projectId]);
    assert.equal(files.rows[0].path, 'index.html');
    assert.equal(files.rows[0].content, '<h1>Teste</h1>');
    assert.deepEqual(records.rows[0].data, {nome:'Ana'});
    assert.equal(env.rows[0].name, 'DATABASE_URL');
    assert.equal(Number(env.rows[0].is_secret), 1);
    assert.equal(keys.rows[0].label, 'Teste');
  } finally {
    await pool.end();
    fsSync.rmSync(tempDir, { recursive: true, force: true });
  }
});


test('static deployments require an exact root-level index.html in server and local mode', async () => {
  const server = await read('server.js');
  const js = await read('public/app.js');
  assert.match(server, /file\.path === 'index\.html'/);
  assert.match(js, /f\.path==='index\.html'/);
  assert.match(server, /com esse nome exacto/);
  assert.match(js, /com esse nome exacto/);
});

test('LUZAWEB is identified as Version 1 and README documents the real Neon setup', async () => {
  const pkg = JSON.parse(await read('package.json'));
  const html = await read('public/index.html');
  const readme = await read('README.md');
  const env = await read('.env.example');
  assert.equal(pkg.version, '1.0.0');
  assert.match(html, /LUZAWEB — Versão 1/);
  assert.match(readme, /LUZAWEB — Versão 1/);
  for (const key of ['DATABASE_URL', 'JWT_SECRET', 'NEON_API_KEY']) {
    assert.match(readme, new RegExp(key));
    assert.match(env, new RegExp(key));
  }
});

test('repository README preview only uses an actual README or available project metadata', async () => {
  const js = await read('public/app.js');
  assert.match(js, /function buildProjectReadme\(project, files\)/);
  assert.match(js, /files\.find\(file=>String\(file\.path\|\|''\)\.toLowerCase\(\)==='readme\.md'\)/);
  assert.match(js, /O ficheiro README\.md existe, mas ainda está vazio\./);
  assert.match(js, /Este projecto ainda não contém ficheiros\./);
  assert.match(js, /Não foram acrescentadas funcionalidades, variáveis ou instruções que não estejam registadas\./);
});

test('Database is split into a creation page, a database overview and a separate table page', async () => {
  const js = await read('public/app.js');
  const css = await read('public/styles.css');
  assert.match(js, /state\.databaseScreen==='create'/);
  assert.match(js, /state\.databaseScreen==='tables'/);
  assert.match(js, /id="databaseCreateForm"/);
  assert.match(js, /id="databaseTablesBtn"[^>]*>Tabela<\/button>/);
  assert.match(js, /id="newTableBtn">＋ Criar nova tabela<\/button>/);
  assert.match(js, /\$\('#databaseTablesBtn'\)\?\.addEventListener\('click'/);
  assert.match(js, /\$\('#newTableBtn'\)\?\.addEventListener\('click',openDbTableDialog\)/);
  assert.match(js, /A ligação guardada ainda não confirma uma base de dados pronta para gerir tabelas/);
  for (const label of ['Hostname', 'Port', 'Database', 'Username', 'Password', 'Internal Database URL', 'External Database URL', 'PSQL Command']) {
    assert.match(js, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(css, /\.database-table-dialog\{[^}]*resize:none/s);
  assert.match(css, /\.database-table-dialog\{[^}]*max-height:88vh/s);
});

test('Neon provisioning uses server-side API credentials and routes table operations to each project database', async () => {
  const server = await read('server.js');
  assert.match(server, /process\.env\.NEON_API_KEY/);
  assert.match(server, /neonApiRequest\('\/projects',\s*\{\s*method:\s*'POST'/);
  assert.match(server, /waitForNeonConnectionUri\(/);
  assert.match(server, /await verificationClient\.query\('SELECT 1'\)/);
  assert.match(server, /new Pool\(\{ connectionString: uri/);
  assert.match(server, /projectPhysicalTableRefFor\(req\.apiProject\.id, table\.name, store\.external\)/);
  assert.match(server, /insertPhysicalRecord\(store\.executor, req\.apiProject\.id, table, data, \{ external: store\.external \}\)/);
});

test('Netlify PostgreSQL deployment does not statically bundle the local SQLite adapter', async () => {
  const server = await read('server.js');
  assert.doesNotMatch(server, /import\s+\{\s*SQLitePool\s*\}\s+from\s+['"]\.\/local-db\.js['"]/);
  assert.match(server, /const localDbModulePath = ['"]\.\/local-db\.js['"];\s*const \{ SQLitePool \} = await import\(localDbModulePath\)/);
  assert.match(server, /if \(!pool\) \{/);
});


test('server path resolution works with Netlify CommonJS function bundles', async () => {
  const server = await read('server.js');
  assert.doesNotMatch(server, /fileURLToPath\(import\.meta\.url\)/);
  assert.match(server, /const __dirname = path\.resolve\(process\.cwd\(\)\)/);
});

test('database initialization failures can be retried by warm server and Netlify Function instances', async () => {
  const server = await read('server.js');
  const fn = await read('netlify/functions/server.mjs');
  assert.match(server, /dbInitializationPromise = attempt\.catch\(error => \{\s*dbInitializationPromise = undefined;/);
  assert.match(fn, /initialization = attempt\.catch\(error => \{\s*initialization = undefined;/);
});

test('registration and login expose actionable server-side diagnostics without leaking credentials', async () => {
  const server = await read('server.js');
  assert.match(server, /registration_failed/);
  assert.match(server, /login_failed/);
  assert.doesNotMatch(server, /console\.(?:error|warn)\(['"](?:Registration failed:|Login failed:)/);
  assert.match(server, /Este email já está registado/);
  assert.match(server, /Não foi possível iniciar sessão\. Consulta os logs do servidor/);
  assert.match(server, /setAuthCookie\(res, rows\[0\]\)/);
  assert.match(server, /app\.get\('\/api\/auth\/me', requireAuth/);
});

test('account security enforces stronger passwords, bounded rate limits and revocable sessions', async () => {
  const server = await read('server.js');
  const html = await read('public/app.js');
  assert.match(server, /password\.length < 12/);
  assert.match(server, /Buffer\.byteLength\(password, 'utf8'\) > 72/);
  assert.match(server, /max: 10, windowMs: 10 \* 60 \* 1000/);
  assert.match(server, /max: 5, windowMs: 15 \* 60 \* 1000/);
  assert.match(server, /token_version=token_version\+1/);
  assert.match(server, /SELECT token_version FROM users WHERE id=\$1/);
  assert.match(server, /clearAuthCookie\(res\)/);
  assert.match(html, /minlength="12" maxlength="72"/);
});

test('project and database record routes scope access to the authenticated owner', async () => {
  const server = await read('server.js');
  assert.match(server, /async function getProject\(projectId, userId[\s\S]*?WHERE id=\$1 AND user_id=\$2/);
  assert.match(server, /async function getDbTable\(tableId, projectId\)[\s\S]*?WHERE t\.id=\$1 AND d\.project_id=\$2/);
  const projectRoutes = server.split("app.get('/api/projects/:id', requireAuth")[1].split("app.get('/api/health'")[0];
  assert.match(projectRoutes, /getProject\(req\.params\.id, req\.user\.id\)/);
  assert.match(server, /UPDATE database_records SET data=\$1::jsonb,updated_at=NOW\(\) WHERE id=\$2 AND table_id=\$3/);
  assert.match(server, /DELETE FROM database_records WHERE id=\$1 AND table_id=\$2/);
  assert.match(server, /database_tables WHERE database_id=\$1 AND name=\$2/);
});

test('repository path validation rejects traversal, absolute paths, control characters and overlong paths', async () => {
  const server = await read('server.js');
  assert.match(server, /function cleanPath\(input\)[\s\S]*?value\.startsWith\('\/'\)/);
  assert.match(server, /rawParts\.some\(part => part === '\.' \|\| part === '\.\.'/);
  assert.match(server, /value\.length > 180/);
  assert.match(server, /function allowedFile\(filePath\) \{ return Boolean\(cleanPath\(filePath\)\); \}/);
});

test('commits, restores and deployments enforce file count, per-file and project size limits', async () => {
  const server = await read('server.js');
  assert.match(server, /const MAX_FILE_BYTES = 300_000/);
  assert.match(server, /const MAX_FILES_PER_PROJECT = 120/);
  assert.match(server, /const MAX_PROJECT_BYTES = 5_000_000/);
  assert.match(server, /O projeto excede os limites de ficheiros, caminhos ou tamanho/);
  assert.match(server, /O commit contém caminhos inválidos ou excede os limites atuais do projeto/);
  assert.match(server, /O projeto excede os limites de ficheiros, caminhos ou tamanho e não pode ser publicado/);
});

test('published sites deny private files and secret-like paths', async () => {
  const server = await read('server.js');
  assert.match(server, /function isPrivatePublishedPath\(filePath\)/);
  assert.match(server, /credentials/);
  assert.match(server, /service\[-_\]\?account/);
  assert.match(server, /if \(isPrivatePublishedPath\(requestedPath\)\) return res\.status\(404\)/);
  assert.match(server, /if \(parts\.some\(part => part\.startsWith\('\.'\) && part !== '\.well-known'\)\) return true/);
});

test('database credentials remain server-side and JWT/encryption keys are separate', async () => {
  const server = await read('server.js');
  const cryptoModule = await read('secret-crypto.js');
  const env = await read('.env.example');
  assert.match(cryptoModule, /createCipheriv\('aes-256-gcm'/);
  assert.match(cryptoModule, /createDecipheriv\('aes-256-gcm'/);
  assert.match(cryptoModule, /SECRET_ENCRYPTION_KEY/);
  assert.match(cryptoModule, /LEGACY_SECRET_ENCRYPTION_KEY/);
  assert.match(cryptoModule, /SECRET_ENCRYPTION_KEY tem de ser diferente de JWT_SECRET/);
  assert.match(cryptoModule, /JWT_SECRET é obrigatória em produção/);
  assert.match(server, /validateSecretConfiguration/);
  assert.match(server, /process\.env\.NEON_API_KEY/);
  assert.match(env, /keep the same value across deployments/);
  assert.match(env, /NEON_API_KEY=replace-with-a-real-neon-api-key/);
});

test('schema migrations are additive and database provisioning errors are surfaced safely', async () => {
  const server = await read('server.js');
  assert.match(server, /ALTER TABLE users ADD COLUMN IF NOT EXISTS/);
  assert.match(server, /ALTER TABLE \$\{tableName\} ADD COLUMN IF NOT EXISTS/);
  assert.match(server, /O utilizador PostgreSQL configurado em DATABASE_URL não tem permissões/);
  assert.match(server, /O serviço de bases de dados não está devidamente configurado/);
  assert.match(server, /Não foi possível criar a base de dados do projeto/);
});


test('login rate limiting counts failed attempts in shared database storage', async () => {
  const server = await read('server.js');
  const schema = await read('schema.sql');
  assert.match(server, /async function recordAuthFailure/);
  assert.match(server, /async function clearAuthEmailFailures/);
  assert.match(server, /async function registrationRateLimit/);
  assert.match(server, /app\.post\('\/api\/auth\/register', registrationRateLimit/);
  assert.match(server, /DELETE FROM auth_rate_limits WHERE reset_at <= \$1/);
  assert.match(server, /ON CONFLICT\(bucket_key\) DO UPDATE SET/);
  assert.match(server, /if \(!rows\[0\] \|\| !\(await bcrypt\.compare/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS auth_rate_limits/);
  assert.match(server, /failed_login_counter_write_failed/);
});

test('full backup includes the internal database and all managed Neon project databases', async () => {
  const backup = await read('scripts/backup-all-postgres.mjs');
  const cryptoModule = await read('scripts/backup-crypto.mjs');
  const extract = await read('scripts/extract-backup-bundle.mjs');
  assert.match(backup, /FROM project_database_connections c/);
  assert.match(backup, /WHERE c\.provider='neon'/);
  assert.match(backup, /connection_uri_cipher/);
  assert.match(backup, /pg_dump/);
  assert.match(backup, /pg_restore/);
  assert.match(backup, /endsWith\('\.neon\.tech'\)/);
  assert.match(backup, /TLS|sslMode/);
  assert.match(backup, /manifest\.json/);
  assert.match(backup, /SHA256SUMS/);
  assert.match(backup, /pg_export_snapshot\(\)/);
  assert.match(backup, /--snapshot=\$\{snapshot\}/);
  assert.match(backup, /database\/project-roles\.sql/);
  assert.match(backup, /CREATE ROLE %I/);
  assert.match(backup, /encryptBackupFile/);
  assert.match(cryptoModule, /aes-256-gcm/);
  assert.match(cryptoModule, /scrypt/);
  assert.match(extract, /verifyChecksums/);
  assert.match(extract, /No database was changed|Nenhuma base de dados foi alterada/);
});

test('backup encryption is authenticated, streams files, and rejects wrong passphrases', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-backup-crypto-test-'));
  const input = path.join(dir, 'plain.tar.gz');
  const encrypted = path.join(dir, 'backup.lzwbackup');
  const output = path.join(dir, 'restored.tar.gz');
  const passphrase = 'a'.repeat(64);
  try {
    await fs.writeFile(input, Buffer.from('test backup payload\n'.repeat(500)));
    await encryptBackupFile(input, encrypted, passphrase);
    await decryptBackupFile(encrypted, output, passphrase);
    assert.deepEqual(await fs.readFile(output), await fs.readFile(input));
    await assert.rejects(() => decryptBackupFile(encrypted, path.join(dir, 'wrong.tar.gz'), 'b'.repeat(64)), /autenticar|backup cifrado|authenticate/i);
    assert.throws(() => validateBackupPassphrase('too-short'), /32 bytes/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('backup database URLs enforce PostgreSQL scheme, TLS and do not expose secrets to pg tools', () => {
  const parsed = parsePostgresConnectionUrl('postgresql://user%40name:p%40ss@db.example:5432/luzadb?sslmode=verify-full', { label: 'test' });
  assert.equal(parsed.user, 'user@name');
  assert.equal(parsed.password, 'p@ss');
  assert.equal(parsed.sslMode, 'verify-full');
  assert.throws(() => parsePostgresConnectionUrl('https://example.com/db'), /PostgreSQL/);
  assert.equal(safeBundleRelativePath('database/internal.dump'), true);
  assert.equal(safeBundleRelativePath('../secret'), false);
  assert.equal(safeBundleRelativePath('/etc/passwd'), false);
  const previous = { DATABASE_URL: process.env.DATABASE_URL, SECRET_ENCRYPTION_KEY: process.env.SECRET_ENCRYPTION_KEY };
  process.env.DATABASE_URL = 'postgresql://leak:should-not-pass@host/db';
  process.env.SECRET_ENCRYPTION_KEY = 'should-not-pass';
  try {
    const { env } = pgClientEnv('postgresql://user:password@db.example:5432/db?sslmode=require');
    assert.equal(env.PGPASSWORD, 'password');
    assert.equal(env.DATABASE_URL, undefined);
    assert.equal(env.SECRET_ENCRYPTION_KEY, undefined);
    assert.equal(env.PROJECT_RESTORE_DATABASE_URL, undefined);
    assert.equal(env.LUZAWEB_BACKUP_ENCRYPTION_PASSPHRASE, undefined);
    assert.equal(cleanChildEnv({ LUZAWEB_DATABASE_URL: 'secret', SAFE_VALUE: 'ok' }).LUZAWEB_DATABASE_URL, undefined);
  } finally {
    if (previous.DATABASE_URL === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = previous.DATABASE_URL;
    if (previous.SECRET_ENCRYPTION_KEY === undefined) delete process.env.SECRET_ENCRYPTION_KEY; else process.env.SECRET_ENCRYPTION_KEY = previous.SECRET_ENCRYPTION_KEY;
  }
});

test('restore scripts require a distinct empty recovery database and verify package hashes', async () => {
  const restore = await read('scripts/restore-postgres.sh');
  const projectRestore = await read('scripts/restore-project-postgres.sh');
  const implementation = await read('scripts/restore-dump.mjs');
  const extract = await read('scripts/extract-backup-bundle.mjs');
  assert.match(restore, /RESTORE_CONFIRM/);
  assert.match(restore, /PRODUCTION_DATABASE_URL/);
  assert.match(projectRestore, /PROJECT_PRODUCTION_DATABASE_URL/);
  assert.match(projectRestore, /PROJECT_RESTORE_DATABASE_URL/);
  assert.match(implementation, /identity\(source\) === identity\(target\)/);
  assert.match(implementation, /RESTORE_TARGET_CLUSTER_DEDICATED/);
  assert.match(implementation, /RESTORE_KIND/);
  assert.match(implementation, /project-roles\.sql/);
  assert.match(implementation, /--single-transaction/);
  assert.match(implementation, /--set=ON_ERROR_STOP=1/);
  assert.match(restore, /RESTORE_TARGET_CLUSTER_DEDICATED/);
  assert.match(implementation, /object_count/);
  assert.match(implementation, /pg_restore/);
  assert.match(implementation, /SHA256SUMS/);
  assert.doesNotMatch(implementation, /--clean/);
  assert.match(extract, /RESTORE_WORK_DIR já existe/);
  assert.match(extract, /supporting_files/);
  assert.match(extract, /project-roles\.sql/);
});

test('GitHub Actions schedules encrypted full backups and uploads only encrypted files', async () => {
  const workflow = await read('.github/workflows/nightly-backup.yml');
  const pkg = JSON.parse(await read('package.json'));
  assert.match(workflow, /schedule:/);
  assert.match(workflow, /npm run backup:all/);
  assert.match(workflow, /LUZAWEB_DATABASE_URL/);
  assert.match(workflow, /LUZAWEB_BACKUP_ENCRYPTION_PASSPHRASE/);
  assert.match(workflow, /\.lzwbackup/);
  assert.match(workflow, /retention-days: 30/);
  assert.equal(pkg.scripts['backup:all'], 'node scripts/backup-all-postgres.mjs');
  assert.equal(pkg.scripts['backup:extract'], 'node scripts/extract-backup-bundle.mjs');
});

test('project deployment snapshots are constrained to the same project at database level', async () => {
  const schema = await read('schema.sqlite.sql');
  const server = await read('server.js');
  assert.match(schema, /CONSTRAINT commits_id_project_id_unique UNIQUE\(id, project_id\)/);
  assert.match(schema, /FOREIGN KEY \(commit_id, project_id\) REFERENCES commits\(id, project_id\)/);
  assert.match(server, /WHERE d\.project_id<>c\.project_id LIMIT 1/);
  assert.match(server, /deployments_commit_project_fk/);

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-isolation-'));
  const db = new SQLitePool(path.join(dir, 'test.sqlite'));
  try {
    db.exec(schema);
    await db.query("INSERT INTO users(name,email,password_hash) VALUES('User A','a@example.test','hash')");
    await db.query("INSERT INTO users(name,email,password_hash) VALUES('User B','b@example.test','hash')");
    await db.query("INSERT INTO projects(user_id,name,slug) VALUES(1,'Project A','project-a')");
    await db.query("INSERT INTO projects(user_id,name,slug) VALUES(2,'Project B','project-b')");
    await db.query("INSERT INTO commits(project_id,message,snapshot) VALUES(1,'A','{}')");
    await db.query("INSERT INTO commits(project_id,message,snapshot) VALUES(2,'B','{}')");
    await assert.rejects(
      db.query("INSERT INTO deployments(project_id,commit_id,status) VALUES(1,2,'LIVE')"),
      /FOREIGN KEY constraint failed/i
    );
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('monitoring exposes liveness/readiness, request IDs, safe logs and optional webhook alerts', async () => {
  const server = await read('server.js');
  const env = await read('.env.example');
  const readme = await read('README.md');
  assert.match(server, /app\.get\('\/api\/health\/live'/);
  assert.match(server, /app\.get\('\/api\/health\/ready'/);
  assert.match(server, /X-Request-ID/);
  assert.match(server, /duration_ms/);
  assert.match(server, /ALERT_COOLDOWN_MS = boundedIntegerEnv\('ALERT_COOLDOWN_MS'/);
  assert.match(server, /claimOperationalAlertCooldown/);
  assert.match(server, /slow_http_request/);
  assert.match(server, /sendOperationalAlert\('http_5xx'/);
  assert.match(server, /sendOperationalAlert\('database_unavailable'/);
  assert.match(env, /ALERT_WEBHOOK_URL/);
  assert.match(readme, /monitor externo/);
});


test('performance settings bound database pools, query timeouts and external project pool cache', async () => {
  const server = await read('server.js');
  const env = await read('.env.example');
  const loadTest = await read('scripts/load-smoke.mjs');
  assert.match(server, /PG_POOL_MAX = boundedIntegerEnv\('PG_POOL_MAX', DEFAULT_POOL_MAX, 1, 20\)/);
  assert.match(server, /statement_timeout: PG_STATEMENT_TIMEOUT_MS/);
  assert.match(server, /query_timeout: Math.max\(PG_STATEMENT_TIMEOUT_MS, PG_MIGRATION_STATEMENT_TIMEOUT_MS\)/);
  assert.match(server, /options: '-c search_path=public'/);
  assert.match(server, /PG_MIGRATION_LOCK_TIMEOUT_MS = boundedIntegerEnv/);
  assert.match(server, /PG_MIGRATION_STATEMENT_TIMEOUT_MS = boundedIntegerEnv/);
  assert.match(server, /PROJECT_POOL_CACHE_MAX/);
  assert.match(server, /evictProjectPoolIfNeeded/);
  assert.match(loadTest, /LOAD_CONCURRENCY/);
  assert.match(loadTest, /p95/);
  assert.match(env, /PG_STATEMENT_TIMEOUT_MS/);
  assert.match(env, /PG_MIGRATION_LOCK_TIMEOUT_MS/);
  assert.match(env, /PG_MIGRATION_STATEMENT_TIMEOUT_MS/);
});

test('secret encryption is versioned and rotation script requires backup-conscious explicit confirmation', async () => {
  const cryptoModule = await read('secret-crypto.js');
  const rotation = await read('scripts/rotate-secrets.mjs');
  const readme = await read('README.md');
  assert.match(cryptoModule, /return `v2\./);
  assert.match(cryptoModule, /versioned \? 2 : 1/);
  assert.match(rotation, /ROTATE_SECRETS_CONFIRM !== 'YES'/);
  assert.match(rotation, /BEGIN/);
  assert.match(rotation, /ROLLBACK/);
  assert.match(rotation, /project_env_vars/);
  assert.match(readme, /LEGACY_SECRET_ENCRYPTION_KEY/);
});


test('legacy JWT-encrypted values require an explicit migration key and support versioned rotation', async () => {
  const oldEnv = {
    JWT_SECRET: process.env.JWT_SECRET,
    SECRET_ENCRYPTION_KEY: process.env.SECRET_ENCRYPTION_KEY,
    LEGACY_SECRET_ENCRYPTION_KEY: process.env.LEGACY_SECRET_ENCRYPTION_KEY,
    NODE_ENV: process.env.NODE_ENV,
    NETLIFY: process.env.NETLIFY,
    DATABASE_URL: process.env.DATABASE_URL
  };
  try {
    process.env.JWT_SECRET = 'old-jwt-secret-for-compatibility-tests';
    process.env.NODE_ENV = 'production';
    delete process.env.NETLIFY;
    delete process.env.DATABASE_URL;
    delete process.env.SECRET_ENCRYPTION_KEY;
    delete process.env.LEGACY_SECRET_ENCRYPTION_KEY;
    const { encryptSecret, decryptSecret } = await import('../secret-crypto.js');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', crypto.createHash('sha256').update(process.env.JWT_SECRET).digest(), iv);
    const data = Buffer.concat([cipher.update('legacy-secret-value', 'utf8'), cipher.final()]);
    const legacy = `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${data.toString('base64')}`;
    assert.throws(() => decryptSecret(legacy), /Não foi possível descodificar/,
      'JWT_SECRET must not be an implicit key for old ciphertexts in production');
    process.env.LEGACY_SECRET_ENCRYPTION_KEY = process.env.JWT_SECRET;
    assert.equal(decryptSecret(legacy), 'legacy-secret-value');

    process.env.SECRET_ENCRYPTION_KEY = 'first-encryption-key-at-least-32-characters';
    const firstVersion = encryptSecret('rotatable-secret');
    process.env.SECRET_ENCRYPTION_KEY = 'second-encryption-key-at-least-32-characters';
    process.env.LEGACY_SECRET_ENCRYPTION_KEY = 'first-encryption-key-at-least-32-characters';
    assert.equal(decryptSecret(firstVersion), 'rotatable-secret');
    const current = encryptSecret('new-secret');
    assert.equal(decryptSecret(current), 'new-secret');
  } finally {
    for (const [key, value] of Object.entries(oldEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('new secret encryption requires a dedicated key in production and keeps JWT_SECRET read-only for legacy data', async () => {
  const oldEnv = {
    JWT_SECRET: process.env.JWT_SECRET,
    SECRET_ENCRYPTION_KEY: process.env.SECRET_ENCRYPTION_KEY,
    LEGACY_SECRET_ENCRYPTION_KEY: process.env.LEGACY_SECRET_ENCRYPTION_KEY,
    NODE_ENV: process.env.NODE_ENV,
    NETLIFY: process.env.NETLIFY
  };
  try {
    const { encryptSecret, decryptSecret } = await import('../secret-crypto.js');
    process.env.JWT_SECRET = 'old-jwt-secret-for-compatibility-tests';
    delete process.env.SECRET_ENCRYPTION_KEY;
    delete process.env.LEGACY_SECRET_ENCRYPTION_KEY;
    delete process.env.NETLIFY;
    process.env.NODE_ENV = 'production';
    assert.throws(() => encryptSecret('must-fail'), /SECRET_ENCRYPTION_KEY é obrigatória/);

    process.env.NODE_ENV = 'development';
    const localCipher = encryptSecret('local-dev-secret');
    assert.equal(decryptSecret(localCipher), 'local-dev-secret');

    // A previous v2 ciphertext that used JWT_SECRET is only readable after an
    // operator explicitly supplies that old key through LEGACY_SECRET_ENCRYPTION_KEY.
    const iv = crypto.randomBytes(12);
    const versionedKey = crypto.createHash('sha256').update(`luzaweb-secret-encryption-v2:${process.env.JWT_SECRET}`).digest();
    const cipher = crypto.createCipheriv('aes-256-gcm', versionedKey, iv);
    const encrypted = Buffer.concat([cipher.update('old-v2-secret', 'utf8'), cipher.final()]);
    const legacyV2 = `v2.${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${encrypted.toString('base64')}`;
    process.env.SECRET_ENCRYPTION_KEY = 'current-independent-encryption-key-32bytes-min';
    assert.throws(() => decryptSecret(legacyV2), /Não foi possível descodificar/);
    process.env.LEGACY_SECRET_ENCRYPTION_KEY = process.env.JWT_SECRET;
    assert.equal(decryptSecret(legacyV2), 'old-v2-secret');
    process.env.SECRET_ENCRYPTION_KEY = process.env.JWT_SECRET;
    assert.throws(() => encryptSecret('same-key'), /diferente de JWT_SECRET/);
  } finally {
    for (const [key, value] of Object.entries(oldEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('snapshot retention keeps recent commits, recent deployments, and the latest LIVE snapshot', async () => {
  const { pruneProjectHistory, historyRetentionLimits } = await import('../history-retention.js');
  const filename = path.join(os.tmpdir(), `luza-history-retention-${crypto.randomUUID()}.sqlite`);
  const pool = new SQLitePool(filename);
  try {
    pool.exec(await read('schema.sqlite.sql'));
    await pool.query("INSERT INTO users(name,email,password_hash) VALUES('Teste','retention@example.test','hash')");
    await pool.query("INSERT INTO projects(user_id,name,slug) VALUES(1,'Retenção','retention-project')");
    const commitIds = [];
    for (let i = 1; i <= 20; i++) {
      const createdAt = `2026-01-01 00:00:${String(i).padStart(2, '0')}`;
      const result = await pool.query('INSERT INTO commits(project_id,message,snapshot,created_at) VALUES(1,$1,$2,$3) RETURNING id', [`commit-${i}`, JSON.stringify({ 'index.html': `<h1>${i}</h1>` }), createdAt]);
      commitIds.push(result.rows[0].id);
    }
    await pool.query("INSERT INTO deployments(project_id,commit_id,status,message,created_at) VALUES(1,$1,'LIVE','current live','2026-02-01 00:00:00')", [commitIds[0]]);
    for (let i = 2; i <= 14; i++) {
      const createdAt = `2026-03-${String(i).padStart(2, '0')} 00:00:00`;
      await pool.query("INSERT INTO deployments(project_id,commit_id,status,message,created_at) VALUES(1,$1,'FAILED','old attempt',$2)", [commitIds[i - 1], createdAt]);
    }
    const result = await pruneProjectHistory(pool, 1, { commitLimit: 5, deploymentLimit: 3 });
    const deployments = await pool.query('SELECT id,commit_id,status FROM deployments WHERE project_id=1 ORDER BY created_at DESC,id DESC');
    const commits = await pool.query('SELECT id FROM commits WHERE project_id=1 ORDER BY created_at DESC,id DESC');
    assert.equal(deployments.rows.length, 4, '3 recent deployment records plus latest LIVE are retained');
    assert.ok(deployments.rows.some(row => row.status === 'LIVE' && String(row.commit_id) === String(commitIds[0])));
    assert.ok(commits.rows.some(row => String(row.id) === String(commitIds[0])), 'snapshot used by latest LIVE deployment is preserved');
    assert.ok(commits.rows.some(row => String(row.id) === String(commitIds[19])), 'newest snapshot is preserved');
    assert.equal(commits.rows.length, 9, 'five latest commits plus four distinct commits still referenced by deployments');
    assert.equal(result.removedDeployments, 10);
    assert.equal(result.removedCommits, 11);
    assert.deepEqual(historyRetentionLimits({ COMMIT_RETENTION_PER_PROJECT: '900', DEPLOYMENT_RETENTION_PER_PROJECT: '1' }), { commitLimit: 200, deploymentLimit: 3 });
  } finally {
    await pool.end();
    fsSync.rmSync(filename, { force: true });
    fsSync.rmSync(`${filename}-wal`, { force: true });
    fsSync.rmSync(`${filename}-shm`, { force: true });
  }
});

test('API internal errors return a safe response and never expose raw provider/database error messages', async () => {
  const server = await read('server.js');
  const errorModule = await read('api-errors.js');
  assert.match(server, /function respondApiError\(req, res, error, publicMessage/);
  assert.match(server, /normalizeApiErrorEnvelope\(res\.statusCode, body, requestId\)/);
  assert.match(server, /request_id: req\.requestId/);
  assert.doesNotMatch(server, /res\.status\(500\)\.json\(\{ error: error\.message/);
  assert.doesNotMatch(server, /error: `Não foi possível ligar à base de dados: \$\{String\(error\.message/);
  assert.match(server, /app\.use\(\(error, req, res, next\) =>/);
  assert.match(errorModule, /SAFE_SERVER_MESSAGES/);
  assert.match(errorModule, /only a small allowlist of metadata|intentionally safe metadata/i);
});

test('API error envelope strips provider details and standardizes 5xx codes while retaining safe 4xx text', () => {
  const providerBody = normalizeApiErrorEnvelope(500, {
    error: 'password=super-secret; relation internal_table does not exist',
    code: '42P01', details: 'private provider detail', stack: 'db stack', host: 'internal.db'
  }, 'req-abc');
  assert.deepEqual(providerBody, {
    error: 'Ocorreu um erro interno. Tenta novamente mais tarde.',
    code: 'INTERNAL_ERROR', request_id: 'req-abc'
  });
  const gateway = normalizeApiErrorEnvelope(502, { error: 'provider said token=secret', detail: 'private' }, 'req-502');
  assert.equal(gateway.code, 'BAD_GATEWAY');
  assert.doesNotMatch(JSON.stringify(gateway), /token=secret|private/);
  const invalid = normalizeApiErrorEnvelope(400, { error: 'Indica um email válido.', code: 'INVALID_COLUMNS', detail: 'ignored' }, 'req-400');
  assert.deepEqual(invalid, { error: 'Indica um email válido.', code: 'INVALID_COLUMNS', request_id: 'req-400' });
  const throttled = normalizeApiErrorEnvelope(429, { error: 'Aguarda.', retry_after_seconds: 12 }, 'req-429');
  assert.equal(throttled.retry_after_seconds, 12);
  assert.equal(normalizeApiErrorEnvelope(413, { error: 'provider detail' }, 'req-413').code, 'PAYLOAD_TOO_LARGE');
});

test('production secret configuration requires a dedicated key, rejects whitespace keys and example JWTs', () => {
  const strongJwt = 'random-jwt-secret-that-is-more-than-32-bytes';
  const strongEncryption = 'different-encryption-key-that-is-also-32-bytes';
  assert.throws(() => validateSecretConfiguration({ NODE_ENV: 'production', JWT_SECRET: strongJwt, SECRET_ENCRYPTION_KEY: ' '.repeat(64) }), /SECRET_ENCRYPTION_KEY é obrigatória/);
  assert.throws(() => validateSecretConfiguration({ NODE_ENV: 'production', JWT_SECRET: strongJwt, SECRET_ENCRYPTION_KEY: strongJwt }), /diferente de JWT_SECRET/);
  assert.throws(() => validateSecretConfiguration({ NODE_ENV: 'production', JWT_SECRET: strongJwt, SECRET_ENCRYPTION_KEY: 'replace-with-a-different-random-secret-at-least-32-bytes' }), /não pode ser um valor de exemplo/);
  assert.throws(() => validateSecretConfiguration({ NODE_ENV: 'production', JWT_SECRET: 'replace-with-a-long-random-secret', SECRET_ENCRYPTION_KEY: strongEncryption }), /JWT_SECRET é obrigatória/);
  assert.deepEqual(validateSecretConfiguration({ NODE_ENV: 'production', JWT_SECRET: strongJwt, SECRET_ENCRYPTION_KEY: strongEncryption }), {
    production: true, encryptionSecret: strongEncryption, jwtSecret: strongJwt
  });
});

test('repository operations reject file/folder path collisions and restore only publishable snapshots', async () => {
  const server = await read('server.js');
  assert.match(server, /async function repositoryPathConflict\(projectId, targetPath, kind, excludeFileId = null, executor = pool\)/);
  assert.match(server, /MAX_FOLDERS_PER_PROJECT = 300/);
  assert.match(server, /O caminho entra em conflito com um ficheiro ou pasta existente/);
  assert.match(server, /Este snapshot não contém index\.html/);
  assert.match(server, /DELETE FROM project_folders WHERE project_id=\$1/);
  assert.match(server, /const restoredFolders = new Set\(\)/);
  assert.match(server, /await client\.query\('BEGIN'\)[\s\S]*?DELETE FROM files WHERE project_id=\$1[\s\S]*?await client\.query\('COMMIT'\)/);
});

test('PostgreSQL project roles are hardened to least privilege and fail closed on effective cross-schema access', async () => {
  const server = await read('server.js');
  const permissions = await read('postgres-role-hardening.js');
  assert.match(server, /hardenProjectDatabaseRoles/);
  assert.match(server, /async function hardenExistingProjectRoles\(executor = pool\)/);
  assert.match(permissions, /NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5/);
  assert.match(permissions, /REVOKE CREATE ON SCHEMA public FROM PUBLIC/);
  assert.match(permissions, /REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC/);
  assert.match(permissions, /ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC/);
  assert.match(permissions, /REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA/);
  assert.match(permissions, /REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA/);
  assert.match(permissions, /FROM pg_auth_members/);
  assert.match(permissions, /has_table_privilege/);
  assert.match(permissions, /has_sequence_privilege/);
  assert.match(permissions, /has_function_privilege/);
  assert.match(permissions, /LZW_PROJECT_ROLE_CROSS_SCHEMA/);
  assert.match(permissions, /ALTER ROLE .*IN DATABASE .*SET search_path TO/);
});

test('PostgreSQL role hardening revokes dangerous grants, restores only project CRUD and audits effective ACLs', async () => {
  const calls = [];
  const result = rows => ({ rows, rowCount: rows.length });
  const executor = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      calls.push({ sql: normalized, params });
      if (normalized.includes('WHERE rolname=current_user')) return result([{ oid: 1, rolname: 'luza_owner' }]);
      if (normalized.includes('FROM project_databases')) return result([
        { project_id: 7, schema_name: 'luza_project_7', db_username: 'lzw_project_7', db_password_cipher: 'cipher', provisioned_at: '2026-01-01' },
        { project_id: 8, schema_name: 'luza_project_8', db_username: '', db_password_cipher: '', provisioned_at: null }
      ]);
      if (normalized.includes('FROM pg_roles WHERE rolname=$1')) return result([{ oid: 701, rolname: 'lzw_project_7' }]);
      if (normalized.includes('FROM pg_namespace WHERE nspname=$1')) return result([{ oid: 801, nspowner: 1 }]);
      if (normalized.includes("SELECT 'schema' AS object_kind")) return result([]);
      if (normalized.includes('FROM pg_auth_members')) return result([]);
      if (normalized.startsWith('SELECT nspname FROM pg_namespace')) return result([{ nspname: 'public' }, { nspname: 'shared' }]);
      if (normalized.includes('has_table_privilege')) return result([]);
      if (normalized.includes('has_sequence_privilege')) return result([]);
      if (normalized.includes('has_function_privilege')) return result([]);
      if (normalized.includes('has_schema_privilege')) return result([]);
      return result([]);
    }
  };
  const report = await hardenProjectDatabaseRoles(executor, { databaseName: 'luza_internal' });
  assert.deepEqual(report, { inspected: 2, hardened: 1 });
  const statements = calls.map(call => call.sql);
  assert.ok(statements.includes('REVOKE CREATE ON SCHEMA public FROM PUBLIC'));
  assert.ok(statements.includes('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC'));
  assert.ok(statements.some(sql => sql.includes('NOCREATEDB NOCREATEROLE NOINHERIT') && sql.includes('NOBYPASSRLS')));
  assert.ok(statements.some(sql => sql.includes('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA "shared" FROM "lzw_project_7"')));
  assert.ok(statements.some(sql => sql.includes('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "luza_project_7"')));
  assert.ok(statements.some(sql => sql.includes('SET search_path TO \'luza_project_7\'')));
});

test('PostgreSQL role hardening fails closed for missing provisioned roles and effective cross-schema grants', async () => {
  const result = rows => ({ rows, rowCount: rows.length });
  const makeExecutor = ({ missingRole = false, relationLeak = false } = {}) => ({
    async query(sql) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      if (normalized.includes('WHERE rolname=current_user')) return result([{ oid: 1, rolname: 'luza_owner' }]);
      if (normalized.includes('FROM project_databases')) return result([
        { project_id: 12, schema_name: 'luza_project_12', db_username: 'lzw_project_12', db_password_cipher: 'cipher', provisioned_at: '2026-01-01' }
      ]);
      if (normalized.includes('FROM pg_roles WHERE rolname=$1')) return result(missingRole ? [] : [{ oid: 1201, rolname: 'lzw_project_12' }]);
      if (normalized.includes('FROM pg_namespace WHERE nspname=$1')) return result([{ oid: 1202, nspowner: 1 }]);
      if (normalized.includes("SELECT 'schema' AS object_kind")) return result([]);
      if (normalized.includes('FROM pg_auth_members')) return result([]);
      if (normalized.startsWith('SELECT nspname FROM pg_namespace')) return result([{ nspname: 'public' }]);
      if (normalized.includes('has_table_privilege')) return result(relationLeak ? [{ nspname: 'public', relname: 'users' }] : []);
      if (normalized.includes('has_sequence_privilege') || normalized.includes('has_function_privilege') || normalized.includes('has_schema_privilege')) return result([]);
      return result([]);
    }
  });
  await assert.rejects(
    hardenProjectDatabaseRoles(makeExecutor({ missingRole: true }), { databaseName: 'luza_internal' }),
    error => error.code === 'LZW_PROJECT_ROLE_OR_SCHEMA_MISSING'
  );
  const failures = [];
  await assert.rejects(
    hardenProjectDatabaseRoles(makeExecutor({ relationLeak: true }), { databaseName: 'luza_internal', onFailure: item => failures.push(item) }),
    error => error.code === 'LZW_PROJECT_ROLE_CROSS_SCHEMA_RELATION_ACCESS'
  );
  assert.equal(failures.at(-1)?.event, 'project_role_hardening_failed');
});

test('PostgreSQL startup migrations are serialized inside a transaction with safe savepoints', async () => {
  const server = await read('server.js');
  assert.match(server, /BEGIN[\s\S]*SET LOCAL lock_timeout[\s\S]*SET LOCAL statement_timeout[\s\S]*SET LOCAL search_path TO public[\s\S]*pg_advisory_xact_lock/);
  assert.match(server, /SAVEPOINT project_isolation_constraint_migration/);
  assert.match(server, /ROLLBACK TO SAVEPOINT project_isolation_constraint_migration/);
  assert.match(server, /migrateLogicalTablesToPostgres\(migrationExecutor, \{ manageTransaction: false \}\)/);
  assert.match(server, /await migrationExecutor\.query\('COMMIT'\)/);
});

test('public API rate limits are atomic and shared in persistent storage', async () => {
  const { consumePublicApiRateLimit, pruneExpiredApiRateLimits } = await import('../api-rate-limit.js');
  const schema = await read('schema.sqlite.sql');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-api-rate-limit-'));
  const db = new SQLitePool(path.join(dir, 'rate-limit.sqlite'));
  try {
    db.exec(schema);
    const options = { keyId: 7, projectId: 3, ip: '203.0.113.10', now: 1_000, perIpLimit: 2, perKeyLimit: 4, perProjectLimit: 10, windowMs: 60_000 };
    assert.equal((await consumePublicApiRateLimit(db, options)).allowed, true);
    assert.equal((await consumePublicApiRateLimit(db, options)).allowed, true);
    const blockedByIp = await consumePublicApiRateLimit(db, options);
    assert.equal(blockedByIp.allowed, false);
    assert.equal(blockedByIp.scope, 'ip');
    const anotherIp = await consumePublicApiRateLimit(db, { ...options, ip: '203.0.113.11' });
    assert.equal(anotherIp.allowed, true);
    const nextFromAnotherIp = await consumePublicApiRateLimit(db, { ...options, ip: '203.0.113.12' });
    assert.equal(nextFromAnotherIp.allowed, false);
    assert.equal(nextFromAnotherIp.scope, 'key');
    const stored = await db.query('SELECT bucket_key FROM api_rate_limits');
    assert.equal(stored.rows.some(row => row.bucket_key.includes('203.0.113.10')), false, 'raw IPs are not persisted');
    assert.ok(await pruneExpiredApiRateLimits(db, 100_000) >= 1);
    const reset = await consumePublicApiRateLimit(db, { ...options, now: 100_001 });
    assert.equal(reset.allowed, true);
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
  const server = await read('server.js');
  assert.match(server, /consumePublicApiRateLimit\(pool/);
  assert.match(server, /PUBLIC_API_RATE_LIMIT_PER_IP/);
  assert.match(server, /PRIVATE_API_RATE_LIMIT_PER_KEY/);
  assert.match(server, /PUBLIC_API_RATE_LIMIT_PER_PROJECT/);
  assert.match(server, /project_api_rate_limiter_unavailable/);
  assert.match(server, /getRequestClientIp\(req\)/);
  assert.doesNotMatch(server, /const publicApiAttempts = new Map\(\)/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS api_rate_limits/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS operational_alert_cooldowns/);
});


test('external PostgreSQL target validation blocks local, private, link-local and reserved IP ranges', () => {
  for (const address of [
    '0.0.0.0', '10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.0.1',
    '192.168.1.25', '192.0.2.10', '192.31.196.1', '198.18.0.1', '203.0.113.10', '100.64.0.1', '224.0.0.1',
    '::', '::1', 'fc00::1', 'fe80::1', '2001:db8::1', '2002::1', '::ffff:8.8.8.8'
  ]) assert.equal(isPublicPostgresIp(address), false, `${address} must not be allowed`);
  for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicPostgresIp(address), true, `${address} should be globally routable`);
  }
});

test('external PostgreSQL host and port inputs reject URLs, local names, aliases and unapproved ports', () => {
  assert.equal(normalizePostgresHostname('ep-example.neon.tech'), 'ep-example.neon.tech');
  assert.equal(normalizePostgresHostname('DB.Example.COM.'), 'db.example.com');
  for (const host of ['localhost', 'db.internal', 'service.local', 'metadata.google', 'host.docker.internal', 'db.cluster.local', '127.0.0.1', '127.1', '0x7f000001', 'http://example.com', 'db.example.com/path', 'bad host']) {
    assert.throws(() => normalizePostgresHostname(host), isPostgresTargetSecurityError, `${host} must be rejected`);
  }
  assert.equal(validatePostgresPort(5432), 5432);
  assert.equal(validatePostgresPort(6432), 6432);
  assert.throws(() => validatePostgresPort(5433), isPostgresTargetSecurityError);
  assert.equal(validatePostgresPort(15432, { ports: new Set([15432]) }), 15432);
});

test('DNS validation rejects all hosts with a mixed public/private answer and pins only validated IPs', async () => {
  const resolver = async host => {
    if (host === 'mixed.example.com') return [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.4', family: 4 }];
    if (host === 'empty.example.com') return [];
    return [{ address: '2606:4700:4700::1111', family: 6 }, { address: '1.1.1.1', family: 4 }];
  };
  await assert.rejects(resolvePublicPostgresTarget('mixed.example.com', 5432, { lookup: resolver }), isPostgresTargetSecurityError);
  await assert.rejects(resolvePublicPostgresTarget('empty.example.com', 5432, { lookup: resolver }), isPostgresTargetSecurityError);
  await assert.rejects(resolvePublicPostgresTarget('timeout.example.com', 5432, { lookup: () => new Promise(() => {}), timeoutMs: 5 }), isPostgresTargetSecurityError);
  const target = await resolvePublicPostgresTarget('safe.example.com', 5432, { lookup: resolver });
  assert.deepEqual(target, {
    hostname: 'safe.example.com', port: 5432, connectAddress: '1.1.1.1', family: 4,
    tlsServername: 'safe.example.com', pinned: true
  });
});

test('pinned PostgreSQL client configuration forces TLS verification and does not reconnect by hostname', async () => {
  const target = await resolvePublicPostgresTarget('db.example.com', 5432, { lookup: async () => [{ address: '8.8.4.4', family: 4 }] });
  const config = buildPinnedPostgresClientConfig(target, { database: 'sample', user: 'tester', password: 'secret', enableChannelBinding: true });
  assert.equal(config.host, '8.8.4.4');
  assert.equal(config.ssl.rejectUnauthorized, true);
  assert.equal(config.ssl.servername, 'db.example.com');
  assert.equal(config.enableChannelBinding, true);
  assert.equal(config.connectionTimeoutMillis, 7000);
  assert.equal(config.query_timeout, 5000);
  assert.equal('connectionString' in config, false);
  assert.throws(() => buildPinnedPostgresClientConfig({ ...target, connectAddress: '127.0.0.1' }, {}), isPostgresTargetSecurityError);
  assert.throws(() => buildPinnedPostgresClientConfig({ ...target, port: 22 }, {}), isPostgresTargetSecurityError);
});

test('PostgreSQL connection test limiter uses shared storage and enforces IP/project windows', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-pg-limit-'));
  const db = new SQLitePool(path.join(dir, 'test.sqlite'));
  try {
    db.exec(await read('schema.sqlite.sql'));
    const opts = { projectId: 7, ip: '203.0.113.99', now: 100000, perIpLimit: 2, perProjectLimit: 10, windowMs: 60000 };
    assert.equal((await consumePostgresConnectionTestLimit(db, opts)).allowed, true);
    assert.equal((await consumePostgresConnectionTestLimit(db, opts)).allowed, true);
    const third = await consumePostgresConnectionTestLimit(db, opts);
    assert.equal(third.allowed, false);
    assert.equal(third.scope, 'ip');
    assert.equal(third.retryAfterMs, 60000);
    const otherIp = await consumePostgresConnectionTestLimit(db, { ...opts, ip: '203.0.113.100' });
    assert.equal(otherIp.allowed, true);
    const afterWindow = await consumePostgresConnectionTestLimit(db, { ...opts, now: 160001 });
    assert.equal(afterWindow.allowed, true);
    const stored = await db.query("SELECT bucket_key FROM api_rate_limits WHERE bucket_key LIKE 'pg-test:%'");
    assert.ok(stored.rows.length >= 2);
    assert.ok(stored.rows.every(row => !row.bucket_key.includes('203.0.113.99')));
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('PostgreSQL test route validates the saved target, pins DNS, forces TLS and fails closed on limiter errors', async () => {
  const server = await read('server.js');
  const route = server.slice(server.indexOf("app.post('/api/projects/:id/database/connection/test'"), server.indexOf("app.get('/api/projects/:id/environment'"));
  assert.match(server, /POSTGRES_ALLOWED_PORTS = allowedPostgresPorts\(\)/);
  const saveRoute = server.slice(server.indexOf("app.post('/api/projects/:id/database/connection', requireAuth"), server.indexOf("app.post('/api/projects/:id/database/connection/test', requireAuth"));
  assert.match(saveRoute, /normalizePostgresHostname\(hostnameInput\)/);
  assert.match(saveRoute, /validatePostgresPort\(portInput, \{ ports: POSTGRES_ALLOWED_PORTS \}\)/);
  assert.match(route, /consumePostgresConnectionTestLimit\(pool/);
  assert.match(route, /perIpLimit: POSTGRES_CONNECTION_TEST_LIMITS\.perIp/);
  assert.match(route, /return respondApiError\(req, res, error, 'O serviço de teste de ligações está temporariamente indisponível\.', 503\)/);
  assert.match(route, /resolvePublicPostgresTarget\(c\.hostname, Number\(c\.port\), \{ ports: POSTGRES_ALLOWED_PORTS \}\)/);
  assert.match(route, /buildPinnedPostgresClientConfig\(target, credentials, \{ ports: POSTGRES_ALLOWED_PORTS \}\)/);
  assert.match(route, /Destino PostgreSQL bloqueado por segurança/);
  assert.doesNotMatch(route, /new Client\(\{ connectionString:/);
});

test('project and Neon creation quotas use atomic shared counters with hashed identities', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-resource-limit-'));
  const db = new SQLitePool(path.join(dir, 'resource.sqlite'));
  try {
    db.exec(await read('schema.sqlite.sql'));
    const options = { action: 'neon-provision', userId: 7, ip: '203.0.113.55', now: 500000, perUserLimit: 2, perIpLimit: 5, windowMs: 3600000 };
    assert.equal((await consumeResourceCreationLimit(db, options)).allowed, true);
    assert.equal((await consumeResourceCreationLimit(db, options)).allowed, true);
    const third = await consumeResourceCreationLimit(db, options);
    assert.equal(third.allowed, false);
    assert.equal(third.scope, 'user');
    const rows = await db.query("SELECT bucket_key FROM api_rate_limits WHERE bucket_key LIKE 'resource:%'");
    assert.equal(rows.rows.length, 2, 'one user bucket and one IP bucket are stored');
    assert.ok(rows.rows.every(row => !row.bucket_key.includes('203.0.113.55')));
    assert.ok(rows.rows.every(row => row.bucket_key !== 'resource:user:neon-provision:7'));
    assert.ok(rows.rows.every(row => row.bucket_key !== 'resource:ip:neon-provision:203.0.113.55'));
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Neon project count parser fails closed for unknown API response shapes and quotas are bounded', () => {
  assert.equal(parseNeonProjectCount({ projects_count: 12 }), 12);
  assert.equal(parseNeonProjectCount({ project_count: '9' }), 9);
  assert.equal(parseNeonProjectCount({ data: { count: 4 } }), 4);
  assert.equal(parseNeonProjectCount({ projects: [{ id: 'x' }] }), null);
  assert.equal(parseNeonProjectCount({ projects_count: -1 }), null);
  assert.equal(parseNeonProjectCount({ projects_count: 'many' }), null);
  const config = resourceQuotaLimits({ PROJECTS_PER_USER_LIMIT: '999', PROJECTS_GLOBAL_LIMIT: '2', NEON_DATABASES_PER_USER_LIMIT: '0', NEON_ACCOUNT_PROJECT_LIMIT: '90' });
  assert.equal(config.projectsPerUser, 100);
  assert.equal(config.projectsGlobal, 10);
  assert.equal(config.neonDatabasesPerUser, 1);
  assert.equal(config.neonAccountProjectLimit, 90);
});

test('project and Neon provisioning endpoints apply per-user/global quotas, shared rate limits and reservations', async () => {
  const server = await read('server.js');
  const createProjectRoute = server.slice(server.indexOf("app.post('/api/projects', requireAuth"), server.indexOf("app.get('/api/projects/:id'"));
  const provisionHelper = await read('resource-limits.js');
  const provisionRoute = server.slice(server.indexOf("app.post('/api/projects/:id/database/provision'"), server.indexOf("app.post('/api/projects/:id/database/tables'"));
  assert.match(createProjectRoute, /consumeResourceCreationLimit\(pool/);
  assert.match(createProjectRoute, /PROJECT_CREATION_RATE_LIMITED/);
  assert.match(createProjectRoute, /pg_advisory_xact_lock\(\$1, \$2\)/);
  assert.match(createProjectRoute, /RESOURCE_QUOTAS\.projectsPerUser/);
  assert.match(createProjectRoute, /RESOURCE_QUOTAS\.projectsGlobal/);
  assert.match(provisionHelper, /neon_provision_reservations/);
  assert.match(provisionHelper, /NEON_USER_QUOTA_REACHED/);
  assert.match(provisionHelper, /NEON_GLOBAL_QUOTA_REACHED/);
  assert.match(provisionHelper, /PROJECT_NOT_FOUND/);
  assert.match(provisionRoute, /consumeResourceCreationLimit\(pool/);
  assert.match(provisionRoute, /NEON_CREATION_RATE_LIMITED/);
  assert.match(provisionRoute, /cleanup_required/);
  assert.match(server, /neonApiRequest\('\/projects\/count'\)/);
  assert.match(server, /parseNeonProjectCount\(countPayload\)/);
  assert.match(server, /NEON_ACCOUNT_PROJECT_LIMIT/);
  for (const schemaName of ['schema.sql', 'schema.sqlite.sql']) {
    const schema = await read(schemaName);
    assert.match(schema, /CREATE TABLE IF NOT EXISTS neon_provision_reservations/);
  }
});


test('project trash/delete operations use durable Neon deletion state and preserve metadata until provider confirmation', async () => {
  const server = await read('server.js');
  const lifecycleHelper = server.slice(server.indexOf('async function changeProjectLifecycle('), server.indexOf("app.delete('/api/projects/:id'"));
  assert.match(lifecycleHelper, /pg_advisory_xact_lock\(\$1, \$2\)/);
  assert.match(lifecycleHelper, /neon_provision_reservations/);
  assert.match(lifecycleHelper, /project_lifecycle_operations/);
  assert.match(lifecycleHelper, /deleteNeonProjectResource\(neonProjectId\)/);
  assert.match(lifecycleHelper, /state='cleanup_required'/);
  assert.match(lifecycleHelper, /NEON_DELETE_FAILED/);
  assert.match(lifecycleHelper, /DELETE FROM deployments WHERE project_id=\$1/);
  assert.match(lifecycleHelper, /await client\.query\('COMMIT'\)/);
  assert.match(lifecycleHelper, /await client\.query\('ROLLBACK'\)/);
  const restoreHelper = server.slice(server.indexOf('async function restoreTrashedProject('), server.indexOf("app.post('/api/trash/:id/restore'"));
  assert.match(restoreHelper, /lifecycleOperationBlocksRestore/);
  assert.match(restoreHelper, /NEON_PROVISION_RECONCILIATION_REQUIRED/);
  const trashRoute = server.slice(server.indexOf("app.delete('/api/projects/:id'"), server.indexOf("app.get('/api/trash'"));
  const hardDeleteRoute = server.slice(server.indexOf("app.delete('/api/trash/:id'"), server.indexOf("app.post('/api/projects/:id/folders'"));
  assert.match(trashRoute, /changeProjectLifecycle\(req\.params\.id, req\.user\.id, 'trash'\)/);
  assert.match(hardDeleteRoute, /changeProjectLifecycle\(req\.params\.id, req\.user\.id, 'delete'\)/);
  for (const schema of [await read('schema.sql'), await read('schema.sqlite.sql')]) {
    assert.match(schema, /CREATE TABLE IF NOT EXISTS project_lifecycle_operations/);
    assert.match(schema, /provider_project_id TEXT NOT NULL DEFAULT ''/);
    assert.match(schema, /cleanup_required/);
  }
  assert.match(server, /UPDATE neon_provision_reservations SET provider_project_id=\$2,updated_at=NOW\(\) WHERE project_id=\$1 AND state='pending' RETURNING project_id/);
  assert.match(server, /deleteNeonProjectResource\(createdProjectId, \{ checkFirst: false \}\)/);
  assert.match(server, /error\.neonCleanupRequired = false/);
  assert.match(server, /currentConnection && currentConnection\.provider !== 'neon'/);
  assert.match(server, /const providerNameSuffix = `-luzaweb-\$\{project\.id\}`/);
  assert.match(server, /const providerNameBase = name\.toLowerCase\(\)\.replace\(\/\[\^a-z0-9-\]\+\/g, '-'\)/);
  assert.match(server, /const providerProjectName = `\$\{providerNameBase\.slice\(0, Math\.max\(2, 60 - providerNameSuffix\.length\)\)\}\$\{providerNameSuffix\}`/);
});

test('Neon lifecycle state machine retries stale or failed deletion but blocks concurrent restore', () => {
  const now = 2_000_000_000_000;
  assert.deepEqual(classifyLifecycleDeleteOperation(null, { now }), { action: 'start' });
  assert.deepEqual(classifyLifecycleDeleteOperation({ state: 'pending', provider_project_id: 'neon-p1', updated_at: new Date(now - 1000).toISOString() }, { now }), { action: 'in_progress', code: 'NEON_DELETION_IN_PROGRESS' });
  assert.deepEqual(classifyLifecycleDeleteOperation({ state: 'pending', provider_project_id: 'neon-p1', updated_at: new Date(now - NEON_DELETE_PENDING_STALE_MS - 1000).toISOString() }, { now }), { action: 'retry', providerProjectId: 'neon-p1' });
  assert.deepEqual(classifyLifecycleDeleteOperation({ state: 'cleanup_required', provider_project_id: 'neon-p2', updated_at: new Date(now).toISOString() }, { now }), { action: 'retry', providerProjectId: 'neon-p2' });
  assert.deepEqual(classifyLifecycleDeleteOperation({ state: 'cleanup_required', provider_project_id: '', updated_at: new Date(now).toISOString() }, { now }), { action: 'manual_reconciliation', code: 'NEON_RESOURCE_ID_MISSING' });
  assert.equal(lifecycleOperationBlocksRestore({ state: 'pending' }), true);
  assert.equal(lifecycleOperationBlocksRestore({ state: 'cleanup_required' }), true);
  assert.equal(lifecycleOperationBlocksRestore(null), false);
});

test('Neon provisioning reservations enforce project ownership, duplicate prevention and per-user/global resource quotas', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-neon-reservation-'));
  const db = new SQLitePool(path.join(dir, 'reservation.sqlite'));
  try {
    db.exec(await read('schema.sqlite.sql'));
    await db.query("INSERT INTO users(name,email,password_hash) VALUES('One','one@example.test','x'),('Two','two@example.test','x')");
    await db.query("INSERT INTO projects(user_id,name,slug) VALUES(1,'Existing','existing'),(1,'Second','second'),(2,'Third','third')");
    await db.query("INSERT INTO project_database_connections(project_id,name,provider,hostname,port,database_name,username,provider_project_id,connection_uri_cipher) VALUES(1,'Existing','neon','db.example.neon.tech',5432,'existing','owner','neon-existing','cipher')");
    const quotas = { neonDatabasesPerUser: 1, neonDatabasesGlobal: 5 };
    await assert.rejects(
      reserveNeonProvisionSlot(db, { id: 3 }, 1, quotas, { databaseConfigured: false }),
      error => error.code === 'PROJECT_NOT_FOUND' && error.statusCode === 404
    );
    await assert.rejects(
      reserveNeonProvisionSlot(db, { id: 2 }, 1, quotas, { databaseConfigured: false }),
      error => error.code === 'NEON_USER_QUOTA_REACHED' && error.statusCode === 429
    );
    await reserveNeonProvisionSlot(db, { id: 3 }, 2, quotas, { databaseConfigured: false });
    await assert.rejects(
      reserveNeonProvisionSlot(db, { id: 3 }, 2, quotas, { databaseConfigured: false }),
      error => error.code === 'NEON_PROVISION_IN_PROGRESS' && error.statusCode === 409
    );
    const reservation = await db.query('SELECT project_id,user_id,state FROM neon_provision_reservations');
    assert.deepEqual(reservation.rows.map(row => [Number(row.project_id), Number(row.user_id), row.state]), [[3, 2, 'pending']]);
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});


test('Neon lifecycle reconciler is dry-run by default and requires explicit confirmation for destructive actions', async () => {
  const script = await read('scripts/reconcile-neon-lifecycle.mjs');
  const packageJson = JSON.parse(await read('package.json'));
  assert.equal(packageJson.scripts['neon:reconcile'], 'node scripts/reconcile-neon-lifecycle.mjs');
  assert.match(script, /NEON_RECONCILE_CONFIRM === 'YES'/);
  assert.match(script, /Modo: \$\{confirmed \? 'EXECUÇÃO CONFIRMADA' : 'SIMULAÇÃO \(sem alterações\)'\}/);
  assert.match(script, /validProviderProjectId/);
  assert.match(script, /state='cleanup_required'/);
  assert.match(script, /DELETE FROM deployments WHERE project_id=\$1/);
  assert.match(script, /if \(row\.connected_provider_project_id && String\(row\.connected_provider_project_id\) === resourceId && row\.provider === 'neon'\)/);
  assert.match(script, /const staleMs/);
});

test('SQLite lifecycle operation table durably tracks and blocks project restore while Neon deletion needs reconciliation', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-lifecycle-state-'));
  const db = new SQLitePool(path.join(dir, 'lifecycle.sqlite'));
  try {
    db.exec(await read('schema.sqlite.sql'));
    await db.query("INSERT INTO users(name,email,password_hash) VALUES('Owner','owner@example.test','x')");
    await db.query("INSERT INTO projects(user_id,name,slug,trashed_at) VALUES(1,'Project','project','2026-10-28 00:00:00')");
    await db.query("INSERT INTO project_lifecycle_operations(project_id,user_id,operation,state,provider_project_id) VALUES(1,1,'delete_neon_project','cleanup_required','neon-test-id')");
    const rows = await db.query('SELECT project_id,state,provider_project_id FROM project_lifecycle_operations WHERE project_id=$1', [1]);
    assert.deepEqual(rows.rows.map(row => [Number(row.project_id), row.state, row.provider_project_id]), [[1, 'cleanup_required', 'neon-test-id']]);
    assert.equal(lifecycleOperationBlocksRestore(rows.rows[0]), true);
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});


test('client IP selection rejects spoofable proxy chains and validates Netlify edge IPs', async () => {
  assert.equal(normalizeClientIp('198.51.100.20'), '198.51.100.20');
  assert.equal(normalizeClientIp('::ffff:198.51.100.20'), '198.51.100.20');
  assert.equal(normalizeClientIp('198.51.100.20, 203.0.113.4'), null);
  assert.equal(normalizeClientIp('198.51.100.20:1234'), null);

  const netlifyRequest = {
    headers: {
      'x-nf-client-connection-ip': '198.51.100.20',
      'x-forwarded-for': '192.0.2.44, 203.0.113.88'
    },
    ip: '192.0.2.44',
    socket: { remoteAddress: '10.0.0.9' }
  };
  assert.equal(getRequestClientIp(netlifyRequest, { netlify: true }), '198.51.100.20');
  assert.equal(getRequestClientIp({ ...netlifyRequest, headers: { 'x-nf-client-connection-ip': '203.0.113.1, 198.51.100.2' } }, { netlify: true }), '10.0.0.9');
  assert.equal(getRequestClientIp(netlifyRequest, { netlify: false, trustProxyHops: 0 }), '10.0.0.9');
  assert.equal(getRequestClientIp(netlifyRequest, { netlify: false, trustProxyHops: 1 }), '192.0.2.44');

  const server = await read('server.js');
  const env = await read('.env.example');
  assert.match(server, /app\.set\('trust proxy', TRUST_PROXY_HOPS\)/);
  assert.match(server, /process\.env\.NETLIFY \? 1 : boundedIntegerEnv\('TRUST_PROXY_HOPS', 0, 0, 5\)/);
  assert.match(env, /TRUST_PROXY_HOPS=0/);
});

test('operational alert cooldown is shared atomically and bounded by event type', async () => {
  const schema = await read('schema.sqlite.sql');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-alert-cooldown-'));
  const db = new SQLitePool(path.join(dir, 'alerts.sqlite'));
  try {
    db.exec(schema);
    assert.equal(await claimOperationalAlertCooldown(db, 'http_5xx', 1000, 5000), true);
    assert.equal(await claimOperationalAlertCooldown(db, 'http_5xx', 2000, 5000), false);
    assert.equal(await claimOperationalAlertCooldown(db, 'database_unavailable', 2000, 5000), true);
    assert.equal(await claimOperationalAlertCooldown(db, 'http_5xx', 7000, 5000), true);
    const stored = await db.query('SELECT event_key,last_sent_at FROM operational_alert_cooldowns ORDER BY last_sent_at');
    assert.equal(stored.rows.length, 2);
    assert.ok(stored.rows.every(row => !String(row.event_key).includes('http_5xx')));
    assert.equal(await pruneOperationalAlertCooldowns(db, 10_000, 1_000), 2);
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
  const server = await read('server.js');
  assert.match(server, /shared_alert_cooldown_unavailable/);
  assert.match(server, /error_code: String\(error\?\.cause\?\.code \|\| error\?\.code \|\| error\?\.name \|\| 'request_failed'\)/);
  assert.doesNotMatch(server, /alert_webhook_failed'.*error\.message/);
});

test('API rate limiter batches key, IP and project buckets in one database operation', async () => {
  const { consumePublicApiRateLimit } = await import('../api-rate-limit.js');
  const schema = await read('schema.sqlite.sql');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'luza-api-rate-batch-'));
  const db = new SQLitePool(path.join(dir, 'rate-limit.sqlite'));
  try {
    db.exec(schema);
    let queries = 0;
    const wrapper = {
      async query(sql, params) { queries += 1; return db.query(sql, params); }
    };
    const result = await consumePublicApiRateLimit(wrapper, {
      keyId: 1, projectId: 4, ip: '203.0.113.77', now: 1_000,
      perIpLimit: 20, perKeyLimit: 50, perProjectLimit: 100, windowMs: 60_000
    });
    assert.equal(result.allowed, true);
    assert.equal(queries, 1);
    const buckets = await db.query('SELECT COUNT(*) AS count FROM api_rate_limits');
    assert.equal(Number(buckets.rows[0].count), 3);
    const publicBudgetExceeded = await consumePublicApiRateLimit(wrapper, {
      keyId: 2, projectId: 4, keyType: 'publishable', ip: '203.0.113.78', now: 1_100,
      perIpLimit: 20, perKeyLimit: 50, perProjectLimit: 1, windowMs: 60_000
    });
    assert.equal(publicBudgetExceeded.allowed, false);
    assert.equal(publicBudgetExceeded.scope, 'project');
    const privateBudgetIndependent = await consumePublicApiRateLimit(wrapper, {
      keyId: 3, projectId: 4, keyType: 'secret', ip: '203.0.113.79', now: 1_200,
      perIpLimit: 20, perKeyLimit: 50, perProjectLimit: 1, windowMs: 60_000
    });
    assert.equal(privateBudgetIndependent.allowed, true, 'private/public project budgets remain independent');
  } finally {
    await db.end();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('load smoke guard requires HTTPS and explicit confirmation for remote hosts', async () => {
  const loadSmoke = await read('scripts/load-smoke.mjs');
  assert.match(loadSmoke, /LOAD_TEST_CONFIRM !== 'YES'/);
  assert.match(loadSmoke, /remote.*LOAD_URL has de usar HTTPS|Para um destino remoto, LOAD_URL tem de usar HTTPS/);
  assert.match(loadSmoke, /new URL\('\/api\/health\/ready', parsedBase\)/);
});

test('phase 08 monitoring workflows, safe readiness and API key budgets are documented', async () => {
  const workflow = await read('.github/workflows/health-check.yml');
  const server = await read('server.js');
  const env = await read('.env.example');
  const readme = await read('README.md');
  assert.match(workflow, /cron: '\*\/15 \* \* \* \*'/);
  assert.match(workflow, /LUZAWEB_HEALTHCHECK_URL/);
  assert.match(workflow, /api\/health\/ready/);
  assert.match(server, /PG_POOL_WAITING_LIMIT/);
  assert.match(server, /SLOW_REQUEST_ALERT_MS/);
  assert.match(server, /last_used_at IS NULL OR last_used_at < \$2/);
  assert.match(server, /if \(!\(await allowProjectApiRequest\(req, res\)\)\) return/);
  assert.match(env, /PRIVATE_API_RATE_LIMIT_PER_PROJECT/);
  assert.match(env, /PUBLIC_API_RATE_LIMIT_WINDOW_MS/);
  assert.match(env, /PRIVATE_API_RATE_LIMIT_WINDOW_MS/);
  assert.match(readme, /Desempenho, limites e monitorização \(Fase 08\)/);
  assert.match(readme, /package-lock\.json/);
});


test('CSRF gate runs before JSON parsing and self-hosted proxy trust is explicit', async () => {
  const server = await read('server.js');
  const csrfIndex = server.indexOf("app.use('/api', enforceSameOriginMutations)");
  const jsonIndex = server.indexOf("app.use(express.json({ limit: '2mb' }))");
  const cookieIndex = server.indexOf('app.use(cookieParser())');
  assert.ok(csrfIndex > -1 && jsonIndex > -1 && cookieIndex > -1);
  assert.ok(csrfIndex < jsonIndex && jsonIndex < cookieIndex, 'blocked cross-origin mutations are rejected before body parsing');
  assert.match(server, /TRUST_PROXY_HOPS = process\.env\.NETLIFY \? 1 : boundedIntegerEnv\('TRUST_PROXY_HOPS', 0, 0, 5\)/);
  assert.match(server, /graceful_shutdown_started/);
  assert.match(server, /graceful_shutdown_complete/);
});
