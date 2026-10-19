import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SQLitePool } from '../local-db.js';

const root = new URL('..', import.meta.url);
const read = file => fs.readFile(new URL(file, root), 'utf8');

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

test('only the first project of each user receives starter files', async () => {
  const js = await read('public/app.js');
  const server = await read('server.js');
  assert.match(js, /const isFirstProject=!db\.projects\.some\(p=>Number\(p\.user_id\)===Number\(user\.id\)\)/);
  assert.match(js, /if\(isFirstProject\)localSeedProject\(db,project\.id\)/);
  assert.match(server, /const isFirstProject = Number\(prior\.rows\[0\]\?\.count \|\| 0\) === 0/);
  assert.match(server, /if \(isFirstProject\) await seedProject/);
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
  const js = await read('public/app.js');
  const pgSchema = await read('schema.sql');
  const sqliteSchema = await read('schema.sqlite.sql');
  for (const route of ['/api/projects/:id/database/connection', '/api/projects/:id/database/connection/test', '/api/projects/:id/environment', '/api/projects/:id/environment/groups', '/api/projects/:id/environment/variables']) assert.ok(server.includes(route));
  for (const label of ['Hostname', 'Internal Database URL', 'External Database URL', 'PSQL Command', 'Variáveis do ambiente', 'Criar grupo']) assert.ok(js.includes(label));
  for (const table of ['project_database_connections', 'project_env_groups', 'project_env_vars']) { assert.ok(pgSchema.includes(`CREATE TABLE IF NOT EXISTS ${table}`)); assert.ok(sqliteSchema.includes(`CREATE TABLE IF NOT EXISTS ${table}`)); }
  assert.match(server, /createCipheriv\('aes-256-gcm'/);
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
  assert.match(server, /process\.env\.NETLIFY && !databaseConfigured/);
  assert.match(server, /process\.env\.NETLIFY && \(JWT_SECRET === 'dev-only-change-me' \|\| Buffer\.byteLength/);
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
