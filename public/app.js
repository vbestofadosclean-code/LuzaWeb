const state = {
  user: null,
  projects: [],
  trash: [],
  currentProject: null,
  currentFile: null,
  view: 'dashboard',
  projectSection: 'repository',
  databaseConnection: null,
  databaseScreen: 'overview',
  database: null,
  selectedTableId: null,
  selectedTable: null,
  lineNumbers: true,
  dirty: false,
  previewTimer: null,
  busy: false,
  revealedApiToken: null,
  projectNavWidth: 220,
  collapsedFolders: new Set(),
  importTargetFolder: '',
  selectedFolderPath: '',
  cutFileId: null
};

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const authView = $('#authView');
const appView = $('#appView');
const landingView = $('#landingView');
const authFormWrap = $('#authFormWrap');
const toastEl = $('#toast');
const BINARY_FILE_PREFIX = 'LUZAWEB_BINARY_V1|';
const TEXT_EXTENSIONS_CLIENT = new Set([
  '.html','.htm','.css','.js','.mjs','.cjs','.ts','.tsx','.jsx','.json','.md','.txt','.xml','.svg',
  '.yaml','.yml','.toml','.sql','.py','.php','.java','.c','.h','.cpp','.hpp','.cs','.go','.rs','.sh',
  '.bat','.ps1','.env','.gitignore','.csv','.scss','.sass','.less','.vue','.svelte','.astro','.graphql',
  '.gql','.webmanifest','.ini','.conf','.properties','.log','.editorconfig','.dockerfile','.config','.map'
]);
const MAX_IMPORT_FILE_BYTES = 300000;
function isSensitiveEnvName(name) {
  return /(?:^|_)(?:DATABASE_URL|DATABASE_URI|DATABASE_CONNECTION_STRING|POSTGRES_URL|REDIS_URL|MONGODB_URI|DB_URL|PGPASSWORD|PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE_KEY|API_KEY|ACCESS_KEY|SIGNING_KEY|SESSION_KEY|CLIENT_SECRET|CREDENTIALS?)(?:_|$)/i.test(String(name || ''));
}
function parseBinaryContent(content) {
  if (typeof content !== 'string' || !content.startsWith(BINARY_FILE_PREFIX)) return null;
  const rest = content.slice(BINARY_FILE_PREFIX.length);
  const splitAt = rest.indexOf('|');
  if (splitAt < 1) return null;
  const mime = rest.slice(0, splitAt);
  const base64 = rest.slice(splitAt + 1);
  if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(mime) || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) return null;
  return { mime, base64 };
}
function isBinaryContent(content) { return Boolean(parseBinaryContent(content)); }
function getContentByteSize(content) {
  const binary = parseBinaryContent(content);
  return binary ? Math.floor(binary.base64.length * 3 / 4) - (binary.base64.endsWith('==') ? 2 : binary.base64.endsWith('=') ? 1 : 0) : new TextEncoder().encode(String(content ?? '')).length;
}
function importPathForFile(file, targetFolder = '') {
  const raw = String(file.name || '').replace(/\\/g, '/');
  const parts = raw.split('/').filter(part => part && part !== '.' && part !== '..');
  if (!parts.length) return '';
  const prefix = String(targetFolder || '').replace(/\\/g, '/').split('/').filter(part => part && part !== '.' && part !== '..').join('/');
  return [prefix, parts.join('/')].filter(Boolean).join('/').slice(0, 180);
}
function isTextFile(file) {
  const ext = pathExt(file.name).toLowerCase();
  return TEXT_EXTENSIONS_CLIENT.has(ext) || String(file.type || '').startsWith('text/') ||
    /^(application\/(json|javascript|xml|x-sh|sql|toml|yaml)|image\/svg\+xml)$/i.test(String(file.type || ''));
}
function isProbablyTextBuffer(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  if (bytes.includes(0)) return false;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    let unusual = 0;
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 32 && ![9,10,12,13].includes(code)) unusual++;
    }
    return unusual <= Math.max(1, text.length * 0.01);
  } catch { return false; }
}
function bytesToBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}
function encodeBinaryContent(mime, base64) {
  const safeMime = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(mime || '') ? mime : 'application/octet-stream';
  return `${BINARY_FILE_PREFIX}${safeMime}|${base64}`;
}
function binaryDataUrl(content) {
  const binary = parseBinaryContent(content);
  return binary ? `data:${binary.mime};base64,${binary.base64}` : null;
}
function relativeRepoPath(fromFilePath, targetPath) {
  const fromParts = String(fromFilePath || '').split('/').filter(Boolean);
  fromParts.pop();
  const targetParts = String(targetPath || '').split('/').filter(Boolean);
  let common = 0;
  while (common < fromParts.length && common < targetParts.length && fromParts[common] === targetParts[common]) common++;
  return [...Array(fromParts.length - common).fill('..'), ...targetParts.slice(common)].join('/');
}
function inlineBinaryAssetReferences(markup, assets, mode = 'html', sourcePath = 'index.html') {
  let result = String(markup || '');
  for (const asset of assets) {
    const paths = new Set([asset.path, `./${asset.path}`, `/${asset.path}`]);
    if (sourcePath) paths.add(relativeRepoPath(sourcePath, asset.path));
    const alternatives = [...paths].filter(Boolean).sort((a,b)=>b.length-a.length).map(value=>value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    if (!alternatives) continue;
    if (mode === 'css') {
      const pattern = new RegExp("url\\(\\s*([\"']?)(?:" + alternatives + ")\\1\\s*\\)", 'gi');
      result = result.replace(pattern, `url("${asset.url}")`);
    } else {
      const pattern = new RegExp("((?:src|href|poster|data-src|content)\\s*=\\s*)([\"'])(?:" + alternatives + ")\\2", 'gi');
      result = result.replace(pattern, (_match, prefix, quote) => `${prefix}${quote}${asset.url}${quote}`);
    }
  }
  return result;
}
let LOCAL_MODE = location.protocol === 'file:';
const LOCAL_DB_KEY = 'luzaweb_local_workspace_v2';
let localMemoryStore = null;

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#039;', '"':'&quot;' }[ch]));
}
function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('pt-PT', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }).format(date);
}
function formatBytes(bytes) {
  const n = Number(bytes || 0);
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function showToast(message) {
  toastEl.textContent = message;
  toastEl.classList.add('show');
  clearTimeout(showToast.t);
  showToast.t = setTimeout(() => toastEl.classList.remove('show'), 3200);
}
function showLanding() {
  landingView.classList.remove('hidden');
  authView.classList.add('hidden');
  appView.classList.add('hidden');
}
function showAuth(mode='login') {
  landingView.classList.add('hidden');
  authView.classList.remove('hidden');
  appView.classList.add('hidden');
  renderAuth(mode);
}
function showServerRequired() {
  showToast('O LUZAWEB está em modo local. Os dados ficam guardados neste navegador.');
}

async function detectRuntimeMode() {
  if (location.protocol === 'file:') { LOCAL_MODE = true; return; }
  // An online site with a broken API must show the backend error, not silently
  // create a different local-only workspace in each visitor's browser.
  LOCAL_MODE = false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    await fetch('/api/health', { credentials:'same-origin', cache:'no-store', signal:controller.signal });
  } catch {
    // Stay in server mode when hosted; the UI will report that the backend is unavailable.
  } finally {
    clearTimeout(timer);
  }
}

function localNow() { return new Date().toISOString(); }
function localRead() {
  try {
    const raw = localStorage.getItem(LOCAL_DB_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    if (localMemoryStore) return JSON.parse(JSON.stringify(localMemoryStore));
  }
  return {
    version: 2, nextId: 1, users: [], projects: [], files: [], commits: [], deployments: [],
    project_databases: [], project_database_connections: [], project_env_groups: [], project_env_vars: [], project_folders: [], database_tables: [], database_records: [], api_keys: [], session_user_id: null
  };
}
function localWrite(db) {
  const snapshot = JSON.parse(JSON.stringify(db));
  localMemoryStore = snapshot;
  try { localStorage.setItem(LOCAL_DB_KEY, JSON.stringify(snapshot)); } catch {}
  return db;
}
function localId(db) { return db.nextId++; }
function localUser(db) { return db.users.find(u => Number(u.id) === Number(db.session_user_id)) || null; }
function localSafeSlug(value) {
  const base = String(value || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || `site-${Date.now()}`;
  let slug = base, n = 2;
  while (dbHasSlug(slug)) slug = `${base}-${n++}`;
  return slug;
}
function dbHasSlug(slug) {
  const db = localRead();
  return db.projects.some(p => p.slug === slug);
}
function localProject(db, projectId, includeTrash = false) {
  const user = localUser(db);
  if (!user) return null;
  const p = db.projects.find(x => Number(x.id) === Number(projectId) && Number(x.user_id) === Number(user.id));
  if (!p || (!includeTrash && p.trashed_at)) return null;
  return p;
}
function localProjectResponse(db, project) {
  const files = db.files.filter(f => Number(f.project_id) === Number(project.id)).sort((a,b)=>a.path.localeCompare(b.path));
  const commits = db.commits.filter(c => Number(c.project_id) === Number(project.id)).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,30);
  const deployments = db.deployments.filter(d => Number(d.project_id) === Number(project.id)).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,30);
  const folders = (db.project_folders || []).filter(f => Number(f.project_id) === Number(project.id)).sort((a,b)=>a.path.localeCompare(b.path));
  return { project, files, commits, deployments, folders };
}
function localSeedProject(db, projectId) {
  const files = [
    ['index.html', `<!doctype html>\n<html lang="pt">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Meu site</title>\n  <link rel="stylesheet" href="style.css">\n</head>\n<body>\n  <main class="hero">\n    <span class="eyebrow">Criado com LUZAWEB</span>\n    <h1>O teu próximo site começa aqui.</h1>\n    <p>Edita HTML, CSS e JavaScript e trabalha localmente.</p>\n    <button id="hello">Testar JavaScript</button>\n  </main>\n  <script src="script.js"></script>\n</body>\n</html>`],
    ['style.css', `:root { font-family: Inter, system-ui, sans-serif; color: #f7faf9; background: #0a0d0d; }\n* { box-sizing: border-box; }\nbody { margin: 0; min-height: 100vh; background: radial-gradient(circle at 15% 10%, #17332b, #0a0d0d 48%); }\n.hero { max-width: 900px; margin: 0 auto; padding: 15vh 24px; }\n.eyebrow { display: inline-block; padding: 7px 11px; border: 1px solid #295b4d; border-radius: 999px; color: #8ff3ca; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }\nh1 { max-width: 800px; margin: 18px 0; font-size: clamp(46px, 8vw, 86px); line-height: .98; letter-spacing: -.06em; }\np { max-width: 640px; color: #9aa9a4; font-size: 18px; line-height: 1.7; }\nbutton { margin-top: 12px; border: 0; border-radius: 12px; padding: 13px 18px; background: #79efbf; color: #07110d; font-weight: 800; cursor: pointer; }`],
    ['script.js', `document.getElementById('hello')?.addEventListener('click', () => alert('JavaScript está a funcionar.'));`]
  ];
  for (const [path, content] of files) {
    db.files.push({ id: localId(db), project_id: projectId, path, content, size_bytes: new TextEncoder().encode(content).length, updated_at: localNow() });
  }
}
function localDbForProject(db, projectId) {
  let found = db.project_databases.find(d => Number(d.project_id) === Number(projectId));
  if (!found) {
    found = { id: localId(db), project_id: projectId, name: 'main', created_at: localNow(), updated_at: localNow() };
    db.project_databases.push(found);
  }
  return found;
}
function localNormalizeColumns(columns) {
  if (!Array.isArray(columns) || !columns.length) throw new Error('Adiciona pelo menos uma coluna.');
  const seen = new Set();
  return columns.slice(0,20).map((c,i)=>{
    const name = String(c?.name || `coluna_${i+1}`).trim().toLowerCase().replace(/[^a-z0-9_-]+/g,'_').replace(/^_+|_+$/g,'').slice(0,50) || `coluna_${i+1}`;
    if (seen.has(name)) throw new Error(`A coluna ${name} está repetida.`);
    seen.add(name);
    const type = new Set(['text','number','boolean','date']).has(c?.type) ? c.type : 'text';
    return {name,type,required:Boolean(c?.required)};
  });
}
function localNormalizeRecord(data, columns) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Os dados devem ser um objeto JSON.');
  const out={};
  for (const c of columns) {
    let v=Object.prototype.hasOwnProperty.call(data,c.name)?data[c.name]:null;
    if (v === '' && c.type !== 'text') v=null;
    if (v !== null && c.type === 'number') { v=Number(v); if (!Number.isFinite(v)) throw new Error(`A coluna ${c.name} precisa de um número.`); }
    if (v !== null && c.type === 'boolean') { if (v===true||v===false) {} else if(v==='true'||v==='1')v=true; else if(v==='false'||v==='0')v=false; else throw new Error(`A coluna ${c.name} precisa ser booleana.`); }
    if (v !== null && c.type === 'date' && Number.isNaN(new Date(v).getTime())) throw new Error(`A coluna ${c.name} precisa de uma data válida.`);
    if (c.required && (v === null || v === '')) throw new Error(`A coluna ${c.name} é obrigatória.`);
    out[c.name]=v;
  }
  return out;
}
function localApiError(message, status=400) { const e=new Error(message); e.status=status; throw e; }

async function localApi(url, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const body = options.body ? JSON.parse(options.body) : {};
  const db = localRead();
  const user = localUser(db);
  const respond = value => { localWrite(db); return value; };

  if (url === '/api/health') return { ok:true, app:'LUZAWEB', database:'browser-local' };

  if (url === '/api/auth/register' && method === 'POST') {
    const name=String(body.name||'').trim(), email=String(body.email||'').trim().toLowerCase(), password=String(body.password||'');
    if (name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<12 || new TextEncoder().encode(password).length>72) localApiError('Preenche nome, email válido e palavra-passe com 12 a 72 bytes.');
    if (db.users.some(u=>u.email===email)) localApiError('Este email já está registado.',409);
    const u={id:localId(db),name,email,password,username:'',bio:'',location:'',website:'',phone:'',created_at:localNow()}; db.users.push(u); db.session_user_id=u.id; respond();
    return {user:{id:u.id,name:u.name,email:u.email,username:u.username,bio:u.bio,location:u.location,website:u.website,phone:u.phone,created_at:u.created_at}};
  }
  if (url === '/api/auth/login' && method === 'POST') {
    const email=String(body.email||'').trim().toLowerCase(), password=String(body.password||'');
    const u=db.users.find(x=>x.email===email && x.password===password);
    if(!u) localApiError('Email ou palavra-passe inválidos.',401);
    db.session_user_id=u.id; respond(); return {user:{id:u.id,name:u.name,email:u.email,username:u.username||'',bio:u.bio||'',location:u.location||'',website:u.website||'',phone:u.phone||'',created_at:u.created_at}};
  }
  if (url === '/api/auth/logout' && method === 'POST') { db.session_user_id=null; respond(); return {ok:true}; }
  if (url === '/api/auth/me') { if(!user) localApiError('Sessão expirada.',401); return {user:{id:user.id,name:user.name,email:user.email,username:user.username||'',bio:user.bio||'',location:user.location||'',website:user.website||'',phone:user.phone||'',created_at:user.created_at}}; }
  if (url === '/api/account' && method === 'PUT') {
    if(!user) localApiError('Sessão expirada.',401);
    const name=String(body.name||'').trim(), email=String(body.email||'').trim().toLowerCase();
    const username=String(body.username||'').trim().replace(/^@+/,'').toLowerCase();
    const bio=String(body.bio||'').trim().slice(0,280), location=String(body.location||'').trim().slice(0,80), phone=String(body.phone||'').trim().slice(0,40);
    let website=String(body.website||'').trim();
    if(name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) localApiError('Indica um nome e email válidos.');
    if(username && !/^[a-z0-9_.-]{3,24}$/.test(username)) localApiError('O nome de utilizador deve ter 3 a 24 caracteres: letras, números, ponto, hífen ou sublinhado.');
    if(website){try{const parsed=new URL(website);if(!['http:','https:'].includes(parsed.protocol))throw new Error();website=parsed.href;}catch{localApiError('Indica um endereço de site válido, começando por https:// ou http://.');}}
    if(db.users.some(u=>u.id!==user.id && u.email===email)) localApiError('Este email já está a ser usado.',409);
    Object.assign(user,{name,email,username,bio,location,website,phone}); respond(); return {user:{id:user.id,name,email,username,bio,location,website,phone,created_at:user.created_at}};
  }
  if (url === '/api/account/password' && method === 'POST') {
    if(!user) localApiError('Sessão expirada.',401);
    const current=String(body.currentPassword||''), next=String(body.newPassword||'');
    if(next.length<12 || new TextEncoder().encode(next).length>72) localApiError('A nova palavra-passe precisa de 12 a 72 bytes.');
    if(user.password!==current) localApiError('A palavra-passe atual está incorreta.',401);
    user.password=next; respond(); return {ok:true};
  }

  if (!user) localApiError('Sessão expirada.',401);
  if (url === '/api/projects' && method === 'GET') {
    const projects=db.projects.filter(p=>p.user_id===user.id && !p.trashed_at).sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at));
    return {projects:projects.map(p=>({...p,file_count:db.files.filter(f=>f.project_id===p.id).length,commit_count:db.commits.filter(c=>c.project_id===p.id).length,live_deploy_count:0,deploy_status:null}))};
  }
  if (url === '/api/projects' && method === 'POST') {
    const name=String(body.name||'').trim(), description=String(body.description||'').trim();
    if(!name) localApiError('Indica um nome para o projeto.');
    let slug=String(name).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,48)||`site-${Date.now()}`;
    const base=slug; let n=2; while(db.projects.some(p=>p.slug===slug)) slug=`${base}-${n++}`;
    const now=localNow(); const project={id:localId(db),user_id:user.id,name,slug,description,created_at:now,updated_at:now,published_at:null,trashed_at:null};
    const isFirstProject=!db.projects.some(p=>Number(p.user_id)===Number(user.id)); db.projects.push(project); if(isFirstProject)localSeedProject(db,project.id); localDbForProject(db,project.id); respond(); return {project};
  }

  let m;
  m=url.match(/^\/api\/projects\/(\d+)\/folders$/);
  if(m&&method==='POST'){
    const project=localProject(db,Number(m[1])); if(!project)localApiError('Projeto não encontrado.',404);
    const folderPath=String(body.path||'').trim().replace(/\\/g,'/').split('/').filter(x=>x&&x!=='.'&&x!=='..').join('/').slice(0,180);
    if(!folderPath)localApiError('Indica um nome de pasta válido.');
    db.project_folders ||= [];
    const parts=folderPath.split('/');let partial='';const folderPaths=[];for(const part of parts){partial=partial?`${partial}/${part}`:part;folderPaths.push(partial);}
    if(folderPaths.some(path=>db.files.some(f=>Number(f.project_id)===Number(project.id)&&f.path===path)))localApiError('Já existe um ficheiro no caminho dessa pasta.',409);
    for(const path of folderPaths){if(!db.project_folders.some(f=>Number(f.project_id)===Number(project.id)&&f.path===path))db.project_folders.push({id:localId(db),project_id:project.id,path,created_at:localNow()});}
    project.updated_at=localNow();respond();return{folder:db.project_folders.find(f=>Number(f.project_id)===Number(project.id)&&f.path===folderPath)};
  }
  m=url.match(/^\/api\/projects\/(\d+)\/files\/(\d+)\/path$/);
  if(m&&method==='PATCH'){
    const project=localProject(db,Number(m[1]));if(!project)localApiError('Projeto não encontrado.',404);
    const file=db.files.find(f=>Number(f.project_id)===Number(project.id)&&Number(f.id)===Number(m[2]));if(!file)localApiError('Ficheiro não encontrado.',404);
    const newPath=String(body.path||'').trim().replace(/\\/g,'/').split('/').filter(x=>x&&x!=='.'&&x!=='..').join('/').slice(0,180);if(!newPath)localApiError('Indica um destino válido.');
    if(file.path!==newPath && db.files.some(f=>Number(f.project_id)===Number(project.id)&&f.path===newPath&&Number(f.id)!==Number(file.id)))localApiError('Já existe um ficheiro com esse nome no destino.',409);
    if(file.path!==newPath && (db.project_folders||[]).some(f=>Number(f.project_id)===Number(project.id)&&f.path===newPath))localApiError('Já existe uma pasta com esse nome no destino.',409);
    if(file.path!==newPath && db.files.some(f=>Number(f.project_id)===Number(project.id)&&Number(f.id)!==Number(file.id)&&f.path.startsWith(`${newPath}/`)))localApiError('Já existe uma pasta com esse nome no destino.',409);
    file.path=newPath;file.updated_at=localNow();project.updated_at=localNow();respond();return{file};
  }
  m=url.match(/^\/api\/projects\/(\d+)$/);
  if(m){const p=localProject(db,Number(m[1])); if(!p)localApiError('Projeto não encontrado.',404); if(method==='GET')return localProjectResponse(db,p); if(method==='PUT'){const name=String(body.name||'').trim(),description=String(body.description||'').trim();if(!name)localApiError('O nome não pode ficar vazio.');p.name=name;p.description=description;p.updated_at=localNow();respond();return{project:p};}if(method==='DELETE'){p.trashed_at=localNow();p.updated_at=localNow();respond();return{ok:true};}}

  if(url==='/api/trash' && method==='GET'){return{projects:db.projects.filter(p=>p.user_id===user.id&&p.trashed_at).sort((a,b)=>new Date(b.trashed_at)-new Date(a.trashed_at))};}
  m=url.match(/^\/api\/trash\/(\d+)\/restore$/); if(m&&method==='POST'){const p=localProject(db,Number(m[1]),true);if(!p||!p.trashed_at)localApiError('Item não encontrado na lixeira.',404);p.trashed_at=null;p.updated_at=localNow();respond();return{ok:true};}
  m=url.match(/^\/api\/trash\/(\d+)$/); if(m&&method==='DELETE'){const p=localProject(db,Number(m[1]),true);if(!p||!p.trashed_at)localApiError('Item não encontrado na lixeira.',404);db.projects=db.projects.filter(x=>x.id!==p.id);db.files=db.files.filter(x=>x.project_id!==p.id);db.project_folders=(db.project_folders||[]).filter(x=>x.project_id!==p.id);db.commits=db.commits.filter(x=>x.project_id!==p.id);db.deployments=db.deployments.filter(x=>x.project_id!==p.id);const dbx=db.project_databases.find(x=>x.project_id===p.id);if(dbx){const tids=db.database_tables.filter(t=>t.database_id===dbx.id).map(t=>t.id);db.database_records=db.database_records.filter(r=>!tids.includes(r.table_id));db.database_tables=db.database_tables.filter(t=>t.database_id!==dbx.id);db.project_databases=db.project_databases.filter(x=>x.id!==dbx.id);}db.api_keys=db.api_keys.filter(k=>k.project_id!==p.id);respond();return{ok:true};}

  m=url.match(/^\/api\/projects\/(\d+)\/files$/); if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);if(method==='POST'){const filePath=String(body.path||'').trim().replace(/\\/g,'/').split('/').filter(x=>x&&x!=='.'&&x!=='..').join('/').slice(0,180);const content=String(body.content??'');const sizeBytes=getContentByteSize(content);if(!filePath)localApiError('Indica um caminho de ficheiro válido.');if(sizeBytes>MAX_IMPORT_FILE_BYTES)localApiError('Ficheiro demasiado grande (máximo 300 KB).',413);const old=db.files.find(f=>f.project_id===p.id&&f.path===filePath);const file={id:old?.id||localId(db),project_id:p.id,path:filePath,content,size_bytes:sizeBytes,updated_at:localNow()};if(old)Object.assign(old,file);else db.files.push(file);p.updated_at=localNow();respond();return{file};}}
  m=url.match(/^\/api\/projects\/(\d+)\/files\/(\d+)$/); if(m&&method==='DELETE'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const idx=db.files.findIndex(f=>f.project_id===p.id&&f.id===Number(m[2]));if(idx<0)localApiError('Ficheiro não encontrado.',404);const path=db.files[idx].path;db.files.splice(idx,1);p.updated_at=localNow();respond();return{ok:true,path};}

  m=url.match(/^\/api\/projects\/(\d+)\/commit$/); if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const files=db.files.filter(f=>f.project_id===p.id);if(!files.some(f=>f.path==='index.html'))localApiError('O projeto precisa de um ficheiro index.html (com esse nome exacto) na raiz antes do commit.');const commit={id:localId(db),project_id:p.id,message:String(body.message||'Atualização do projeto').trim().slice(0,120)||'Atualização do projeto',snapshot:Object.fromEntries(files.map(f=>[f.path,f.content])),created_at:localNow()};db.commits.push(commit);p.updated_at=localNow();respond();return{commit};}
  m=url.match(/^\/api\/projects\/(\d+)\/commits\/(\d+)\/restore$/); if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const c=db.commits.find(x=>x.project_id===p.id&&x.id===Number(m[2]));if(!c)localApiError('Commit não encontrado.',404);db.files=db.files.filter(f=>f.project_id!==p.id);for(const [filePath,content] of Object.entries(c.snapshot||{})){db.files.push({id:localId(db),project_id:p.id,path:filePath,content:String(content),size_bytes:getContentByteSize(String(content)),updated_at:localNow()});}p.updated_at=localNow();respond();return{ok:true};}

  m=url.match(/^\/api\/projects\/(\d+)\/database\/connection$/); if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);let c=(db.project_database_connections||[]).find(x=>Number(x.project_id)===p.id);if(method==='GET'){if(!c)return{connection:null};return{connection:{...c,password:'',has_password:Boolean(c.password),internal_url:null,external_url:`postgresql://${encodeURIComponent(c.username)}:••••••@${c.hostname}:${c.port}/${encodeURIComponent(c.database)}`,psql_command:`psql "host=${c.hostname} port=${c.port} dbname=${c.database} user=${c.username} sslmode=require"`}};}if(method==='POST'){const name=String(body.name||'').trim(),hostname=String(body.hostname||'').trim(),port=Number(body.port||5432),database=String(body.database||'').trim(),username=String(body.username||'').trim(),password=String(body.password||'');if(!name||!hostname||!database||!username||!password||!Number.isInteger(port)||port<1||port>65535)localApiError('Preenche os campos obrigatórios corretamente.');c={id:c?.id||localId(db),project_id:p.id,name,provider:String(body.provider||'external'),hostname,port,database,username,password,created_at:c?.created_at||localNow(),updated_at:localNow()};db.project_database_connections=db.project_database_connections||[];const idx=db.project_database_connections.findIndex(x=>x.project_id===p.id);if(idx>=0)db.project_database_connections[idx]=c;else db.project_database_connections.push(c);respond();return{ok:true,connection:{...c,password:'',has_password:true}};}}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/connection\/test$/);if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const c=(db.project_database_connections||[]).find(x=>x.project_id===p.id);if(!c)localApiError('Configura primeiro uma ligação PostgreSQL.');localApiError('O teste de ligação a PostgreSQL externo só funciona quando o LuzaWeb está ligado ao servidor backend. No modo local, a configuração foi guardada apenas neste navegador.');}
  m=url.match(/^\/api\/projects\/(\d+)\/environment$/);if(m&&method==='GET'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);db.project_env_groups=db.project_env_groups||[];db.project_env_vars=db.project_env_vars||[];return{groups:db.project_env_groups.filter(g=>g.project_id===p.id),variables:db.project_env_vars.filter(v=>v.project_id===p.id).map(v=>({...v,is_secret:Boolean(v.is_secret)||isSensitiveEnvName(v.name),value:(v.is_secret||isSensitiveEnvName(v.name))?'':v.value,has_value:Boolean(v.value)}))};}
  m=url.match(/^\/api\/projects\/(\d+)\/environment\/groups$/);if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const name=String(body.name||'').trim().slice(0,80);if(!name)localApiError('Indica o nome do grupo.');db.project_env_groups=db.project_env_groups||[];if(db.project_env_groups.some(g=>g.project_id===p.id&&g.name.toLowerCase()===name.toLowerCase()))localApiError('Já existe um grupo com esse nome.',409);const group={id:localId(db),project_id:p.id,name,created_at:localNow(),updated_at:localNow()};db.project_env_groups.push(group);respond();return{group};}
  m=url.match(/^\/api\/projects\/(\d+)\/environment\/groups\/(\d+)$/);if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const groups=db.project_env_groups||[],g=groups.find(x=>x.project_id===p.id&&x.id===Number(m[2]));if(!g)localApiError('Grupo não encontrado.',404);if(method==='PATCH'){const name=String(body.name||'').trim().slice(0,80);if(!name)localApiError('Indica o nome do grupo.');if(groups.some(x=>x.project_id===p.id&&x.id!==g.id&&x.name.toLowerCase()===name.toLowerCase()))localApiError('Já existe um grupo com esse nome.',409);g.name=name;g.updated_at=localNow();respond();return{group:g};}if(method==='DELETE'){(db.project_env_vars||[]).filter(v=>v.group_id===g.id).forEach(v=>v.group_id=null);db.project_env_groups=groups.filter(x=>x.id!==g.id);respond();return{ok:true};}}
  m=url.match(/^\/api\/projects\/(\d+)\/environment\/variables$/);if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const name=String(body.name||'').trim(),value=String(body.value??''),group_id=body.group_id?Number(body.group_id):null,is_secret=Boolean(body.is_secret)||isSensitiveEnvName(name);if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))localApiError('Nome de variável inválido.');if(!value)localApiError('Indica o valor da variável.');db.project_env_vars=db.project_env_vars||[];if(db.project_env_vars.some(v=>v.project_id===p.id&&v.name===name))localApiError('Já existe uma variável com esse nome.',409);if(group_id&&!(db.project_env_groups||[]).some(g=>g.id===group_id&&g.project_id===p.id))localApiError('Grupo inválido.');const variable={id:localId(db),project_id:p.id,group_id,name,value,is_secret,created_at:localNow(),updated_at:localNow()};db.project_env_vars.push(variable);respond();return{variable:{...variable,value:is_secret?'':value,has_value:true}};}
  m=url.match(/^\/api\/projects\/(\d+)\/environment\/variables\/(\d+)$/);if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const vars=db.project_env_vars||[],v=vars.find(x=>x.project_id===p.id&&x.id===Number(m[2]));if(!v)localApiError('Variável não encontrada.',404);if(method==='PUT'){const name=String(body.name||'').trim();if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))localApiError('Nome de variável inválido.');if(vars.some(x=>x.project_id===p.id&&x.id!==v.id&&x.name===name))localApiError('Já existe uma variável com esse nome.',409);if(body.value)v.value=String(body.value);v.name=name;v.is_secret=Boolean(body.is_secret)||isSensitiveEnvName(name);v.group_id=body.group_id?Number(body.group_id):null;v.updated_at=localNow();respond();return{variable:{...v,value:v.is_secret?'':v.value,has_value:true}};}if(method==='DELETE'){db.project_env_vars=vars.filter(x=>x.id!==v.id);respond();return{ok:true};}}
  m=url.match(/^\/api\/projects\/(\d+)\/database$/); if(m&&method==='GET'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id);const tables=db.database_tables.filter(t=>t.database_id===database.id).map(t=>({...t,record_count:db.database_records.filter(r=>r.table_id===t.id).length}));respond();return{database,tables};}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables$/); if(m&&method==='POST'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id);const name=String(body.name||'tabela').trim().toLowerCase().replace(/[^a-z0-9_-]+/g,'_').slice(0,50)||'tabela';if(db.database_tables.some(t=>t.database_id===database.id&&t.name===name))localApiError('Já existe uma tabela com esse nome.',409);const table={id:localId(db),database_id:database.id,name,columns:localNormalizeColumns(body.columns),physical_ready:false,public_read:false,public_insert:false,created_at:localNow(),updated_at:localNow()};db.database_tables.push(table);database.updated_at=localNow();respond();return{table};}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables\/(\d+)\/public-access$/); if(m&&method==='PATCH'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id),table=db.database_tables.find(t=>t.id===Number(m[2])&&t.database_id===database.id);if(!table)localApiError('Tabela não encontrada.',404);table.public_read=Boolean(body.public_read);table.public_insert=Boolean(body.public_insert);table.updated_at=localNow();respond();return{table};}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables\/(\d+)$/); if(m&&method==='DELETE'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id);const tid=Number(m[2]),table=db.database_tables.find(t=>t.id===tid&&t.database_id===database.id);if(!table)localApiError('Tabela não encontrada.',404);db.database_tables=db.database_tables.filter(t=>t.id!==tid);db.database_records=db.database_records.filter(r=>r.table_id!==tid);respond();return{ok:true};}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables\/(\d+)\/records$/); if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id),table=db.database_tables.find(t=>t.id===Number(m[2])&&t.database_id===database.id);if(!table)localApiError('Tabela não encontrada.',404);if(method==='GET'){return{table,records:db.database_records.filter(r=>r.table_id===table.id).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,100)};}if(method==='POST'){const data=localNormalizeRecord(body.data,table.columns);const record={id:localId(db),table_id:table.id,data,created_at:localNow(),updated_at:localNow()};db.database_records.push(record);table.updated_at=localNow();respond();return{record};}}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables\/(\d+)\/records\/(\d+)$/); if(m&&method==='DELETE'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id);const table=db.database_tables.find(t=>t.id===Number(m[2])&&t.database_id===database.id);if(!table)localApiError('Tabela não encontrada.',404);const before=db.database_records.length;db.database_records=db.database_records.filter(r=>!(r.table_id===table.id&&r.id===Number(m[3])));if(db.database_records.length===before)localApiError('Registo não encontrado.',404);respond();return{ok:true};}
  m=url.match(/^\/api\/projects\/(\d+)\/database\/tables\/(\d+)\/records\/(\d+)$/); if(m&&method==='PUT'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const database=localDbForProject(db,p.id);const table=db.database_tables.find(t=>t.id===Number(m[2])&&t.database_id===database.id);if(!table)localApiError('Tabela não encontrada.',404);const record=db.database_records.find(r=>r.table_id===table.id&&r.id===Number(m[3]));if(!record)localApiError('Registo não encontrado.',404);record.data=localNormalizeRecord(body.data,table.columns);record.updated_at=localNow();respond();return{record};}

  m=url.match(/^\/api\/projects\/(\d+)\/api-keys$/); if(m){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);if(method==='GET')return{keys:db.api_keys.filter(k=>k.project_id===p.id).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).map(({token,...safe})=>safe)};if(method==='POST'){const raw=`lzw_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;const key={id:localId(db),project_id:p.id,label:String(body.label||'Chave principal').trim().slice(0,80)||'Chave principal',key_type:body.key_type==='publishable'?'publishable':'secret',token:raw,token_hint:raw.slice(-8),created_at:localNow(),last_used_at:null};db.api_keys.push(key);respond();return{key:{id:key.id,label:key.label,key_type:key.key_type,token_hint:key.token_hint,created_at:key.created_at,last_used_at:null},token:raw};}}
  m=url.match(/^\/api\/projects\/(\d+)\/api-keys\/(\d+)$/); if(m&&method==='DELETE'){const p=localProject(db,Number(m[1]));if(!p)localApiError('Projeto não encontrado.',404);const idx=db.api_keys.findIndex(k=>k.project_id===p.id&&k.id===Number(m[2]));if(idx<0)localApiError('API key não encontrada.',404);db.api_keys.splice(idx,1);respond();return{ok:true};}

  localApiError('Operação local não suportada.',404);
}

async function checkBackendStatus() {
  if (LOCAL_MODE) return { ok:true, database:'browser-local' };
  try { return await api('/api/health'); }
  catch (err) { return { ok:false, database:'unavailable', error:err.message }; }
}
async function refreshAuthStatus() {
  const status = $('#authStatus');
  if (!status) return;
  status.className = 'auth-status';
  if (LOCAL_MODE) {
    status.textContent = 'Modo local · os dados ficam guardados neste navegador';
    status.classList.add('ok');
    return;
  }
  const result = await checkBackendStatus();
  if (result.ok) {
    status.textContent = 'Servidor online · PostgreSQL ligado';
    status.classList.add('ok');
  } else {
    status.textContent = result.error || 'Não foi possível ligar ao servidor.';
    status.classList.add('warning');
  }
}

async function api(url, options = {}) {
  if (LOCAL_MODE) return localApi(url, options);
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data.error || `Erro ${response.status}`);
  return data;
}

function renderAuth(mode='login') {
  $$('.auth-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.auth === mode));
  authFormWrap.innerHTML = `<div id="authStatus" class="auth-status">A verificar ligação…</div>` + (mode === 'login' ? `
    <form id="loginForm" class="auth-form">
      <div class="auth-kicker">ENTRAR NO LUZAWEB</div>
      <h2>Bem-vindo de volta</h2>
      <p>Acede ao teu workspace, abre os teus projetos e publica versões reais.</p>
      <div class="field"><span>Email</span><input id="loginEmail" type="email" autocomplete="email" required placeholder="voce@email.com"></div>
      <div class="field"><span>Palavra-passe</span><input id="loginPassword" type="password" autocomplete="current-password" required placeholder="••••••••"></div>
      <button class="btn primary wide">Entrar</button>
      <button type="button" class="auth-back" id="backLanding">← Voltar à página inicial</button>
    </form>` : `
    <form id="registerForm" class="auth-form">
      <div class="auth-kicker">PRIMEIRO PASSO</div>
      <h2>Criar a tua conta</h2>
      <p>Depois de criar a conta, entras no teu workspace e desbloqueias todas as funcionalidades.</p>
      <div class="field"><span>Nome</span><input id="regName" required maxlength="60" placeholder="O teu nome"></div>
      <div class="field"><span>Email</span><input id="regEmail" type="email" required autocomplete="email" placeholder="voce@email.com"></div>
      <div class="field"><span>Palavra-passe</span><input id="regPassword" type="password" required minlength="12" maxlength="72" autocomplete="new-password" placeholder="mínimo 12 caracteres"></div>
      <button class="btn primary wide">Criar conta</button>
      <button type="button" class="auth-back" id="backLanding">← Voltar à página inicial</button>
    </form>`);
  $('#loginForm')?.addEventListener('submit', login);
  $('#registerForm')?.addEventListener('submit', register);
  $('#backLanding')?.addEventListener('click', showLanding);
  refreshAuthStatus();
}
async function login(e) {
  e.preventDefault();
  const button = $('button', e.currentTarget);
  button.disabled = true;
  try {
    const data = await api('/api/auth/login', { method:'POST', body: JSON.stringify({ email: $('#loginEmail').value, password: $('#loginPassword').value }) });
    state.user = data.user;
    await openApp();
  } catch (err) { showToast(err.message); }
  finally { button.disabled = false; }
}
async function register(e) {
  e.preventDefault();
  const button = $('button', e.currentTarget);
  button.disabled = true;
  try {
    const data = await api('/api/auth/register', { method:'POST', body: JSON.stringify({ name: $('#regName').value, email: $('#regEmail').value, password: $('#regPassword').value }) });
    state.user = data.user;
    await openApp();
  } catch (err) { showToast(err.message); }
  finally { button.disabled = false; }
}
async function checkSession() {
  await detectRuntimeMode();
  try {
    const data = await api('/api/auth/me');
    state.user = data.user;
    await openApp();
  } catch { showLanding(); }
}
async function openApp() {
  landingView.classList.add('hidden');
  authView.classList.add('hidden');
  appView.classList.remove('hidden');
  updateUserChrome();
  try {
    await loadProjects();
    showView('dashboard');
  } catch (err) { showToast(err.message); }
}
function updateUserChrome() {
  $('#userName').textContent = state.user?.name || 'Utilizador';
  $('#userAvatar').textContent = (state.user?.name || 'L').trim().slice(0,1).toUpperCase();
}
async function loadProjects() {
  const data = await api('/api/projects');
  state.projects = data.projects;
}
async function loadTrash() {
  const data = await api('/api/trash');
  state.trash = data.projects;
}
function setHeader(title, crumb='Dashboard') {
  $('#pageTitle').textContent = title;
  $('#crumb').textContent = crumb;
}
function closeProjectView() {
  appView.classList.remove('project-open');
  state.currentProject = null;
  state.currentFile = null;
  state.projectSection = 'repository';
  state.selectedFolderPath = '';
  state.cutFileId = null;
  state.selectedTableId = null;
  state.revealedApiToken = null;
  state.dirty = false;
}

function showView(view) {
  state.view = view;
  appView.classList.remove('project-open');
  $$('.page-view').forEach(el => el.classList.add('hidden'));
  const target = $(`#${view}View`);
  if (target) target.classList.remove('hidden');
  $$('.nav-item[data-view]').forEach(item => item.classList.toggle('active', item.dataset.view === view));
  if (view === 'dashboard') renderDashboard();
  if (view === 'projects') renderProjects();
  if (view === 'activity') renderActivity();
  if (view === 'editor') renderEditorHome();
  if (view === 'trash') renderTrash();
  if (view === 'account') renderAccount();
}
function projectNav(section) {
  const p = state.currentProject.project;
  return `<aside class="project-nav" style="--project-nav-width:${state.projectNavWidth}px">
    <div class="project-nav-head">
      <button class="icon-btn" id="backProjects" title="Voltar aos projetos">←</button>
      <div class="project-nav-title">
        <span class="project-nav-kicker">PROJETO</span>
        <strong>${escapeHtml(p.name)}</strong>
        <span class="project-nav-slug">/${escapeHtml(p.slug)}/</span>
      </div>
    </div>
    <nav>
      <button class="project-nav-item ${section==='repository'?'active':''}" data-project-section="repository"><span>▱</span> Repository</button>
      <button class="project-nav-item ${section==='deploy'?'active':''}" data-project-section="deploy"><span>↑</span> Deploy</button>
      <button class="project-nav-item ${section==='database'?'active':''}" data-project-section="database"><span>▦</span> Database</button>
      <button class="project-nav-item ${section==='api'?'active':''}" data-project-section="api"><span>⌁</span> API</button>
      <button class="project-nav-item ${section==='environment'?'active':''}" data-project-section="environment"><span>⚙</span> Variáveis do ambiente</button>
    </nav>
    <div class="project-nav-foot">
      <button class="project-delete-link" id="projectDeleteBtn"><span>⌫</span> Eliminar projeto</button>
    </div>
    <div class="project-nav-resizer" id="projectNavResizer" role="separator" aria-orientation="vertical" aria-label="Redimensionar barra lateral do projeto" title="Arrastar para aumentar ou diminuir"></div>
  </aside>`;
}

function renderDashboard() {
  setHeader('Os teus projetos', 'Dashboard');
  const totalFiles = state.projects.reduce((sum,p)=>sum+Number(p.file_count||0),0);
  const published = state.projects.filter(p=>p.published_at).length;
  const commits = state.projects.reduce((sum,p)=>sum+Number(p.commit_count||0),0);
  $('#dashboardView').innerHTML = `
    <div class="section-head"><div><div class="eyebrow">LUZAWEB WORKSPACE</div><h3>Cria. Publica. Liga uma base de dados real.</h3><p>Os projetos, deploys e dados ficam ligados ao teu workspace.</p></div><button class="btn primary" id="dashNew">＋ Novo projeto</button></div>
    <div class="stats">
      <div class="stat"><small>Projetos</small><strong>${state.projects.length}</strong><span>no teu workspace</span></div>
      <div class="stat"><small>Ficheiros</small><strong>${totalFiles}</strong><span>HTML · CSS · JS</span></div>
      <div class="stat"><small>Sites online</small><strong>${published}</strong><span>deploys ativos</span></div>
      <div class="stat"><small>Commits</small><strong>${commits}</strong><span>versões guardadas</span></div>
    </div>
    <div style="height:22px"></div>
    ${state.projects.length ? `<div class="section-head"><div><div class="eyebrow">RECENTES</div><h3>Projetos</h3></div><button class="btn ghost" id="dashProjects">Ver todos</button></div><div class="project-grid">${state.projects.slice(0,3).map(projectCard).join('')}</div>` : emptyState()}`;
  $('#dashNew')?.addEventListener('click', openProjectDialog);
  $('#dashProjects')?.addEventListener('click', () => showView('projects'));
  bindProjectCards();
}
function emptyState(label='O teu workspace está vazio', text='Cria o primeiro projeto e começa com HTML, CSS e JavaScript.') {
  return `<div class="empty-state"><div class="empty-icon">＋</div><h3>${escapeHtml(label)}</h3><p>${escapeHtml(text)}</p><button class="btn primary empty-new">Criar projeto</button></div>`;
}
function projectCard(project) {
  const live = !!project.published_at;
  return `<article class="project-card" data-project="${project.id}"><div class="project-card-top"><div><div class="project-name">${escapeHtml(project.name)}</div><div class="project-slug">/sites/${escapeHtml(project.slug)}/</div></div><span class="pill ${live?'':'muted'}">${live?'LIVE':'DRAFT'}</span></div><p class="project-desc">${escapeHtml(project.description || 'Projeto HTML, CSS e JavaScript.')}</p><div class="meta"><span>${project.file_count} ficheiros</span><span>${project.commit_count} commits</span></div><div class="project-actions"><button class="btn secondary open-project">Abrir projeto</button><button class="btn ghost quick-deploy" title="Publicar">↑</button></div></article>`;
}
function bindProjectCards(root = document) {
  $$('.project-card', root).forEach(card => {
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
    const open = () => openProject(Number(card.dataset.project));
    card.addEventListener('click', e => {
      if (e.target.closest('button,a,input,textarea,select')) return;
      open();
    });
    card.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button,a,input,textarea,select')) {
        e.preventDefault();
        open();
      }
    });
  });
  $$('.open-project', root).forEach(btn => btn.addEventListener('click', e => {
    e.stopPropagation();
    openProject(Number(e.currentTarget.closest('[data-project]').dataset.project));
  }));
  $$('.quick-deploy', root).forEach(btn => btn.addEventListener('click', async e => {
    e.stopPropagation();
    await openProject(Number(e.currentTarget.closest('[data-project]').dataset.project), true);
  }));
  $$('.empty-new', root).forEach(btn => btn.addEventListener('click', e => {
    e.stopPropagation();
    openProjectDialog();
  }));
}
function renderProjects() {
  setHeader('Projetos', 'Projetos');
  $('#projectsView').innerHTML = `<div class="section-head"><div><div class="eyebrow">WORKSPACE</div><h3>Todos os projetos</h3><p>${state.projects.length ? 'Abre, edita, publica e liga dados.' : 'Ainda não tens projetos.'}</p></div><button class="btn primary" id="projectsNew">＋ Novo projeto</button></div>${state.projects.length ? `<div class="project-grid">${state.projects.map(projectCard).join('')}</div>` : emptyState()}`;
  $('#projectsNew')?.addEventListener('click', openProjectDialog);
  bindProjectCards();
}
async function renderActivity() {
  setHeader('Atividade', 'Atividade');
  $('#activityView').innerHTML = `<div class="section-head"><div><div class="eyebrow">HISTÓRICO</div><h3>O que aconteceu</h3><p>Commits e deploys do teu workspace.</p></div></div><div id="activityContent"><div class="loading-state">A carregar atividade…</div></div>`;
  const rows = [];
  for (const p of state.projects) {
    try {
      const data = await api(`/api/projects/${p.id}`);
      data.commits.slice(0,10).forEach(c=>rows.push({type:'Commit',project:p.name,text:c.message,date:c.created_at}));
      data.deployments.slice(0,10).forEach(d=>rows.push({type:'Deploy',project:p.name,text:d.message,date:d.created_at}));
    } catch {}
  }
  rows.sort((a,b)=>new Date(b.date)-new Date(a.date));
  $('#activityContent').innerHTML = rows.length ? `<div class="activity-list">${rows.slice(0,40).map(r=>`<div class="activity-row"><div class="activity-icon">${r.type==='Deploy'?'↑':'●'}</div><div class="activity-main"><strong>${escapeHtml(r.type)} · ${escapeHtml(r.project)}</strong><span>${escapeHtml(r.text)}</span></div><div class="activity-time">${formatDate(r.date)}</div></div>`).join('')}</div>` : `<div class="empty-state"><div class="empty-icon">◌</div><h3>Ainda não há atividade</h3><p>Os teus commits e deploys vão aparecer aqui.</p></div>`;
}
function renderEditorHome() {
  setHeader('Editor', 'Editor');
  $('#editorView').innerHTML = `<div class="section-head"><div><div class="eyebrow">EDITOR</div><h3>Escolhe um projeto para editar</h3><p>O Editor abre diretamente o Repository do projeto selecionado.</p></div></div><div class="project-grid">${state.projects.length ? state.projects.map(projectCard).join('') : emptyState()}</div>`;
  bindProjectCards();
}
async function renderTrash() {
  setHeader('Lixeira', 'Lixeira');
  $('#trashView').innerHTML = `<div class="section-head"><div><div class="eyebrow">RECUPERAÇÃO</div><h3>Projetos eliminados</h3><p>Eliminar um projeto move-o para aqui. Só desaparece definitivamente quando o eliminares da lixeira.</p></div></div><div id="trashContent" class="loading-state">A carregar lixeira…</div>`;
  try { await loadTrash(); } catch (err) { $('#trashContent').innerHTML = `<div class="error-card">${escapeHtml(err.message)}</div>`; return; }
  $('#trashContent').outerHTML = state.trash.length ? `<div id="trashContent" class="trash-grid">${state.trash.map(trashCard).join('')}</div>` : `<div id="trashContent" class="empty-state"><div class="empty-icon">⌫</div><h3>A lixeira está vazia</h3><p>Quando enviares um projeto para a lixeira, ele aparece aqui para ser restaurado ou eliminado definitivamente.</p></div>`;
  bindTrash();
}
function trashCard(project) {
  return `<article class="trash-card"><div class="project-card-top"><div><div class="project-name">${escapeHtml(project.name)}</div><div class="project-slug">/${escapeHtml(project.slug)}</div></div><span class="pill muted">TRASH</span></div><p class="project-desc">Eliminado em ${escapeHtml(formatDate(project.trashed_at))}</p><div class="project-actions"><button class="btn secondary restore-project" data-id="${project.id}">Restaurar</button><button class="btn danger permanent-delete" data-id="${project.id}">Eliminar de vez</button></div></article>`;
}
function bindTrash() {
  $$('.restore-project').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/trash/${btn.dataset.id}/restore`, {method:'POST',body:'{}'}); await loadProjects(); await renderTrash(); showToast('Projeto restaurado.'); } catch(err) { showToast(err.message); }
  }));
  $$('.permanent-delete').forEach(btn => btn.addEventListener('click', async () => {
    if (!confirm('Eliminar este projeto definitivamente? Se tiver uma base Neon gerida pelo LuzaWeb, ela também será eliminada no Neon. Confirma que tens um backup; esta operação não pode ser desfeita pelo LuzaWeb.')) return;
    try { await api(`/api/trash/${btn.dataset.id}`, {method:'DELETE'}); await renderTrash(); showToast('Projeto eliminado definitivamente.'); } catch(err) { showToast(err.message); }
  }));
}
function profileInitials(name,email){
  const value=String(name||email||'U').trim();
  const parts=value.split(/\s+/).filter(Boolean);
  return (parts.length>1?parts[0][0]+parts[parts.length-1][0]:value.slice(0,2)).toUpperCase();
}
function renderAccount() {
  setHeader('Conta', 'Conta');
  const user=state.user||{};
  const created=user.created_at ? formatDate(user.created_at) : '—';
  const username=String(user.username||'').trim();
  const projectCount=state.projects.length;
  const fileCount=state.projects.reduce((sum,project)=>sum+Number(project.file_count||0),0);
  $('#accountView').innerHTML = `<div class="account-page">
    <section class="account-profile-hero">
      <div class="profile-avatar-large" aria-hidden="true">${escapeHtml(profileInitials(user.name,user.email))}</div>
      <div class="account-profile-main"><div class="eyebrow">PERFIL DE UTILIZADOR</div><h3>${escapeHtml(user.name||'Utilizador LUZAWEB')}</h3><p>${escapeHtml(username?`@${username}`:(user.email||'Configura o teu nome de utilizador'))}</p><div class="profile-tags"><span>● Conta activa</span><span>✦ Membro desde ${escapeHtml(created)}</span></div></div>
      <div class="profile-id-card"><span>ID DA CONTA</span><strong>#${escapeHtml(String(user.id??'—'))}</strong><small>Perfil pessoal LUZAWEB</small></div>
    </section>
    <div class="profile-stats"><article class="profile-stat"><span>PROJECTOS</span><strong>${projectCount}</strong><small>Projectos na tua conta</small></article><article class="profile-stat"><span>FICHEIROS</span><strong>${fileCount}</strong><small>Ficheiros nos projectos</small></article><article class="profile-stat"><span>SEGURANÇA</span><strong>Protegida</strong><small>Palavra-passe gerida pela conta</small></article></div>
    <div class="account-grid account-grid-profile">
      <section class="settings-card account-form-card"><div class="eyebrow">INFORMAÇÕES PESSOAIS</div><h3>Editar perfil</h3><p class="muted">Personaliza os dados apresentados na tua conta. Os campos de contacto são opcionais.</p>
        <form id="profileForm" class="settings-form profile-form">
          <div class="profile-form-two"><label>Nome completo<input id="accountName" value="${escapeHtml(user.name||'')}" maxlength="60" required autocomplete="name"></label><label>Nome de utilizador<input id="accountUsername" value="${escapeHtml(username)}" maxlength="24" placeholder="ex.: claudio_dev" autocomplete="username"><small>3–24 caracteres: letras, números, ponto, hífen ou sublinhado.</small></label></div>
          <label>Email<input id="accountEmail" type="email" value="${escapeHtml(user.email||'')}" required autocomplete="email"></label>
          <label>Biografia<textarea id="accountBio" maxlength="280" rows="4" placeholder="Fala um pouco sobre ti e sobre o que crias…">${escapeHtml(user.bio||'')}</textarea><small id="bioCount">${String(user.bio||'').length}/280 caracteres</small></label>
          <div class="profile-form-two"><label>Localização<input id="accountLocation" value="${escapeHtml(user.location||'')}" maxlength="80" placeholder="Cidade, país" autocomplete="address-level2"></label><label>Telefone<input id="accountPhone" value="${escapeHtml(user.phone||'')}" maxlength="40" placeholder="Contacto (opcional)" autocomplete="tel"></label></div>
          <label>Site pessoal<input id="accountWebsite" type="url" value="${escapeHtml(user.website||'')}" maxlength="240" placeholder="https://teusite.com" autocomplete="url"></label>
          <div class="account-meta"><span>Conta criada em</span><strong>${escapeHtml(created)}</strong></div><button class="btn primary">Guardar perfil</button>
        </form>
      </section>
      <div class="account-security-column"><section class="settings-card"><div class="eyebrow">SEGURANÇA</div><h3>Palavra-passe</h3><p class="muted">Altera a palavra-passe sem terminar a sessão.</p><form id="passwordForm" class="settings-form"><label>Palavra-passe actual<input id="currentPassword" type="password" autocomplete="current-password" required></label><label>Nova palavra-passe<input id="newPassword" type="password" minlength="12" maxlength="72" autocomplete="new-password" required></label><label>Confirmar nova palavra-passe<input id="confirmPassword" type="password" minlength="12" maxlength="72" autocomplete="new-password" required></label><button class="btn secondary">Actualizar palavra-passe</button></form></section>
      <section class="settings-card account-help-card"><div class="eyebrow">DICAS DE PERFIL</div><h3>Deixa a conta completa</h3><ul><li>Escolhe um nome de utilizador fácil de reconhecer.</li><li>Escreve uma biografia curta sobre os teus projectos.</li><li>Adiciona o teu site pessoal para mostrar o teu trabalho.</li></ul></section></div>
    </div>
  </div>`;
  $('#profileForm').addEventListener('submit', updateAccount);
  $('#passwordForm').addEventListener('submit', changePassword);
  $('#accountBio')?.addEventListener('input',e=>{const count=$('#bioCount');if(count)count.textContent=`${e.target.value.length}/280 caracteres`;});
}
async function updateAccount(e) {
  e.preventDefault();
  try { const data = await api('/api/account',{method:'PUT',body:JSON.stringify({name:$('#accountName').value,email:$('#accountEmail').value,username:$('#accountUsername').value,bio:$('#accountBio').value,location:$('#accountLocation').value,website:$('#accountWebsite').value,phone:$('#accountPhone').value})}); state.user=data.user; updateUserChrome(); renderAccount(); showToast('Perfil actualizado.'); }
  catch(err){ showToast(err.message); }
}
async function changePassword(e) {
  e.preventDefault();
  if ($('#newPassword').value !== $('#confirmPassword').value) return showToast('As novas palavras-passe não coincidem.');
  try { await api('/api/account/password',{method:'POST',body:JSON.stringify({currentPassword:$('#currentPassword').value,newPassword:$('#newPassword').value})}); e.currentTarget.reset(); showToast('Palavra-passe alterada.'); }
  catch(err){ showToast(err.message); }
}

async function openProject(projectId, autoDeploy=false) {
  try {
    const data = await api(`/api/projects/${projectId}`);
    state.currentProject = data;
    state.currentFile = data.files[0]?.id || null;
    state.selectedFolderPath = '';
    state.cutFileId = null;
    state.projectSection = 'repository';
    state.databaseScreen = 'overview';
    state.database = null;
    state.databaseConnection = null;
    state.selectedTableId = null;
    state.dirty = false;
    state.revealedApiToken = null;
    $$('.page-view').forEach(el => el.classList.add('hidden'));
    $$('.nav-item[data-view]').forEach(item => item.classList.remove('active'));
    $('#projectView').classList.remove('hidden');
    renderProject();
    if (autoDeploy) await deployProject();
  } catch (err) { showToast(err.message); }
}
function renderProject() {
  if (!state.currentProject?.project) return;
  const p = state.currentProject.project;
  $$('.page-view').forEach(el => el.classList.add('hidden'));
  $('#projectView').classList.remove('hidden');
  appView.classList.add('project-open');
  setHeader(p.name, `Projetos / ${p.name} / ${capitalize(state.projectSection)}`);
  $('#projectView').innerHTML = `<div class="project-layout">${projectNav(state.projectSection)}<section class="project-content">${renderProjectSection()}</section></div>`;
  applyProjectNavWidth();
  bindProjectNavResize();
  $('#backProjects')?.addEventListener('click', async ()=>{ await loadProjects(); closeProjectView(); showView('projects'); });
  $$('.project-nav-item').forEach(btn=>btn.addEventListener('click',()=>switchProjectSection(btn.dataset.projectSection)));
  $('#projectDeleteBtn')?.addEventListener('click', deleteCurrentProject);
  bindProjectSectionEvents();
}
function applyProjectNavWidth() {
  const layout = $('.project-layout');
  if (!layout) return;
  const width = Math.max(180, Math.min(420, Number(state.projectNavWidth) || 220));
  state.projectNavWidth = width;
  layout.style.setProperty('--project-nav-width', `${width}px`);
  const nav = $('.project-nav');
  if (nav) nav.style.setProperty('--project-nav-width', `${width}px`);
}
function bindProjectNavResize() {
  const handle = $('#projectNavResizer');
  const layout = $('.project-layout');
  if (!handle || !layout) return;
  let dragging = false;
  let startX = 0;
  let startWidth = state.projectNavWidth;
  const onMove = (event) => {
    if (!dragging) return;
    const next = Math.max(180, Math.min(420, startWidth + (event.clientX - startX)));
    state.projectNavWidth = next;
    layout.style.setProperty('--project-nav-width', `${next}px`);
    handle.setPointerCapture?.(event.pointerId);
  };
  const stop = () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.classList.remove('project-resizing');
  };
  handle.addEventListener('pointerdown', (event) => {
    if (window.matchMedia('(max-width: 980px)').matches) return;
    event.preventDefault();
    dragging = true;
    startX = event.clientX;
    startWidth = state.projectNavWidth;
    handle.classList.add('dragging');
    document.body.classList.add('project-resizing');
    handle.setPointerCapture?.(event.pointerId);
  });
  handle.addEventListener('pointermove', onMove);
  handle.addEventListener('pointerup', stop);
  handle.addEventListener('pointercancel', stop);
}
function capitalize(v){ return String(v||'').charAt(0).toUpperCase()+String(v||'').slice(1); }
function switchProjectSection(section){
  if (state.dirty && section !== 'repository' && !confirm('Tens alterações não guardadas. Continuar?')) return;
  state.projectSection = section;
  if (section === 'database') state.databaseScreen = 'overview';
  state.revealedApiToken = null;
  renderProject();
}
function renderProjectSection(){
  if (state.projectSection === 'deploy') return renderDeploySection();
  if (state.projectSection === 'database') return renderDatabaseSection();
  if (state.projectSection === 'api') return renderApiSection();
  if (state.projectSection === 'environment') return renderEnvironmentSection();
  return renderRepositorySection();
}
function renderRepositorySection(){
  const p = state.currentProject.project;
  const files = [...state.currentProject.files].sort((a,b)=>a.path.localeCompare(b.path));
  const totalSize = files.reduce((sum,f)=>sum+Number(f.size_bytes||0),0);
  const latestCommit = state.currentProject.commits?.[0];
  const readme = buildProjectReadme(p, files);
  return `<div class="repository-page">
    <section class="repo-header-card">
      <div class="repo-heading">
        <div>
          <div class="eyebrow">REPOSITORY</div>
          <h3>${escapeHtml(p.name)}</h3>
          <p>${escapeHtml(p.description || 'Repositório do teu site criado no LUZAWEB.')}</p>
        </div>
        <div class="repo-header-meta">
          <span class="pill muted">/${escapeHtml(p.slug)}/</span>
          <span class="repo-metric">${files.length} ficheiros</span>
          <span class="repo-metric">${formatBytes(totalSize)}</span>
        </div>
      </div>
      <div class="repo-toolbar-row">
        <div class="repo-branch"><span>◉</span> main</div>
        <div class="repo-toolbar-actions">
          <button id="createFolderBtn" class="btn secondary">＋ Pasta</button><button id="addFileBtn" class="btn secondary">＋ Ficheiro</button>
          <button id="importBtn" class="btn ghost">↥ Importar ficheiros</button>
          <button id="repoDeployBtn" class="btn primary">↑ Deploy</button>
        </div>
      </div>
    </section>

    <div class="repository-shell repository-shell-modern">
      <section class="pane repo-files-pane">
        <div class="pane-head"><div><span class="pane-title">Code</span><span class="pane-subtitle">Arquivos do projeto</span></div><button id="deleteFileBtn" class="icon-btn danger-icon" title="Eliminar ficheiro">⌫</button></div>
        <div class="repo-latest-commit">${latestCommit?`<strong>${escapeHtml(latestCommit.message)}</strong><span>${formatDate(latestCommit.created_at)}</span>`:'<strong>Primeira versão</strong><span>Sem commits ainda</span>'}</div>
        <div id="fileTree" class="file-tree"></div>
      </section>

      <section class="pane editor-pane">
        <div class="editor-toolbar"><div class="file-open"><span class="file-ext" id="openExt">—</span><span id="openName">Nenhum ficheiro</span><span id="saveState" class="save-dot"></span></div><div class="toolbar-actions"><button class="btn ghost" id="lineBtn" aria-pressed="true">Ocultar linhas</button><button class="btn ghost" id="commitBtn">Commit</button><button class="btn secondary" id="previewBtn">Pré-visualizar</button><button class="btn primary" id="saveBtn">Guardar</button></div></div><div class="editor-wrap"><pre id="lineNos" class="line-nos"></pre><textarea id="codeEditor" class="code-editor" spellcheck="false" wrap="off"></textarea></div><div class="editor-bottom"><span id="statusLeft">Pronto</span><span>Ctrl + S para guardar</span></div>
      </section>

      <aside class="repo-right">
        <section class="side-card"><div class="pane-head"><span class="pane-title">Pré-visualização</span><span class="repo-mini-status">local</span></div><div id="previewWrap" class="side-body preview-container"><div id="previewEmpty" class="preview-empty">Sandbox de pré-visualização.</div><iframe id="previewFrame" class="preview-frame hidden" sandbox="allow-scripts allow-forms allow-popups"></iframe><div class="preview-tools"><span>preview local</span><a href="#" id="previewRefresh">actualizar</a></div></div></section>
        <section class="side-card"><div class="pane-head"><span class="pane-title">Histórico</span></div><div class="side-body history-list">${state.currentProject.commits.length?state.currentProject.commits.slice(0,8).map(c=>`<div class="history-row"><div><strong>${escapeHtml(c.message)}</strong><span>${formatDate(c.created_at)}</span></div><button class="btn ghost restore-commit" data-commit-id="${c.id}">Restaurar</button></div>`).join(''):'<div class="preview-empty">Ainda não há commits.</div>'}</div></section>
      </aside>
    </div>

    <section class="repo-readme">
      <div class="readme-head"><div><div class="eyebrow">README</div><h3>README do projecto</h3><p>Conteúdo do README.md ou informações disponíveis no repositório ${escapeHtml(p.name)}.</p></div><span class="pill muted">README.md</span></div>
      <article class="readme-body">${readme}</article>
    </section>
  </div><input id="fileInput" type="file" class="visually-hidden" multiple>`;
}
function renderReadmeMarkdown(source){
  const escaped=escapeHtml(String(source||''));
  const lines=escaped.replace(/\r\n?/g,'\n').split('\n');
  const html=[];let paragraph=[];let list=[];let code=[];let inCode=false;
  const flushParagraph=()=>{if(paragraph.length){html.push(`<p>${paragraph.join('<br>')}</p>`);paragraph=[];}};
  const flushList=()=>{if(list.length){html.push(`<ul>${list.map(item=>`<li>${item}</li>`).join('')}</ul>`);list=[];}};
  const inline=txt=>txt.replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/\*([^*]+)\*/g,'<em>$1</em>');
  for(const line of lines){
    if(line.trim().startsWith('```')){flushParagraph();flushList();if(inCode){html.push(`<pre><code>${code.join('\n')}</code></pre>`);code=[];inCode=false;}else inCode=true;continue;}
    if(inCode){code.push(line);continue;}
    const heading=line.match(/^(#{1,4})\s+(.+)$/);
    if(heading){flushParagraph();flushList();const level=heading[1].length;html.push(`<h${level}>${inline(heading[2])}</h${level}>`);continue;}
    const item=line.match(/^\s*[-*+]\s+(.+)$/);
    if(item){flushParagraph();list.push(inline(item[1]));continue;}
    if(!line.trim()){flushParagraph();flushList();continue;}
    flushList();paragraph.push(inline(line));
  }
  if(inCode)html.push(`<pre><code>${code.join('\n')}</code></pre>`);
  flushParagraph();flushList();
  return html.join('');
}
function buildProjectReadme(project, files){
  const rootReadme=files.find(file=>String(file.path||'').toLowerCase()==='readme.md');
  if(rootReadme){
    const content=String(rootReadme.content||'').trim();
    return content ? `<div class="project-readme-source">${renderReadmeMarkdown(content)}</div>` : '<p class="readme-muted">O ficheiro README.md existe, mas ainda está vazio.</p>';
  }
  const names=files.map(file=>String(file.path||'')).filter(Boolean).sort((a,b)=>a.localeCompare(b));
  const sections=[];
  sections.push(`<section class="readme-section"><h4>${escapeHtml(project.name||'Projecto')}</h4>${project.description?`<p>${escapeHtml(project.description)}</p>`:'<p>Este projecto ainda não tem uma descrição registada.</p>'}</section>`);
  sections.push(`<section class="readme-section"><h4>Ficheiros existentes</h4>${names.length?`<ul>${names.map(name=>`<li><code>${escapeHtml(name)}</code></li>`).join('')}</ul>`:'<p>Este projecto ainda não contém ficheiros.</p>'}</section>`);
  sections.push('<p class="readme-muted">Não existe um README.md neste repositório. Não foram acrescentadas funcionalidades, variáveis ou instruções que não estejam registadas.</p>');
  return sections.join('');
}
function renderDeploySection(){
  const p=state.currentProject.project;
  const liveUrl=new URL(`/sites/${encodeURIComponent(p.slug)}/`,location.origin).href;
  return `<div class="full-panel"><div class="page-panel-head"><div><div class="eyebrow">DEPLOY</div><h3>Publicação real</h3><p>Publica a versão actual do projecto e recebe um endereço público. Esta etapa publica sites estáticos HTML, CSS, JavaScript e ficheiros associados.</p></div><span class="pill ${p.published_at?'':'muted'}">${p.published_at?'LIVE':'DRAFT'}</span></div>
    <div class="deploy-hero"><div><span class="deploy-icon">↑</span><div><span class="panel-label">ENDEREÇO DO SITE</span><h4>${p.published_at?escapeHtml(liveUrl):'Ainda sem endereço público'}</h4><p>${p.published_at?'Esta URL serve a última versão publicada.':'Faz o primeiro deploy para gerar o endereço público.'}</p></div></div><div class="deploy-actions"><button class="btn primary" id="deployBtn">↑ Deploy</button>${p.published_at?`<button class="btn secondary" id="openSiteBtn">Abrir site</button><button class="btn ghost" id="copySiteBtn">Copiar URL</button>`:''}</div></div>
    <div class="two-col"><section class="side-card"><div class="pane-head"><span class="pane-title">O que acontece no deploy</span></div><div class="side-body steps"><div><b>01</b><span>Guardar</span><small>Os ficheiros actuais são validados e guardados como uma versão.</small></div><div><b>02</b><span>Publicar</span><small>A versão recebe estado LIVE depois de validada.</small></div><div><b>03</b><span>URL pública</span><small>O endereço /sites/${escapeHtml(p.slug)}/ serve os ficheiros publicados.</small></div></div></section><section class="side-card"><div class="pane-head"><span class="pane-title">Deploys recentes</span></div><div class="side-body deploy-list">${state.currentProject.deployments.length?state.currentProject.deployments.map(d=>`<div class="deploy-row"><strong>${escapeHtml(d.status)}</strong><span>${escapeHtml(d.message)} · ${formatDate(d.created_at)}</span></div>`).join(''):'<div class="preview-empty">Sem deploys ainda.</div>'}</div></section></div>
  </div>`;
}
function renderDatabaseSection(){
  if(state.databaseScreen==='create'){
    return `<div class="full-panel database-create-page"><div class="page-panel-head"><div><div class="eyebrow">DATABASE / NOVA BASE</div><h3>Criar base de dados</h3><p>O LuzaWeb vai criar uma base PostgreSQL real no Neon. Os dados de ligação só serão apresentados depois de o fornecedor confirmar a criação.</p></div><button class="btn secondary" id="cancelDatabaseCreateBtn">← Voltar</button></div>
      <form id="databaseCreateForm" class="database-create-form">
        <label>Nome da base de dados<input id="databaseCreateName" name="name" maxlength="60" required pattern="[A-Za-z0-9_-]+" placeholder="minha_base"><small>Usado no nome do projecto Neon e, quando suportado, no nome da base PostgreSQL. Utiliza letras, números, traços e sublinhados.</small></label>
        <div class="database-form-grid"><label>Região<select id="databaseCreateRegion" name="region_id" required><option value="aws-eu-central-1">Europa — Frankfurt</option><option value="aws-eu-west-2">Europa — Londres</option><option value="aws-us-east-1">Estados Unidos — N. Virginia</option><option value="aws-us-east-2">Estados Unidos — Ohio</option><option value="aws-us-west-2">Estados Unidos — Oregon</option><option value="aws-sa-east-1">América do Sul — São Paulo</option><option value="aws-ap-southeast-1">Ásia — Singapura</option><option value="aws-ap-southeast-2">Ásia — Sydney</option></select></label>
        <label>Versão PostgreSQL<select id="databaseCreateVersion" name="pg_version" required><option value="18">PostgreSQL 18</option><option value="17">PostgreSQL 17</option><option value="16" selected>PostgreSQL 16</option><option value="15">PostgreSQL 15</option><option value="14">PostgreSQL 14</option></select></label></div>
        <p class="database-form-note">O servidor do LuzaWeb tem de estar configurado com <code>NEON_API_KEY</code>, <code>DATABASE_URL</code> e <code>JWT_SECRET</code>. A chave da API nunca é enviada ao navegador.</p>
        <div class="dialog-actions"><button type="button" class="btn secondary" id="cancelDatabaseCreateBtn2">Cancelar</button><button class="btn primary" type="submit" id="submitDatabaseCreateBtn">Criar base de dados</button></div>
      </form></div>`;
  }
  if(state.databaseScreen==='tables'){
    return `<div class="full-panel"><div class="page-panel-head"><div><div class="eyebrow">DATABASE / TABELAS</div><h3>Tabela</h3><p>Estas tabelas pertencem à base de dados PostgreSQL seleccionada.</p></div><div class="repo-toolbar-actions"><button class="btn secondary" id="backDatabaseOverviewBtn">← Base de dados</button><button class="btn primary" id="newTableBtn">＋ Criar nova tabela</button></div></div><div id="databaseArea" class="database-area"><div class="loading-state">A carregar tabelas…</div></div></div>`;
  }
  const existingConnection=state.databaseConnection;
  return `<div class="full-panel"><div class="page-panel-head"><div><div class="eyebrow">DATABASE</div><h3>Base de dados</h3><p>Cria e consulta as bases de dados deste projecto. A gestão das tabelas fica na opção «Tabela».</p></div><div class="repo-toolbar-actions"><button class="btn secondary" id="createDatabaseBtn">＋ Criar base de dados</button><button class="btn primary" id="databaseTablesBtn" type="button" title="Abre a gestão das tabelas quando existir uma base de dados pronta.">Tabela</button></div></div>
    <section class="side-card db-connection-card"><div class="pane-head"><span class="pane-title">Base de dados do projecto</span><span class="pill muted" id="managedDatabaseStatus">A verificar</span></div><div class="side-body" id="projectDatabaseDetails"><div class="loading-state">A carregar informações da base…</div></div></section>
    <section class="side-card db-connection-card"><div class="pane-head"><span class="pane-title">Dados de ligação</span><button class="btn ghost" id="editDatabaseConnectionBtn">Ligar PostgreSQL existente</button></div><div class="side-body" id="databaseConnectionArea"><div class="loading-state">A carregar dados de ligação…</div></div></section>
    <div id="databaseArea" class="database-area" hidden><div class="loading-state">A carregar estrutura…</div></div></div>`;
}
function renderEnvironmentSection(){return `<div class="full-panel"><div class="page-panel-head"><div><div class="eyebrow">CONFIGURAÇÃO DO PROJETO</div><h3>Variáveis do ambiente</h3><p>As variáveis não secretas ficam disponíveis no site estático publicado através de <code>window.LUZA_ENV</code>. Segredos permanecem no servidor e não são enviados ao navegador; aplicações com backend precisarão de runtime próprio para os consumir.</p></div><div class="repo-toolbar-actions"><button class="btn secondary" id="newEnvGroupBtn">＋ Criar grupo</button><button class="btn primary" id="newEnvVariableBtn">＋ Criar variável</button></div></div><div id="environmentArea"><div class="loading-state">A carregar variáveis…</div></div></div>`;}
function renderApiSection(){
  const p=state.currentProject.project;
  return `<div class="full-panel"><div class="page-panel-head"><div><div class="eyebrow">API</div><h3>API do projeto</h3><p>Gera chaves para integrar aplicações com as tabelas deste projeto.</p></div><button class="btn primary" id="newApiKeyBtn">＋ Nova API key</button></div><div id="apiArea" class="api-area"><div class="loading-state">A carregar API…</div></div><div class="api-note"><b>Endpoint base:</b> <code>${location.origin}/v1/${escapeHtml(p.slug)}/&lt;table&gt;</code><span>A chave é enviada no cabeçalho <code>Authorization: Bearer ...</code> ou <code>X-LUZA-KEY</code>.</span></div></div>`;
}
function renderFileTree(){
  const tree=$('#fileTree');
  if(!tree) return;
  const project=state.currentProject;
  const rootNode={name:'',path:'',folders:new Map(),files:[]};
  const ensureFolder=folderPath=>{
    let node=rootNode; const parts=String(folderPath||'').split('/').filter(Boolean); let current='';
    for(const part of parts){
      current=current?`${current}/${part}`:part;
      if(!node.folders.has(part))node.folders.set(part,{name:part,path:current,folders:new Map(),files:[]});
      node=node.folders.get(part);
    }
    return node;
  };
  for(const folder of (project.folders||[]))ensureFolder(typeof folder==='string'?folder:folder.path);
  for(const file of project.files||[]){
    const parts=String(file.path||'').split('/').filter(Boolean); const name=parts.pop();
    if(!name)continue;
    const parent=ensureFolder(parts.join('/'));
    parent.files.push({...file,displayName:name});
  }
  const renderNode=node=>{
    const folderHtml=[...node.folders.values()].sort((a,b)=>a.name.localeCompare(b.name)).map(folder=>{
      const expanded=!state.collapsedFolders.has(folder.path);
      const children=expanded?`<div class="file-tree-children">${renderNode(folder)}</div>`:'';
      return `<div class="file-tree-folder" data-folder-path="${escapeHtml(folder.path)}">
        <div class="file-tree-folder-row" data-folder-path="${escapeHtml(folder.path)}">
          <button type="button" class="folder-main ${state.selectedFolderPath===folder.path?'selected-folder':''}" data-folder-path="${escapeHtml(folder.path)}" aria-expanded="${expanded?'true':'false'}"><span class="folder-caret">${expanded?'⌄':'›'}</span><span class="folder-icon">📁</span><span class="folder-name">${escapeHtml(folder.name)}</span></button>
          <button type="button" class="folder-import" data-folder-path="${escapeHtml(folder.path)}" title="Importar ficheiros para ${escapeHtml(folder.name)}" aria-label="Importar ficheiros para ${escapeHtml(folder.name)}">↑</button>
        </div>${children}</div>`;
    }).join('');
    const filesHtml=[...node.files].sort((a,b)=>a.displayName.localeCompare(b.displayName)).map(file=>`<button type="button" draggable="true" class="file-tree-file ${String(file.id)===String(state.currentFile)?'active':''} ${String(file.id)===String(state.cutFileId)?'cut-pending':''}" data-file-id="${file.id}" title="${escapeHtml(file.path)}"><span class="file-ext">${escapeHtml(pathExt(file.displayName).slice(1).toUpperCase()||'TXT').slice(0,4)}</span><span class="file-tree-file-name">${escapeHtml(file.displayName)}</span></button>`).join('');
    return folderHtml+filesHtml;
  };
  tree.innerHTML=renderNode(rootNode)||'<div class="preview-empty">Sem ficheiros ou pastas. Cria uma pasta ou importa ficheiros.</div>';
  $$('.file-tree-file',tree).forEach(btn=>{
    btn.addEventListener('click',()=>selectFile(Number(btn.dataset.fileId)));
    btn.addEventListener('dragstart',event=>{event.dataTransfer?.setData('text/plain',String(btn.dataset.fileId));if(event.dataTransfer)event.dataTransfer.effectAllowed='move';btn.classList.add('dragging');});
    btn.addEventListener('dragend',()=>{$$('.file-tree-file.dragging',tree).forEach(item=>item.classList.remove('dragging'));$$('.file-tree-folder-row.drop-target',tree).forEach(item=>item.classList.remove('drop-target'));});
  });
  $$('.folder-main',tree).forEach(btn=>btn.addEventListener('click',()=>{const folderPath=btn.dataset.folderPath;state.selectedFolderPath=folderPath;if(state.collapsedFolders.has(folderPath))state.collapsedFolders.delete(folderPath);else state.collapsedFolders.add(folderPath);renderFileTree();}));
  $$('.folder-import',tree).forEach(btn=>btn.addEventListener('click',event=>{event.preventDefault();event.stopPropagation();state.importTargetFolder=btn.dataset.folderPath||'';let prefix='';for(const part of state.importTargetFolder.split('/').filter(Boolean)){prefix=prefix?`${prefix}/${part}`:part;state.collapsedFolders.delete(prefix);}$('#fileInput')?.click();}));
  $$('.file-tree-folder-row',tree).forEach(row=>{
    row.addEventListener('dragover',event=>{event.preventDefault();if(event.dataTransfer)event.dataTransfer.dropEffect='move';row.classList.add('drop-target');});
    row.addEventListener('dragleave',event=>{if(!row.contains(event.relatedTarget))row.classList.remove('drop-target');});
    row.addEventListener('drop',async event=>{event.preventDefault();event.stopPropagation();row.classList.remove('drop-target');const id=Number(event.dataTransfer?.getData('text/plain'));if(id)await moveRepositoryFile(id,row.dataset.folderPath||'');});
  });
  tree.addEventListener('click',event=>{if(!event.target.closest('.file-tree-folder-row,.file-tree-file')){state.selectedFolderPath='';renderFileTree();}});
  tree.ondragover=event=>{if(!event.target.closest('.file-tree-folder-row')){event.preventDefault();if(event.dataTransfer)event.dataTransfer.dropEffect='move';}};
  tree.ondrop=async event=>{if(event.target.closest('.file-tree-folder-row'))return;event.preventDefault();const id=Number(event.dataTransfer?.getData('text/plain'));if(id)await moveRepositoryFile(id,'');};
}
function pathExt(p){ return p.includes('.') ? p.slice(p.lastIndexOf('.')) : ''; }
function selectFile(fileId){
  if(state.dirty && !confirm('Tens alterações não guardadas. Continuar e perdê-las?')) return;
  state.currentFile=fileId; selectCurrentFile();
}
function selectCurrentFile(){
  const file=state.currentProject?.files.find(f=>String(f.id)===String(state.currentFile)) || state.currentProject?.files[0];
  state.currentFile=file?.id||null;
  const editor=$('#codeEditor');
  if(!editor||!file)return;
  const binary = parseBinaryContent(file.content);
  editor.readOnly = Boolean(binary);
  editor.value = binary
    ? `Este ficheiro é binário (${binary.mime}) e foi preservado. Não pode ser editado como texto neste editor.`
    : file.content;
  $('#openName').textContent=file.path;
  $('#openExt').textContent=(pathExt(file.path).slice(1)||'txt').toUpperCase();
  $('#statusLeft').textContent=binary?`${formatBytes(file.size_bytes)} · binário preservado`:formatBytes(file.size_bytes);
  $('#saveBtn').disabled=Boolean(binary);
  $('#saveState').classList.remove('dirty');
  state.dirty=false;
  syncLines();
  $$('.file-item').forEach(el=>el.classList.toggle('active',Number(el.dataset.fileId)===file.id));
}
function syncLines(){
  const editor=$('#codeEditor'),nums=$('#lineNos'); if(!editor||!nums)return;
  const wrap=editor.closest('.editor-wrap');
  const lineCount=Math.max(1,editor.value.split('\n').length);
  nums.textContent=Array.from({length:lineCount},(_,i)=>String(i+1)).join('\n');
  if(wrap)wrap.classList.toggle('line-numbers-hidden',!state.lineNumbers);
  nums.hidden=!state.lineNumbers;
  nums.scrollTop=editor.scrollTop;
  updateLineButton();
}
function updateLineButton(){
  const button=$('#lineBtn');
  if(!button)return;
  button.textContent=state.lineNumbers?'Ocultar linhas':'Mostrar linhas';
  button.setAttribute('aria-pressed',state.lineNumbers?'true':'false');
}
function currentPreviewHtml(){
  const files=Object.fromEntries(state.currentProject.files.map(f=>[f.path,f.content]));
  const selected=state.currentProject.files.find(f=>String(f.id)===String(state.currentFile));
  if(selected && !isBinaryContent(selected.content))files[selected.path]=$('#codeEditor')?.value??selected.content;
  let html=files['index.html']||'<!doctype html><html><body><h1>Sem index.html</h1></body></html>';
  const assets=state.currentProject.files.map(f=>{
    const binaryUrl=binaryDataUrl(f.content);
    if(binaryUrl)return {path:f.path.replace(/^\.\//,''),url:binaryUrl};
    if(pathExt(f.path).toLowerCase()==='.svg')return {path:f.path.replace(/^\.\//,''),url:`data:image/svg+xml;charset=utf-8,${encodeURIComponent(f.content)}`};
    return null;
  }).filter(Boolean);
  html=inlineBinaryAssetReferences(html,assets,'html','index.html');
  const css=Object.entries(files).filter(([name,content])=>pathExt(name).toLowerCase()==='.css'&&!isBinaryContent(content)).map(([name,content])=>`<style>\n${inlineBinaryAssetReferences(content,assets,'css',name)}\n</style>`).join('\n');
  const js=Object.entries(files).filter(([name,content])=>['.js','.mjs','.cjs'].includes(pathExt(name).toLowerCase())&&!isBinaryContent(content)).map(([,content])=>`<script>\n${String(content).replace(/<\/script/gi,'<\\/script')}\n<\/script>`).join('\n');
  html=html.replace(/<link[^>]+href=["'][^"']+\.css[^>]*>/gi,''); html=html.replace(/<script[^>]+src=["'][^"']+\.(?:m?js|cjs)[^"']*["'][^>]*><\/script>/gi,'');
  if(/<\/head>/i.test(html))html=html.replace(/<\/head>/i,`${css}</head>`);else html=`${css}${html}`;
  if(/<\/body>/i.test(html))html=html.replace(/<\/body>/i,`${js}</body>`);else html+=js;
  return html;
}
function refreshPreview(showMessage=false){
  const frame=$('#previewFrame'),empty=$('#previewEmpty'); if(!frame||!empty)return; frame.srcdoc=currentPreviewHtml(); frame.classList.remove('hidden'); empty.classList.add('hidden'); if(showMessage)showToast('Pré-visualização atualizada.');
}
function bindProjectSectionEvents(){
  if(state.projectSection==='repository') bindRepositoryEvents();
  if(state.projectSection==='deploy') bindDeployEvents();
  if(state.projectSection==='database') {
    loadDatabaseUI();
    $('#createDatabaseBtn')?.addEventListener('click',()=>{state.databaseScreen='create';renderProject();});
    $('#databaseTablesBtn')?.addEventListener('click',()=>{
      const database=state.database?.database||{};
      const connection=state.databaseConnection;
      const isReady=Boolean(database.provider==='neon'&&database.has_connection || database.has_connection || database.engine==='SQLite local' || LOCAL_MODE);
      if(!isReady){
        showToast(connection
          ? 'A ligação guardada ainda não confirma uma base de dados pronta para gerir tabelas. Testa a ligação ou cria uma base no Neon.'
          : 'Antes de abrir as tabelas, cria uma base de dados PostgreSQL. Se já a criaste, verifica a configuração e a ligação do servidor.');
        return;
      }
      state.databaseScreen='tables';renderProject();
    });
    $('#newTableBtn')?.addEventListener('click',openDbTableDialog);
    $('#backDatabaseOverviewBtn')?.addEventListener('click',()=>{state.databaseScreen='overview';renderProject();});
    $('#cancelDatabaseCreateBtn')?.addEventListener('click',()=>{state.databaseScreen='overview';renderProject();});
    $('#cancelDatabaseCreateBtn2')?.addEventListener('click',()=>{state.databaseScreen='overview';renderProject();});
    $('#databaseCreateForm')?.addEventListener('submit',createProjectDatabase);
    $('#editDatabaseConnectionBtn')?.addEventListener('click',openDatabaseConnectionDialog);
  }
  if(state.projectSection==='api') loadApiUI();
  if(state.projectSection==='environment') loadEnvironmentUI();
}
function bindRepositoryEvents(){
  renderFileTree(); selectCurrentFile(); refreshPreview();
  $('#addFileBtn')?.addEventListener('click',openFileDialog); $('#createFolderBtn')?.addEventListener('click',createRepositoryFolder); $('#importBtn')?.addEventListener('click',()=>{state.importTargetFolder='';$('#fileInput')?.click();}); $('#fileInput')?.addEventListener('change',e=>importFiles(e)); $('#deleteFileBtn')?.addEventListener('click',deleteCurrentFile);
  $('#lineBtn')?.addEventListener('click',()=>{state.lineNumbers=!state.lineNumbers;syncLines();updateLineButton();}); $('#saveBtn')?.addEventListener('click',saveCurrentFile); $('#commitBtn')?.addEventListener('click',commitProject); $('#previewBtn')?.addEventListener('click',()=>refreshPreview(true)); $('#previewRefresh')?.addEventListener('click',e=>{e.preventDefault();refreshPreview(true);}); $('#repoDeployBtn')?.addEventListener('click',deployProject);
  $$('.restore-commit').forEach(btn=>btn.addEventListener('click',()=>restoreCommit(btn.dataset.commitId)));
  $('#codeEditor')?.addEventListener('input',()=>{state.dirty=true;$('#saveState').classList.add('dirty');syncLines();clearTimeout(state.previewTimer);state.previewTimer=setTimeout(()=>refreshPreview(false),350);});
  $('#codeEditor')?.addEventListener('scroll',()=>{const n=$('#lineNos');if(n)n.scrollTop=$('#codeEditor').scrollTop;});
  $('#codeEditor')?.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();saveCurrentFile();}if(e.key==='Tab'){e.preventDefault();const el=e.currentTarget,start=el.selectionStart,end=el.selectionEnd;el.setRangeText('  ',start,end,'end');el.dispatchEvent(new Event('input'));}});
}
function bindDeployEvents(){
  $('#deployBtn')?.addEventListener('click',deployProject); $('#openSiteBtn')?.addEventListener('click',()=>window.open(`/sites/${encodeURIComponent(state.currentProject.project.slug)}/`,'_blank','noopener')); $('#copySiteBtn')?.addEventListener('click',copySiteUrl);
}
async function saveCurrentFile({silent=false}={}){
  const file=state.currentProject?.files.find(f=>String(f.id)===String(state.currentFile)); if(!file)return true;
  if(isBinaryContent(file.content)){if(!silent)showToast('O ficheiro binário foi preservado e não pode ser guardado como texto.');return false;}
  const btn=$('#saveBtn'); if(btn)btn.disabled=true;
  try{const content=$('#codeEditor').value;const data=await api(`/api/projects/${state.currentProject.project.id}/files`,{method:'POST',body:JSON.stringify({path:file.path,content})});Object.assign(file,data.file);state.dirty=false;$('#saveState')?.classList.remove('dirty');$('#statusLeft').textContent=`${formatBytes(file.size_bytes)} · guardado`;await loadProjectAgain();if(!silent)showToast('Ficheiro guardado.');return true;}catch(err){showToast(err.message);return false;}finally{if(btn)btn.disabled=false;}
}
async function loadProjectAgain(){const id=state.currentProject.project.id,data=await api(`/api/projects/${id}`),selected=state.currentFile;state.currentProject=data;state.currentFile=selected;renderProject();}
async function commitProject(){try{if(state.dirty&&!(await saveCurrentFile({silent:true})))return;const message=prompt('Mensagem do commit:','Atualização do projeto');if(message===null)return;await api(`/api/projects/${state.currentProject.project.id}/commit`,{method:'POST',body:JSON.stringify({message})});await loadProjectAgain();showToast('Commit criado.');}catch(err){showToast(err.message);}}
async function restoreCommit(commitId){if(!confirm('Restaurar este commit? As alterações atuais serão substituídas.'))return;try{await api(`/api/projects/${state.currentProject.project.id}/commits/${commitId}/restore`,{method:'POST',body:'{}'});state.dirty=false;await loadProjectAgain();showToast('Commit restaurado.');}catch(err){showToast(err.message);}}
async function deleteCurrentFile(){const file=state.currentProject.files.find(f=>String(f.id)===String(state.currentFile));if(!file)return;if(!confirm(`Eliminar ${file.path}?`))return;try{await api(`/api/projects/${state.currentProject.project.id}/files/${file.id}`,{method:'DELETE'});state.currentFile=null;state.dirty=false;await loadProjectAgain();showToast('Ficheiro eliminado.');}catch(err){showToast(err.message);}}
async function deployProject(){
  const project=state.currentProject?.project;
  if(!project){showToast('Abre um projecto antes de publicar.');return;}
  if(LOCAL_MODE){showToast('O Deploy público precisa do LuzaWeb publicado com o backend e o PostgreSQL configurados.');return;}
  const buttons=[$('#repoDeployBtn'),$('#deployBtn')].filter(Boolean);
  buttons.forEach(button=>{button.disabled=true;button.dataset.originalText=button.textContent;button.textContent='A publicar…';});
  try{
    if(state.dirty&&!(await saveCurrentFile({silent:true})))return;
    const result=await api(`/api/projects/${project.id}/deploy`,{method:'POST',body:'{}'});
    state.projectSection='deploy';
    await loadProjectAgain();
    const url=new URL(result.url||`/sites/${encodeURIComponent(project.slug)}/`,location.origin).href;
    showToast(`Deploy concluído: ${url}`);
  }catch(err){showToast(err.message||'Não foi possível publicar este projecto.');}
  finally{[$('#repoDeployBtn'),$('#deployBtn')].filter(Boolean).forEach(button=>{button.disabled=false;button.textContent=button.dataset.originalText||'↑ Deploy';delete button.dataset.originalText;});}
}
async function copySiteUrl(){const url=new URL(`/sites/${encodeURIComponent(state.currentProject.project.slug)}/`,location.origin).href;try{await navigator.clipboard.writeText(url);showToast('URL copiada.');}catch{prompt('Copia a URL:',url);}}
function mimeTypeForPath(filePath){
  const ext=pathExt(filePath).toLowerCase();
  return ({'.html':'text/html','.htm':'text/html','.css':'text/css','.js':'text/javascript','.mjs':'text/javascript','.json':'application/json','.xml':'application/xml','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.avif':'image/avif','.ico':'image/x-icon','.bmp':'image/bmp','.pdf':'application/pdf','.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.otf':'font/otf','.mp3':'audio/mpeg','.wav':'audio/wav','.ogg':'audio/ogg','.mp4':'video/mp4','.webm':'video/webm','.wasm':'application/wasm','.txt':'text/plain','.md':'text/markdown','.csv':'text/csv'})[ext]||'application/octet-stream';
}
async function ensureRepositoryChangesSaved(){
  if(!state.dirty)return true;
  return await saveCurrentFile({silent:true});
}
async function createRepositoryFolder(){
  const name=String(prompt('Nome da nova pasta:','nova-pasta')||'').trim();
  if(!name)return;
  if(name==='.'||name==='..'||/[\\/]/.test(name)){showToast('Indica apenas o nome da pasta, sem barras.');return;}
  if(!(await ensureRepositoryChangesSaved()))return;
  try{
    await api(`/api/projects/${state.currentProject.project.id}/folders`,{method:'POST',body:JSON.stringify({path:name})});
    state.collapsedFolders.delete(name);
    await loadProjectAgain();
    showToast('Pasta criada.');
  }catch(err){showToast(err.message||'Não foi possível criar a pasta.');}
}
async function moveRepositoryFile(fileId,targetFolder=''){
  const file=state.currentProject?.files.find(item=>Number(item.id)===Number(fileId));
  if(!file)return false;
  const baseName=String(file.path).split('/').filter(Boolean).pop();
  const newPath=[String(targetFolder||'').replace(/^\/+|\/+$/g,''),baseName].filter(Boolean).join('/');
  if(newPath===file.path){showToast('O ficheiro já está nessa pasta.');return true;}
  if(!(await ensureRepositoryChangesSaved()))return false;
  try{
    await api(`/api/projects/${state.currentProject.project.id}/files/${file.id}/path`,{method:'PATCH',body:JSON.stringify({path:newPath})});
    const parent=String(targetFolder||'').split('/').filter(Boolean);let prefix='';for(const part of parent){prefix=prefix?`${prefix}/${part}`:part;state.collapsedFolders.delete(prefix);}
    state.cutFileId=null;
    await loadProjectAgain();
    showToast(`Ficheiro movido para ${targetFolder||'a raiz do repositório'}.`);
    return true;
  }catch(err){showToast(err.message||'Não foi possível mover o ficheiro.');return false;}
}

async function importFiles(e){
  const input=e.target;
  const selectedFiles=[...(input.files||[])];
  if(!selectedFiles.length){input.value='';state.importTargetFolder='';return;}
  const candidates=[];
  let skipped=0;
  for(const file of selectedFiles){
    if(file.size>MAX_IMPORT_FILE_BYTES){skipped++;continue;}
    const filePath=importPathForFile(file,state.importTargetFolder);
    if(!filePath){skipped++;continue;}
    candidates.push({file,path:filePath});
  }
  if(!candidates.length){showToast('Não foi possível importar os ficheiros seleccionados. O limite é 300 KB por ficheiro.');input.value='';state.importTargetFolder='';return;}
  if(!(await ensureRepositoryChangesSaved())){input.value='';state.importTargetFolder='';return;}
  const originalFiles=state.currentProject?.files||[];
  const originalPaths=new Set(originalFiles.map(file=>file.path));
  const overwrites=candidates.filter(item=>originalPaths.has(item.path));
  if(overwrites.length&&!confirm(`${overwrites.length} ficheiro(s) já existem no repositório e serão substituídos. Continuar?`)){input.value='';state.importTargetFolder='';return;}

  const sizesByPath=new Map(originalFiles.map(file=>[file.path,Number(file.size_bytes||0)]));
  let projectBytes=[...sizesByPath.values()].reduce((sum,size)=>sum+size,0);
  let projectCount=sizesByPath.size;
  let imported=0;
  showToast(`A importar ${candidates.length} ficheiro(s)…`);
  try{
    for(const item of candidates){
      const currentSize=sizesByPath.get(item.path);
      if(currentSize===undefined&&projectCount>=120){skipped++;continue;}
      try{
        const buffer=await item.file.arrayBuffer();
        let content;
        if(isTextFile(item.file)||isProbablyTextBuffer(buffer)){
          try{content=new TextDecoder('utf-8',{fatal:true}).decode(buffer);}
          catch{content=await item.file.text();}
        }else{
          content=encodeBinaryContent(item.file.type||mimeTypeForPath(item.path),bytesToBase64(buffer));
        }
        const storedSize=getContentByteSize(content);
        if(storedSize>MAX_IMPORT_FILE_BYTES){skipped++;continue;}
        const nextTotal=projectBytes-(currentSize||0)+storedSize;
        if(nextTotal>5000000){skipped++;continue;}
        await api(`/api/projects/${state.currentProject.project.id}/files`,{method:'POST',body:JSON.stringify({path:item.path,content})});
        projectBytes=nextTotal;
        if(currentSize===undefined)projectCount++;
        sizesByPath.set(item.path,storedSize);
        imported++;
      }catch{skipped++;}
    }
    await loadProjectAgain();
    const summary=`Importados ${imported} ficheiro(s)${skipped?` · ${skipped} ignorado(s) (limite de 300 KB por ficheiro, 120 ficheiros ou 5 MB por projecto)`:''}.`;
    showToast(summary);
  }catch(err){showToast(err.message||'Ocorreu um erro durante a importação.');}
  finally{input.value='';state.importTargetFolder='';}
}

async function loadDatabaseConnectionUI(){
 const area=$('#databaseConnectionArea');
 if(!area)return;
 try{
  const data=await api(`/api/projects/${state.currentProject.project.id}/database/connection`);
  const c=data.connection;
  state.databaseConnection=c||null;
  if(!c){
   area.innerHTML='<div class="preview-empty">Ainda não existe uma ligação PostgreSQL guardada para este projecto. Usa «Criar base de dados» para criar uma base real no Neon. Também podes ligar uma base PostgreSQL que já exista.</div>';
   return;
  }
  const internalText=c.internal_url||(c.provider==='neon'&&c.is_provisioned?'O Neon não fornece uma URL interna privada separada':'Não fornecida para esta ligação');
  const changeConnectionBtn=$('#editDatabaseConnectionBtn');
  if(changeConnectionBtn && c.is_provisioned){changeConnectionBtn.disabled=true;changeConnectionBtn.textContent='Base criada no Neon';changeConnectionBtn.title='Esta base já está ligada ao projecto.';}
  else if(changeConnectionBtn){changeConnectionBtn.disabled=false;changeConnectionBtn.textContent='Ligar PostgreSQL existente';changeConnectionBtn.title='Guardar os dados de uma ligação existente.';}
  const rows=[['Hostname',c.hostname],['Port',c.port],['Database',c.database],['Username',c.username],['Password',c.has_password?'••••••••':'Não definida'],['Internal Database URL',internalText],['External Database URL',c.external_url],['PSQL Command',c.psql_command]];
  area.innerHTML=`<div class="db-connection-grid">${rows.map(([k,v])=>`<div class="db-connection-field"><small>${escapeHtml(k)}</small><code>${escapeHtml(String(v??'—'))}</code>${k==='External Database URL'||k==='PSQL Command'?`<button type="button" class="btn ghost copy-db-value" data-copy-value="${escapeHtml(String(v??''))}">Copiar</button>`:''}</div>`).join('')}</div><div class="repo-toolbar-actions" style="margin-top:12px"><button class="btn secondary" id="testDatabaseConnectionBtn">Testar ligação</button><span class="muted" id="databaseConnectionStatus">A ligação é testada no servidor. Credenciais completas só são mostradas no momento da criação.</span></div><p class="muted database-connection-note">${escapeHtml(c.connection_note||'As credenciais completas são protegidas no servidor. Não partilhes URLs nem palavras-passe publicamente.')}</p>`;
  $$('.copy-db-value',area).forEach(btn=>btn.addEventListener('click',()=>copyText(btn.dataset.copyValue)));
  $('#testDatabaseConnectionBtn')?.addEventListener('click',async()=>{
   const btn=$('#testDatabaseConnectionBtn');
   btn.disabled=true;
   try{
    const result=await api(`/api/projects/${state.currentProject.project.id}/database/connection/test`,{method:'POST',body:'{}'});
    $('#databaseConnectionStatus').textContent=result.message||'Ligação testada.';
    showToast(result.message||'Ligação testada.');
   }catch(err){
    $('#databaseConnectionStatus').textContent=err.message;
    showToast(err.message);
   }finally{btn.disabled=false;}
  });
 }catch(err){area.innerHTML=`<div class="error-card">${escapeHtml(err.message)}</div>`;}
}
async function createProjectDatabase(event){
  event?.preventDefault();
  if(LOCAL_MODE){showToast('Para criar uma base PostgreSQL real, publica o LuzaWeb com NEON_API_KEY, DATABASE_URL e JWT_SECRET configuradas no servidor.');return;}
  const form=$('#databaseCreateForm');if(!form)return;
  const button=$('#submitDatabaseCreateBtn');if(button)button.disabled=true;
  try{
    const payload={name:$('#databaseCreateName').value.trim(),region_id:$('#databaseCreateRegion').value,pg_version:Number($('#databaseCreateVersion').value)};
    const result=await api(`/api/projects/${state.currentProject.project.id}/database/provision`,{method:'POST',body:JSON.stringify(payload)});
    state.databaseScreen='overview';
    renderProject();
    showProjectDatabaseCredentials(result.connection);
    showToast('A base de dados PostgreSQL foi criada pelo Neon.');
  }catch(err){showToast(err.message||'Não foi possível criar a base de dados.');}
  finally{const current=$('#submitDatabaseCreateBtn');if(current)current.disabled=false;}
}
function showProjectDatabaseCredentials(connection){
  const dlg=document.createElement('dialog');dlg.className='dialog';
  const fields=[['Hostname',connection.hostname],['Port',connection.port],['Database',connection.database],['Username',connection.username],['Password',connection.password],['Internal Database URL',connection.internal_url||'O Neon não fornece uma URL interna privada separada'],['External Database URL',connection.external_url],['PSQL Command',connection.psql_command]];
  dlg.innerHTML=`<form method="dialog" class="dialog-card wide-dialog"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">POSTGRESQL DO PROJECTO</div><h3>Base de dados preparada</h3><p class="muted">Estas informações vieram do fornecedor PostgreSQL após a criação e o teste real da ligação. O Neon não disponibiliza uma URL interna privada separada. Guarda a palavra-passe e a URL completa num local seguro; não serão novamente mostradas em texto aberto.</p><div class="db-connection-grid">${fields.map(([label,value])=>`<div class="db-connection-field"><small>${escapeHtml(label)}</small><code>${escapeHtml(String(value??''))}</code><button type="button" class="btn ghost copy-provision-value" data-copy-value="${escapeHtml(String(value??''))}" ${label==='Internal Database URL'&&!connection.internal_url?'disabled':''}>Copiar</button></div>`).join('')}</div><p class="muted">${escapeHtml(connection.connection_note||'Não partilhes URLs nem credenciais publicamente.')}</p><div class="dialog-actions"><button type="button" class="btn secondary" data-x>Fechar</button></div></form>`;
  document.body.appendChild(dlg);dlg.showModal();$$('.copy-provision-value',dlg).forEach(btn=>btn.addEventListener('click',()=>copyText(btn.dataset.copyValue)));$$('[data-x]',dlg).forEach(btn=>btn.addEventListener('click',()=>dlg.close()));dlg.addEventListener('close',()=>dlg.remove());
}
function openDatabaseConnectionDialog(){
 const current=state.databaseConnection||{};const dlg=document.createElement('dialog');dlg.className='dialog';dlg.innerHTML=`<form class="dialog-card wide-dialog"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">POSTGRESQL</div><h3>Ligar PostgreSQL externo</h3><p class="muted">Guarda os dados de uma instância PostgreSQL que já existe. Esta ligação é testada pelo backend, mas não substitui automaticamente a base de dados gerida na secção acima.</p><label>Nome da ligação<input id="dbConnName" maxlength="80" required value="${escapeHtml(current.name||state.currentProject.project.slug+'-db')}" placeholder="minha-base"></label><label>Fornecedor<select id="dbConnProvider"><option value="external">PostgreSQL externo</option><option value="render">Render</option><option value="neon">Neon</option><option value="supabase">Supabase</option><option value="railway">Railway</option><option value="other">Outro</option></select></label><div class="profile-form-two"><label>Hostname<input id="dbConnHost" required value="${escapeHtml(current.hostname||'')}" placeholder="ep-example.neon.tech"></label><label>Port<input id="dbConnPort" type="number" min="1" max="65535" required value="${escapeHtml(String(current.port||5432))}"></label><label>Database<input id="dbConnDatabase" required value="${escapeHtml(current.database||'')}" placeholder="app_db"></label><label>Username<input id="dbConnUsername" required value="${escapeHtml(current.username||'')}" placeholder="database_user"></label></div><label>Password<input id="dbConnPassword" type="password" required autocomplete="new-password" placeholder="${current.has_password?'Guardada; introduz novamente para substituir':''}"></label><div class="dialog-actions"><button type="button" class="btn secondary" data-cancel>Cancelar</button><button type="submit" class="btn primary">Guardar ligação</button></div></form>`;document.body.appendChild(dlg);dlg.showModal();$('#dbConnProvider',dlg).value=current.provider||'external';$('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('[data-cancel]',dlg).addEventListener('click',()=>dlg.close());dlg.addEventListener('submit',async e=>{e.preventDefault();try{await api(`/api/projects/${state.currentProject.project.id}/database/connection`,{method:'POST',body:JSON.stringify({name:$('#dbConnName',dlg).value,provider:$('#dbConnProvider',dlg).value,hostname:$('#dbConnHost',dlg).value,port:Number($('#dbConnPort',dlg).value),database:$('#dbConnDatabase',dlg).value,username:$('#dbConnUsername',dlg).value,password:$('#dbConnPassword',dlg).value})});dlg.close();dlg.remove();await loadDatabaseConnectionUI();showToast('Configuração da ligação guardada.');}catch(err){showToast(err.message);}});dlg.addEventListener('close',()=>dlg.remove());}
async function copyText(value){try{await navigator.clipboard.writeText(String(value||''));showToast('Copiado.');}catch{prompt('Copia o valor:',String(value||''));}}
async function loadEnvironmentUI(){const area=$('#environmentArea');if(!area)return;try{const data=await api(`/api/projects/${state.currentProject.project.id}/environment`);const groups=data.groups||[],vars=data.variables||[];area.innerHTML=`<div class="env-groups">${groups.map(g=>`<section class="side-card env-group"><div class="pane-head"><span class="pane-title">📁 ${escapeHtml(g.name)}</span><div class="repo-toolbar-actions"><button class="btn ghost edit-env-group" data-id="${g.id}" data-name="${escapeHtml(g.name)}">Editar</button><button class="btn danger delete-env-group" data-id="${g.id}">Eliminar</button></div></div><div class="side-body">${vars.filter(v=>Number(v.group_id)===Number(g.id)).map(envVariableRow).join('')||'<div class="preview-empty">Este grupo ainda não tem variáveis.</div>'}</div></section>`).join('')}${vars.some(v=>!v.group_id)?`<section class="side-card env-group"><div class="pane-head"><span class="pane-title">Variáveis sem grupo</span></div><div class="side-body">${vars.filter(v=>!v.group_id).map(envVariableRow).join('')}</div></section>`:''}${!groups.length&&!vars.length?'<div class="empty-state"><div class="empty-icon">⚙</div><h3>Sem variáveis ambientais</h3><p>Cria uma variável ou um grupo para começar a configurar este projeto.</p></div>':''}</div>`;
 $('#newEnvVariableBtn')?.addEventListener('click',()=>openEnvVariableDialog(groups));$('#newEnvGroupBtn')?.addEventListener('click',()=>openEnvGroupDialog());$$('.edit-env-group',area).forEach(b=>b.addEventListener('click',()=>openEnvGroupDialog({id:b.dataset.id,name:b.dataset.name})));$$('.delete-env-group',area).forEach(b=>b.addEventListener('click',async()=>{if(!confirm('Eliminar este grupo? As variáveis serão mantidas sem grupo.'))return;try{await api(`/api/projects/${state.currentProject.project.id}/environment/groups/${b.dataset.id}`,{method:'DELETE'});await loadEnvironmentUI();showToast('Grupo eliminado.');}catch(err){showToast(err.message);}}));$$('.edit-env-var',area).forEach(b=>b.addEventListener('click',()=>openEnvVariableDialog(groups,vars.find(v=>Number(v.id)===Number(b.dataset.id)))));$$('.delete-env-var',area).forEach(b=>b.addEventListener('click',async()=>{if(!confirm('Eliminar esta variável?'))return;try{await api(`/api/projects/${state.currentProject.project.id}/environment/variables/${b.dataset.id}`,{method:'DELETE'});await loadEnvironmentUI();showToast('Variável eliminada.');}catch(err){showToast(err.message);}}));
 }catch(err){area.innerHTML=`<div class="error-card">${escapeHtml(err.message)}</div>`;}}
function envVariableRow(v){return `<div class="env-var-row"><div class="env-var-main"><strong>${escapeHtml(v.name)}</strong><code>${v.is_secret?'••••••••':escapeHtml(v.value||'')}</code><small>${v.is_secret?'Segredo protegido':'Valor visível'}${v.has_value?' · configurada':' · sem valor'}</small></div><div class="repo-toolbar-actions"><button class="btn ghost edit-env-var" data-id="${v.id}">Editar</button><button class="btn danger delete-env-var" data-id="${v.id}">Eliminar</button></div></div>`;}
function openEnvGroupDialog(current=null){const dlg=document.createElement('dialog');dlg.className='dialog';dlg.innerHTML=`<form class="dialog-card"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">GRUPO DE VARIÁVEIS</div><h3>${current?'Editar grupo':'Criar grupo'}</h3><label>Nome do grupo<input id="envGroupName" required maxlength="80" value="${escapeHtml(current?.name||'')}" placeholder="Desenvolvimento"></label><div class="dialog-actions"><button type="button" class="btn secondary" data-cancel>Cancelar</button><button class="btn primary">Guardar grupo</button></div></form>`;document.body.appendChild(dlg);dlg.showModal();$('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('[data-cancel]',dlg).addEventListener('click',()=>dlg.close());dlg.addEventListener('submit',async e=>{e.preventDefault();try{const url=`/api/projects/${state.currentProject.project.id}/environment/groups${current?'/'+current.id:''}`;await api(url,{method:current?'PATCH':'POST',body:JSON.stringify({name:$('#envGroupName',dlg).value})});dlg.close();dlg.remove();await loadEnvironmentUI();showToast(current?'Grupo atualizado.':'Grupo criado.');}catch(err){showToast(err.message);}});dlg.addEventListener('close',()=>dlg.remove());}
function openEnvVariableDialog(groups,current=null){
  const initialName=String(current?.name||'');
  const forceSecret= isSensitiveEnvName(initialName);
  const dlg=document.createElement('dialog');dlg.className='dialog';
  dlg.innerHTML=`<form class="dialog-card"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">VARIÁVEL DO AMBIENTE</div><h3>${current?'Editar variável':'Criar variável'}</h3><label>Nome<input id="envVarName" required maxlength="120" value="${escapeHtml(initialName)}" placeholder="DATABASE_URL" pattern="[A-Za-z_][A-Za-z0-9_]*"></label><label>Valor<input id="envVarValue" ${current?'':'required'} autocomplete="off" type="${(current?.is_secret||forceSecret)?'password':'text'}" placeholder="${current?'Deixa vazio para manter o valor atual':'Valor da variável'}"></label><label>Grupo<select id="envVarGroup"><option value="">Sem grupo</option>${groups.map(g=>`<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}</select></label><label class="check-inline"><input id="envVarSecret" type="checkbox" ${(current?.is_secret===false&&!forceSecret)?'':'checked'}> Valor secreto (ocultar)</label><p class="muted" id="envSecretHelp">Os valores secretos são cifrados no servidor. Nomes associados a palavras-passe, tokens e ligações de bases de dados são sempre tratados como secretos e não são enviados a sites publicados.</p><div class="dialog-actions"><button type="button" class="btn secondary" data-cancel>Cancelar</button><button class="btn primary">Guardar variável</button></div></form>`;
  document.body.appendChild(dlg);dlg.showModal();$('#envVarGroup',dlg).value=current?.group_id||'';
  const nameInput=$('#envVarName',dlg),valueInput=$('#envVarValue',dlg),secretInput=$('#envVarSecret',dlg);
  const syncSecretControl=()=>{const forced=isSensitiveEnvName(nameInput.value);if(forced)secretInput.checked=true;secretInput.disabled=forced;valueInput.type=secretInput.checked?'password':'text';};
  syncSecretControl();nameInput.addEventListener('input',syncSecretControl);secretInput.addEventListener('change',syncSecretControl);
  $('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('[data-cancel]',dlg).addEventListener('click',()=>dlg.close());
  dlg.addEventListener('submit',async e=>{e.preventDefault();try{const payload={name:nameInput.value,value:valueInput.value,group_id:$('#envVarGroup',dlg).value||null,is_secret:secretInput.checked||isSensitiveEnvName(nameInput.value)};if(current&&!payload.value)delete payload.value;await api(`/api/projects/${state.currentProject.project.id}/environment/variables${current?'/'+current.id:''}`,{method:current?'PUT':'POST',body:JSON.stringify(payload)});dlg.close();dlg.remove();await loadEnvironmentUI();showToast(current?'Variável atualizada.':'Variável criada.');}catch(err){showToast(err.message);}});
  dlg.addEventListener('close',()=>dlg.remove());
}

async function loadDatabaseUI(){
  const area = $('#databaseArea');
  if(!area) return;
  try {
    const data = await api(`/api/projects/${state.currentProject.project.id}/database`);
    state.database = data;
    await loadDatabaseConnectionUI();

    const managedArea=$('#projectDatabaseDetails');
    const managedStatus=$('#managedDatabaseStatus');
    const database=data.database||{};
    const isNeon=database.provider==='neon' && Boolean(database.has_connection);
    const isLocal=database.engine==='SQLite local';
    const isReady=Boolean(isNeon || database.has_connection || isLocal);
    const statusText=isNeon?'Ligada ao Neon':isLocal?'Armazenamento local':database.has_connection?'Ligação preparada':'Ainda não criada';
    if(managedStatus){
      managedStatus.textContent=statusText;
      managedStatus.classList.toggle('muted',!database.has_connection);
    }
    const tablesButton=$('#databaseTablesBtn');
    if(tablesButton){
      // Do not leave the navigation looking dead when connection loading fails.
      // The click handler explains what is missing if the database is not ready.
      tablesButton.disabled=false;
      tablesButton.title=isReady?'Abrir a gestão das tabelas.':'Cria primeiro uma base de dados PostgreSQL ou verifica a ligação do projecto.';
      tablesButton.setAttribute('aria-disabled',isReady?'false':'true');
    }

    if(managedArea){
      const detailRows=[
        ['Nome da base de dados',database.name||'—'],
        ['Fornecedor',database.engine||'—'],
        ['Hostname',state.databaseConnection?.hostname||'Disponível após a criação'],
        ['Username',database.db_username||state.databaseConnection?.username||'Disponível após a criação'],
        ['Região',database.region_id||'—'],
        ['Versão PostgreSQL',database.pg_version?`PostgreSQL ${database.pg_version}`:'—'],
        ['Estado',statusText]
      ];
      const description=isNeon
        ? 'Esta base de dados foi criada no Neon. As tabelas e os registos criados nesta secção serão guardados nessa base PostgreSQL.'
        : isLocal
          ? 'Este ambiente está a utilizar armazenamento local. Para criar uma base PostgreSQL independente, publica o LuzaWeb com as variáveis de servidor configuradas.'
          : 'Ainda não existe uma base PostgreSQL independente para este projecto. Usa «Criar base de dados» para solicitar a criação real no Neon.';
      managedArea.innerHTML=`<p>${escapeHtml(description)}</p><div class="db-connection-grid">${detailRows.map(([label,value])=>`<div class="db-connection-field"><small>${escapeHtml(label)}</small><code>${escapeHtml(String(value))}</code></div>`).join('')}</div>`;
    }

    // In the Database overview, keep the screen focused on the database and its details.
    // The table list and its records are loaded only after the user opens the Tabela page.
    if(state.databaseScreen!=='tables') { area.innerHTML=''; return; }

    const tableCards = (data.tables||[]).map(t => `
      <button class="db-table-item ${Number(state.selectedTableId)===Number(t.id)?'active':''}" data-table-id="${t.id}">
        <span>▦</span><div><strong>${escapeHtml(t.name)}</strong><small>${(t.columns||[]).length} colunas · ${t.record_count} registos</small></div><b>›</b>
      </button>`).join('');
    let html = `
      <div class="database-summary">
        <div class="stat-mini"><span>Base</span><strong>${escapeHtml(database.name||'—')}</strong><small>${escapeHtml(database.engine||'Base de dados')}</small></div>
        <div class="stat-mini"><span>Tabelas</span><strong>${(data.tables||[]).length}</strong><small>estruturas deste projecto</small></div>
        <div class="stat-mini"><span>Registos</span><strong>${(data.tables||[]).reduce((sum,t)=>sum+Number(t.record_count||0),0)}</strong><small>guardados na base configurada</small></div>
      </div>`;
    if((data.tables||[]).length){
      html += `<div class="db-layout">
        <section class="db-table-list"><div class="sub-head"><div><b>Tabelas</b><span>Escolhe uma tabela.</span></div></div>${tableCards}</section>
        <section class="db-detail" id="dbDetail"><div class="empty-state"><div class="empty-icon">▦</div><h3>Escolhe uma tabela</h3><p>Cria ou selecciona uma tabela para gerir os registos.</p></div></section>
      </div>`;
    } else {
      html += `<div class="empty-state"><div class="empty-icon">＋</div><h3>Ainda não há tabelas</h3><p>Cria uma tabela para começar a guardar dados nesta base de dados.</p><button class="btn primary" id="emptyTableBtn">Criar nova tabela</button></div>`;
    }
    area.innerHTML = html;
    $('#emptyTableBtn')?.addEventListener('click', openDbTableDialog);
    $$('.db-table-item').forEach(btn => btn.addEventListener('click', () => selectDbTable(Number(btn.dataset.tableId))));
    if((data.tables||[]).length){
      const selected = data.tables.find(t => Number(t.id) === Number(state.selectedTableId)) || data.tables[0];
      await selectDbTable(selected.id);
    }
  } catch(err) {
    area.innerHTML = `<div class="error-card">${escapeHtml(err.message)}</div>`;
    const tablesButton=$('#databaseTablesBtn');
    if(tablesButton){tablesButton.disabled=false;tablesButton.setAttribute('aria-disabled','true');tablesButton.title='Não foi possível verificar a base de dados. Verifica a configuração do servidor.';}
  }
}
async function selectDbTable(tableId){
  state.selectedTableId=tableId;state.selectedTable=null;
  $$('.db-table-item').forEach(el=>el.classList.toggle('active',Number(el.dataset.tableId)===tableId));
  const detail=$('#dbDetail');if(!detail)return;detail.innerHTML='<div class="loading-state">A carregar registos…</div>';
  try{
    const data=await api(`/api/projects/${state.currentProject.project.id}/database/tables/${tableId}/records`);
    state.selectedTable=data.table;
    detail.innerHTML=`<div class="db-detail-head"><div><div class="panel-label">TABELA</div><h4>${escapeHtml(data.table.name)}</h4><p>${data.records.length} registos carregados.</p></div><div><button class="btn secondary" id="newRecordBtn">＋ Novo registo</button><button class="btn danger" id="deleteTableBtn">Eliminar tabela</button></div></div><div class="schema-chips">${data.table.columns.map(c=>`<span><b>${escapeHtml(c.name)}</b> · ${escapeHtml(c.type)}${c.required?' · obrigatório':''}</span>`).join('')}</div><section class="side-card" style="margin:12px 0"><div class="pane-head"><span class="pane-title">Permissões da API pública</span></div><div class="side-body"><label class="check-inline"><input type="checkbox" id="publicReadAccess" ${data.table.public_read?'checked':''}> Permitir leitura pública desta tabela</label><label class="check-inline"><input type="checkbox" id="publicInsertAccess" ${data.table.public_insert?'checked':''}> Permitir inserção pública nesta tabela</label><p class="muted">Aplica-se apenas a uma API key do tipo publishable. Nunca activa actualização ou eliminação públicas.</p><button class="btn secondary" id="savePublicAccessBtn">Guardar permissões</button></div></section>${data.records.length?`<div class="records-list"><table><thead><tr><th>ID</th>${data.table.columns.map(c=>`<th>${escapeHtml(c.name)}</th>`).join('')}<th>Acções</th></tr></thead><tbody>${data.records.map(r=>`<tr><td>${r.id}</td>${data.table.columns.map(c=>`<td>${escapeHtml(displayRecordValue(r.data?.[c.name]))}</td>`).join('')}<td><button class="btn ghost edit-record" data-id="${r.id}">Editar</button> <button class="btn ghost delete-record" data-id="${r.id}">Eliminar</button></td></tr>`).join('')}</tbody></table></div>`:'<div class="preview-empty record-empty">Ainda não há registos nesta tabela.</div>'}`;
    $('#newRecordBtn').addEventListener('click',()=>openRecordDialog(data.table));
    $('#deleteTableBtn').addEventListener('click',()=>deleteDbTable(data.table.id));
    $$('.edit-record').forEach(btn=>btn.addEventListener('click',()=>openRecordDialog(data.table,data.records.find(r=>Number(r.id)===Number(btn.dataset.id)))));
    $$('.delete-record').forEach(btn=>btn.addEventListener('click',()=>deleteDbRecord(data.table.id,btn.dataset.id)));
    $('#savePublicAccessBtn').addEventListener('click',async()=>{const btn=$('#savePublicAccessBtn');btn.disabled=true;try{await api(`/api/projects/${state.currentProject.project.id}/database/tables/${data.table.id}/public-access`,{method:'PATCH',body:JSON.stringify({public_read:$('#publicReadAccess').checked,public_insert:$('#publicInsertAccess').checked})});showToast('Permissões da API actualizadas.');}catch(err){showToast(err.message);}finally{btn.disabled=false;}});
  }catch(err){detail.innerHTML=`<div class="error-card">${escapeHtml(err.message)}</div>`;}
}
function displayRecordValue(value){if(value===null||value===undefined)return'—';if(typeof value==='object')return JSON.stringify(value);return String(value);}
async function deleteDbTable(tableId){if(!confirm('Eliminar esta tabela e todos os seus registos?'))return;try{await api(`/api/projects/${state.currentProject.project.id}/database/tables/${tableId}`,{method:'DELETE'});state.selectedTableId=null;renderProject();showToast('Tabela eliminada.');}catch(err){showToast(err.message);}}
async function deleteDbRecord(tableId,recordId){if(!confirm('Eliminar este registo?'))return;try{await api(`/api/projects/${state.currentProject.project.id}/database/tables/${tableId}/records/${recordId}`,{method:'DELETE'});await selectDbTable(tableId);showToast('Registo eliminado.');}catch(err){showToast(err.message);}}
function openDbTableDialog(){
  const dlg=document.createElement('dialog');dlg.className='dialog database-table-dialog-shell';dlg.innerHTML=`<form method="dialog" class="dialog-card wide-dialog database-table-dialog"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">NOVA TABELA</div><h3>Criar tabela</h3><p class="muted">A tabela será criada na base de dados configurada para este projecto.</p><label>Nome da tabela<input id="dbTableName" maxlength="50" required placeholder="clientes"></label><div class="columns-builder"><div class="columns-builder-head"><span>Colunas</span><button type="button" class="btn ghost" id="addColumnBtn">＋ Coluna</button></div><div id="dbColumns"></div></div><div class="dialog-actions"><button type="button" class="btn secondary" data-cancel>Cancelar</button><button type="submit" class="btn primary">Criar tabela</button></div></form>`;document.body.appendChild(dlg);dlg.showModal();const columns=$('#dbColumns',dlg);const addRow=(seed={name:'',type:'text',required:false})=>{const row=document.createElement('div');row.className='column-row';row.innerHTML=`<input class="col-name" value="${escapeHtml(seed.name)}" maxlength="50" placeholder="nome"><select class="col-type"><option value="text">text</option><option value="number">number</option><option value="boolean">boolean</option><option value="date">date</option></select><label class="check-inline"><input type="checkbox" class="col-required" ${seed.required?'checked':''}> obrigatório</label><button type="button" class="btn ghost remove-column">×</button>`;$('.col-type',row).value=seed.type;$('.remove-column',row).addEventListener('click',()=>row.remove());columns.appendChild(row);};addRow({name:'nome',type:'text',required:true});addRow({name:'valor',type:'text',required:false});$('#addColumnBtn',dlg).addEventListener('click',()=>addRow());$('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('[data-cancel]',dlg).addEventListener('click',()=>dlg.close());dlg.addEventListener('submit',async e=>{e.preventDefault();try{const rows=$$('.column-row',dlg);const cols=rows.map(r=>({name:$('.col-name',r).value,type:$('.col-type',r).value,required:$('.col-required',r).checked}));const data=await api(`/api/projects/${state.currentProject.project.id}/database/tables`,{method:'POST',body:JSON.stringify({name:$('#dbTableName',dlg).value,columns:cols})});state.selectedTableId=data.table.id;dlg.close();dlg.remove();renderProject();showToast('Tabela criada.');}catch(err){showToast(err.message);}});dlg.addEventListener('close',()=>dlg.remove());
}
function openRecordDialog(table, record=null){
  const example=record?.data?{...record.data}:Object.fromEntries((table.columns||[]).map(c=>[c.name,c.type==='boolean'?false:c.type==='number'?0:c.type==='date'?new Date().toISOString().slice(0,10):'']));
  const dlg=document.createElement('dialog');dlg.className='dialog';dlg.innerHTML=`<form class="dialog-card"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">${record?'EDITAR REGISTO':'NOVO REGISTO'}</div><h3>${escapeHtml(table.name)}</h3><p class="muted">Preenche um objecto JSON com as colunas da tabela.</p><textarea id="recordJson" class="big-textarea" spellcheck="false">${escapeHtml(JSON.stringify(example,null,2))}</textarea><div class="dialog-actions"><button type="button" class="btn secondary" data-cancel>Cancelar</button><button class="btn primary">${record?'Guardar alterações':'Guardar registo'}</button></div></form>`;
  document.body.appendChild(dlg);dlg.showModal();$('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('[data-cancel]',dlg).addEventListener('click',()=>dlg.close());
  dlg.addEventListener('submit',async e=>{e.preventDefault();try{let data;try{data=JSON.parse($('#recordJson',dlg).value);}catch{throw new Error('JSON inválido.');}await api(`/api/projects/${state.currentProject.project.id}/database/tables/${table.id}/records${record?`/${record.id}`:''}`,{method:record?'PUT':'POST',body:JSON.stringify({data})});dlg.close();dlg.remove();await selectDbTable(table.id);showToast(record?'Registo actualizado.':'Registo guardado na base de dados.');}catch(err){showToast(err.message);}});dlg.addEventListener('close',()=>dlg.remove());
}

async function loadApiUI(){
  const area=$('#apiArea');if(!area)return;
  try{const data=await api(`/api/projects/${state.currentProject.project.id}/api-keys`);area.innerHTML=`${state.revealedApiToken?`<div class="secret-box"><div><div class="eyebrow">NOVA CHAVE</div><h4>Guarda esta API key agora</h4><p>Por segurança, o token completo só é mostrado neste momento.</p><code id="revealedToken">${escapeHtml(state.revealedApiToken)}</code></div><button class="btn secondary" id="copyApiKey">Copiar</button></div>`:''}<div class="api-layout"><section class="side-card"><div class="pane-head"><span class="pane-title">Chaves</span></div><div class="side-body">${data.keys.length?data.keys.map(k=>`<div class="api-key-row"><div><strong>${escapeHtml(k.label)}</strong><span>${k.key_type==='publishable'?'Chave pública limitada':'Chave secreta de servidor'} · ••••${escapeHtml(k.token_hint)} · criada ${formatDate(k.created_at)}${k.last_used_at?` · usada ${formatDate(k.last_used_at)}`:''}</span></div><button class="btn danger delete-api-key" data-id="${k.id}">Revogar</button></div>`).join(''):'<div class="preview-empty">Ainda não criaste nenhuma API key.</div>'}</div></section><section class="side-card"><div class="pane-head"><span class="pane-title">Exemplo</span></div><div class="side-body"><p class="muted">Depois de criares uma key, podes consultar uma tabela assim:</p><pre class="api-code">curl -H "Authorization: Bearer LZW_KEY" "${location.origin}/v1/${escapeHtml(state.currentProject.project.slug)}/clientes"</pre><p class="muted">Para inserir um registo:</p><pre class="api-code">curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer LZW_KEY" \\\n  -d '{"nome":"Exemplo"}' \\\n  "${location.origin}/v1/${escapeHtml(state.currentProject.project.slug)}/clientes"</pre></div></section></div>`;$('#copyApiKey')?.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(state.revealedApiToken);showToast('API key copiada.')}catch{prompt('Copia a API key:',state.revealedApiToken)}});$$('.delete-api-key').forEach(btn=>btn.addEventListener('click',()=>revokeApiKey(btn.dataset.id)));$('#newApiKeyBtn')?.addEventListener('click',createApiKey);}catch(err){area.innerHTML=`<div class="error-card">${escapeHtml(err.message)}</div>`;}}
async function createApiKey(){const label=prompt('Nome da API key:','Chave principal');if(label===null)return;const choice=prompt('Tipo da chave: escreve publishable para uma chave pública limitada; deixa vazio para secret (servidor).','secret');if(choice===null)return;const key_type=String(choice).trim().toLowerCase()==='publishable'?'publishable':'secret';try{const data=await api(`/api/projects/${state.currentProject.project.id}/api-keys`,{method:'POST',body:JSON.stringify({label,key_type})});state.revealedApiToken=data.token;await loadApiUI();showToast(key_type==='publishable'?'Chave pública criada. Configura as permissões das tabelas antes de a usar.':'Chave secreta criada. Mantém-na no servidor.');}catch(err){showToast(err.message);}}
async function revokeApiKey(id){if(!confirm('Revogar esta API key? As integrações que a usam deixarão de funcionar.'))return;try{await api(`/api/projects/${state.currentProject.project.id}/api-keys/${id}`,{method:'DELETE'});await loadApiUI();showToast('API key revogada.');}catch(err){showToast(err.message);}}

function openProjectDialog(){const dlg=$('#projectDialog');$('#projectName').value='';$('#projectDescription').value='';const hint=$('#projectDialog .muted');if(hint)hint.innerHTML='O primeiro projeto da tua conta inclui ficheiros de exemplo. Os projetos seguintes começam vazios para adicionares ou criares os teus próprios ficheiros.';dlg.showModal();setTimeout(()=>$('#projectName').focus(),50);}
function openFileDialog(){const dlg=$('#fileDialog');$('#fileName').value='';$('#fileContent').value='';dlg.showModal();setTimeout(()=>$('#fileName').focus(),50);}
async function createProject(e){e.preventDefault();const submit=$('#projectForm button[type="submit"]');submit.disabled=true;try{const data=await api('/api/projects',{method:'POST',body:JSON.stringify({name:$('#projectName').value,description:$('#projectDescription').value})});$('#projectDialog').close();await loadProjects();await openProject(data.project.id);showToast('Projeto criado.');}catch(err){showToast(err.message)}finally{submit.disabled=false;}}
async function createFile(e){e.preventDefault();const submit=$('#fileForm button[type="submit"]');submit.disabled=true;try{const data=await api(`/api/projects/${state.currentProject.project.id}/files`,{method:'POST',body:JSON.stringify({path:$('#fileName').value,content:$('#fileContent').value})});$('#fileDialog').close();state.currentFile=null;await loadProjectAgain();state.currentFile=state.currentProject.files.find(f=>f.path===data.file.path)?.id||null;renderProject();showToast('Ficheiro adicionado.');}catch(err){showToast(err.message)}finally{submit.disabled=false;}}
async function deleteCurrentProject() {
  const p = state.currentProject?.project;
  if (!p) return;
  if (!confirm(`Mover \"${p.name}\" para a lixeira?`)) return;
  try {
    await api(`/api/projects/${p.id}`, { method: 'DELETE' });
    await loadProjects();
    closeProjectView();
    showView('projects');
    showToast('Projeto movido para a lixeira.');
  } catch (err) {
    showToast(err.message);
  }
}

function openProjectSettings(){
  const p=state.currentProject.project;const dlg=document.createElement('dialog');dlg.className='dialog';dlg.innerHTML=`<form class="dialog-card"><button type="button" class="dialog-close" data-x>×</button><div class="dialog-kicker">CONFIGURAÇÃO</div><h3>Editar projeto</h3><label>Nome<input id="setName" maxlength="60" value="${escapeHtml(p.name)}" required></label><label>Descrição<textarea id="setDesc" maxlength="180">${escapeHtml(p.description||'')}</textarea></label><div class="dialog-actions"><button type="button" class="btn danger" id="deleteProject">Mover para lixeira</button><span style="flex:1"></span><button type="button" class="btn secondary" id="cancelSettings">Cancelar</button><button type="submit" class="btn primary" id="saveSettings">Guardar</button></div></form>`;document.body.appendChild(dlg);dlg.showModal();$('[data-x]',dlg).addEventListener('click',()=>dlg.close());$('#cancelSettings',dlg).addEventListener('click',()=>dlg.close());dlg.addEventListener('submit',async e=>{e.preventDefault();try{const data=await api(`/api/projects/${p.id}`,{method:'PUT',body:JSON.stringify({name:$('#setName',dlg).value,description:$('#setDesc',dlg).value})});state.currentProject.project=data.project;dlg.close();dlg.remove();await loadProjects();renderProject();showToast('Projeto atualizado.');}catch(err){showToast(err.message);}});$('#deleteProject',dlg).addEventListener('click',async()=>{if(!confirm('Mover este projeto para a lixeira?'))return;try{await api(`/api/projects/${p.id}`,{method:'DELETE'});dlg.close();dlg.remove();state.currentProject=null;await loadProjects();showView('projects');showToast('Projeto movido para a lixeira.');}catch(err){showToast(err.message);}});dlg.addEventListener('close',()=>dlg.remove());}
async function logout(){try{await api('/api/auth/logout',{method:'POST',body:'{}'});}catch{}state.user=null;state.projects=[];state.trash=[];state.currentProject=null;landingView.classList.remove('hidden');authView.classList.add('hidden');appView.classList.add('hidden');showLanding();showToast('Sessão terminada.');}

$$('.auth-tab').forEach(t=>t.addEventListener('click',()=>renderAuth(t.dataset.auth)));
$$('[data-close-dialog]').forEach(btn=>btn.addEventListener('click',()=>btn.closest('dialog').close()));
$('#projectForm').addEventListener('submit',createProject);
$('#fileForm').addEventListener('submit',createFile);
$('#globalNewBtn').addEventListener('click',openProjectDialog);
$('#logoutBtn').addEventListener('click',logout);
$$('.nav-item[data-view]').forEach(btn=>btn.addEventListener('click',()=>{showView(btn.dataset.view);$('#sidebar').classList.remove('open');}));
$('#sidebarToggle').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
$('#landingCreate')?.addEventListener('click',()=>showAuth('register'));
$('#landingCreateHero')?.addEventListener('click',()=>showAuth('register'));
$('#landingLogin')?.addEventListener('click',()=>showAuth('login'));
$('#authBackHome')?.addEventListener('click',showLanding);
document.addEventListener('keydown',async e=>{
  if(e.key==='Escape')$$('dialog[open]').forEach(d=>d.close());
  if(!(e.ctrlKey||e.metaKey)||e.altKey||e.shiftKey||!state.currentProject||state.projectSection!=='repository'||!appView.classList.contains('project-open')||$$('dialog[open]').length)return;
  const target=e.target;
  const isTextEditingTarget=target instanceof HTMLElement && (target.matches('input,textarea,select,[contenteditable="true"]') || target.closest('[contenteditable="true"]'));
  if(isTextEditingTarget)return; // Preserve native copy/cut/paste while editing code or form values.
  const key=e.key.toLowerCase();
  if(key==='x'){
    const file=state.currentProject.files.find(item=>String(item.id)===String(state.currentFile));
    if(!file)return;
    e.preventDefault();state.cutFileId=file.id;renderFileTree();showToast(`Ficheiro preparado para mover: ${file.path}. Escolhe uma pasta e usa Ctrl+V.`);
  }else if(key==='v'&&state.cutFileId!==null){
    e.preventDefault();const cutId=state.cutFileId;const moved=await moveRepositoryFile(cutId,state.selectedFolderPath||'');
    if(moved){state.cutFileId=null;renderFileTree();}
  }
});

checkSession();
