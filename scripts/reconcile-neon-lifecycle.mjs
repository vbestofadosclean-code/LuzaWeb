import { Pool } from 'pg';

const databaseUrl = String(process.env.DATABASE_URL || '').trim();
const apiKey = String(process.env.NEON_API_KEY || '').trim();
const confirmed = process.env.NEON_RECONCILE_CONFIRM === 'YES';
const staleMinutesInput = Number.parseInt(process.env.NEON_RECONCILE_STALE_MINUTES || '15', 10);
const staleMinutes = Number.isInteger(staleMinutesInput) ? Math.max(5, Math.min(1440, staleMinutesInput)) : 15;
const staleMs = staleMinutes * 60 * 1000;

if (!databaseUrl) throw new Error('Configura DATABASE_URL para consultar o inventário interno do LuzaWeb.');
if (!/^postgres(?:ql)?:\/\//i.test(databaseUrl)) throw new Error('DATABASE_URL tem de ser uma URL PostgreSQL válida.');
if (!apiKey && confirmed) throw new Error('NEON_API_KEY é obrigatória para executar operações de reconciliação.');

const pool = new Pool({
  connectionString: databaseUrl,
  options: '-c search_path=public',
  max: 1,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 5000,
  application_name: 'luzaweb-neon-lifecycle-reconcile'
});

function isStale(timestamp) {
  const time = timestamp instanceof Date ? timestamp.getTime() : Date.parse(String(timestamp || ''));
  return Number.isFinite(time) && Date.now() - time >= staleMs;
}
function validProviderProjectId(id) {
  return /^[a-z0-9-]{1,60}$/i.test(String(id || ''));
}
async function requestProviderProject(id, method = 'GET') {
  const response = await fetch(`https://console.neon.tech/api/v2/projects/${encodeURIComponent(id)}`, {
    method,
    headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    signal: AbortSignal.timeout(25000)
  });
  if (response.ok) return;
  let code = `HTTP_${response.status}`;
  try {
    const body = await response.json();
    if (body?.code) code = String(body.code).slice(0, 80);
  } catch {}
  const error = new Error(`A API Neon recusou a operação (${code}).`);
  error.providerCode = code;
  error.httpStatus = response.status;
  throw error;
}
async function deleteProviderProject(id) {
  if (!validProviderProjectId(id)) throw new Error('Identificador de projeto Neon inválido; remoção bloqueada.');
  // After a timeout, inspect with a safe GET before sending another DELETE.
  try { await requestProviderProject(id, 'GET'); }
  catch (error) { if (error.httpStatus === 404 || error.httpStatus === 410) return; throw error; }
  try { await requestProviderProject(id, 'DELETE'); }
  catch (error) { if (error.httpStatus === 404 || error.httpStatus === 410) return; throw error; }
}
async function noteLifecycleCleanup(projectId, code) {
  await pool.query("UPDATE project_lifecycle_operations SET state='cleanup_required',last_error_code=$2,updated_at=NOW() WHERE project_id=$1", [projectId, String(code || 'RECONCILIATION_FAILED').slice(0, 80)]).catch(() => {});
}

let failed = false;
try {
  const lifecycleRows = await pool.query(`SELECT o.project_id,o.user_id,o.state,o.provider_project_id,o.updated_at,
      p.trashed_at,c.provider,c.provider_project_id AS connected_provider_project_id
    FROM project_lifecycle_operations o
    LEFT JOIN projects p ON p.id=o.project_id
    LEFT JOIN project_database_connections c ON c.project_id=o.project_id
    WHERE o.operation='delete_neon_project' AND o.state IN ('pending','cleanup_required')
    ORDER BY o.updated_at ASC`);

  console.log(`Modo: ${confirmed ? 'EXECUÇÃO CONFIRMADA' : 'SIMULAÇÃO (sem alterações)'}; limite de pendência: ${staleMinutes} min.`);
  for (const row of lifecycleRows.rows) {
    const stale = isStale(row.updated_at);
    const actionable = row.state === 'cleanup_required' || stale;
    console.log(`[eliminação] project_id=${row.project_id} state=${row.state} provider_project_id=${row.provider_project_id || '(ausente)'} stale=${stale} ação=${actionable ? 'reconciliar' : 'aguardar'}`);
    if (!confirmed || !actionable) continue;
    if (!validProviderProjectId(row.provider_project_id)) {
      await noteLifecycleCleanup(row.project_id, 'NEON_RESOURCE_ID_MISSING');
      console.error(`[manual] project_id=${row.project_id}: falta provider_project_id; não foi feita chamada destrutiva.`);
      failed = true;
      continue;
    }
    if (!row.trashed_at) {
      await noteLifecycleCleanup(row.project_id, 'PROJECT_NOT_IN_TRASH');
      console.error(`[manual] project_id=${row.project_id}: o projeto não está na lixeira; foi preservado.`);
      failed = true;
      continue;
    }
    if (row.connected_provider_project_id && String(row.connected_provider_project_id) !== String(row.provider_project_id)) {
      await noteLifecycleCleanup(row.project_id, 'PROVIDER_ID_MISMATCH');
      console.error(`[manual] project_id=${row.project_id}: os IDs local e remoto divergem; foi preservado.`);
      failed = true;
      continue;
    }
    try {
      await deleteProviderProject(String(row.provider_project_id));
      const client = await pool.connect();
      let tx = false;
      try {
        await client.query('BEGIN'); tx = true;
        await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
        const current = (await client.query(`SELECT p.id,p.trashed_at,o.provider_project_id,o.state
          FROM projects p JOIN project_lifecycle_operations o ON o.project_id=p.id
          WHERE p.id=$1 AND p.user_id=$2 FOR UPDATE`, [row.project_id, row.user_id])).rows[0];
        if (!current || !current.trashed_at || String(current.provider_project_id) !== String(row.provider_project_id)) {
          throw new Error('O estado interno mudou durante a reconciliação; a limpeza local foi cancelada.');
        }
        if (row.connected_provider_project_id && String(row.connected_provider_project_id) !== String(current.provider_project_id)) {
          throw new Error('A ligação guardada mudou durante a reconciliação; a limpeza local foi cancelada.');
        }
        await client.query('DELETE FROM deployments WHERE project_id=$1', [row.project_id]);
        await client.query('DELETE FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL', [row.project_id, row.user_id]);
        await client.query('COMMIT'); tx = false;
        console.log(`[concluído] project_id=${row.project_id}: recurso Neon confirmado ausente e projeto local eliminado.`);
      } catch (error) {
        if (tx) { try { await client.query('ROLLBACK'); } catch {} tx = false; }
        // Reuse the same connection while it is checked out (the pool max is 1).
        await client.query("UPDATE project_lifecycle_operations SET state='cleanup_required',last_error_code=$2,updated_at=NOW() WHERE project_id=$1", [row.project_id, String(error?.code || 'LOCAL_FINALIZATION_FAILED').slice(0, 80)]).catch(() => {});
        console.error(`[falha] project_id=${row.project_id}: remoção remota confirmada, limpeza local pendente.`);
        failed = true;
      } finally { client.release(); }
    } catch (error) {
      await noteLifecycleCleanup(row.project_id, error?.providerCode || (error?.httpStatus ? `HTTP_${error.httpStatus}` : 'NEON_DELETE_FAILED'));
      console.error(`[falha] project_id=${row.project_id}: Neon não confirmou a remoção; a referência local foi mantida.`);
      failed = true;
    }
  }

  // A creation reservation with a matching active connection is a completed
  // resource whose reservation cleanup failed; release only the reservation,
  // never delete a database that is already attached to a project.
  const reservations = await pool.query(`SELECT r.project_id,r.user_id,r.state,r.provider_project_id,r.updated_at,
      c.provider,c.provider_project_id AS connected_provider_project_id
    FROM neon_provision_reservations r
    LEFT JOIN project_database_connections c ON c.project_id=r.project_id
    WHERE r.state IN ('pending','cleanup_required')
    ORDER BY r.updated_at ASC`);
  for (const row of reservations.rows) {
    const stale = isStale(row.updated_at);
    const actionable = row.state === 'cleanup_required' || stale;
    console.log(`[provisionamento] project_id=${row.project_id} state=${row.state} provider_project_id=${row.provider_project_id || '(ausente)'} stale=${stale} ação=${actionable ? 'reconciliar' : 'aguardar'}`);
    if (!confirmed || !actionable) continue;
    const resourceId = String(row.provider_project_id || '');
    if (row.connected_provider_project_id && String(row.connected_provider_project_id) === resourceId && row.provider === 'neon') {
      await pool.query("UPDATE neon_provision_reservations SET state='failed',updated_at=NOW() WHERE project_id=$1 AND provider_project_id=$2", [row.project_id, resourceId]);
      console.log(`[corrigido] project_id=${row.project_id}: a base está ativa e ligada; libertada apenas a reserva.`);
      continue;
    }
    if (row.connected_provider_project_id && String(row.connected_provider_project_id) !== resourceId) {
      console.error(`[manual] project_id=${row.project_id}: a reserva diverge da base ligada; nada foi apagado.`);
      failed = true;
      continue;
    }
    if (!validProviderProjectId(resourceId)) {
      console.error(`[manual] project_id=${row.project_id}: a reserva não contém ID Neon; inspeção manual necessária.`);
      failed = true;
      continue;
    }
    try {
      await deleteProviderProject(resourceId);
      await pool.query("UPDATE neon_provision_reservations SET state='failed',updated_at=NOW() WHERE project_id=$1 AND provider_project_id=$2", [row.project_id, resourceId]);
      console.log(`[concluído] project_id=${row.project_id}: recurso de provisionamento removido ou já ausente; reserva marcada como falhada.`);
    } catch (error) {
      await pool.query("UPDATE neon_provision_reservations SET state='cleanup_required',updated_at=NOW() WHERE project_id=$1", [row.project_id]).catch(() => {});
      console.error(`[falha] project_id=${row.project_id}: Neon não confirmou a limpeza do provisionamento.`);
      failed = true;
    }
  }
  if (!lifecycleRows.rows.length && !reservations.rows.length) console.log('Não há operações de ciclo de vida nem reservas pendentes de reconciliação.');
  if (!confirmed) console.log('Para aplicar as operações listadas, executa com NEON_RECONCILE_CONFIRM=YES após rever cada ID.');
} finally {
  await pool.end();
}
if (failed) process.exitCode = 2;
