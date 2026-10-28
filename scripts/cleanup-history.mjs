import pg from 'pg';
import { pruneProjectHistory, historyRetentionLimits } from '../history-retention.js';

if (!process.env.DATABASE_URL) throw new Error('Define DATABASE_URL para apontar à base PostgreSQL interna do LuzaWeb.');
if (process.env.HISTORY_CLEANUP_CONFIRM !== 'YES') {
  throw new Error('Limpeza cancelada. Cria e verifica primeiro um backup; depois define HISTORY_CLEANUP_CONFIRM=YES.');
}

const { Pool } = pg;
const limits = historyRetentionLimits(process.env);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 2,
  connectionTimeoutMillis: 5000,
  statement_timeout: 30000,
  query_timeout: 30000
});
let totals = { projects: 0, removedCommits: 0, removedDeployments: 0 };
try {
  const { rows: projects } = await pool.query('SELECT id FROM projects ORDER BY id');
  for (const project of projects) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT id FROM projects WHERE id=$1 FOR UPDATE', [project.id]);
      const result = await pruneProjectHistory(client, project.id, limits);
      await client.query('COMMIT');
      totals.projects++;
      totals.removedCommits += result.removedCommits;
      totals.removedDeployments += result.removedDeployments;
      console.log(`Histórico do projeto ${project.id}: removidos ${result.removedCommits} snapshots e ${result.removedDeployments} publicações antigas.`);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  console.log(`Limpeza concluída: ${totals.projects} projeto(s), ${totals.removedCommits} snapshot(s) e ${totals.removedDeployments} publicação(ões) removidos. Política: ${limits.commitLimit} commits e ${limits.deploymentLimit} deployments por projeto, com snapshots publicados preservados.`);
} finally { await pool.end(); }
