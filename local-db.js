import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

function translateSql(sql) {
  return String(sql)
    .replace(/::(?:int|integer|text|jsonb|bigint|timestamptz|timestamp)/gi, '')
    .replace(/\bNOW\(\)/gi, 'CURRENT_TIMESTAMP')
    .replace(/\$([0-9]+)/g, '@p$1');
}

function paramsObject(params = []) {
  const out = {};
  params.forEach((value, index) => { out[`p${index + 1}`] = value; });
  return out;
}

function parseJsonFields(row) {
  if (!row) return row;
  const out = { ...row };
  for (const key of ['snapshot', 'columns', 'data']) {
    if (typeof out[key] === 'string') {
      try { out[key] = JSON.parse(out[key]); } catch { /* keep as text */ }
    }
  }
  return out;
}

function prepareError(error) {
  if (error && /UNIQUE constraint failed/i.test(String(error.message || ''))) {
    error.code = '23505';
  }
  return error;
}

class SQLiteConnection {
  constructor(filename) {
    this.filename = filename;
    this.db = new DatabaseSync(filename);
    this.db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  }

  exec(sql) {
    return this.db.exec(sql);
  }

  async query(sql, params = []) {
    const translated = translateSql(sql);
    const bound = paramsObject(params);
    const normalized = translated.trim().replace(/^\(+/, '').toUpperCase();
    const isRead = /^(SELECT|WITH|PRAGMA)\b/.test(normalized);
    const hasReturning = /\bRETURNING\b/i.test(translated);
    try {
      const statement = this.db.prepare(translated);
      if (isRead || hasReturning) {
        const rows = statement.all(bound).map(parseJsonFields);
        return { rows, rowCount: rows.length };
      }
      const result = statement.run(bound);
      return { rows: [], rowCount: Number(result.changes || 0), lastInsertRowid: Number(result.lastInsertRowid || 0) };
    } catch (error) {
      throw prepareError(error);
    }
  }

  release() {
    try { this.db.close(); } catch {}
  }
}

export class SQLitePool {
  constructor(filename) {
    this.filename = filename;
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    this.main = new SQLiteConnection(filename);
  }

  async query(sql, params = []) {
    return this.main.query(sql, params);
  }

  async connect() {
    return new SQLiteConnection(this.filename);
  }

  exec(sql) {
    return this.main.exec(sql);
  }

  async end() {
    this.main.release();
  }
}
