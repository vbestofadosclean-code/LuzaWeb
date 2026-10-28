const quoteIdentifier = value => `"${String(value).replace(/"/g, '""')}"`;
const quoteLiteral = value => `'${String(value).replace(/'/g, "''")}'`;

function projectRoleName(projectId) { return `lzw_project_${projectId}`; }
function projectSchemaName(projectId) { return `luza_project_${projectId}`; }
function errorWithCode(message, code = 'LZW_ROLE_HARDENING_FAILED', cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

/**
 * Restrict credentials provisioned for project schemas in the internal database.
 * Must run inside the caller's startup migration transaction so any unexpected
 * ACL or ownership problem rolls the entire migration back (fail closed).
 */
export async function hardenProjectDatabaseRoles(executor, {
  databaseName,
  onFailure = () => {},
} = {}) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('A PostgreSQL query executor is required.');
  if (typeof databaseName !== 'string' || !databaseName.trim()) throw new TypeError('The PostgreSQL database name is required.');

  const databaseIdent = quoteIdentifier(databaseName);
  const { rows: serviceRoleRows } = await executor.query('SELECT oid, rolname FROM pg_roles WHERE rolname=current_user');
  if (!serviceRoleRows.length) throw errorWithCode('Não foi possível identificar a role de serviço da ligação DATABASE_URL.', 'LZW_DATABASE_SERVICE_ROLE_UNKNOWN');
  const serviceRoleOid = serviceRoleRows[0].oid;
  const { rows: projects } = await executor.query(`
    SELECT project_id, COALESCE(schema_name, '') AS schema_name,
      COALESCE(db_username, '') AS db_username,
      COALESCE(db_password_cipher, '') AS db_password_cipher,
      provisioned_at
    FROM project_databases
    ORDER BY project_id
  `);

  // PostgreSQL 15+ defaults this safely, but older databases grant CREATE on
  // public to PUBLIC. The internal LuzaWeb database must be dedicated to the
  // platform; remove public-schema object creation and public function execution.
  try {
    await executor.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    await executor.query('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC');
    await executor.query('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC');
    await executor.query('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC');
    // Function EXECUTE is granted to PUBLIC by PostgreSQL's global defaults;
    // per-schema REVOKE cannot cancel a global default grant, so change defaults
    // for objects created by this application role at database scope.
    await executor.query('ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC');
    await executor.query('ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC');
    await executor.query('ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC');
  } catch (cause) {
    const error = errorWithCode(
      'Não foi possível aplicar as permissões base do schema public. A conta DATABASE_URL deve administrar o schema public da base interna dedicada ao LuzaWeb.',
      'LZW_PUBLIC_SCHEMA_HARDENING_FAILED', cause
    );
    onFailure({ event: 'public_schema_hardening_failed', error_code: String(cause?.code || 'unknown').slice(0, 40) });
    throw error;
  }

  for (const row of projects) {
    const projectId = Number(row.project_id);
    if (!Number.isSafeInteger(projectId) || projectId < 1) {
      throw errorWithCode('Foi encontrado um project_id inválido em project_databases.', 'LZW_PROJECT_DATABASE_METADATA_INVALID');
    }

    // Most projects start with logical/metadata-only database rows. Only enforce
    // provisioned PostgreSQL roles when credentials/provisioned_at indicate one.
    const provisioned = Boolean(String(row.db_username || '').trim() || String(row.db_password_cipher || '').trim() || row.provisioned_at);
    if (!provisioned) continue;

    const roleName = projectRoleName(projectId);
    const schemaName = projectSchemaName(projectId);
    const storedSchemaName = String(row.schema_name || '').trim();
    if (storedSchemaName && storedSchemaName !== schemaName) {
      const error = errorWithCode(
        `O schema registado para o projecto ${projectId} não corresponde ao nome isolado esperado. É necessária uma reconciliação manual antes do arranque.`,
        'LZW_PROJECT_SCHEMA_MISMATCH'
      );
      onFailure({ event: 'project_schema_mismatch', project_id: projectId, error_code: error.code });
      throw error;
    }

    try {
      const roleResult = await executor.query(
        'SELECT oid, rolname FROM pg_roles WHERE rolname=$1', [roleName]
      );
      const schemaResult = await executor.query(
        'SELECT oid, nspowner FROM pg_namespace WHERE nspname=$1', [schemaName]
      );
      if (!roleResult.rowCount || !schemaResult.rowCount) {
        throw errorWithCode(
          `O projecto ${projectId} está marcado como provisionado, mas a role ou o schema PostgreSQL não existe. O arranque foi bloqueado para evitar permissões inconsistentes.`,
          'LZW_PROJECT_ROLE_OR_SCHEMA_MISSING'
        );
      }
      if (String(schemaResult.rows[0].nspowner) !== String(serviceRoleOid)) {
        throw errorWithCode(
          `O schema do projecto ${projectId} não pertence à role de serviço DATABASE_URL. A migração exige uma transferência de propriedade controlada antes de continuar.`,
          'LZW_PROJECT_SCHEMA_OWNER_MISMATCH'
        );
      }
      const roleOid = roleResult.rows[0].oid;

      // A project credential must never own the database, a schema or any
      // relations/functions. Ownership bypasses ordinary GRANT/REVOKE controls.
      const ownership = await executor.query(`
        SELECT 'schema' AS object_kind, n.nspname::text AS schema_name, n.nspname::text AS object_name
          FROM pg_namespace n WHERE n.nspowner=$1
            AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
        UNION ALL
        SELECT 'relation' AS object_kind, n.nspname::text AS schema_name, c.relname::text AS object_name
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner=$1
            AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
        UNION ALL
        SELECT 'function' AS object_kind, n.nspname::text AS schema_name, p.proname::text AS object_name
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.proowner=$1
            AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
        UNION ALL
        SELECT 'database' AS object_kind, ''::text AS schema_name, d.datname::text AS object_name
          FROM pg_database d WHERE d.datdba=$1
        LIMIT 1
      `, [roleOid]);
      if (ownership.rowCount) {
        const owned = ownership.rows[0];
        throw errorWithCode(
          `A credencial do projecto ${projectId} é proprietária de um objecto PostgreSQL (${owned.object_kind}) e não pode ser limitada apenas com GRANT/REVOKE. É necessária uma migração de propriedade controlada.`,
          'LZW_PROJECT_ROLE_OWNS_OBJECT'
        );
      }

      // Remove role memberships in both directions. NOINHERIT alone is not
      // sufficient because SET ROLE can still activate memberships.
      const { rows: memberships } = await executor.query(`
        SELECT parent.rolname AS granted_role, member.rolname AS member_role
        FROM pg_auth_members m
        JOIN pg_roles parent ON parent.oid=m.roleid
        JOIN pg_roles member ON member.oid=m.member
        WHERE parent.rolname=$1 OR member.rolname=$1
      `, [roleName]);
      for (const membership of memberships) {
        await executor.query(
          `REVOKE ${quoteIdentifier(membership.granted_role)} FROM ${quoteIdentifier(membership.member_role)}`
        );
      }

      await executor.query(
        `ALTER ROLE ${quoteIdentifier(roleName)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5`
      );

      // Remove direct ACLs from every other non-system schema. Then re-grant
      // only the data operations required in this project's own schema.
      const { rows: schemas } = await executor.query(`
        SELECT nspname FROM pg_namespace
        WHERE nspname <> $1 AND nspname <> 'information_schema'
          AND nspname NOT LIKE 'pg_%'
        ORDER BY nspname
      `, [schemaName]);
      for (const item of schemas) {
        const otherSchema = quoteIdentifier(item.nspname);
        await executor.query(`REVOKE ALL PRIVILEGES ON SCHEMA ${otherSchema} FROM ${quoteIdentifier(roleName)}`);
        await executor.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${otherSchema} FROM ${quoteIdentifier(roleName)}`);
        await executor.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ${otherSchema} FROM ${quoteIdentifier(roleName)}`);
        await executor.query(`REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ${otherSchema} FROM ${quoteIdentifier(roleName)}`);
      }

      // Project schemas must not expose access via PUBLIC either. This prevents
      // an unrelated role from inheriting data access even if it guesses a schema.
      await executor.query(`REVOKE ALL PRIVILEGES ON SCHEMA ${quoteIdentifier(schemaName)} FROM PUBLIC`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${quoteIdentifier(schemaName)} FROM PUBLIC`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ${quoteIdentifier(schemaName)} FROM PUBLIC`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ${quoteIdentifier(schemaName)} FROM PUBLIC`);
      await executor.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdentifier(schemaName)} REVOKE ALL ON TABLES FROM PUBLIC`);
      await executor.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdentifier(schemaName)} REVOKE ALL ON SEQUENCES FROM PUBLIC`);
      await executor.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdentifier(schemaName)} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`);
      await executor.query(`REVOKE CREATE ON DATABASE ${databaseIdent} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`REVOKE ALL PRIVILEGES ON SCHEMA ${quoteIdentifier(schemaName)} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`GRANT CONNECT ON DATABASE ${databaseIdent} TO ${quoteIdentifier(roleName)}`);
      await executor.query(`GRANT USAGE ON SCHEMA ${quoteIdentifier(schemaName)} TO ${quoteIdentifier(roleName)}`);
      await executor.query(`REVOKE CREATE ON SCHEMA ${quoteIdentifier(schemaName)} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${quoteIdentifier(schemaName)} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${quoteIdentifier(schemaName)} TO ${quoteIdentifier(roleName)}`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ${quoteIdentifier(schemaName)} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${quoteIdentifier(schemaName)} TO ${quoteIdentifier(roleName)}`);
      await executor.query(`REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ${quoteIdentifier(schemaName)} FROM ${quoteIdentifier(roleName)}`);
      await executor.query(`ALTER ROLE ${quoteIdentifier(roleName)} SET search_path TO ${quoteLiteral(schemaName)}`);
      await executor.query(`ALTER ROLE ${quoteIdentifier(roleName)} IN DATABASE ${databaseIdent} SET search_path TO ${quoteLiteral(schemaName)}`);

      // Fail closed if any effective privilege still leaks from PUBLIC or another
      // role. REVOKE FROM the project role cannot cancel privileges inherited via PUBLIC.
      const escapedSchema = schemaName;
      const relationLeak = await executor.query(`
        SELECT n.nspname, c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema',$2)
          AND n.nspname NOT LIKE 'pg_toast%'
          AND c.relkind IN ('r','p','v','m','f')
          AND has_schema_privilege($1::name,n.oid,'USAGE')
          AND (has_table_privilege($1::name,c.oid,'SELECT') OR
               has_table_privilege($1::name,c.oid,'INSERT') OR
               has_table_privilege($1::name,c.oid,'UPDATE') OR
               has_table_privilege($1::name,c.oid,'DELETE') OR
               has_table_privilege($1::name,c.oid,'TRUNCATE') OR
               has_table_privilege($1::name,c.oid,'REFERENCES') OR
               has_table_privilege($1::name,c.oid,'TRIGGER'))
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (relationLeak.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém acesso efectivo a uma relação fora do seu schema (${relationLeak.rows[0].nspname}.${relationLeak.rows[0].relname}). Revê ACLs concedidas a PUBLIC ou a roles externas.`,
          'LZW_PROJECT_ROLE_CROSS_SCHEMA_RELATION_ACCESS'
        );
      }
      const sequenceLeak = await executor.query(`
        SELECT n.nspname, c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema',$2)
          AND n.nspname NOT LIKE 'pg_toast%'
          AND c.relkind='S'
          AND has_schema_privilege($1::name,n.oid,'USAGE')
          AND (has_sequence_privilege($1::name,c.oid,'USAGE') OR
               has_sequence_privilege($1::name,c.oid,'SELECT') OR
               has_sequence_privilege($1::name,c.oid,'UPDATE'))
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (sequenceLeak.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém acesso efectivo a uma sequência fora do seu schema. Revê ACLs concedidas a PUBLIC ou a roles externas.`,
          'LZW_PROJECT_ROLE_CROSS_SCHEMA_SEQUENCE_ACCESS'
        );
      }
      const functionLeak = await executor.query(`
        SELECT n.nspname, p.proname FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema',$2)
          AND n.nspname NOT LIKE 'pg_toast%'
          AND has_schema_privilege($1::name,n.oid,'USAGE')
          AND has_function_privilege($1::name,p.oid,'EXECUTE')
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (functionLeak.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} ainda pode executar uma função fora do seu schema (${functionLeak.rows[0].nspname}.${functionLeak.rows[0].proname}). Revê ACLs concedidas a PUBLIC ou a roles externas.`,
          'LZW_PROJECT_ROLE_CROSS_SCHEMA_FUNCTION_ACCESS'
        );
      }
      const databaseCreateLeak = await executor.query(
        "SELECT has_database_privilege($1::name,$2::name,'CREATE') AS can_create_schema",
        [roleName, databaseName]
      );
      if (databaseCreateLeak.rows[0]?.can_create_schema === true) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém permissão CREATE na base de dados, podendo criar schemas adicionais.`,
          'LZW_PROJECT_ROLE_DATABASE_CREATE'
        );
      }
      const ownSchemaCreateLeak = await executor.query(`
        SELECT n.nspname FROM pg_namespace n
        WHERE n.nspname=$2 AND has_schema_privilege($1::name,n.oid,'CREATE')
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (ownSchemaCreateLeak.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém permissão CREATE no próprio schema, possivelmente herdada de PUBLIC.`,
          'LZW_PROJECT_ROLE_OWN_SCHEMA_CREATE'
        );
      }
      const ownRelationExtraPrivileges = await executor.query(`
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$2 AND c.relkind IN ('r','p','v','m','f')
          AND (has_table_privilege($1::name,c.oid,'TRUNCATE') OR
               has_table_privilege($1::name,c.oid,'REFERENCES') OR
               has_table_privilege($1::name,c.oid,'TRIGGER'))
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (ownRelationExtraPrivileges.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém privilégios de tabela acima de CRUD no seu schema (${ownRelationExtraPrivileges.rows[0].relname}).`,
          'LZW_PROJECT_ROLE_EXCESS_TABLE_PRIVILEGES'
        );
      }
      const ownSequenceExtraPrivilege = await executor.query(`
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$2 AND c.relkind='S'
          AND has_sequence_privilege($1::name,c.oid,'UPDATE')
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (ownSequenceExtraPrivilege.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém permissão UPDATE numa sequência, acima do necessário para utilização normal.`,
          'LZW_PROJECT_ROLE_EXCESS_SEQUENCE_PRIVILEGES'
        );
      }
      const createLeak = await executor.query(`
        SELECT n.nspname FROM pg_namespace n
        WHERE n.nspname NOT IN ('pg_catalog','information_schema',$2)
          AND n.nspname NOT LIKE 'pg_toast%'
          AND has_schema_privilege($1::name,n.oid,'CREATE')
        LIMIT 1
      `, [roleName, escapedSchema]);
      if (createLeak.rowCount) {
        throw errorWithCode(
          `A credencial do projecto ${projectId} mantém permissão CREATE no schema ${createLeak.rows[0].nspname}. Revê privilégios herdados, incluindo os concedidos a PUBLIC.`,
          'LZW_PROJECT_ROLE_CROSS_SCHEMA_CREATE'
        );
      }
    } catch (cause) {
      onFailure({ event: 'project_role_hardening_failed', project_id: projectId, error_code: String(cause?.code || 'unknown').slice(0, 40) });
      if (cause?.code?.startsWith('LZW_')) throw cause;
      throw errorWithCode(
        `Não foi possível endurecer as permissões PostgreSQL do projecto ${projectId}; a migração foi cancelada para evitar permissões inseguras.`,
        'LZW_PROJECT_ROLE_HARDENING_FAILED', cause
      );
    }
  }

  return { inspected: projects.length, hardened: projects.filter(row => Boolean(String(row.db_username || '').trim() || String(row.db_password_cipher || '').trim() || row.provisioned_at)).length };
}
