# LUZAWEB — Versão 1

**Versão oficial do projecto: 1.0.0.**

LUZAWEB é uma plataforma web com autenticação, múltiplos projetos, editor de HTML/CSS/JavaScript, deploy real de sites estáticos, base de dados persistente em PostgreSQL e API por projeto.

## Fluxo principal

1. O utilizador entra na página inicial do LUZAWEB.
2. Escolhe **Criar conta** ou **Entrar**.
3. Depois da autenticação, chega ao workspace.
4. Pode criar vários projetos.
5. Ao abrir um projeto, aparece uma barra própria:

```text
PROJETO
├── Repository
├── Deploy
├── Database
└── API
```

## Funcionalidades do workspace

```text
Dashboard
Projetos
Atividade
Editor
Lixeira
Conta
```

**Editor** abre o Repository de um projeto. **Lixeira** recebe projetos removidos para permitir restauração ou eliminação definitiva. **Conta** permite alterar nome, email e palavra-passe. No Repository, `Ctrl+X` prepara o ficheiro seleccionado para mover; depois selecciona uma pasta de destino e usa `Ctrl+V`. Clica na área vazia da lista para escolher a raiz como destino. Estes atalhos para ficheiros não interceptam copiar/colar texto enquanto o editor estiver activo.

## Deploy de sites estáticos

O botão **Deploy** está activo quando o LUZAWEB está ligado a um backend real. O projecto tem de conter `index.html`. Ao publicar, o servidor guarda um snapshot dos ficheiros do projecto, regista o deployment como `LIVE` e serve a última versão através de `/sites/<slug>/`. Em alojamento Netlify, as rotas `/sites/*` passam pela Function do backend para servir o snapshot guardado no PostgreSQL.

Exemplo de endereço depois de publicar no Netlify:

```text
https://NOME-DO-SITE.netlify.app/sites/meu-projeto/
```

O endereço real utiliza o domínio atribuído ao teu site no Netlify. O ficheiro obrigatório é exactamente `index.html` (minúsculas e na raiz do projecto). Nesta fase, o Deploy suporta **sites estáticos** (HTML, CSS, JavaScript executado no navegador, imagens e outros ficheiros). O sistema ainda não executa código de servidor arbitrário, como um projecto Node.js que precise de permanecer activo.

Publicar novamente passa a servir a versão mais recente. O histórico aplica retenção automática por projeto: mantém por padrão os 30 commits recentes e as 10 publicações recentes, preservando sempre o snapshot da publicação LIVE mais recente e todos os snapshots associados às publicações mantidas.

## Database

Quando `DATABASE_URL` está definida, o LUZAWEB usa PostgreSQL para guardar contas, projectos, ficheiros, metadados e estado da plataforma. Em desenvolvimento sem `DATABASE_URL`, o servidor usa SQLite persistente em `.data/luzaweb.sqlite`; este modo local não provisiona bases PostgreSQL remotas.

A área **Database** está organizada em dois níveis: a página principal mostra a base de dados e os seus dados de ligação; o botão **Tabela** abre a gestão das tabelas e o botão **Criar nova tabela**. A criação da base abre uma página com nome, região e versão PostgreSQL.

A criação de uma base de dados independente é efectuada através da API do Neon. O backend cria um projecto Neon, obtém o identificador da base/branch e uma URI devolvida pelo fornecedor, guarda os dados confidenciais cifrados no PostgreSQL interno do LuzaWeb e testa a ligação com uma consulta real. A URL privada interna não é apresentada como se existisse: o Neon pode fornecer a URL directa e uma URL pooled. As credenciais completas são mostradas no ecrã imediatamente após a criação; as URLs mostradas posteriormente no painel ficam mascaradas.

As tabelas do projecto são criadas como tabelas PostgreSQL reais na base Neon correspondente. As colunas aceites pelo editor são `text`, `number`, `boolean` e `date`. O metadata das tabelas e as permissões da API ficam guardados na base interna do LuzaWeb.

A criação remota só funciona quando o backend tem `DATABASE_URL`, `JWT_SECRET` e `NEON_API_KEY` configurados. Sem essas variáveis e sem uma conta Neon válida, o formulário não finge que criou uma base: apresenta uma mensagem de configuração/erro.

## API

Cada projeto pode gerar uma ou mais API keys. A aplicação fornece endpoints HTTP para consultar e inserir registos das tabelas do projeto.

Exemplo de leitura:

```bash
curl -H "Authorization: Bearer LZW_KEY" \
  "https://teu-dominio.com/v1/meu-projeto/clientes"
```

Exemplo de criação:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer LZW_KEY" \
  -d '{"nome":"Exemplo"}' \
  "https://teu-dominio.com/v1/meu-projeto/clientes"
```

A chave completa só é mostrada no momento em que é criada. Depois, a interface mostra apenas uma pequena parte do token. As chaves **secret** são destinadas apenas a servidores; as chaves **publishable** podem ser usadas no JavaScript público, mas só conseguem ler/inserir nas tabelas em que o proprietário activou explicitamente essas permissões. Não coloques chaves secretas nem `DATABASE_URL` no código do navegador.

Para que um formulário do site publicado grave dados, o código do site tem de enviar o pedido HTTP à API do LUZAWEB. O Deploy publica ficheiros e disponibiliza o endpoint; não detecta nem transforma automaticamente qualquer formulário em operações de base de dados.

## Criar conta e modo local

A criação de conta pode ser testada **sem publicar o LUZAWEB e sem servidor**. Ao abrir `public/index.html` diretamente, ou ao servir apenas a pasta `public/` num servidor estático, o LUZAWEB entra automaticamente em **modo local** e guarda contas, projetos, ficheiros, commits, tabelas, registos e API keys no armazenamento local do navegador.

Quando o LUZAWEB estiver ligado a um backend real, a aplicação detecta `/api/health` e passa a usar o servidor e a base de dados configurados.

## Publicar no Netlify com PostgreSQL interno e bases de projecto Neon

1. Cria uma base PostgreSQL persistente para o próprio LuzaWeb (por exemplo, no Neon ou noutro fornecedor compatível) e copia a URI de ligação. Esta é a `DATABASE_URL` interna da plataforma; não é a mesma base que o LuzaWeb cria para um projecto de utilizador.
2. Cria uma chave API no Neon para permitir ao backend criar bases/projectos de utilizador. Essa chave é necessária para a função **Criar base de dados**. Se a chave da API exigir organização, guarda também o identificador em `NEON_ORG_ID`.
3. Liga este projecto Git ao Netlify ou publica com Netlify CLI (`netlify deploy --build`). Não uses apenas drag-and-drop da pasta `public`, porque isso não constrói a Function do backend. O `netlify.toml` define `public` como pasta publicada, `npm test` como comando de build e `netlify/functions/server.mjs` como Function para as rotas `/api/*`, `/v1/*` e `/sites/*`.
4. Nas variáveis de ambiente do Netlify configura `DATABASE_URL`, `JWT_SECRET`, `SECRET_ENCRYPTION_KEY`, `NEON_API_KEY` e `NODE_ENV=production`. `NEON_ORG_ID` é opcional quando não é exigido pela chave usada. Gera `JWT_SECRET` e `SECRET_ENCRYPTION_KEY` com valores aleatórios diferentes (por exemplo, `openssl rand -base64 48`) e guarda-os num gestor de segredos. `JWT_SECRET` assina sessões; `SECRET_ENCRYPTION_KEY` cifra credenciais guardadas. Nunca uses os valores de exemplo nem coloques segredos no frontend, no README ou no `netlify.toml`.
5. Publica e verifica `https://TEU-SITE.netlify.app/api/health`; a resposta deve indicar `database: "connected"`. Depois testa registo/login, cria uma base de projecto, confirma os dados de ligação, testa a ligação, cria uma tabela, adiciona/consulta um registo e publica um projecto HTML estático.

A chave `NEON_API_KEY`, a `DATABASE_URL`, o `JWT_SECRET` e a `SECRET_ENCRYPTION_KEY` são consumidos apenas pelo backend. Em produção, `SECRET_ENCRYPTION_KEY` é obrigatória, deve ter pelo menos 32 bytes e tem de ser diferente de `JWT_SECRET`; o serviço não inicia sem essa separação. A configuração inicial e as migrações da base interna ocorrem no primeiro arranque. O teste publicado deve ser efectuado com os segredos reais configurados no painel Netlify; um ZIP isolado não contém nem deve conter essas credenciais.

**Limite actual:** a publicação de projectos suporta sites estáticos. O backend do próprio LuzaWeb funciona por Netlify Function, mas os projectos dos utilizadores ainda não recebem um runtime Node.js arbitrário. As variáveis marcadas como secretas não são enviadas ao site estático; apenas as variáveis não secretas ficam disponíveis em `window.LUZA_ENV`.

## Executar localmente

**Opção mais simples:** extrai o ZIP e abre `public/index.html`. Não precisas de npm, Node.js, PostgreSQL ou internet para criar a conta e testar o workspace. Os dados ficam guardados no navegador.

**Opção com backend local:** instala as dependências com `npm install` e inicia com `npm start`. Sem `DATABASE_URL`, o servidor usa automaticamente SQLite persistente em `.data/luzaweb.sqlite`. Quando `DATABASE_URL` for configurada no futuro, a aplicação passa a usar PostgreSQL.


## Ligação PostgreSQL e variáveis do ambiente

A secção **Database** tem uma página dedicada à criação de uma base PostgreSQL independente no Neon, com nome, região e versão. Após a criação, apresenta `Hostname`, `Port`, `Database`, `Username`, `Password`, `Internal Database URL`, `External Database URL` e `PSQL Command`, preenchidos a partir da ligação devolvida pelo fornecedor. Para o Neon, o campo de URL interna informa que não é fornecida uma URL privada separada, em vez de inventar uma. A página principal mantém apenas a informação da base e a ligação; a gestão das tabelas está no nível **Tabela**.

A secção **Variáveis do ambiente** permite criar, editar, eliminar e agrupar variáveis por projecto. Os valores secretos são cifrados no backend e não são devolvidos ao browser; ao editar uma variável secreta, deixa o campo de valor vazio para manter o segredo actual. No modo local de browser, os dados ficam no armazenamento local do navegador e não têm a mesma protecção do backend.

No Deploy estático, as variáveis não secretas são disponibilizadas ao HTML publicado através de `window.LUZA_ENV`; valores marcados como secretos nunca são enviados ao navegador. Nomes reconhecidos como credenciais (por exemplo, `DATABASE_URL`, `JWT_SECRET`, `PASSWORD`, `TOKEN`, `API_KEY` e chaves privadas) são forçados a secretos, mesmo que alguém tente desmarcar essa opção. Ainda não há runtime para executar código de backend arbitrário criado por utilizadores nem para injectar segredos nesses servidores.


### Correção adicional de publicação (Netlify)

A resolução dos caminhos no servidor usa agora `process.cwd()` em vez de `import.meta.url`, para evitar falha quando o bundler do Netlify empacota o módulo em formato CommonJS. Se o repositório já tinha sido atualizado pelo browser, substitui também o ficheiro da raiz `server.js` por esta versão e faz commit; depois aguarda o novo deploy. Não é necessário alterar as variáveis de ambiente para corrigir este erro de caminho.


## Backups completos e recuperação PostgreSQL (Fase 06)

O backup recomendado é o pacote cifrado `npm run backup:all`. Não uses apenas `scripts/backup-postgres.sh` como política completa: esse script antigo cobre somente a base interna e produz um dump individual sem a camada de cifragem do pacote completo.

### O que entra no backup

- **Base interna (`DATABASE_URL`)**: contas, projetos, ficheiros, pastas, snapshots, publicações, variáveis e metadados cifrados.
- **Cada base PostgreSQL Neon gerida pelo LuzaWeb**: o script lê o inventário interno, descifra a URL de ligação com `SECRET_ENCRYPTION_KEY` (ou `LEGACY_SECRET_ENCRYPTION_KEY` durante uma migração) e cria um dump independente. Se uma ligação Neon gerida estiver incompleta, não puder ser descifrada, não exigir TLS ou não apontar para `*.neon.tech`, o backup total falha em vez de ignorar silenciosamente essa base.
- **Manifesto e checksums**: `manifest.json` regista as bases, a relação com os projetos e versões conhecidas; `SHA256SUMS` verifica cada dump e o manifesto.
- **Cifragem do pacote**: o resultado `.lzwbackup` usa AES-256-GCM com chave derivada por scrypt de `BACKUP_ENCRYPTION_PASSPHRASE`. A passphrase precisa de pelo menos 32 bytes e deve ser guardada separadamente. Se a perderes, os backups não podem ser recuperados.

As ligações externas de bases que não são geridas pelo LuzaWeb são listadas no manifesto, mas **não são copiadas** por este processo; cria uma política de backup própria com o respetivo fornecedor. O inventário e o dump da base interna usam o mesmo snapshot PostgreSQL exportado, evitando diferenças entre os metadados recuperados e o ficheiro de recuperação das roles. As bases Neon externas continuam a ser copiadas uma a uma e não constituem uma transação distribuída.

### Executar manualmente

Instala Node.js 22+, `pg_dump`, `pg_restore` e `tar`, e configura as variáveis em ambiente seguro. O `DATABASE_URL` deve apontar para a base PostgreSQL interna dedicada ao LuzaWeb. Define também a chave de cifragem actual para que as ligações Neon armazenadas possam ser lidas.

```bash
export DATABASE_URL='postgresql://...'
export SECRET_ENCRYPTION_KEY='chave-de-cifragem-actual-com-pelo-menos-32-bytes'
export BACKUP_ENCRYPTION_PASSPHRASE='passphrase-aleatoria-com-pelo-menos-32-bytes'
export BACKUP_DIR='./backups'
export BACKUP_KEEP_DAYS=30
npm run backup:all
```

Gera uma passphrase aleatória (por exemplo, `openssl rand -hex 32`) e guarda-a num gestor de segredos fora do repositório. Não a coloques no `.env.example`, no código nem nos registos. O script cria um pacote cifrado, valida os dumps com `pg_restore --list`, verifica a autenticação da cifra antes de publicar o ficheiro final e apaga os dados temporários não cifrados. O destino local tem permissões restritas; guarda também uma cópia num destino separado e privado.

### Agendamento diário no GitHub Actions

Foi incluído `.github/workflows/nightly-backup.yml`, configurado para executar diariamente às **02:17 UTC**, além de permitir execução manual. Para o ativar:

1. Coloca o repositório no GitHub e mantém-no privado, com permissões de leitura de Actions restritas às pessoas necessárias.
2. Em **Settings → Secrets and variables → Actions**, cria os segredos `LUZAWEB_DATABASE_URL`, `LUZAWEB_SECRET_ENCRYPTION_KEY` e `LUZAWEB_BACKUP_ENCRYPTION_PASSPHRASE`. Se houver credenciais cifradas com uma chave antiga, configura também `LUZAWEB_LEGACY_SECRET_ENCRYPTION_KEY` até a rotação estar concluída.
3. Confirma que o workflow está no branch padrão e ativa Actions. Executa-o manualmente uma vez e verifica o resultado antes de confiar no agendamento.
4. O workflow guarda apenas o pacote **já cifrado** como artefacto privado com retenção de 30 dias. Configura notificações para falhas do workflow e descarrega cópias periódicas para outro armazenamento privado, preferencialmente numa conta/serviço independente. A retenção do artefacto é limitada; não substitui arquivo de longo prazo.

O agendamento depende do GitHub Actions e pode atrasar-se ou falhar. Confirma os resultados de execução; não assumes que um backup ocorreu só porque o workflow existe.

### Verificar e extrair um pacote

Faz primeiro o download do artefacto cifrado e do ficheiro `.sha256`. Para decifrar e validar o pacote, escolhe um caminho de destino que **ainda não exista**:

```bash
BACKUP_FILE='./backups/luzaweb-full-AAAAMMDDTHHMMSSZ-1234.lzwbackup' \
RESTORE_WORK_DIR='./restore-work/run-01' \
BACKUP_ENCRYPTION_PASSPHRASE="$BACKUP_ENCRYPTION_PASSPHRASE" \
npm run backup:extract
```

O comando confirma o checksum externo quando existe, autentica a cifragem, verifica caminhos internos, checksums e o índice dos dumps. Apenas extrai os ficheiros e mostra o manifesto; **não altera bases de dados**.

### Recuperar a base interna

Cria uma base de recuperação nova e vazia, separada da produção. Usa `database/internal.dump` dentro da pasta extraída:

```bash
PRODUCTION_DATABASE_URL="$DATABASE_URL" \
RESTORE_DATABASE_URL="$RESTORE_DATABASE_URL" \
BACKUP_FILE='./restore-work/run-01/database/internal.dump' \
RESTORE_TARGET_CLUSTER_DEDICATED=YES \
RESTORE_CONFIRM=YES ./scripts/restore-postgres.sh
```

O script compara origem e destino, exige que o cluster de recuperação seja dedicado e diferente do cluster de produção, verifica os checksums do pacote, confirma que a base de destino não contém tabelas/views/sequências de utilizador, executa `database/project-roles.sql` com `psql` antes do dump e usa `pg_restore --single-transaction --exit-on-error --no-owner --no-privileges`. A recriação de roles é global ao cluster, por isso nunca apontes para um cluster partilhado nem para produção. A conta usada em `RESTORE_DATABASE_URL` deve ser a conta de serviço que será usada depois em `DATABASE_URL` e precisa de permissões para criar/alterar as roles `lzw_project_*`. Se o fornecedor acrescentar um sufixo de pooler ao nome de utilizador (por exemplo, Supabase), revê os nomes guardados em `project_databases.db_username` durante a preparação da recuperação para corresponderem ao endpoint de destino. Não restaura sobre a produção nem elimina objectos existentes para forçar o restauro.

### Recuperar uma base Neon de projeto

1. Consulta `manifest.json` para identificar o `project_id`, `neon_project_id`, versão PostgreSQL e o ficheiro `project-databases/project-....dump`.
2. Cria no fornecedor uma **base de recuperação nova e vazia**, com uma versão PostgreSQL compatível com a versão registada no manifesto. Não uses a URL da base original como destino.
3. Executa:

```bash
PROJECT_PRODUCTION_DATABASE_URL="$URL_NEON_ORIGINAL" \
PROJECT_RESTORE_DATABASE_URL="$URL_NEON_RECUPERACAO_NOVA" \
BACKUP_FILE='./restore-work/run-01/project-databases/project-123-meu-projeto.dump' \
RESTORE_CONFIRM=YES ./scripts/restore-project-postgres.sh
```

Restaura um dump de cada vez. Depois, verifica tabelas e contagens, atualiza a ligação do projeto através de um procedimento operacional controlado e testa a aplicação com dados de validação antes de reabrir o acesso. Não alteres os registos de ligação internos manualmente sem backup e revisão.

### Limites e objetivo de recuperação

O pacote inclui todas as bases Neon **registadas e geridas** pelo LuzaWeb no momento do inventário, incluindo projetos na lixeira. O dump interno e o inventário das roles usam um snapshot consistente da própria base interna. As bases Neon são copiadas sequencialmente; não há uma transação distribuída entre a base interna e cada base Neon, por isso escritas concorrentes ainda podem fazer os pontos temporais diferir. O processo é uma estratégia de backup lógico, não substitui PITR/snapshots do fornecedor. Para dados críticos, ativa também a funcionalidade de recuperação do fornecedor, quando disponível, e testa periodicamente a recuperação completa num ambiente separado.

## Limitação de tentativas de login

As tentativas falhadas são contadas por IP e por email normalizado, usando a tabela partilhada `auth_rate_limits` na base PostgreSQL (ou SQLite em desenvolvimento). Logins bem-sucedidos não consomem tentativas e limpam o contador do email. O registo tem um limite separado por IP para evitar que falhas de login bloqueiem o formulário de criação de conta. Em produção, a tabela partilhada permite aplicar os limites entre instâncias do backend. Se o armazenamento do limitador estiver indisponível, a autenticação falha de forma fechada com HTTP 503 em vez de ignorar a proteção.


## Isolamento de projectos

Todas as operações autenticadas sobre um projecto verificam o proprietário (`user_id`) antes de ler ou alterar ficheiros, snapshots, publicações, bases de dados, variáveis do ambiente e chaves API. Os recursos filhos são consultados também pelo identificador do projecto, e a API pública valida a chave contra o projecto indicado pelo slug. Os caminhos de ficheiros publicados são virtuais, rejeitam travessia (`..`) e bloqueiam ficheiros privados/credenciais. Em instalações PostgreSQL, a migração adiciona uma restrição composta que impede uma publicação de associar um snapshot de outro projecto; se encontrar dados antigos inconsistentes, regista e alerta sem apagar dados.

## Permissões PostgreSQL e migrações concorrentes (fase 05)

A base `DATABASE_URL` interna deve ser uma base dedicada ao LuzaWeb, não partilhada com aplicações independentes. Durante o arranque, o backend força `search_path=public` para o próprio serviço, executa o schema e migrações dentro de uma transacção e serializa as instâncias com `pg_advisory_xact_lock`. O lock tem timeout (`PG_MIGRATION_LOCK_TIMEOUT_MS`, padrão 15000 ms) e o bloco de migração tem timeout (`PG_MIGRATION_STATEMENT_TIMEOUT_MS`, padrão 120000 ms); se não for possível obter o lock ou terminar as migrações, o arranque falha em vez de servir uma versão parcialmente migrada.

As credenciais PostgreSQL dos projectos são limitadas a `CONNECT`, `USAGE` no schema próprio e `SELECT`/`INSERT`/`UPDATE`/`DELETE` nas tabelas desse schema. A migração remove memberships de roles, privilégios directos em schemas de outros projectos, permissões de criação de objectos e privilégios excessivos; audita também permissões efectivas que possam continuar a vir de `PUBLIC`. Uma role provisionada sem schema, role ou integridade esperada bloqueia o arranque e gera um alerta, para evitar continuar com isolamento incompleto. Roles com ownership de objectos exigem uma migração manual de ownership, pois `REVOKE` não remove poderes de proprietário.

Como medida global de isolamento, a migração revoga `CREATE` no schema `public` e `EXECUTE` das funções de `public` a `PUBLIC`, e remove as concessões padrão a `PUBLIC` para novas tabelas, sequências e funções criadas pelo utilizador actual. Isto evita depender apenas de `REVOKE` directo, que não cancela privilégios herdados de `PUBLIC` ou de memberships. Isto pode afectar outras aplicações que partilhem a mesma base; por isso, usa uma base dedicada ao LuzaWeb e faz um backup verificado antes de actualizar uma base existente. A conta em `DATABASE_URL` precisa de privilégios suficientes para administrar o schema e criar/alterar roles (`CREATEROLE`), além de modificar ACLs. O código deliberadamente cancela o arranque se encontrar uma role provisionada em falta, ownership incompatível ou acesso efectivo a objectos de outros schemas. Não confirmes a migração em produção até a testares primeiro numa base PostgreSQL de staging.

## Monitorização e alertas

- `GET /api/health/live`: confirma que o processo responde, sem depender da base de dados.
- `GET /api/health/ready` (e o compatível `GET /api/health`): testa a ligação à base de dados; devolve HTTP 503 quando não está disponível.
- Os pedidos API e erros HTTP 5xx são registados em JSON com `request_id`, caminho sem query string, estado e duração. Não são registados cookies, corpo dos pedidos, tokens nem endereços IP.
- Opcionalmente, configura `ALERT_WEBHOOK_URL` no ambiente do backend para enviar alertas JSON quando houver erros 5xx, falha da base de dados ou problema na migração de isolamento. Em produção o webhook tem de usar HTTPS. Os alertas repetidos do mesmo tipo têm um intervalo mínimo de cinco minutos por instância.
- Para receber alertas mesmo quando o backend está completamente fora do ar, configura também um monitor externo para consultar `/api/health/ready`; o webhook da aplicação não substitui um monitor externo e não agenda verificações sozinho.

Exemplo de configuração privada no Netlify: `ALERT_WEBHOOK_URL` com o endereço do teu serviço de alertas. Nunca coloques o endereço com token no frontend nem no repositório.


## Desempenho sob carga

O backend usa limites explícitos para o pool PostgreSQL, timeout de ligação e timeout de consulta. O valor padrão do pool principal é 1 ligação por instância Netlify e 10 num servidor Node tradicional; `PG_POOL_MAX` é limitado entre 1 e 20. As bases Neon dos utilizadores usam pools individuais de uma ligação, com cache LRU limitada por `PG_PROJECT_POOL_CACHE_MAX` (padrão 20), para evitar acumular ligações ilimitadas. `PG_CONNECTION_TIMEOUT_MS` e `PG_STATEMENT_TIMEOUT_MS` permitem ajustar esperas (padrões 5000 ms e 15000 ms). Os valores devem ser dimensionados de acordo com o limite de ligações do fornecedor PostgreSQL.

Foi incluído um teste de carga leve para a rota de prontidão. Executa-o apenas contra um ambiente que controlas, começando com poucos pedidos:

```bash
LOAD_URL=https://TEU-SITE-STAGING.netlify.app LOAD_TEST_CONFIRM=YES LOAD_CONCURRENCY=5 LOAD_REQUESTS=50 npm run load:smoke
```

O relatório mostra taxa de sucesso, latência mediana, p95 e erros. O script exige `LOAD_TEST_CONFIRM=YES` para qualquer destino remoto e HTTPS obrigatório; começa em staging com poucos pedidos. Isto é um teste de fumo HTTP, não uma certificação de capacidade máxima; executa testes maiores gradualmente e observa também métricas do Netlify e do fornecedor da base de dados.

## Gestão e rotação de segredos

As credenciais guardadas usam AES-256-GCM com formato cifrado versionado (`v2`). A chave de cifragem é separada da chave JWT. O descodificador aceita formatos antigos em modo de leitura apenas com uma chave anterior explicitamente configurada. Os novos valores nunca são cifrados com `JWT_SECRET`, e o `JWT_SECRET` nunca é uma chave de descifragem automática. Ciphertexts antigos, tanto no formato `v2` como no formato sem versão, que tenham usado o `JWT_SECRET` como fallback exigem que essa chave antiga seja configurada temporariamente em `LEGACY_SECRET_ENCRYPTION_KEY`.

**Antes de rodar qualquer chave:** cria e verifica um backup da base interna. Para a primeira migração, cria e configura uma `SECRET_ENCRYPTION_KEY` aleatória, independente e com pelo menos 32 bytes. Se valores cifrados antigos — `v2` ou sem versão — foram criados quando o código ainda usava `JWT_SECRET` como fallback, configura temporariamente o valor antigo de `JWT_SECRET` em `LEGACY_SECRET_ENCRYPTION_KEY`. Sem essa configuração explícita, o descodificador recusa esses valores em vez de experimentar `JWT_SECRET` automaticamente. Mantém `JWT_SECRET` para validar sessões existentes. Depois executa o script de rotação com as mesmas variáveis e acesso à base interna:

```bash
ROTATE_SECRETS_CONFIRM=YES node scripts/rotate-secrets.mjs
```

O script exige confirmação explícita, processa as colunas de credenciais numa transação e faz rollback se ocorrer um erro. Para rodar novamente a chave de cifragem, define a nova `SECRET_ENCRYPTION_KEY` e coloca a chave anterior em `LEGACY_SECRET_ENCRYPTION_KEY` durante a migração; depois de confirmar que a rotação terminou e os segredos são legíveis, remove a variável antiga. Não apagues a chave anterior antes de terminar e validar a migração. As respostas de erro das APIs `/api` e `/v1` usam envelopes normalizados com `code` e `request_id`. Respostas 5xx nunca devolvem mensagens de exceções, SQL, fornecedor ou stack trace; o cliente recebe uma mensagem genérica e deve usar `request_id` para correlacionar com os registos de execução. Alterar `JWT_SECRET` invalida sessões existentes e não deve ser confundido com a rotação da chave de cifragem.


## Operações de ficheiros e snapshots

O repositório valida caminhos virtuais, rejeita traversal e colisões entre ficheiros/pastas, limita cada ficheiro a 300 KB, cada projecto a 120 ficheiros e 5 MB no total, e limita pastas a 300. A gravação, movimentação e criação de pastas usam transacções; no PostgreSQL, as operações de escrita bloqueiam a linha do projecto para reduzir corridas de quota. A restauração só aceita snapshots com `index.html` e valida os caminhos e tamanhos antes de substituir os ficheiros. A retenção automática mantém por padrão 30 commits e 10 publicações por projeto, preservando a publicação `LIVE` mais recente, publicações `BUILDING` e todos os snapshots referenciados por publicações retidas. Os limites são configuráveis com `COMMIT_RETENTION_PER_PROJECT` (5-200) e `DEPLOYMENT_RETENTION_PER_PROJECT` (3-100).

## Migrações e permissões PostgreSQL

As migrações existentes são executadas dentro de uma transação protegida por um bloqueio consultivo, com limites de espera de lock e de execução. Se a role de serviço não conseguir aplicar a política de permissões, se uma role/schema provisionada estiver em falta ou se a auditoria encontrar privilégios efectivos indevidos, a transação é revertida e a inicialização falha de forma segura; não se deve interpretar isso como um arranque bem-sucedido.

Para as credenciais PostgreSQL por projecto, o backend concede `USAGE` no schema isolado, limita o acesso às operações normais de dados, remove `CREATE`, fixa o `search_path` para o schema do projecto e audita privilégios herdados por `PUBLIC` ou memberships. A rotina também revoga privilégios gerais no schema `public` e altera os privilégios padrão globais para novos objectos criados pela role de serviço. **Isto pode afectar outras aplicações na mesma base de dados; `DATABASE_URL` deve apontar para uma base dedicada ao LuzaWeb, nunca para uma base partilhada com aplicações alheias.** A conta de serviço necessita de permissões suficientes para administrar estes ACLs e roles. Objectos cujo ownership pertença ao fornecedor ou a outra role podem fazer a migração falhar e exigir uma revisão específica, em vez de serem ignorados silenciosamente.

Antes de aplicar em produção, faz um backup verificado e testa numa cópia PostgreSQL do mesmo fornecedor, com roles e extensões semelhantes. A verificação automatizada local e os testes com executor simulado não substituem a validação de ACLs no PostgreSQL real; Neon, Supabase e outros serviços podem ter políticas de roles diferentes.

## Migrações simultâneas e limitação centralizada da API pública

O arranque em PostgreSQL executa a criação/atualização de schema e as migrações de dados numa transação que obtém `pg_advisory_xact_lock`; instâncias novas aguardam a conclusão da migração anterior. A restrição de isolamento que pode encontrar dados antigos inconsistentes usa um savepoint para não deixar a transação inteira num estado abortado. A migração de tabelas lógicas existentes é executada na mesma transação e usa bloqueio de tabela. As alterações continuam a ser idempotentes, permitindo repetir um arranque após falha. Este mecanismo deve ser testado com a URL PostgreSQL real, especialmente se houver um pooler ou roles com privilégios reduzidos.

A API `/v1` aplica limitação persistente a **todas** as chaves, incluindo as chaves `publishable` e `secret`, com limites distintos. Os contadores por chave, por combinação de chave/IP e por projeto são atualizados numa única operação atómica multi-row em `api_rate_limits`; todas as instâncias partilham os mesmos buckets e os identificadores são protegidos por hashes, sem IP em texto claro. Por padrão, as chaves `publishable` têm 120 pedidos/minuto por IP, 600 por chave e 1.200 por projeto; as chaves `secret` têm 300 pedidos/minuto por IP, 3.000 por chave e 6.000 por projeto. Ao atingir o limite, a API devolve HTTP 429 e `Retry-After`; se o armazenamento central falhar, os pedidos são recusados com HTTP 503. Registos expirados são limpos em lotes periódicos.

Configura os limites através de `PUBLIC_API_RATE_LIMIT_PER_IP`, `PUBLIC_API_RATE_LIMIT_PER_KEY`, `PUBLIC_API_RATE_LIMIT_PER_PROJECT`, `PRIVATE_API_RATE_LIMIT_PER_IP`, `PRIVATE_API_RATE_LIMIT_PER_KEY`, `PRIVATE_API_RATE_LIMIT_PER_PROJECT` e os respetivos valores `*_WINDOW_MS`. Todas as instâncias devem usar a mesma `DATABASE_URL` interna. Os limites são contadores de pedidos, não um orçamento de compute ou transferência da base de dados.


## Desempenho, limites e monitorização (Fase 08)

Os pools PostgreSQL e os pools por projeto têm limites configuráveis, timeouts de conexão/consulta e cache LRU. A rota `/api/health/live` só indica que o handler responde; `/api/health/ready` verifica a base interna e sinaliza saturação se a fila de ligações ultrapassar `PG_POOL_WAITING_LIMIT`. Pedidos com duração acima de `SLOW_REQUEST_ALERT_MS` geram registo estruturado e podem gerar alerta. `ALERT_COOLDOWN_MS` controla o intervalo mínimo entre alertas iguais; em produção o cooldown é partilhado pela tabela `operational_alert_cooldowns`. Durante uma indisponibilidade da base, o código usa um cooldown local de contingência, que não coordena várias instâncias.

O IP usado para limites de frequência em Netlify é obtido primeiro do cabeçalho de cliente fornecido pela edge da plataforma (`x-nf-client-connection-ip`) e validado como IP literal. Se estiver ausente/malformado, o código não confia no `X-Forwarded-For` arbitrário e usa o endereço socket; isto pode juntar utilizadores sob o mesmo endereço interno, sendo mais seguro do que permitir contornar os limites. Em self-hosting, `TRUST_PROXY_HOPS` é `0` por padrão; configura-o apenas se os proxies forem controlados por ti e sobrescreverem os cabeçalhos `X-Forwarded-*`.

Foi adicionado `.github/workflows/health-check.yml` para testar `/api/health/ready` a cada 15 minutos e por execução manual. Para ativar, configura o secret de repositório `LUZAWEB_HEALTHCHECK_URL` com o URL HTTPS completo que termina em `/api/health/ready`; configura também notificações do GitHub para falhas de workflow. O webhook `ALERT_WEBHOOK_URL` é opcional e tem de usar HTTPS em produção. Os alertas usam `operational_alert_cooldowns` para reduzir alertas duplicados entre instâncias quando a base está acessível. O payload tem allowlist de campos e não inclui mensagens de erro nem URLs do webhook.

O teste de carga `npm run load:smoke` só permite destinos remotos com HTTPS e confirmação explícita `LOAD_TEST_CONFIRM=YES`. Começa sempre em staging; o teste apenas consulta o readiness e não demonstra a capacidade máxima nem substitui o teste de carga do fornecedor.

**Limitações conhecidas:** a limitação por IP da Netlify depende de o ambiente de produção fornecer corretamente `x-nf-client-connection-ip`; confirma-o em staging sem registar o valor bruto. Os alertas não conseguem garantir entrega se o próprio provedor de funções ou a rede estiver completamente indisponível, por isso o monitor externo é necessário. O repositório ainda não tem `package-lock.json`; a tentativa de gerá-lo neste ambiente não conseguiu obter metadados do registo npm, pelo que instalações não estão totalmente bloqueadas/reproduzíveis. Gera o lockfile num ambiente com acesso ao npm registry e revê-o antes da publicação.

## Estado da auditoria profunda (após as fases 01 a 08 e correções seguintes)

Os testes locais cobrem regras de caminhos, limites e transacções do repositório, retenção de snapshots, respostas de erro da API, cifragem e compatibilidade/rotação de chaves, restrições de isolamento e política de permissões PostgreSQL. Ainda são necessárias validações no ambiente real antes de considerar a plataforma pronta para produção:

- Executar migrações numa cópia PostgreSQL da base real, incluindo dados legados inconsistentes e roles com privilégios limitados.
- Testar a rotação com as chaves reais e confirmar que todas as credenciais guardadas continuam legíveis antes de remover `LEGACY_SECRET_ENCRYPTION_KEY`.
- Validar em PostgreSQL real a migração serializada por bloqueio consultivo transaccional e o limitador centralizado da API pública sob concorrência de várias instâncias.
- Fazer teste de carga real com várias instâncias e bases Neon; os testes automatizados locais não demonstram a capacidade máxima de utilizadores simultâneos.
- Rever o ciclo de vida dos pools Neon sob concorrência e o comportamento do provisionamento quando o fornecedor falha a meio.

A retenção automática e a uniformização das respostas de erro da API foram implementadas. O teste local não substitui uma validação em PostgreSQL real, e o site publicado não foi alterado por esta revisão.


## Retenção e limpeza de histórico

A retenção é aplicada transaccionalmente quando um projeto cria um commit ou uma publicação. Por padrão ficam guardados os 30 commits mais recentes e 10 publicações por projeto; a publicação `LIVE` mais recente e as publicações `BUILDING` também são preservadas quando necessário. São mantidos todos os snapshots referenciados pelas publicações retidas, pelo que o total de commits pode exceder 30 quando isso é necessário para permitir servir ou recuperar uma publicação. Configura `COMMIT_RETENTION_PER_PROJECT` e `DEPLOYMENT_RETENTION_PER_PROJECT` para ajustar os limites.

Para aplicar a política também a projetos que não foram modificados desde a instalação desta versão, faz primeiro um backup verificado e executa `HISTORY_CLEANUP_CONFIRM=YES npm run history:cleanup` com `DATABASE_URL` da base interna. O script processa um projeto por transação, bloqueia a linha desse projeto e pede confirmação explícita. A limpeza remove snapshots e registos históricos além da política; confirma previamente os requisitos legais ou operacionais de retenção da tua organização.

## Proteção CSRF e isolamento entre painel e sites publicados (fase 01)

Os pedidos que alteram estado no painel (`POST`, `PUT`, `PATCH` e `DELETE` sob `/api`) passam por uma validação de origem antes de chegar às rotas, incluindo registo, login, logout, publicação e restauração de snapshots. É exigida uma `Origin` exacta do mesmo origin; quando `Origin` não existe, é aceite apenas um `Referer` válido do mesmo origin. Pedidos com `Sec-Fetch-Site: cross-site`, origem `null`, origem divergente ou sem metadados de origem são rejeitados com HTTP 403. A API pública `/v1` permanece separada porque autentica por API key e foi desenhada para CORS.

O cookie de sessão mantém `HttpOnly`, `SameSite=Lax`, `Path=/` e `Secure` em produção/Netlify. Os sites publicados continuam a receber o cabeçalho CSP `sandbox` sem `allow-same-origin` nem `allow-top-navigation`: scripts de conteúdo publicado ficam numa origem opaca e não devem conseguir actuar como a origem do painel. Não remover essa restrição sem separar primeiro os sites publicados num domínio/origem independente.

Esta protecção depende de o proxy de produção preservar correctamente `Host` e protocolo (`X-Forwarded-Proto` confiável). Para self-hosting, `TRUST_PROXY_HOPS` fica em `0` por padrão; configura os saltos apenas depois de verificar os proxies de confiança. Depois de publicar uma versão de teste, validar login, registo, logout, criação/edição de ficheiros, publicação, restauração de snapshot e pedidos originados em páginas publicadas. Clientes externos que chamem `/api` directamente sem `Origin`/`Referer` serão rejeitados por desenho; a API de integrações deve usar `/v1` com API keys.


## Segurança das ligações PostgreSQL externas (fase 02)

O formulário de ligação PostgreSQL aceita apenas um hostname DNS válido ou um IP público global; bloqueia loopback, redes privadas, link-local, endereços reservados, nomes locais (`localhost`, `.local`, `.internal`, `.test`, `.example`, `.invalid`, `.home`, `.lan` e `.onion`) e formas não canónicas de IP. No teste de ligação, o backend resolve todos os registos DNS, recusa o destino se qualquer resposta for privada/reservada e liga directamente a um dos IPs públicos validados. Isso evita uma segunda resolução do hostname pelo driver durante o teste (DNS rebinding entre validação e ligação). TLS está sempre activo e a validação do certificado é mantida usando o hostname original como `servername`.

Por padrão, só são permitidas as portas `5432` e `6432`. Se um fornecedor legítimo exigir uma porta diferente, define `POSTGRES_ALLOWED_PORTS` como lista explícita de portas no ambiente do backend (por exemplo `5432,6432,15432`); valores inválidos impedem o arranque da configuração de segurança. Não abras portas indiscriminadamente só para fazer um teste funcionar.

O endpoint de teste aplica um limitador partilhado na tabela `api_rate_limits`: por padrão, no máximo 5 tentativas por IP e projecto e 20 tentativas por projecto na janela de 10 minutos. Os buckets guardam hashes em vez de IPs em texto claro. Se o armazenamento central falhar, o endpoint recusa a operação com HTTP 503. Os limites são configuráveis com `POSTGRES_CONNECTION_TESTS_PER_IP`, `POSTGRES_CONNECTION_TESTS_PER_PROJECT` e `POSTGRES_CONNECTION_TEST_WINDOW_MS`.

A validação local testa a política de endereços e a resolução DNS simulada, mas não confirma conectividade para um PostgreSQL real, regras de saída de rede da Netlify, configuração TLS de cada fornecedor ou a exactidão dos valores de `DATABASE_URL`/credenciais. Depois de publicar em staging, testa uma base Neon e uma base externa legítima, além de confirmar que destinos locais/privados são rejeitados antes de se tentar a ligação.


## Quotas de projetos e bases Neon

Para reduzir abuso e criação acidental de recursos externos, o backend aplica quotas partilhadas na base interna:

- `PROJECTS_PER_USER_LIMIT=10`: máximo de projetos por conta, contando também os projetos na lixeira; `PROJECTS_GLOBAL_LIMIT=1000` limita o total da instalação, incluindo a lixeira. Mover para a lixeira não liberta uma vaga da quota.
- `PROJECT_CREATIONS_PER_USER_PER_HOUR=5` e `PROJECT_CREATIONS_PER_IP_PER_HOUR=10`: limites de frequência de criação de projetos.
- `NEON_DATABASES_PER_USER_LIMIT=3` e `NEON_DATABASES_GLOBAL_LIMIT=80`: limites de bases/projectos Neon geridos pelo LuzaWeb.
- `NEON_DATABASE_CREATIONS_PER_USER_PER_HOUR=3`, `NEON_DATABASE_CREATIONS_PER_IP_PER_HOUR=5` e `RESOURCE_CREATION_WINDOW_MS=3600000`: limites de frequência para provisionamento Neon.
- `NEON_ACCOUNT_PROJECT_LIMIT=90`: limite conservador de todos os projetos activos visíveis à chave Neon, incluindo os que não foram criados pelo LuzaWeb. O backend consulta `/projects/count` antes de criar e bloqueia a operação quando não consegue confirmar a contagem. O número pode ser ajustado à política e ao plano da conta.

Os limitadores de frequência usam a tabela partilhada `api_rate_limits`, guardam hashes dos identificadores e falham fechados se a base interna não estiver disponível. A criação de projetos é serializada no PostgreSQL por um bloqueio consultivo, para evitar ultrapassar quotas em pedidos concorrentes. A criação Neon usa reservas persistentes em `neon_provision_reservations`; se a eliminação de um recurso Neon falhar durante uma criação incompleta, a reserva fica `cleanup_required` e a quota conta esse recurso até reconciliação manual. Não apagues essa reserva sem verificar primeiro o projeto correspondente no painel Neon.

As operações de mover projetos para a lixeira, restaurar e eliminar definitivamente são sincronizadas com o provisionamento de bases. A eliminação definitiva de uma base Neon gerida só remove a referência local depois de o fornecedor confirmar a operação. Em caso de falha, o projeto mantém-se na lixeira e a operação fica registada para nova tentativa ou reconciliação administrativa.

Estas quotas limitam a quantidade e a frequência de recursos, mas **não são um limite monetário rígido**. O Neon pode cobrar de acordo com utilização de compute, armazenamento e transferência; configura também as notificações e, se disponível no teu plano, o limite de gastos na consola Neon. A documentação atual do Neon descreve esse limite de gastos como um mecanismo de notificação, não como suspensão automática do compute: https://api-docs.neon.tech/reference/setorganizationspendinglimit.


## Ciclo de vida de projetos e bases Neon (Fase 07)

A lixeira é uma remoção lógica: projetos na lixeira continuam a contar para os limites de utilização e as bases Neon associadas continuam existentes. Restaurar um projeto é bloqueado enquanto existir uma operação Neon pendente ou que necessite de reconciliação.

Ao eliminar definitivamente um projeto que tenha uma base Neon gerida pelo LuzaWeb, o backend regista primeiro uma operação durável em `project_lifecycle_operations`. Só remove o projeto interno depois de a API do Neon confirmar a eliminação (ou indicar que o recurso já não existe). Se houver timeout, erro de permissões ou falha de rede, o LuzaWeb mantém o projeto na lixeira, conserva a referência externa e assinala `cleanup_required`. O pedido pode ser repetido depois de rever o estado no painel Neon. A API de eliminação do Neon apaga o projeto, endpoints, branches, bases e utilizadores; o fornecedor documenta um período de recuperação de sete dias ([documentação oficial da API Neon](https://neon.com/docs/reference/api/projects/delete-project)), mas a eliminação do projeto no LuzaWeb também remove a sua associação local, por isso confirma sempre backups antes de continuar.

Depois de o Neon criar um projeto, o ID externo é guardado imediatamente na reserva de provisionamento. Se a instância for interrompida durante a criação, esta referência permite investigar ou limpar o recurso em vez de o perder silenciosamente.

### Inspecionar e reconciliar operações pendentes

O comando `npm run neon:reconcile` executa primeiro em **modo simulação**, sem chamar a API destrutiva. Requer `DATABASE_URL`; para aplicar ações, também requer `NEON_API_KEY`.

```bash
DATABASE_URL='postgresql://...' NEON_API_KEY='...' npm run neon:reconcile
```

Revisa os IDs apresentados. Para executar a reconciliação, define explicitamente `NEON_RECONCILE_CONFIRM=YES`. Por padrão, as operações `pending` só são processadas depois de estarem pendentes há 15 minutos; podes ajustar `NEON_RECONCILE_STALE_MINUTES` entre 5 e 1440. Os estados `cleanup_required` são sempre mostrados. O script nunca apaga uma base de provisionamento se encontrar uma ligação activa do mesmo projeto, não tenta adivinhar IDs ausentes e preserva o inventário quando a API do Neon não confirma a operação. Executa-o apenas com uma cópia de segurança recente e numa base interna dedicada ao LuzaWeb.

O script não descobre todos os projetos Neon externos que nunca chegaram a ser registados na base interna. Recursos que tenham sido criados antes de o ID ser persistido ou apagados manualmente no painel Neon podem exigir uma reconciliação manual a partir dos nomes dos projetos e do histórico de operações do Neon.
