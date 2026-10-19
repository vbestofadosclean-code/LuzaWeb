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

Publicar novamente substitui a versão servida pelo snapshot mais recente, preservando o histórico de commits e deployments.

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
4. Nas variáveis de ambiente do Netlify configura `DATABASE_URL`, `JWT_SECRET`, `NEON_API_KEY` e `NODE_ENV=production`. `NEON_ORG_ID` é opcional quando não é exigido pela chave usada. Gera `JWT_SECRET` uma vez, por exemplo com `openssl rand -base64 48`, e mantém o mesmo valor em futuras publicações para que os segredos já cifrados continuem a poder ser lidos. Nunca uses os valores de exemplo nem coloques segredos no frontend, no README ou no `netlify.toml`.
5. Publica e verifica `https://TEU-SITE.netlify.app/api/health`; a resposta deve indicar `database: "connected"`. Depois testa registo/login, cria uma base de projecto, confirma os dados de ligação, testa a ligação, cria uma tabela, adiciona/consulta um registo e publica um projecto HTML estático.

A chave `NEON_API_KEY`, a `DATABASE_URL` e o `JWT_SECRET` são consumidos apenas pelo backend. A configuração inicial e as migrações da base interna ocorrem no primeiro arranque. O teste publicado deve ser efectuado com os segredos reais configurados no painel Netlify; um ZIP isolado não contém nem deve conter essas credenciais.

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
