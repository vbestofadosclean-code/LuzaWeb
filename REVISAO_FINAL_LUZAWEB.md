# LuzaWeb V1 — Revisão final após a Fase 08

**Estado:** correções de código das fases 01–08 incluídas no pacote; **ainda não aprovado para lançamento público sem staging e validação real**.

## Resumo da Fase 08

- Centralização da determinação do IP do cliente: em Netlify usa primeiro `x-nf-client-connection-ip` se válido; não confia num `X-Forwarded-For` arbitrário. Em self-hosting, o proxy só é confiável quando `TRUST_PROXY_HOPS` é configurado explicitamente.
- Limitação persistente de pedidos da API por chave, IP e projeto, com janelas separadas para chaves `publishable` e `secret`. Os três buckets são atualizados numa operação SQL atómica para reduzir viagens à base de dados. O sistema devolve HTTP 429 com `Retry-After`; se o armazenamento central falhar, bloqueia a operação com HTTP 503.
- Redução de contenção: `last_used_at` não é atualizado em todas as chamadas; há limites de pools, timeouts, tamanho de cache de pools por projeto e alerta de saturação na rota readiness.
- Monitorização: logs JSON com identificador de pedido, rótulos de rota de baixa cardinalidade, alertas de pedidos 5xx, pedidos lentos, erros de pool e falhas da base de dados. Os payloads de alerta usam allowlist; não incluem cookies, tokens, corpo de pedidos, IP bruto ou URL do webhook.
- Cooldown de alertas partilhado pela base interna quando esta está acessível; contingência local quando a base está indisponível.
- Verificação externa de readiness a cada 15 minutos através de GitHub Actions, ativada apenas depois de configurar `LUZAWEB_HEALTHCHECK_URL` e notificações do workflow.
- O teste `npm run load:smoke` exige HTTPS e confirmação explícita para destinos remotos; consulta readiness e não prova a capacidade máxima da aplicação.
- Encerramento gracioso para execução self-hosted e versão Node 22 definida na configuração.

## Verificações feitas neste ambiente

- `npm test`: **82 testes passaram, 0 falharam**.
- `node --check` em todos os ficheiros `.js` e `.mjs`: passou.
- `bash -n` nos scripts shell: passou.
- Parsing de `netlify.toml`: passou.
- Parsing dos workflows YAML: passou.
- Integridade do ZIP final: verificada após a criação do pacote.

Os testes são sobretudo unitários, de integração local com SQLite e verificações de regressão do código. Não equivalem a ensaios completos com Express, Netlify, PostgreSQL ou Neon reais.

## Bloqueios antes de um lançamento público

1. **Adicionar e rever `package-lock.json`.** Ainda não existe lockfile. A tentativa de o gerar nesta sessão não conseguiu obter os metadados do registo npm. Sem lockfile, versões compatíveis dentro de intervalos semver podem variar entre instalações. Gerar o ficheiro num ambiente com acesso ao npm registry, rever as alterações e testar com `npm ci`.
2. **Executar a aplicação completa num staging Node 22**, com instalação limpa das dependências e `npm start`, confirmar que a função Netlify arranca e testar todos os fluxos HTTP reais.
3. **Validar PostgreSQL com uma cópia da base de produção:** migrações concorrentes, permissões/roles efetivas, privilégios sobre schemas e sequências e limitador centralizado sob várias instâncias. A fase de hardening pode exigir privilégios superiores aos disponíveis em algumas contas de fornecedor; não usar a produção para descobrir isso.
4. **Validar Neon real:** criação, falha parcial, eliminação, lixeira, restauração e reconciliador em modo simulação. Confirmar que não ficam bases órfãs nem recursos removidos indevidamente.
5. **Executar e restaurar um backup completo real** em destino separado, incluindo a base interna, as bases Neon geridas e a recuperação das roles necessárias. O workflow só começa a funcionar depois de ser ativado no GitHub e receber os secrets exigidos.
6. **Testar CSRF e publicação num navegador real:** registo, login, logout, criação/edição de ficheiros, publicação e restauro de snapshots; verificar o isolamento dos sites publicados e qualquer funcionalidade que dependa de cookies, `localStorage` ou origem normal.
7. **Validar ligação externa PostgreSQL em staging:** uma base pública legítima deve ligar por TLS válido; destinos internos, privados e reservados devem ser rejeitados. Confirmar também que o cabeçalho `x-nf-client-connection-ip` é o esperado no Netlify sem registar o valor bruto.
8. **Configurar operacionalmente os alertas e monitorização:** `ALERT_WEBHOOK_URL` se desejado; secret GitHub `LUZAWEB_HEALTHCHECK_URL`; notificações de falha dos workflows. O monitor externo é necessário porque uma função completamente indisponível não consegue enviar alertas por si mesma.
9. **Definir valores de produção explicitamente:** `DATABASE_URL`, `JWT_SECRET`, `SECRET_ENCRYPTION_KEY` independente e forte, `NEON_API_KEY` se Neon for usado, limites de pedidos e pool. Usar `LEGACY_SECRET_ENCRYPTION_KEY` só durante uma migração de segredos antigos e removê-la depois de validar a rotação.

## Variáveis de limite da API

Valores padrão do código, ajustáveis no ambiente do backend:

- Chaves públicas: `PUBLIC_API_RATE_LIMIT_PER_IP=120`, `PUBLIC_API_RATE_LIMIT_PER_KEY=600`, `PUBLIC_API_RATE_LIMIT_PER_PROJECT=1200`, `PUBLIC_API_RATE_LIMIT_WINDOW_MS=60000`.
- Chaves privadas: `PRIVATE_API_RATE_LIMIT_PER_IP=300`, `PRIVATE_API_RATE_LIMIT_PER_KEY=3000`, `PRIVATE_API_RATE_LIMIT_PER_PROJECT=6000`, `PRIVATE_API_RATE_LIMIT_WINDOW_MS=60000`.
- Todas as instâncias precisam de usar a mesma `DATABASE_URL` interna para que os limites e os cooldowns partilhados sejam eficazes.

## Veredito

O pacote incorpora as alterações da Fase 08 e passou as verificações locais disponíveis. **Não há evidência suficiente para declarar o projeto pronto para um lançamento público aberto**, porque ainda faltam instalação reproduzível, execução end-to-end e provas reais de PostgreSQL/Neon, backup/restauro e comportamento em staging. Recomendação: primeiro staging com dados descartáveis; só abrir ao público depois de fechar a lista acima. O site publicado não foi alterado por esta revisão.
