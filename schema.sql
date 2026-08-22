# EMIRATES PARQUE FLAMBOYANT — Controle de Ponto e Produção

Sistema inicial compartilhado da obra EMIRATES PARQUE FLAMBOYANT, com interface Terral + Cloudflare Worker + banco D1.

## Estrutura

- `public/index.html` — site
- `public/terral_logo.png` — logo
- `src/index.js` — API do Worker
- `schema.sql` — tabelas do banco
- `wrangler.jsonc` — configuração Cloudflare
- `package.json` — comandos de implantação

## IMPORTANTE

O banco D1 já foi criado e configurado:

- Nome: `emirates-ponto-db`
- Database ID: `497a3cae-8439-4495-a1f4-89af2f1e2d9e`

As tabelas principais também já foram criadas no D1.

## Dados compartilhados

Esta versão salva no D1:
- Funcionários
- Tarefas e valores
- Ponto
- Produção
- Nome de quem fez cada lançamento

## Próxima etapa

Depois de confirmar que o banco está funcionando para todos:
- Login e níveis de acesso
- Editar/excluir lançamentos com histórico
- Fechamento por período
- Filtros
- Exportação para Excel/PDF
- Dashboards por funcionário/equipe/local