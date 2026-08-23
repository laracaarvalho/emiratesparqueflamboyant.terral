# Emirates Parque Flamboyant — Terral

Pacote completo para upload no repositório GitHub do sistema de ponto e produção.

## Arquivos principais
- `worker.js` — Worker + API + página inicial visual
- `wrangler.jsonc` — configuração Cloudflare e binding D1
- `package.json` — dependência do Wrangler
- `schema.sql` — estrutura do banco D1
- `index_visual.html` — prévia do layout
- `assets/` — logos e favicon separados para uso futuro

## Banco configurado
- Nome: `emirates-ponto-db`
- Binding: `DB`
- Database ID: `497a3cae-8439-4495-a1f4-89af2f1e2d9e`

As imagens principais já estão embutidas no `worker.js`, então o site funciona mesmo sem servir a pasta `assets`.
