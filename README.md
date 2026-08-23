# EMIRATES — V5 Login e Controle de Acesso

## Antes do GitHub
Execute **uma única vez** o arquivo `MIGRACAO_LOGIN_V5.sql` no Console do D1 `emirates-ponto-db`.

## O que esta versão faz
- Tela de login real.
- Senhas armazenadas como PBKDF2-SHA256 com salt individual (não ficam em texto puro no banco).
- Sessão em cookie `HttpOnly`, `Secure` e `SameSite=Lax`, com duração de 12 horas.
- Único Administrador: `LARA.RODRIGUES`.
- Os demais usuários cadastrados têm acesso comum.
- A API de funcionários aplica a regra ADM/comum no servidor: usuários comuns não conseguem solicitar funcionários `admin_only`, mesmo alterando a URL ou JavaScript.
- Cadastro de funcionário pela API fica restrito ao Administrador.
- Rotas do sistema e APIs ficam protegidas por sessão.
- Botão Sair incluído na página inicial.

## Depois da migração
Suba todos os arquivos desta pasta no GitHub, substituindo os existentes. O Cloudflare fará novo deploy automaticamente.

## V5.1 - Correção de login
- Corrigida a criação da sessão no D1.
- Expiração calculada no Worker em vez de parâmetro dentro de datetime().
- Tratamento de erro no login para evitar resposta genérica.
- Não requer nova alteração no banco.
