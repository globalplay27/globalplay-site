# Global Play Site

Projeto separado do NEXUS AI 2.0.

Site público: https://globalplay.fun

## Estrutura
- `src/index.js`: Cloudflare Worker do site e painel administrativo.
- `SEO-AUDIT.md`: auditoria e plano de melhoria.
- `wrangler.example.jsonc`: modelo de configuração para ligar ao Worker/D1 existente.
- `.github/workflows/ci.yml`: validação automática de sintaxe.
- Binding D1 esperado pelo código: `DB`.

## Branches
- `main`: baseline preservado.
- `seo/globalplay-audit-20260926`: melhorias SEO auditadas antes da publicação.

## Deploy
Este repositório não deve criar um banco novo para substituir o site atual. O deploy precisa apontar para o **D1 já usado pelo globalplay.fun**, preservando administradores, planos, FAQ, imagens e estatísticas.

## Segurança
Não versionar senhas, tokens, IDs privados ou credenciais do Cloudflare/Google.
