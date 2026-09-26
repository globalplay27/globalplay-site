# Auditoria SEO — Global Play

Data: 26/09/2026  
Domínio: https://globalplay.fun/

## Escopo auditado
- Última cópia completa disponível do Cloudflare Worker do site.
- Estrutura HTML renderizada pelo Worker.
- robots.txt e sitemap.xml.
- Metadados da home.
- Painel administrativo de SEO.
- Estrutura de indexação das áreas administrativas.

## Pontos que já estavam corretos
- HTML em pt-BR.
- Título e meta description configuráveis.
- Um H1 principal.
- robots.txt com sitemap.
- sitemap.xml válido para a home.
- Seções reais de planos, dispositivos, aplicativos e perguntas.
- Página 404 retorna status 404.
- Site renderizado no servidor, sem depender de JavaScript para o conteúdo principal.

## Problemas encontrados
1. Canonical era construído a partir do host da requisição e poderia apontar para worker.dev/outro host.
2. Não havia Open Graph.
3. Não havia Twitter Card.
4. Não havia dados estruturados JSON-LD.
5. /favicon.ico retornava 204.
6. Páginas de administração/login não declaravam noindex.
7. Imagens de aplicativos tinham alt vazio.
8. Título, descrição e H1 padrão eram genéricos para intenção de busca.
9. Painel SEO controlava somente title e description.
10. Site é essencialmente uma única URL indexável; crescimento orgânico futuro exigirá conteúdo/páginas úteis adicionais.

## Correções aplicadas nesta branch
- Canonical fixo em https://globalplay.fun/.
- meta robots da home.
- Open Graph completo.
- Twitter Card.
- JSON-LD com Organization, WebSite e Service.
- Favicon SVG real.
- noindex/nofollow/noarchive em admin e autenticação.
- alt descritivo nas imagens dos aplicativos.
- novos defaults de title, description, H1 e texto principal.
- campo de imagem social no painel SEO.
- simplificação do sitemap para sinais suportados.
- CI para validar sintaxe do Worker em cada alteração.

## Próxima fase recomendada
Depois de ligar este repositório ao Worker real:
1. validar a home publicada, robots.txt e sitemap.xml;
2. confirmar a propriedade no Google Search Console;
3. registrar baseline;
4. medir PageSpeed/Core Web Vitals;
5. planejar páginas úteis adicionais com intenção clara de busca, sem criar conteúdo raso ou repetitivo.

Nenhuma credencial deve ser salva no repositório.
