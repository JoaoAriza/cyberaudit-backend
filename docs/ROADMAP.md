# ROADMAP — trabalho futuro

Itens levantados mas deliberadamente adiados. Cada um é uma feature nova, não um
conserto. Registrado aqui para retomar depois.

---

## 1. Crawler / descoberta de superfície de input

**Levantado em:** 2026-09-07, ao validar os módulos de injeção contra o VulnTarget.

### O problema

O scanner é **single-URL**: ele testa exatamente a URL colada (seguindo apenas os
redirects HTTP dela — `target = fetch.getFinalUrl()` no `ScanOrchestrator`), sem
navegar pelos links da página. Duas consequências:

1. **Sondas de injeção quase nunca têm o que testar.** XSS, SQLi/DB error, Path
   Traversal e SSRF são gated por `inputSurfaceDetected = hasQueryParams(target)`
   (`ScanOrchestrator` ~linha 237; probes em ~486-507). Sem um `?param` na URL,
   pulam. A home quase nunca tem query string, e sites com **URL limpa**
   (`/produto/42` em vez de `?id=42`) nunca têm — então essas quatro sondas
   ficam sem superfície na prática.

2. **Exposições por caminho passam batido.** Headers, cookies, métodos HTTP,
   directory listing e afins são medidos **só** na URL colada. Uma rota profunda
   (`/api/*`, `/admin`, uma página de login) pode expor o que a home esconde
   (header de segurança ausente, cookie de sessão sem flag, versão de servidor),
   e o scan da home não vê.

### O objetivo

Um modo **opt-in** ("deep scan") que descobre URLs representativas sob o mesmo
host — em especial URLs com parâmetro e endpoints de formulário — e as alimenta
nos módulos de caminho e de injeção. O usuário verifica o domínio uma vez e o
scanner cobre a superfície, em vez de exigir que ele cole cada URL à mão.

### Onde encaixa no código

- Hoje `ScanOrchestrator.runScan` trabalha com **um** `target`. O crawler
  produziria uma **lista** de URLs; os módulos de caminho rodariam por URL (ou o
  orchestrator agregaria os achados de todas).
- O gate `inputSurfaceDetected` deixaria de olhar só a URL semente e passaria a
  valer por URL descoberta.
- `SsrfGuard.validate` continua valendo **por URL** — cada destino revalidado.

### Esboço (v1 — HTML estático)

- BFS a partir da URL semente, **mesmo host apenas**, profundidade ~2, teto de
  ~50 páginas, timeout global.
- Extrair `<a href>` (para descobrir caminhos) e `<form action>` + nomes de
  `<input>` (para descobrir parâmetros e endpoints que processam entrada).
- Priorizar URLs que já tenham query string e endpoints de formulário — são os
  que dão superfície às sondas de injeção.
- **Gating:** deep scan é intrusivo (muitos requests + injeção em vários
  endpoints) → exigir modo ATIVO **e** posse de domínio verificada, como as
  sondas ativas de hoje. Nunca ligado por padrão.

### Riscos / limites conhecidos

- **Intrusividade:** precisa de rate-limit e teto de páginas — senão vira um mini
  stress test no alvo (e no Render). Respeitar `Disallow` do robots é decisão de
  produto (mais educado; menos cobertura).
- **SPAs com JS:** os `href` não estão no HTML inicial (roteamento client-side) —
  extração estática não os acha. Renderização headless resolveria, mas fica
  **fora do v1**.
- **Armadilhas:** paginação infinita, calendários, `mailto:`/`tel:`,
  logout links. Precisa de dedupe e blocklist de padrões.
- **Áreas autenticadas:** sem sessão, o crawler só vê o público. Cobrir área
  logada exigiria injeção de cookie/credencial — escopo bem maior.

### Esforço

Médio. v1 (extração estática de links/forms, mesmo host, profundidade 2, teto de
páginas) é contido. Renderização de SPA e áreas autenticadas são fases seguintes.
