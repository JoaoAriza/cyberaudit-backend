# 🚀 Checklist de deploy — CyberAudit

> Consolida o que a revisão de segurança (3 rodadas, 2026-08-03 a 06) deixou como
> **pendência de configuração**. O detalhamento técnico de cada item está em
> [`SECURITY_REVIEW_SCOPE.md`](SECURITY_REVIEW_SCOPE.md); aqui é só o que precisa ser
> feito para subir.
>
> Regra geral: **segredos por variável de ambiente ou secret manager**, nunca `.env`
> em disco no servidor e nunca `ENV` no Dockerfile (o valor fica na imagem).

---

## 1. Variáveis que BLOQUEIAM o deploy

Sem estas, ou a aplicação não sobe, ou sobe com um controle de segurança desligado.

| Variável | Por quê |
|---|---|
| `DB_PASSWORD` | **Sem default** — a app não sobe. Era `cyberaudit123`; o default foi removido justamente para o deploy falhar alto em vez de subir com senha de exemplo pública. |
| `JWT_SECRET` | Sem default, mínimo 32 chars. **Nunca use** `31082005@JoaoAriza-cyberaudit-chave-segura!!` — está no histórico público do GitHub (ver §4). |
| `ALLOWED_ORIGINS` | O boot **falha** se vier vazio ou com `*`. Use a origem real do front, ex.: `https://app.seudominio.com.br`. |
| `PLATFORM_STAFF_EMAILS` | Vazio = **ninguém** dispensa a prova de posse de domínio em scan ativo, nem você. Preencha com os e-mails da sua equipe. |
| `FORWARD_HEADERS=framework` | **Se houver proxy reverso** (nginx/Caddy/Let's Encrypt). Sem isso, `getRemoteAddr()` devolve o IP do proxy: todos os visitantes compartilham o mesmo balde de rate-limit e o mesmo dono de scan assíncrono. Deixe `none` se a app estiver exposta direto — `X-Forwarded-For` é forjável. |

## 2. Variáveis que decidem comportamento de segurança

| Variável | Recomendação |
|---|---|
| `DOMAIN_VERIFICATION_SECRET` | **Defina antes do lançamento, com valor estável.** Vazio = cai no `JWT_SECRET`, e aí rotacionar o JWT invalida todo `/.well-known/cyberaudit.txt` já publicado pelos clientes. Verificado: a variável tem efeito real sobre o token gerado. |
| `MP_WEBHOOK_SECRET` | **Obrigatório se `MP_ACCESS_TOKEN` estiver setado.** Com MP ativo e sem este secret, o webhook agora responde 401 (antes ficava aberto). |
| `MP_ACCESS_TOKEN` | Token de **produção** do Mercado Pago. Vazio = pagamentos desativados com 503 claro. |
| `SCAN_MAX_CONCURRENT` | Padrão 4. Cada scan abre ~16 threads — ajuste conforme a CPU/memória da instância, não para cima "por precaução". |
| `MAIL_*` | Se `MAIL_ENABLED=true`, configure tudo. Para Gmail use **senha de app**, não a senha da conta. |
| `APP_BASE_URL` | URL pública do front — vai no `back_url` do checkout do Mercado Pago. |

## 3. Ações obrigatórias (não são variáveis)

- [ ] **Pedir a quem já ativou TOTP que refaça o setup do autenticador.** O QR code
      era gerado em `api.qrserver.com` com o segredo na query string — todos os seeds
      de 2FA existentes devem ser considerados expostos a terceiro.
- [ ] **Confirmar que o host do frontend está lendo os headers de segurança.** O repo
      traz `vercel.json` **e** `public/_headers` (Netlify/Cloudflare Pages) porque o
      host ainda não estava definido. Em nginx/Caddy, replique os valores à mão.
      `frame-ancestors` e HSTS **só funcionam como header**, não em `<meta>`.
- [ ] **Postgres não exposto publicamente.** O compose local já publica só em
      `127.0.0.1`; em produção, garanta rede interna / security group fechado.
- [ ] **Backup e restore testados** (restore, não só backup).
- [ ] **HTTPS + HSTS** no proxy reverso.
- [ ] **Documentar na Política de Privacidade** que `audit_logs` sobrevivem à exclusão
      de conta e contêm e-mail e nome, com o prazo de retenção
      (`data.retention.audit-logs-days`, padrão 365 dias).

## 4. O segredo vazado — decisão sua

`31082005@JoaoAriza-cyberaudit-chave-segura!!` foi commitado como default do
`jwt.secret` e está em `origin/main` de `github.com/JoaoAriza/cyberaudit-backend`,
que é **público**. Commits `7edf6a4` e `65e0e0f`.

Não é o segredo em uso (o `.env` local usa outro), então o impacto direto é baixo.
Em ordem de importância:

1. **Nunca usar essa string** como `JWT_SECRET` em ambiente nenhum.
2. **Se o padrão (data de nascimento + nome) se repete em senhas pessoais, trocar** —
   está indexável no GitHub e associado ao seu usuário.
3. Reescrever o histórico é **opcional** e é higiene, não contenção. Se fizer:
   `git filter-repo`/BFG + force-push, avisando quem tiver clones. O GitHub mantém
   os blobs antigos acessíveis por SHA mesmo após o force-push — precisa de chamado
   no suporte para expurgo real.

## 5. Verificações depois de subir

- [ ] `GET /actuator/health` → **200 `{"status":"UP"}`**. (Respondia 503 permanentemente
      por causa do indicador de e-mail; corrigido, mas confirme no ambiente real antes
      de apontar o monitor de uptime para lá.)
- [ ] `GET /actuator/env` e `/actuator/beans` → **401/404**, nunca 200.
- [ ] Headers na resposta da API: `Content-Security-Policy`, `X-Frame-Options`,
      `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`,
      `Cache-Control: no-store`.
- [ ] Headers no **front**: os mesmos, vindos do host (não do `<meta>`).
- [ ] `curl` de outra origem → CORS deve **negar** origem não listada.
- [ ] Nenhum `.map` servido em produção (`curl https://app.../assets/index-*.js.map`
      → 404).
- [ ] Container rodando como **não-root**: `docker exec <c> id` → `uid=10001`.
- [ ] Fluxo completo de pagamento em sandbox antes de ligar o token de produção.
- [ ] Exclusão de conta (`DELETE /user/account`) funcionando de ponta a ponta —
      estava quebrada para qualquer conta que já tivesse rodado um scan.

## 6. Fica em aberto (fora do código)

- **Dogfooding**: rodar o CyberAudit contra a instância publicada. Não dá para fazer
  local — o `SsrfGuard` bloqueia `localhost` corretamente.
- **Trivy/Grype** na imagem de container.
- **Pentest externo**, mesmo que básico, por outra pessoa/ferramenta — recomendação
  final do próprio escopo. Auto-análise não pega o que auto-análise não vê.
- **Migrations versionadas** (Flyway/Liquibase) no lugar de `ddl-auto=update`, que já
  falha em ALTER de coluna e não atualiza CHECK constraints de enum.
- **Retenção de scans por plano** — hoje o prazo é global (365 dias) para todos;
  `deleteOlderThan(cutoff, account)` existe no repositório sem nenhum chamador.
- **Criptografia em repouso** para `totpSecret` (hoje em texto no banco).
- **401 no lugar de 403** para não autenticado — hoje o front não redireciona para o
  login quando o token expira.
