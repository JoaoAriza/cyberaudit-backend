# Deploy — CyberAudit

Checklist completo de variáveis e verificações em
[`../docs/DEPLOY_CHECKLIST.md`](../docs/DEPLOY_CHECKLIST.md).

```
   cyberauditapp.com ──► Cloudflare Pages   (dist/ estático, _headers)

api.cyberauditapp.com ──► Render Web Service ──► Render PostgreSQL
                          (Docker, TLS gerenciado)
```

O Cloudflare **não** hospeda o backend: Pages serve estático e Workers roda
JavaScript/WASM. O CyberAudit é JVM + PostgreSQL, por isso o backend vai para o
Render e só o frontend fica no Cloudflare.

---

## 1. Frontend — Cloudflare Pages

[dash.cloudflare.com](https://dash.cloudflare.com) → *Workers & Pages* →
*Create* → *Pages* → conectar o repo do frontend:

| Campo | Valor |
|---|---|
| Build command | `npm run build` |
| Output directory | `dist` |
| Variável | `VITE_API_URL` = `https://api.cyberauditapp.com` |

O `public/_headers` do repo passa a valer automaticamente — é dele que vêm
`frame-ancestors` e HSTS, que `<meta>` não consegue definir.

## 2. Backend — Render

*New* → *Web Service* → conectar o repo do backend → **Runtime: Docker**
(o `Dockerfile` já roda como não-root e tem healthcheck).

| Campo | Valor |
|---|---|
| Health Check Path | `/actuator/health` |
| Custom Domain | `api.cyberauditapp.com` |

Variáveis de ambiente: cole o conteúdo do `.env.production`, **menos `SERVER_PORT`**.

### Três detalhes do Render que quebram o deploy se passarem batido

**`PORT`, não `SERVER_PORT`.** O Render injeta `PORT` (padrão 10000) e exige que o
processo escute nela. O `application.properties` já prioriza `PORT`; só não
defina `SERVER_PORT`, que sobrescreveria com 8081 e o health check nunca
alcançaria a aplicação — o sintoma é 502.

**`FORWARD_HEADERS=native`, não `framework`.** O proxy do Render **apenda** o IP
real ao `X-Forwarded-For` que o cliente mandou, em vez de substituir. Com
`framework` o Spring lê o *primeiro* valor da lista, que é o que o cliente
escreveu — qualquer um mandaria `X-Forwarded-For: 1.2.3.4` e teria scans de guest
ilimitados e login sem lockout. `native` usa o `RemoteIpValve` do Tomcat, que lê
da direita para a esquerda e pega o valor que o proxy acrescentou.

**A URL do Postgres precisa ser convertida.** O painel do Render mostra
`postgresql://user:senha@host/banco`; o Spring não aceita esse formato. Use a
*Internal Database URL* (não sai da rede do Render) e monte:

```
DB_URL=jdbc:postgresql://<host>:5432/<banco>
DB_USERNAME=<user>
DB_PASSWORD=<senha>
```

## 3. DNS

No Cloudflare, depois de apontar os nameservers do registrador para lá:

| Tipo | Nome | Valor | Proxy |
|---|---|---|---|
| CNAME | `api` | host que o Render fornecer | **DNS only** (nuvem cinza) |

Deixe `api` **sem proxy**. Com Cloudflare na frente do Render, o
`X-Forwarded-For` ganha mais um salto e o `native` passaria a enxergar o IP da
borda do Cloudflare como cliente — os limites por IP voltariam a ficar errados.
O Render já entrega TLS gerenciado, então não se perde HTTPS.

O apex e o `www` o próprio Pages configura.

---

## Depois de subir

```bash
curl -s https://api.cyberauditapp.com/actuator/health
```

Deve responder `{"status":"UP"}`. Se vier 503, é o indicador de e-mail
reclamando do SMTP.

Teste que o IP real está chegando — crie uma conta e erre a senha 6 vezes: a
partir da 6ª deve vir **429**. Se nunca bloquear, o `FORWARD_HEADERS` está
errado e os limites por IP não estão valendo.

## ⚠ Antes de tudo: avise o suporte do Render

O backend faz **port scan e dispara probes de injeção contra hosts de
terceiros**. É exatamente o padrão que sistemas antiabuso detectam, e a reação
padrão é suspender a conta primeiro e perguntar depois.

Explique no e-mail que:

- é um scanner de segurança comercial;
- scan ativo **só roda em domínio verificado pelo cliente**, por posse
  comprovada via arquivo em `/.well-known/cyberaudit.txt`;
- existe teto global de scans simultâneos (`SCAN_MAX_CONCURRENT`).

## Se o WAF do Cloudflare bloquear scans legítimos

Só se aplica ao frontend (o `api` fica sem proxy). O produto recebe URLs com
cara de ataque na query string (`/scan?url=https://site.com/?q=<script>`); se
algum dia proxiar a API, as regras gerenciadas lerão isso como XSS e devolverão
403 ao próprio cliente. Correção: *Security → WAF → Custom rules*, exceção para
`/scan*`.

---

## Variante: VPS em vez de Render

Os arquivos `nginx-api.conf` e `cloudflared-config.yml` deste diretório cobrem o
cenário de servidor próprio (VPS + Cloudflare Tunnel). Nesse caminho:

- o nginx **substitui** o `X-Forwarded-For`, então lá o correto é
  `FORWARD_HEADERS=framework`;
- `client_max_body_size 2m` fecha o corpo JSON ilimitado do Spring MVC;
- o túnel dispensa abrir 80/443 — mas **remova as regras de entrada no firewall**
  do provedor, senão a origem continua alcançável e o `X-Forwarded-For` volta a
  ser forjável.
