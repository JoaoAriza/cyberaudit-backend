# Deploy — CyberAudit

Arquivos prontos para o cenário **Cloudflare Pages (frontend) + Cloudflare Tunnel
(API)**. Checklist completo de variáveis e verificações em
[`../docs/DEPLOY_CHECKLIST.md`](../docs/DEPLOY_CHECKLIST.md).

```
                        ┌──────────────────┐
   cyberaudit.com.br ──►│ Cloudflare Pages │  (dist/ estático, _headers)
                        └──────────────────┘

                        ┌────────────┐   túnel de saída   ┌───────┐   ┌────────┐
api.cyberaudit.com.br ─►│ Cloudflare │◄───────────────────│ nginx │──►│ Spring │
                        └────────────┘   (sem porta       │ :8080 │   │ :8081  │
                                          aberta)         └───────┘   └────────┘
```

## Ordem

**1. Nameservers** — no [Registro.br](https://registro.br), trocar
`ns1/ns2.digitalocean.com` pelos que o Cloudflare indicar ao adicionar o domínio.
É o passo com maior latência (pode levar horas): dispare primeiro.

**2. Frontend no Pages** — [dash.cloudflare.com](https://dash.cloudflare.com) →
*Workers & Pages* → *Create* → *Pages* → conectar o repo do frontend:

| Campo | Valor |
|---|---|
| Build command | `npm run build` |
| Output directory | `dist` |
| Variável | `VITE_API_URL` = `https://api.cyberaudit.com.br` |

O `public/_headers` do repo passa a valer automaticamente — é dele que vêm
`frame-ancestors`, HSTS e os demais headers que `<meta>` não consegue definir.

**3. nginx no droplet**

```bash
sudo cp nginx-api.conf /etc/nginx/sites-available/cyberaudit-api
sudo ln -s /etc/nginx/sites-available/cyberaudit-api /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**4. Tunnel**

```bash
cloudflared tunnel login
cloudflared tunnel create cyberaudit
cloudflared tunnel route dns cyberaudit api.cyberaudit.com.br
sudo cp cloudflared-config.yml /etc/cloudflared/config.yml   # ajuste o <TUNNEL-ID>
sudo cloudflared service install
sudo systemctl status cloudflared
```

**5. Fechar a origem** — o túnel não fecha as portas sozinho. Em
*Networking → Firewalls* na DigitalOcean: **remova** as regras de entrada 80/443
e deixe SSH (22) só para o seu IP. Sem isso, o IP antigo continua alcançável e o
`X-Forwarded-For` volta a ser forjável.

**6. Backend** — Postgres, preencher `.env.production` e subir.

## Depois de subir

```bash
curl -s https://api.cyberaudit.com.br/actuator/health
```

Deve responder `{"status":"UP"}`. Se vier 503, é o indicador de e-mail
reclamando do SMTP.

```bash
curl -sI --resolve api.cyberaudit.com.br:443:192.241.149.151 https://api.cyberaudit.com.br/
```

Este **tem que falhar**. Se responder, a origem ainda está exposta e o passo 5
não surtiu efeito — o rate-limit por IP fica burlável enquanto isso for verdade.

## Se o WAF bloquear scans legítimos

O produto recebe URLs com cara de ataque na query string
(`/scan?url=https://site.com/?q=<script>`). As regras gerenciadas do Cloudflare
leem isso como XSS e devolvem 403 — bloqueando o próprio cliente.

Sintoma: usuário relata que o scan "não funciona" só em certas URLs.
Correção: *Security → WAF → Custom rules*, exceção para o caminho `/scan*`.

## Variante sem Cloudflare

Se preferir Let's Encrypt direto no droplet, o `nginx-api.conf` muda em três pontos:
`listen 443 ssl` no lugar de `127.0.0.1:8080`, as diretivas de certificado que o
`certbot --nginx` insere, e um `server` extra redirecionando 80 → 443. O resto —
timeouts, `client_max_body_size`, `X-Forwarded-*` — continua igual. Nesse caso o
firewall do passo 5 vira **obrigatório com as faixas do Cloudflare removidas**:
80/443 abertos para todos, e aí o `X-Forwarded-For` só é confiável porque nada
está na frente.
