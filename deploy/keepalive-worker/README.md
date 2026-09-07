# Keep-alive do Web Service

Worker da Cloudflare que impede o Backend na Render de hibernar nas horas que
importam.

## Por que existe

O plano gratuito da Render desliga o web service após **15 minutos sem tráfego
de entrada**. A próxima requisição precisa subir a JVM e o Spring Boot inteiro em
0.1 CPU — atingindo login, cadastro, scan e até recarregar a página.

Medido contra a produção em 06/09/2026, no mesmo endpoint:

| estado | tempo de resposta |
|---|---|
| dormindo | **65,6 s** (uma tentativa anterior não completou em 100 s) |
| acordado | **0,84 s** |

Pior que a lentidão: dormindo, o processo está parado, então **os `@Scheduled`
não rodam**. O scan agendado para as 3h dispara quando alguém acordar o serviço,
e a retenção de dados só acontece nos dias em que houver acesso às 3h da manhã.

Trabalho interno não impede o desligamento — o gatilho é requisição chegando de
fora. Por isso a solução tem de vir de fora.

## O que ele NÃO resolve

- **Cold start depois de cada deploy** — a publicação reinicia o ciclo
- **Horas de instância** consumidas na Render enquanto o serviço fica acordado.
  Confira o teto do seu plano; estourar significa serviço **suspenso**, que é
  pior que hibernando

É ponte, não destino. O web service pago elimina a hibernação sem cota e sem esta
peça no caminho — e é o único jeito de o agendamento cumprir horário de verdade.

## Horários

Tudo em **UTC**, igual ao container da Render (nenhum `TZ` no Dockerfile) e ao
`preferredHour` dos agendamentos. Para ler em Brasília, subtraia 3.

| cron | quando | para quê |
|---|---|---|
| `*/10 9-23,0-4 * * *` | 06:00–01:59 BRT, a cada 10 min | visitante real |
| `55 2 * * *` | 23:55 BRT | guarda da retenção das 03:00 UTC |

Cobre **20h por dia**. O serviço dorme das 02:00 às 05:59 BRT, quando não há
tráfego de lugar nenhum.

A janela começou em 16h (08:00–23:59) e foi ampliada por causa da divulgação: um
post circula em horários que não se controla, e quem vê de outro fuso caía na
madrugada brasileira — esperando um minuto numa tela branca.

O segundo cron é **redundante hoje** (a janela já cobre a hora 2). Fica como
guarda: se a janela encolher de novo, a retenção continua protegida.

**Se você tem agendamento em hora da madrugada**, some um cron para ela — o
`preferredHour` é UTC, então confira o valor gravado antes de escolher.

## Quanto custa em horas de instância

20h/dia ≈ **600 h/mês** na Render. Confira o teto do seu plano antes de ampliar
mais: estourar significa serviço **suspenso**, que é pior que hibernando. Cobrir
24h seria ~730 h/mês — margem fina demais para valer a pena.

## Publicar

Requer Node e a conta Cloudflare que já hospeda o `cyberauditapp.com`.

```bash
cd deploy/keepalive-worker && npx wrangler login && npx wrangler deploy
```

## Conferir se está funcionando

Abrir a URL do Worker no navegador dispara um ping na hora e mostra o resultado:

```json
{ "ok": true, "status": 200, "ms": 65621, "acordouAgora": true }
```

`acordouAgora: true` significa que o serviço estava dormindo e este ping pagou o
cold start.

Um `ok: false` por timeout **não quer dizer que o serviço continuou dormindo** —
a requisição já chegou à Render e o boot já começou. O ping seguinte encontra o
serviço de pé. Ver os disparos agendados em tempo real:

```bash
cd deploy/keepalive-worker && npx wrangler tail
```

Se os logs mostrarem `acordouAgora: true` **dentro da janela de vigília**, há um
buraco nos horários — o serviço dormiu quando não devia. Fora da janela é o
esperado: é o primeiro ping da manhã fazendo o trabalho dele.
