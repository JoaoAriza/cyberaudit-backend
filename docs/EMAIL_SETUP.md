# Configuração de e-mail

O sistema envia quatro tipos de e-mail: código 2FA, scan concluído, alerta de
degradação de score e notificação de contestação. O transporte é escolhido por
`MAIL_PROVIDER`.

Só o código 2FA é **essencial**: se ele não sai, o usuário não entra. Os outros
três são acessórios e falham em silêncio de propósito — ver `EmailDeliveryException`.

---

## Por que Resend (e não Gmail)

O Gmail SMTP funciona na máquina do desenvolvedor e falha no Render. Dois motivos,
ambos fora do nosso controle:

- **IP de datacenter compartilhado.** O Google limita e frequentemente recusa
  conexões vindas de faixas de nuvem, independentemente da credencial.
- **Porta de saída.** PaaS costuma bloquear 465/587. O sintoma é timeout, não
  erro de autenticação — o que torna o diagnóstico confuso.

O transporte Resend usa **HTTPS na 443**, que nunca é bloqueada (se fosse, nenhum
scan funcionaria), e devolve erro em JSON legível em vez de código SMTP genérico.

Brevo e Mailgun resolveriam igualmente o envio. Resend foi escolhido por ter API
HTTP simples, plano gratuito permanente (não é trial) e log de entrega por
mensagem — que é exatamente o que faltava para diagnosticar as falhas anteriores.

---

## Passo a passo

### 1. Criar a conta e a chave

1. Conta em `resend.com`
2. **API Keys → Create API Key**, permissão de envio
3. Guarde o valor — ele só aparece uma vez

### 1b. (Opcional) Validar o caminho antes de mexer no DNS

Enquanto o domínio não está verificado, o Resend entrega apenas para o e-mail dono
da conta, usando o remetente `onboarding@resend.dev`. Dá para usar isso como teste
de fumaça antes de tocar em registro de DNS:

```
MAIL_ENABLED=true
MAIL_PROVIDER=resend
RESEND_API_KEY=<a chave>
MAIL_FROM=onboarding@resend.dev
```

Ative o Email OTP na conta cujo e-mail é o dono do Resend. Passando, estão provados
chave, rede e entrega — sobra só o domínio. Mudar uma coisa de cada vez faz a falha
apontar a causa sozinha.

### 2. Verificar o domínio

Sem domínio verificado, o Resend só entrega para o e-mail dono da conta — suficiente
para testar, insuficiente para clientes.

1. **Domains → Add Domain** → `cyberauditapp.com`
2. O Resend mostra os registros DNS (SPF, DKIM e, opcionalmente, DMARC)
3. Crie cada um no Cloudflare, no painel de DNS do domínio
4. **Importante:** deixe esses registros como *DNS only* (nuvem cinza). Registro de
   e-mail proxiado pelo Cloudflare não é resolvido corretamente pelos servidores
   que validam SPF/DKIM.
5. Volte ao Resend e clique em verificar

### 3. Variáveis no Render

```
MAIL_ENABLED=true
MAIL_PROVIDER=resend
RESEND_API_KEY=<a chave do passo 1>
MAIL_FROM=nao-responda@cyberauditapp.com
```

`MAIL_FROM` precisa usar o domínio verificado no passo 2 — é isso que faz o
e-mail passar em SPF/DKIM e não cair em spam. As variáveis `MAIL_HOST`,
`MAIL_PORT`, `MAIL_USERNAME` e `MAIL_PASSWORD` deixam de ser usadas e podem ser
removidas.

### 4. Conferir

O boot avisa se a chave faltar:

```
MAIL_PROVIDER=resend mas RESEND_API_KEY vazio: 2FA por e-mail e convites vão falhar no envio.
```

O teste real é ativar o **Email OTP** em Segurança: a ativação envia um código de
teste antes de gravar a flag, então ela **falha** se o e-mail não sair — e a
mensagem de erro diz o motivo. Nenhuma conta é trancada nesse processo.

---

## Voltar para SMTP

Basta `MAIL_PROVIDER=smtp` (ou remover a variável) e preencher as `MAIL_*`. O
`SmtpEmailSender` continua no código e é o padrão quando nada é definido.
