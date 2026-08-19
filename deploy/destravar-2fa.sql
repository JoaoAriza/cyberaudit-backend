-- Recuperação de conta trancada por 2FA de e-mail.
--
-- Quando usar: o login para na tela "Verificação em 2 etapas" e o código nunca
-- chega. Não existe código de backup no sistema, e desativar o 2FA pela interface
-- exige estar logado — então a saída é pelo banco.
--
-- Troque SEU_EMAIL nas duas opções abaixo.

-- ── OPÇÃO A — entrar usando o código que já foi gerado (não altera nada) ─────
--
-- O código é gravado em otp_codes ANTES da tentativa de envio, então ele existe
-- mesmo com o SMTP quebrado. Passo a passo:
--   1. Na tela de 2FA, clique em "Reenviar código por email"
--   2. Rode este SELECT
--   3. Digite o código na tela (vale 10 minutos)

SELECT o.code,
       o.expires_at,
       o.used
  FROM otp_codes o
  JOIN app_users u ON u.id = o.user_id
 WHERE lower(u.email) = lower('SEU_EMAIL')
   AND o.used = false
   AND o.expires_at > now()
 ORDER BY o.created_at DESC
 LIMIT 1;

-- ── OPÇÃO B — desligar o Email OTP da conta ─────────────────────────────────
--
-- Use se preferir voltar ao login normal. Confira primeiro quem será afetado:

SELECT id, email, name, totp_enabled, email_otp_enabled
  FROM app_users
 WHERE lower(email) = lower('SEU_EMAIL');

-- Só depois de conferir:
-- BEGIN;
-- UPDATE app_users
--    SET email_otp_enabled = false
--  WHERE lower(email) = lower('SEU_EMAIL');
-- DELETE FROM otp_codes
--  WHERE user_id IN (SELECT id FROM app_users WHERE lower(email) = lower('SEU_EMAIL'));
-- COMMIT;
--
-- ATENÇÃO: se totp_enabled também for false, a conta fica sem 2FA nenhum.
-- Reative pelo app autenticador (TOTP) depois de entrar — ele não depende de
-- e-mail e por isso não tem esse modo de falha.
