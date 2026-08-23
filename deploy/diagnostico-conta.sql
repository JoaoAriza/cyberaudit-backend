-- Por que uma conta específica não consegue entrar.
--
-- Troque SEU_EMAIL nas consultas abaixo.
--
-- O login barra por quatro motivos diferentes, e três deles chegam ao usuário
-- como a MESMA mensagem genérica. Este script mostra qual é.

-- ── 1) Estado da conta ──────────────────────────────────────────────────────
--
-- active=false          → login barrado pelo Spring Security (mensagem
--                         "Conta desativada" a partir da correção; antes vinha
--                         como "Credenciais inválidas")
-- totp_enabled=true     → login para na tela de código e exige o app
--                         autenticador; sem o app, não entra
-- email_otp_enabled=true→ idem, mas por e-mail

SELECT u.email,
       u.name,
       u.active,
       u.role,
       u.totp_enabled,
       u.email_otp_enabled,
       (u.totp_secret IS NOT NULL) AS tem_segredo_totp,
       u.created_at,
       a.plan,
       a.require2fa
  FROM app_users u
  LEFT JOIN accounts a ON a.id = u.account_id
 WHERE lower(u.email) = lower('SEU_EMAIL');

-- ── 2) O que o log de auditoria registrou nas últimas tentativas ────────────
--
-- O campo `details` diz o motivo quando existe ("Conta desativada").
-- Sem details, foi senha incorreta mesmo.

SELECT timestamp, action, success, details, ip_address
  FROM audit_logs
 WHERE lower(user_email) = lower('SEU_EMAIL')
 ORDER BY timestamp DESC
 LIMIT 15;

-- ── 3) Correções, conforme o que apareceu acima ─────────────────────────────

-- 3a) Conta desativada → reativar:
-- UPDATE app_users SET active = true WHERE lower(email) = lower('SEU_EMAIL');

-- 3b) Preso no 2FA sem conseguir o código → desligar os dois fatores:
-- BEGIN;
-- UPDATE app_users
--    SET totp_enabled = false, totp_secret = NULL, email_otp_enabled = false
--  WHERE lower(email) = lower('SEU_EMAIL');
-- DELETE FROM otp_codes
--  WHERE user_id IN (SELECT id FROM app_users WHERE lower(email) = lower('SEU_EMAIL'));
-- COMMIT;
--
-- Depois de entrar, reative o 2FA pela interface (TOTP de preferência: não
-- depende de e-mail e por isso não tem o modo de falha que trancou a conta).
