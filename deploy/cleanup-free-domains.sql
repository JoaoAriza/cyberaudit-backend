-- Remoção dos domínios de contas FREE.
--
-- Contexto: cadastrar domínio virou PRO+ (Plan.domainRegistrationAllowed). O gate
-- novo só barra cadastros futuros; os domínios criados antes dele continuam na
-- base. Este script limpa o que ficou para trás.
--
-- Seguro quanto a integridade: nenhuma tabela referencia `domains` por FK.
-- ScheduledScan guarda o host como texto e aponta para app_users, não para
-- domains — então remover aqui não deixa órfão nem quebra agendamento.
--
-- ATENÇÃO — equipe da plataforma. Contas em PLATFORM_STAFF_EMAILS recebem
-- tratamento ENTERPRISE em código, mas na base o plano delas continua 'FREE'.
-- Sem a exclusão abaixo, os domínios da própria equipe seriam apagados junto.
-- Mantenha esta lista igual à variável PLATFORM_STAFF_EMAILS do Render.

-- ── 1) Confira ANTES de apagar (dry-run) ────────────────────────────────────
SELECT d.host,
       d.verified,
       d.created_at,
       a.display_name,
       a.plan
  FROM domains  d
  JOIN accounts a ON a.id = d.account_id
 WHERE a.plan = 'FREE'
   AND a.id NOT IN (
       SELECT u.account_id
         FROM app_users u
        WHERE lower(u.email) IN ('zcorp1ne@gmail.com')
   )
 ORDER BY a.display_name, d.host;

-- ── 2) Só depois de conferir a lista acima ──────────────────────────────────
-- BEGIN;
-- DELETE FROM domains d
--  USING accounts a
--  WHERE a.id = d.account_id
--    AND a.plan = 'FREE'
--    AND a.id NOT IN (
--        SELECT u.account_id
--          FROM app_users u
--         WHERE lower(u.email) IN ('zcorp1ne@gmail.com')
--    );
-- COMMIT;
