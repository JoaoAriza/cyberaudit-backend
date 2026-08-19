-- Atualiza o CHECK constraint de audit_logs.action.
--
-- RODE ANTES do deploy que adiciona PASSWORD_RESET_REQUESTED e
-- PASSWORD_RESET_COMPLETED ao enum AuditAction.
--
-- Por quê: AuditAction é persistido como STRING e o Hibernate cria um CHECK
-- constraint com os valores que existiam quando a tabela foi criada.
-- `ddl-auto=update` NÃO atualiza esse constraint. Sem rodar este script, a
-- primeira gravação de auditoria de redefinição de senha falha com violação de
-- constraint — e, como o audit é gravado no mesmo fluxo, a redefinição quebra
-- junto. Nada disso aparece em teste: o constraint só existe no banco real.
--
-- O nome do constraint é gerado pelo Hibernate e varia. O bloco abaixo descobre
-- e remove qualquer CHECK sobre a coluna `action`; o Hibernate recria no próximo
-- boot já com a lista completa.

-- ── 1) Ver o que existe hoje ────────────────────────────────────────────────
SELECT con.conname,
       pg_get_constraintdef(con.oid) AS definicao
  FROM pg_constraint con
  JOIN pg_class rel ON rel.oid = con.conrelid
 WHERE rel.relname = 'audit_logs'
   AND con.contype = 'c';

-- ── 2) Remover o CHECK da coluna action ─────────────────────────────────────
-- Confira a saída acima antes de rodar.

-- BEGIN;
-- DO $$
-- DECLARE
--     nome text;
-- BEGIN
--     FOR nome IN
--         SELECT con.conname
--           FROM pg_constraint con
--           JOIN pg_class rel ON rel.oid = con.conrelid
--          WHERE rel.relname = 'audit_logs'
--            AND con.contype = 'c'
--            AND pg_get_constraintdef(con.oid) LIKE '%action%'
--     LOOP
--         EXECUTE format('ALTER TABLE audit_logs DROP CONSTRAINT %I', nome);
--     END LOOP;
-- END $$;
-- COMMIT;

-- ── 3) Depois do deploy, confirme ───────────────────────────────────────────
-- Repita a consulta do passo 1: o constraint recriado deve listar também
-- PASSWORD_RESET_REQUESTED e PASSWORD_RESET_COMPLETED.
