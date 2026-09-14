-- Preenche scan_records.impact nos scans gravados antes da coluna existir.
--
-- OPCIONAL e idempotente. Rode DEPOIS do deploy do Backend: a coluna é criada
-- pelo ddl-auto no boot, e antes disso o UPDATE falha por coluna inexistente.
--
-- O que recupera: só o impacto que o laudo JÁ tinha. O campo "impact" entrou no
-- result_json no commit 34a3a93 (13/09/2026); scans daquele deploy em diante têm
-- o valor no JSON, só não na coluna.
--
-- O que NÃO faz, de propósito: re-derivar o impacto de laudo antigo. Laudo
-- anterior a 34a3a93 não tem formSurface — re-derivar marcaria todo formulário de
-- contato e todo campo de cartão como VITRINE. Esses ficam NULL, e a tela mostra
-- "sem rótulo" até o próximo scan da página.
--
-- Por que regex e não result_json::jsonb: um único laudo malformado derruba o
-- UPDATE inteiro no cast. A regex só casa os quatro valores do enum, então o
-- texto de "impact" dentro dos achados (frases) nunca casa.

-- ── 1) Quantos seriam preenchidos ─────────────────────────────────────────
SELECT count(*) AS sem_impacto,
       count(*) FILTER (
           WHERE result_json ~ '"impact":"(SHOWCASE|CONTACT|ACCOUNT|PAYMENT)"'
       ) AS recuperaveis
  FROM scan_records
 WHERE impact IS NULL;

-- ── 2) Preencher ──────────────────────────────────────────────────────────
-- Confira a saída acima antes de rodar.

-- BEGIN;
-- UPDATE scan_records
--    SET impact = substring(result_json from '"impact":"(SHOWCASE|CONTACT|ACCOUNT|PAYMENT)"')
--  WHERE impact IS NULL
--    AND result_json ~ '"impact":"(SHOWCASE|CONTACT|ACCOUNT|PAYMENT)"';
-- COMMIT;
