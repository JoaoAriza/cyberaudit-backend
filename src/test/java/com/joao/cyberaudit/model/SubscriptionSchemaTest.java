package com.joao.cyberaudit.model;

import jakarta.persistence.Column;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Trava a regressão que quebrou produção em 2026-09-29: {@code ddl-auto=update}
 * tentou adicionar {@code payment_method} como NOT NULL numa tabela `subscriptions`
 * que já tinha linhas reais — o Postgres recusa isso sem um default, a migração
 * falhou no boot (Hibernate só logou e seguiu), a coluna nunca chegou a existir, e
 * todo endpoint que tocava Subscription passou a quebrar em produção.
 *
 * O teste local nunca pegou isso porque o H2 de teste usa `ddl-auto=create-drop` —
 * schema novo a cada run, sem linha pré-existente pra colidir. Isto aqui não
 * substitui testar migração contra um banco com dado (fora do escopo hoje), mas
 * pelo menos impede alguém de marcar esta coluna como NOT NULL de novo sem pensar
 * na tabela de produção que já existe.
 */
class SubscriptionSchemaTest {

    @Test
    @DisplayName("paymentMethod tem que continuar nullable — NOT NULL quebra o ddl-auto contra a tabela de produção existente")
    void paymentMethodPrecisaSerNullable() throws NoSuchFieldException {
        Field field = Subscription.class.getDeclaredField("paymentMethod");
        Column column = field.getAnnotation(Column.class);

        assertTrue(column.nullable(),
                "payment_method virou NOT NULL de novo — isso derruba /billing/** em produção "
                        + "porque a tabela subscriptions já tem linhas sem essa coluna. "
                        + "Ou mantém nullable, ou adiciona um default via columnDefinition "
                        + "E confirma que o ddl-auto consegue popular as linhas existentes.");
    }
}
