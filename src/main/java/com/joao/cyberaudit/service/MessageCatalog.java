package com.joao.cyberaudit.service;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

/**
 * Texto dos achados de segurança, indexado por ID.
 *
 * O texto nascia embutido no {@link ScoreService}, em português. Vender fora do
 * Brasil exige traduzir o LAUDO, não só a interface: cliente lendo tela em inglês
 * e achado em português não compra. Todo achado já tinha ID estável, então o ID
 * virou a chave e o texto saiu do código.
 *
 * Nesta etapa o contrato da API não muda — a resposta continua trazendo texto
 * pronto, só que vindo de {@code messages.properties}. Ela existe para que a
 * etapa seguinte precise apenas somar {@code messages_en.properties}, sem tocar
 * na lógica de scan.
 *
 * O locale sai do {@link LocaleContextHolder}, que hoje devolve sempre o padrão
 * porque não há resolvedor configurado. É de propósito: o ponto de virada já fica
 * no lugar certo.
 */
@Component
public class MessageCatalog {

    private final MessageSource messages;

    public MessageCatalog(MessageSource messages) {
        this.messages = messages;
    }

    public String title(String chave, Object... args) {
        return texto(chave, "title", args);
    }

    public String impact(String chave, Object... args) {
        return texto(chave, "impact", args);
    }

    public String recommendation(String chave, Object... args) {
        return texto(chave, "recommendation", args);
    }

    /** Fragmento avulso do catálogo — ver issue.CVE.reference e issue.GRAPHQL.typeCount. */
    public String fragment(String chave, String sufixo, Object... args) {
        return texto(chave, sufixo, args);
    }

    /**
     * Nota do breakdown do score — "HTTPS não suportado: -40" e afins.
     *
     * Prefixo próprio (`note.`) porque é outra família de texto: o achado descreve
     * o problema, a nota justifica o desconto. Um achado pode existir sem nota
     * (não descontou nada) e uma nota sem achado (bônus de WAF, "OK" do SSL).
     */
    public String note(String chave, Object... args) {
        return prefixado("note.", chave, args);
    }

    /**
     * Nome de exibição de uma verificação do scan — {@code ScanCheck}.
     *
     * Prefixo próprio porque não é achado nem nota: é o rótulo do que rodou, e
     * aparece quando o scan precisa dizer o que NÃO conseguiu verificar.
     */
    public String check(String chave, Object... args) {
        return prefixado("check.", chave, args);
    }

    /**
     * Evidência de um achado — o que foi encontrado, em uma linha.
     *
     * Prefixo próprio porque não é o achado nem a nota: é o detalhe concreto que
     * aparece dentro do card ("Spring Boot Actuator — endpoint raiz exposto").
     * Nasceu chumbado em português nos serviços de sonda e saía assim no laudo em
     * inglês.
     */
    public String evidence(String chave, Object... args) {
        return prefixado("evidence.", chave, args);
    }

    /**
     * Descrição de um achado de módulo — o parágrafo que explica o que foi exposto.
     *
     * Separado da evidência porque são coisas diferentes no card: a evidência é o que
     * se encontrou, a descrição é o que aquilo significa.
     */
    public String desc(String chave, Object... args) {
        return prefixado("desc.", chave, args);
    }

    /**
     * Texto dos e-mails — assunto e corpo.
     *
     * A estrutura HTML fica no {@link EmailService}: só a prosa vem daqui. Marcação
     * em arquivo de mensagens não é traduzível na prática (o tradutor teria de
     * mexer em tags) e some do controle de versão do código, onde ela pertence.
     */
    public String email(String chave, Object... args) {
        return prefixado("email.", chave, args);
    }

    private String prefixado(String prefixo, String chave, Object[] args) {
        String id = prefixo + chave;
        return messages.getMessage(id, args, id, LocaleContextHolder.getLocale());
    }

    private String texto(String chave, String campo, Object[] args) {
        String id = "issue." + chave + "." + campo;
        // Chave ausente devolve a própria chave, que aparece feia no laudo. É o
        // mesmo princípio do id cru no cardápio: achado novo sem tradução salta
        // aos olhos em vez de sair com texto vazio.
        return messages.getMessage(id, args, id, LocaleContextHolder.getLocale());
    }
}
