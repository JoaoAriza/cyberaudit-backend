package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.TargetUnreachableException;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Confere se o alvo do scan existe antes de auditar (BUG-16 do cyberaudit-qa).
 *
 * Um domínio que não resolve não tem o que auditar. Antes o scan seguia e devolvia nota
 * (17/100, CRITICAL, para um domínio digitado errado). Decisão do dono (2026-11-22): recusar
 * com 422 e sem gastar cota. Por isso {@link #exigeQueResolva} roda duas vezes:
 * - no {@code ScanLimitsService.checkBeforeScan}, antes da cota, para todo endpoint;
 * - no {@code ScanOrchestrator.execute}, para quem chama o motor direto (o agendador).
 *
 * A segunda resolução sai do cache de DNS da JVM, então custa pouco.
 */
@Service
public class ScanTargetService {

    private final MessageCatalog catalog;

    public ScanTargetService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * Recusa o alvo cujo domínio não resolve no DNS.
     *
     * Usa o mesmo {@code InetAddress} do {@code SsrfGuard}: o que um aceita, o outro
     * aceita. Duas coisas passam daqui sem erro, porque quem as recusa, com a mensagem
     * certa (403), é o {@code SsrfGuard} dentro do orchestrator:
     * - URL que não dá para ler;
     * - nome que o guard bloqueia sem consultar DNS ({@code metadata.google.internal},
     *   {@code http://2130706433}). Esses não resolvem, e sem a ressalva sairiam como
     *   "domínio não encontrado" em vez de "bloqueado".
     */
    public void exigeQueResolva(String url) {
        String host = hostDe(url);
        if (host == null) return;
        try {
            InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            if (SsrfGuard.refusesByName(host)) return;
            throw new TargetUnreachableException(TargetUnreachableException.NAO_RESOLVE, host,
                    catalog.erro("ALVO_NAO_RESOLVE", host));
        }
    }

    /** Recusa do alvo que resolve, mas onde nada aceitou a conexão. */
    public TargetUnreachableException semResposta(String host) {
        return new TargetUnreachableException(TargetUnreachableException.SEM_RESPOSTA, host,
                catalog.erro("ALVO_SEM_RESPOSTA", host));
    }

    /** Host da URL como o orchestrator a normaliza: sem esquema, vira https. */
    static String hostDe(String url) {
        if (url == null || url.isBlank()) return null;
        String u = url.trim();
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
        try {
            String host = URI.create(u).getHost();
            return (host == null || host.isBlank()) ? null : host;
        } catch (Exception e) {
            return null;
        }
    }
}
