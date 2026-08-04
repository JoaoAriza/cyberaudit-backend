package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.AsyncScanStatus.State;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AsyncScanService {

    /** Quanto tempo um resultado fica disponível para ser buscado pelo cliente. */
    private static final Duration ENTRY_TTL = Duration.ofHours(1);

    /** Teto duro de entradas — protege a heap se o TTL não der conta do volume. */
    private static final int MAX_ENTRIES = 5_000;

    /**
     * Entrada do scan em memória. O dono fica FORA do {@link AsyncScanStatus} de
     * propósito: aquele objeto é serializado para o cliente e não deve carregar
     * identidade de ninguém.
     */
    private record Entry(AsyncScanStatus status, String ownerKey, Instant createdAt) {}

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();

    private final ScanOrchestrator       scanOrchestrator;
    private final EmailService           emailService;
    private final AppUserRepository      appUserRepository;
    private final ScanEntitlementService scanEntitlement;

    public AsyncScanService(ScanOrchestrator scanOrchestrator,
                            EmailService emailService,
                            AppUserRepository appUserRepository,
                            ScanEntitlementService scanEntitlement) {
        this.scanOrchestrator  = scanOrchestrator;
        this.emailService      = emailService;
        this.appUserRepository = appUserRepository;
        this.scanEntitlement   = scanEntitlement;
    }

    /**
     * Chave de dono de um scan assíncrono: e-mail para autenticado, IP para guest.
     * É o que amarra o scanId a quem pediu — sem isso, qualquer um que descubra o
     * UUID lê o resultado (inclusive sem autenticação, já que /scan/async/** é público).
     */
    public static String ownerKey(AppUser user, String remoteAddr) {
        if (user != null && user.getEmail() != null) return "user:" + user.getEmail();
        return "ip:" + (remoteAddr == null ? "desconhecido" : remoteAddr);
    }

    public String submit(String url, boolean active, AppUser currentUser,
                         boolean refresh, boolean notify, String ownerKey) {
        evictStale();
        String scanId = UUID.randomUUID().toString();
        put(scanId, new AsyncScanStatus(scanId, State.PENDING, null, null), ownerKey);
        executeAsync(scanId, url, active, currentUser, refresh, notify, ownerKey);
        return scanId;
    }

    /**
     * Status de um scan, apenas para quem o submeteu. Devolve null tanto para
     * scanId inexistente quanto para scanId de outro dono — o cliente não
     * consegue distinguir os dois casos.
     */
    public AsyncScanStatus getStatusFor(String scanId, String ownerKey) {
        Entry entry = entries.get(scanId);
        if (entry == null || !entry.ownerKey().equals(ownerKey)) return null;
        return entry.status();
    }

    @Async
    public void executeAsync(String scanId, String url, boolean active,
                             AppUser currentUser, boolean refresh, boolean notify,
                             String ownerKey) {
        put(scanId, new AsyncScanStatus(scanId, State.RUNNING, null, null), ownerKey);
        try {
            // Re-fetch user WITH eager account (JOIN FETCH) in the async thread's own JPA session.
            // The principal from Spring Security is a detached entity — its lazy account proxy
            // cannot be initialized outside the original session. findByEmailWithAccount uses
            // LEFT JOIN FETCH u.account to avoid LazyInitializationException / NPE on pk.
            if (currentUser != null) {
                currentUser = appUserRepository
                        .findByEmailWithAccount(currentUser.getEmail())
                        .orElse(null);
            }

            ScanResult result = scanOrchestrator.execute(url, active, currentUser, refresh);

            // E-mail pessoal (ao próprio usuário) usa o resultado completo.
            if (notify && currentUser != null && result != null) {
                emailService.sendScanComplete(
                        currentUser.getEmail(),
                        currentUser.getName(),
                        result);
            }

            // A UI recebe o resultado já com gating por plano (guest/FREE não veem
            // impacto/correção/breakdown). applyEntitlement nunca muta o cache.
            put(scanId, new AsyncScanStatus(scanId, State.DONE,
                    scanEntitlement.applyEntitlement(result, currentUser), null), ownerKey);
        } catch (Exception e) {
            put(scanId, new AsyncScanStatus(scanId, State.ERROR, null,
                    safeErrorMessage(e)), ownerKey);
        }
    }

    /**
     * Mensagem de erro segura para o cliente.
     *
     * Antes o texto era {@code e.getMessage()} cru — qualquer exceção interna (SQL,
     * caminho de arquivo, host de infra) ia direto para a resposta HTTP. Aqui só
     * passam as mensagens que existem para serem lidas pelo usuário e as falhas de
     * rede do alvo, que a UI usa para dizer "domínio inacessível".
     */
    private String safeErrorMessage(Throwable error) {
        for (Throwable t = error; t != null && t != t.getCause(); t = t.getCause()) {
            if (t instanceof com.joao.cyberaudit.exception.OwnershipNotVerifiedException
                    || t instanceof com.joao.cyberaudit.exception.DomainBlockedException
                    || t instanceof com.joao.cyberaudit.exception.ScanCapacityException) {
                return t.getMessage();
            }
            if (t instanceof java.net.UnknownHostException) {
                // A UI procura este marcador para renderizar "domínio não encontrado".
                return "UnknownHostException: domínio não encontrado ou sem resolução DNS.";
            }
            if (t instanceof java.net.ConnectException
                    || t instanceof java.net.SocketTimeoutException
                    || t instanceof java.net.http.HttpConnectTimeoutException) {
                return "Não foi possível conectar ao host: ele pode estar offline ou bloqueando o acesso.";
            }
        }
        return "Erro ao executar o scan. Verifique a URL e tente novamente.";
    }

    // ── Interno ──────────────────────────────────────────────────────────────

    private void put(String scanId, AsyncScanStatus status, String ownerKey) {
        Entry previous = entries.get(scanId);
        Instant createdAt = previous != null ? previous.createdAt() : Instant.now();
        entries.put(scanId, new Entry(status, ownerKey, createdAt));
    }

    /**
     * Remove entradas vencidas e, se ainda assim houver excesso, as mais antigas.
     * O mapa vivia para sempre: cada scan submetido era memória que nunca voltava.
     */
    private void evictStale() {
        Instant cutoff = Instant.now().minus(ENTRY_TTL);
        entries.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));

        int excess = entries.size() - MAX_ENTRIES;
        if (excess <= 0) return;

        List<String> oldest = entries.entrySet().stream()
                .sorted(Comparator.comparing(e -> e.getValue().createdAt()))
                .limit(excess)
                .map(Map.Entry::getKey)
                .toList();
        oldest.forEach(entries::remove);
    }
}
