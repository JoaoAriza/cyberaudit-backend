package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.AsyncScanStatus.State;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Locale;
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
    private record Entry(AsyncScanStatus status, String ownerKey, Instant createdAt,
                         ScanProgress progresso) {}

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();

    private final ScanOrchestrator       scanOrchestrator;
    private final EmailService           emailService;
    private final AppUserRepository      appUserRepository;
    private final ScanEntitlementService scanEntitlement;
    private final MessageCatalog         catalog;
    private final BackgroundRunner       background;
    private final PlanLimitService       planLimitService;

    public AsyncScanService(ScanOrchestrator scanOrchestrator,
                            EmailService emailService,
                            AppUserRepository appUserRepository,
                            ScanEntitlementService scanEntitlement,
                            MessageCatalog catalog,
                            BackgroundRunner background,
                            PlanLimitService planLimitService) {
        this.scanOrchestrator  = scanOrchestrator;
        this.emailService      = emailService;
        this.appUserRepository = appUserRepository;
        this.scanEntitlement   = scanEntitlement;
        this.catalog           = catalog;
        this.background        = background;
        this.planLimitService  = planLimitService;
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
        // Nasce junto com o scanId: o cliente pode perguntar o progresso antes mesmo
        // de a thread do scan começar, e recebe a lista inteira ainda pendente.
        put(scanId, new AsyncScanStatus(scanId, State.PENDING, null, null), ownerKey,
                new ScanProgress(catalog, active,
                        planLimitService.activeScanAllowedByPlan(currentUser)));
        // O idioma tem de ser capturado AQUI, na thread da requisição. O
        // LocaleContextHolder é ThreadLocal e o scan roda em outra thread: sem
        // carregá-lo junto, todo scan assíncrono sairia no idioma padrão — e este
        // é o caminho que a interface usa.
        //
        // Via BackgroundRunner, e não com um @Async aqui: método anotado chamado de
        // dentro da própria classe não passa pelo proxy do Spring e roda síncrono.
        // Ver o javadoc do BackgroundRunner — foi assim que este endpoint passou a
        // devolver o scanId só depois do scan inteiro terminar.
        final AppUser usuario = currentUser;
        final Locale  idioma  = LocaleContextHolder.getLocale();
        background.run(() -> executeScan(scanId, url, active, usuario, refresh, notify,
                ownerKey, idioma));
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

        // O progresso é montado aqui, e não guardado com o status, por duas razões:
        // muda a cada instante enquanto o scan roda, e os rótulos são traduzidos no
        // idioma de QUEM PERGUNTOU — o feed acompanha quem troca de idioma no meio.
        AsyncScanStatus s = entry.status();
        return new AsyncScanStatus(s.getScanId(), s.getState(), s.getResult(),
                s.getErrorMessage(), entry.progresso().instantaneo());
    }

    /**
     * O scan em si. Já roda na thread do {@link BackgroundRunner} — sem anotação
     * aqui, que daria a impressão de garantir a troca de thread e não garante.
     */
    void executeScan(String scanId, String url, boolean active,
                     AppUser currentUser, boolean refresh, boolean notify,
                     String ownerKey, Locale idioma) {
        put(scanId, new AsyncScanStatus(scanId, State.RUNNING, null, null), ownerKey);
        // Reinstala o idioma da requisição nesta thread; o finally limpa porque a
        // thread volta para o pool e serviria outro scan com o idioma errado.
        LocaleContextHolder.setLocale(idioma);
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

            ScanResult result = scanOrchestrator.execute(url, active, currentUser, refresh,
                    com.joao.cyberaudit.model.ScanOrigin.MANUAL, progressoDe(scanId));

            // O gating vale para QUALQUER canal de entrega, não só para a tela.
            // O e-mail mandava o resultado cru: um FREE via na caixa de entrada os
            // títulos MEDIUM/HIGH que a UI borrava ao lado. Era a trava do produto
            // inteira contornável marcando um checkbox.
            ScanResult visivel = scanEntitlement.applyEntitlement(result, currentUser);

            if (notify && currentUser != null && visivel != null) {
                emailService.sendScanComplete(
                        currentUser.getEmail(),
                        currentUser.getName(),
                        visivel);
            }

            // applyEntitlement nunca muta o cache — `visivel` é cópia quando trava.
            put(scanId, new AsyncScanStatus(scanId, State.DONE, visivel, null), ownerKey);
        } catch (Exception e) {
            put(scanId, new AsyncScanStatus(scanId, State.ERROR, null,
                    safeErrorMessage(e)), ownerKey);
        } finally {
            LocaleContextHolder.resetLocaleContext();
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

    /** Atualiza o status preservando o progresso que já está sendo escrito. */
    private void put(String scanId, AsyncScanStatus status, String ownerKey) {
        Entry previous = entries.get(scanId);
        put(scanId, status, ownerKey,
                previous != null ? previous.progresso() : ScanProgress.desligado());
    }

    private void put(String scanId, AsyncScanStatus status, String ownerKey, ScanProgress progresso) {
        Entry previous = entries.get(scanId);
        Instant createdAt = previous != null ? previous.createdAt() : Instant.now();
        entries.put(scanId, new Entry(status, ownerKey, createdAt, progresso));
    }

    private ScanProgress progressoDe(String scanId) {
        Entry entry = entries.get(scanId);
        return entry != null ? entry.progresso() : ScanProgress.desligado();
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
