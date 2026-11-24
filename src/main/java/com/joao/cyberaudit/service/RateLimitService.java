package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Requisições por minuto nos endpoints que disparam scan ou requisição de saída
 * (via {@link ScanLimitsService#checkRateLimit}).
 *
 * O limite segue o plano efetivo da conta ({@link PlanLimitService#effectivePlan}):
 * FREE 5, PRO 60, ENTERPRISE 120. Membro de equipe herda o plano da conta, como na
 * cota diária. Visitante tem 5 por IP. Só a equipe da plataforma
 * (PLATFORM_STAFF_EMAILS) fica de fora.
 *
 * Regressão do BUG-20 (cyberaudit-qa): o limite vinha do papel. Todo OWNER, que é
 * como sai todo cadastro, ficava sem limite nenhum, e o FREE_EMPLOYEE tinha 60 por
 * minuto mesmo numa conta FREE. Na prática, só o visitante era limitado.
 */
@Service
public class RateLimitService {

    public static final int GUEST_RPM      = 5;
    public static final int FREE_RPM       = 5;
    public static final int PRO_RPM        = 60;
    public static final int ENTERPRISE_RPM = 120;

    private final PlanLimitService planLimitService;

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitService(PlanLimitService planLimitService) {
        this.planLimitService = planLimitService;
    }

    /**
     * @param key         IP do cliente; só é a chave do balde para visitante
     * @param currentUser usuário logado, ou {@code null} para visitante
     */
    public boolean allow(String key, AppUser currentUser) {
        if (currentUser == null) {
            return balde("ip:" + key, GUEST_RPM).tryConsume(1);
        }
        if (planLimitService.isPlatformStaff(currentUser)) {
            return true;
        }
        int rpm = rpmDoPlano(planLimitService.effectivePlan(currentUser));
        // O rpm entra na chave: quem troca de plano passa a usar o balde do plano novo
        // na hora, em vez de ficar preso ao tamanho do balde criado no plano antigo.
        return balde("user:" + currentUser.getId() + ":" + rpm, rpm).tryConsume(1);
    }

    /** Limite genérico, com chave e janela de quem chama (billing). */
    public boolean allow(String key, int maxRequests, long windowMs) {
        Bucket bucket = buckets.computeIfAbsent(key, k ->
                Bucket.builder()
                        .addLimit(Bandwidth.builder()
                                .capacity(maxRequests)
                                .refillGreedy(maxRequests,
                                        Duration.ofMillis(windowMs))
                                .build())
                        .build()
        );
        return bucket.tryConsume(1);
    }

    /**
     * Requisições por minuto de cada plano. O switch não tem {@code default}: um plano
     * novo no enum não compila até alguém decidir o limite dele aqui.
     */
    public static int rpmDoPlano(Plan plan) {
        return switch (plan) {
            case FREE       -> FREE_RPM;
            case PRO        -> PRO_RPM;
            case ENTERPRISE -> ENTERPRISE_RPM;
        };
    }

    private Bucket balde(String chave, int rpm) {
        return buckets.computeIfAbsent(chave, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(rpm)
                        .refillGreedy(rpm, Duration.ofMinutes(1))
                        .build())
                .build());
    }
}
