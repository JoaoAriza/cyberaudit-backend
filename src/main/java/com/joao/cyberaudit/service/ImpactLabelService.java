package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Deriva o rótulo de impacto a partir do que o scan já coletou.
 *
 * Função pura: não faz requisição, não lê banco. Todo sinal vem do
 * {@link ScanResult} que já está montado — por isso é testável sem rede, como o
 * {@code caminhoDe} e o {@code pareceExistir}.
 */
@Service
public class ImpactLabelService {

    /** Segmentos de caminho que indicam fluxo de pagamento. */
    private static final Set<String> CAMINHOS_PAGAMENTO = Set.of(
            "checkout", "carrinho", "cart", "pagamento", "payment", "finalizar-compra");

    /** Segmentos que indicam área autenticada. */
    private static final Set<String> CAMINHOS_CONTA = Set.of(
            "conta", "minha-conta", "login", "entrar", "signin", "sign-in",
            "account", "cadastro", "register", "painel", "dashboard", "admin");

    /** Plataformas de e-commerce: a presença já implica fluxo de pagamento. */
    private static final Set<String> PLATAFORMAS_COMERCIO = Set.of(
            "shopify", "woocommerce", "magento", "prestashop", "vtex",
            "nuvemshop", "tiendanube", "bigcommerce", "loja integrada", "tray");

    /**
     * Cookies de CDN, bot-management e analytics — comparados por PREFIXO, porque
     * vários carregam sufixo dinâmico ({@code _hjSession_1873402}).
     *
     * Os que importam de verdade são os do fim da lista: {@code _hjSession} contém
     * "sess" e {@code ajs_user_id} contém "user", os mesmos fragmentos que
     * identificam sessão logo abaixo. Sem excluí-los, qualquer site institucional
     * com Hotjar ou Segment — que é a maioria — sairia como ACCOUNT sem ter área
     * autenticada nenhuma.
     */
    private static final Set<String> COOKIES_INFRA = Set.of(
            "__cf_bm", "_cfuvid", "cf_clearance", "__cfruid", "__cflb",
            "_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "_clck", "_clsk",
            "_hjsession", "_hjsessionuser", "ajs_user_id", "ajs_anonymous_id");

    /** Fragmentos que identificam cookie de sessão/autenticação. */
    private static final Set<String> COOKIES_SESSAO = Set.of(
            "sess", "sid", "auth", "token", "login", "usuario", "user");

    public ImpactLevel derive(ScanResult r) {
        if (r == null) return ImpactLevel.SHOWCASE;

        String caminho = ScanHistoryService.caminhoDe(
                r.getFinalUrl() != null ? r.getFinalUrl() : r.getUrl());
        FormSurfaceResult form = r.getFormSurface();

        if (ehPagamento(caminho, form, r.getTechFingerprint())) return ImpactLevel.PAYMENT;
        if (ehConta(caminho, form, r))                          return ImpactLevel.ACCOUNT;
        if (ehContato(form))                                     return ImpactLevel.CONTACT;
        return ImpactLevel.SHOWCASE;
    }

    private boolean ehPagamento(String caminho, FormSurfaceResult form, TechFingerprintResult tech) {
        if (form != null && form.isHasPaymentField()) return true;
        if (casaSegmento(caminho, CAMINHOS_PAGAMENTO)) return true;
        return tech != null && ehComercio(tech.getCms());
    }

    private boolean ehConta(String caminho, FormSurfaceResult form, ScanResult r) {
        if (form != null && form.isHasPasswordField()) return true;
        if (casaSegmento(caminho, CAMINHOS_CONTA)) return true;
        if (temCookieDeSessao(r.getCookieIssues())) return true;
        if (naoVazio(r.getJwtSecurity())) return true;
        // API exposta implica backend com dado por trás, não página estática.
        return naoVazio(r.getApiDocsExposure()) || naoVazio(r.getGraphQlIntrospection());
    }

    private boolean ehContato(FormSurfaceResult form) {
        return form != null && (form.isHasForm() || form.isCollectsPii());
    }

    /**
     * Casa por SEGMENTO do caminho, e não por "contém": senão "/carta-de-servicos"
     * casaria com "cart" e uma página institucional viraria PAYMENT.
     */
    private boolean casaSegmento(String caminho, Set<String> alvos) {
        if (caminho == null || caminho.isBlank()) return false;
        for (String segmento : caminho.toLowerCase(Locale.ROOT).split("/")) {
            if (!segmento.isBlank() && alvos.contains(segmento)) return true;
        }
        return false;
    }

    private boolean ehComercio(String cms) {
        if (cms == null || cms.isBlank()) return false;
        String lower = cms.toLowerCase(Locale.ROOT);
        return PLATAFORMAS_COMERCIO.stream().anyMatch(lower::contains);
    }

    private boolean temCookieDeSessao(List<CookieFinding> cookies) {
        if (cookies == null) return false;
        for (CookieFinding c : cookies) {
            String nome = c.getName() == null ? "" : c.getName().toLowerCase(Locale.ROOT);
            if (nome.isBlank() || ehInfra(nome)) continue;
            if (COOKIES_SESSAO.stream().anyMatch(nome::contains)) return true;
        }
        return false;
    }

    /**
     * Por PREFIXO, não por igualdade: {@code _hjSession_1873402} e
     * {@code _ga_XYZ123} trazem sufixo dinâmico e nunca casariam com uma lista de
     * nomes exatos — que era o estado anterior, no qual a exclusão inteira não
     * mudava resultado nenhum.
     */
    private boolean ehInfra(String nome) {
        return COOKIES_INFRA.stream().anyMatch(nome::startsWith);
    }

    private boolean naoVazio(List<?> lista) {
        return lista != null && !lista.isEmpty();
    }
}
