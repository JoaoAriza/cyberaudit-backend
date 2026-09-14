package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ImpactSignal;
import com.joao.cyberaudit.model.ImpactSource;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Deriva o rótulo de impacto a partir do que o scan já coletou.
 *
 * Função pura: não faz requisição, não lê banco. Todo sinal vem do
 * {@link ScanResult} que já está montado — por isso é testável sem rede, como o
 * {@code caminhoDe} e o {@code pareceExistir}.
 */
@Service
public class ImpactLabelService {

    /**
     * O nível, os sinais que o sustentam e a plataforma que responde pelo checkout.
     *
     * Os sinais são só os do nível VENCEDOR: uma página de checkout com campo de
     * senha é PAGAMENTO por causa do checkout, e listar a senha como motivo
     * confundiria o porquê.
     */
    public record Avaliacao(ImpactLevel level, List<ImpactSignal> signals, String managedPlatform) {}

    /** Segmentos de caminho que indicam fluxo de pagamento. */
    private static final Set<String> CAMINHOS_PAGAMENTO = Set.of(
            "checkout", "carrinho", "cart", "pagamento", "payment", "finalizar-compra");

    /** Segmentos que indicam área autenticada. */
    private static final Set<String> CAMINHOS_CONTA = Set.of(
            "conta", "minha-conta", "login", "entrar", "signin", "sign-in",
            "account", "cadastro", "register", "painel", "dashboard", "admin");

    /**
     * Plataformas de loja HOSPEDADA (prefixo do nome detectado → nome exibido): o
     * checkout, os cabeçalhos e o certificado são da plataforma, não do lojista.
     *
     * NÃO elevam o nível — decisão de 13/09/2026. Antes, detectar a plataforma
     * marcava PAYMENT em qualquer página da loja, inclusive a home que não coleta
     * nada; só não aparecia porque o fingerprint reconhecia apenas Shopify. O nível
     * vem do que a PÁGINA coleta. A plataforma vira aviso, porque apontar ao lojista
     * um cabeçalho que ele não controla derruba a conversa comercial.
     *
     * WooCommerce, Magento e PrestaShop ficam de fora de propósito: são instalados
     * pelo próprio lojista, que controla o servidor e portanto o conserto.
     */
    private static final Map<String, String> PLATAFORMAS_GERIDAS = Map.of(
            "shopify",        "Shopify",
            "vtex",           "VTEX",
            "nuvemshop",      "Nuvemshop",
            "tiendanube",     "Nuvemshop",
            "bigcommerce",    "BigCommerce",
            "loja integrada", "Loja Integrada",
            "tray",           "Tray");

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

    /** Teto de sinais por origem — dez cookies de sessão não explicam mais que três. */
    private static final int MAX_POR_ORIGEM = 3;

    public ImpactLevel derive(ScanResult r) {
        return assess(r).level();
    }

    /** Grava nível, sinais e plataforma no próprio resultado, antes dele ir para o cache. */
    public void rotular(ScanResult r) {
        Avaliacao a = assess(r);
        r.setImpact(a.level());
        r.setImpactSignals(a.signals());
        r.setManagedPlatform(a.managedPlatform());
    }

    public Avaliacao assess(ScanResult r) {
        if (r == null) return new Avaliacao(ImpactLevel.SHOWCASE, List.of(), null);

        String caminho = ScanHistoryService.caminhoDe(
                r.getFinalUrl() != null ? r.getFinalUrl() : r.getUrl());
        FormSurfaceResult form = r.getFormSurface();
        String plataforma = plataformaGerida(r.getTechFingerprint());

        List<ImpactSignal> sinais = sinaisDePagamento(caminho, form);
        if (!sinais.isEmpty()) return new Avaliacao(ImpactLevel.PAYMENT, sinais, plataforma);

        sinais = sinaisDeConta(caminho, form, r);
        if (!sinais.isEmpty()) return new Avaliacao(ImpactLevel.ACCOUNT, sinais, plataforma);

        sinais = sinaisDeContato(form);
        if (!sinais.isEmpty()) return new Avaliacao(ImpactLevel.CONTACT, sinais, plataforma);

        return new Avaliacao(ImpactLevel.SHOWCASE, List.of(), plataforma);
    }

    private List<ImpactSignal> sinaisDePagamento(String caminho, FormSurfaceResult form) {
        List<ImpactSignal> out = new ArrayList<>();
        if (form != null && form.isHasPaymentField()) out.add(sinal(ImpactSource.FORM, "payment-field"));
        segmentoQueCasa(caminho, CAMINHOS_PAGAMENTO).ifPresent(s -> out.add(sinal(ImpactSource.PATH, "/" + s)));
        return out;
    }

    private List<ImpactSignal> sinaisDeConta(String caminho, FormSurfaceResult form, ScanResult r) {
        List<ImpactSignal> out = new ArrayList<>();
        if (form != null && form.isHasPasswordField()) out.add(sinal(ImpactSource.FORM, "password-field"));
        segmentoQueCasa(caminho, CAMINHOS_CONTA).ifPresent(s -> out.add(sinal(ImpactSource.PATH, "/" + s)));
        cookiesDeSessao(r.getCookieIssues()).forEach(nome -> out.add(sinal(ImpactSource.COOKIES, nome)));
        primeiros(r.getJwtSecurity(), j -> j.getSource())
                .forEach(s -> out.add(sinal(ImpactSource.JWT, s)));
        // API exposta implica backend com dado por trás, não página estática.
        primeiros(r.getApiDocsExposure(), a -> a.getPath())
                .forEach(p -> out.add(sinal(ImpactSource.API_DOCS, p)));
        primeiros(r.getGraphQlIntrospection(), g -> g.getEndpoint())
                .forEach(e -> out.add(sinal(ImpactSource.GRAPHQL, e)));
        return out;
    }

    private List<ImpactSignal> sinaisDeContato(FormSurfaceResult form) {
        List<ImpactSignal> out = new ArrayList<>();
        if (form == null) return out;
        if (form.isCollectsPii()) out.add(sinal(ImpactSource.FORM, "pii-field"));
        if (form.isHasForm())     out.add(sinal(ImpactSource.FORM, "form"));
        return out;
    }

    private ImpactSignal sinal(ImpactSource source, String detail) {
        return new ImpactSignal(source, detail);
    }

    /**
     * Casa por SEGMENTO do caminho, e não por "contém": senão "/carta-de-servicos"
     * casaria com "cart" e uma página institucional viraria PAYMENT.
     */
    private Optional<String> segmentoQueCasa(String caminho, Set<String> alvos) {
        if (caminho == null || caminho.isBlank()) return Optional.empty();
        for (String segmento : caminho.toLowerCase(Locale.ROOT).split("/")) {
            if (!segmento.isBlank() && alvos.contains(segmento)) return Optional.of(segmento);
        }
        return Optional.empty();
    }

    /**
     * Nome exibido da plataforma hospedada, olhando o CMS e as bibliotecas — o
     * WooCommerce, por exemplo, entra como biblioteca para o CMS continuar sendo
     * WordPress (é por ele que a busca de CVE casa a versão).
     */
    private String plataformaGerida(TechFingerprintResult tech) {
        if (tech == null) return null;
        Stream<String> nomes = Stream.concat(
                Stream.ofNullable(tech.getCms()),
                tech.getLibraries() == null ? Stream.empty() : tech.getLibraries().stream());
        return nomes
                .filter(n -> n != null && !n.isBlank())
                .map(n -> n.toLowerCase(Locale.ROOT))
                .flatMap(n -> PLATAFORMAS_GERIDAS.entrySet().stream()
                        .filter(e -> n.equals(e.getKey()) || n.startsWith(e.getKey() + " "))
                        .map(Map.Entry::getValue))
                .findFirst()
                .orElse(null);
    }

    private List<String> cookiesDeSessao(List<CookieFinding> cookies) {
        if (cookies == null) return List.of();
        return cookies.stream()
                .map(CookieFinding::getName)
                .filter(nome -> nome != null && !nome.isBlank())
                .filter(nome -> {
                    String lower = nome.toLowerCase(Locale.ROOT);
                    return !ehInfra(lower) && COOKIES_SESSAO.stream().anyMatch(lower::contains);
                })
                .distinct()
                .limit(MAX_POR_ORIGEM)
                .toList();
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

    /**
     * Até {@link #MAX_POR_ORIGEM} valores distintos de uma lista de achados. Achado
     * sem o campo ainda conta — a presença já é o sinal, que vai sem detalhe (null).
     */
    private <T> List<String> primeiros(List<T> achados, Function<T, String> campo) {
        if (achados == null || achados.isEmpty()) return List.of();
        return achados.stream()
                .map(a -> {
                    String v = campo.apply(a);
                    return v == null || v.isBlank() ? null : v;
                })
                .distinct()
                .limit(MAX_POR_ORIGEM)
                .toList();
    }
}
