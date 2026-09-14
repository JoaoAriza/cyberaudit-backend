package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ImpactSignal;
import com.joao.cyberaudit.model.ImpactSource;
import com.joao.cyberaudit.model.ImpactUndetermined;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Deriva o rótulo de impacto a partir do que o scan já coletou.
 *
 * Função pura: não faz requisição, não lê banco. Todo sinal vem do
 * {@link ScanResult} que já está montado — por isso é testável sem rede, como o
 * {@code caminhoDe} e o {@code pareceExistir}.
 *
 * O NÍVEL vem só dos campos da página escaneada. A primeira versão também subia o
 * nível por sinais que não pertencem à página, e errou em produção:
 * <ul>
 *   <li>a palavra "checkout" no endereço fez de uma tela de login bloqueada
 *       (HTTP 403, corpo vazio) um PAGAMENTO;</li>
 *   <li>o cookie de sessão anônimo que um site de imobiliária entrega a todo
 *       visitante fez de uma home só com busca uma CONTA — e só porque o cookie não
 *       tinha as flags, já que o módulo de cookies lista apenas cookie com
 *       problema.</li>
 * </ul>
 * Cookie de sessão, JWT, documentação de API e GraphQL continuam úteis, mas como
 * INDÍCIO do domínio: aparecem ao lado do rótulo e não mexem nele.
 */
@Service
public class ImpactLabelService {

    /**
     * O nível, o sinal de página que o sustenta, os indícios do domínio, a
     * plataforma que responde pelo checkout e — quando não há nível — o motivo.
     */
    public record Avaliacao(ImpactLevel level, List<ImpactSignal> signals, List<ImpactSignal> indicators,
                            String managedPlatform, ImpactUndetermined undetermined) {}

    /**
     * Plataformas de loja HOSPEDADA (prefixo do nome detectado → nome exibido): o
     * checkout, os cabeçalhos e o certificado são da plataforma, não do lojista.
     *
     * NÃO elevam o nível — decisão de 13/09/2026. O nível vem do que a PÁGINA
     * coleta. A plataforma vira aviso, porque apontar ao lojista um cabeçalho que
     * ele não controla derruba a conversa comercial.
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
     * Os do fim da lista são os que importam: {@code _hjSession} contém "sess" e
     * {@code ajs_user_id} contém "user", os mesmos fragmentos que identificam
     * sessão logo abaixo.
     */
    private static final Set<String> COOKIES_INFRA = Set.of(
            "__cf_bm", "_cfuvid", "cf_clearance", "__cfruid", "__cflb",
            "_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "_clck", "_clsk",
            "_hjsession", "_hjsessionuser", "ajs_user_id", "ajs_anonymous_id");

    /** Fragmentos que identificam cookie de sessão/autenticação. */
    private static final Set<String> COOKIES_SESSAO = Set.of(
            "sess", "sid", "auth", "token", "login", "usuario", "user");

    /** Teto de indícios por origem — dez cookies de sessão não explicam mais que três. */
    private static final int MAX_POR_ORIGEM = 3;

    public ImpactLevel derive(ScanResult r) {
        return assess(r).level();
    }

    /** Grava a avaliação no próprio resultado, antes dele ir para o cache. */
    public void rotular(ScanResult r) {
        Avaliacao a = assess(r);
        r.setImpact(a.level());
        r.setImpactSignals(a.signals());
        r.setImpactIndicators(a.indicators());
        r.setManagedPlatform(a.managedPlatform());
        r.setImpactUndetermined(a.undetermined());
    }

    public Avaliacao assess(ScanResult r) {
        if (r == null) return new Avaliacao(null, List.of(), List.of(), null, ImpactUndetermined.EMPTY);

        FormSurfaceResult form = r.getFormSurface();
        String plataforma = plataformaGerida(r.getTechFingerprint());
        List<ImpactSignal> indicios = indicios(r);

        ImpactUndetermined motivo = motivoIndeterminado(r.getHttpStatus(), form);
        if (motivo != null) return new Avaliacao(null, List.of(), indicios, plataforma, motivo);

        ImpactLevel nivel;
        String marcador;
        if (form.isHasPaymentField())       { nivel = ImpactLevel.PAYMENT; marcador = "payment-field"; }
        else if (form.isHasPasswordField()) { nivel = ImpactLevel.ACCOUNT; marcador = "password-field"; }
        else if (form.isCollectsPii())      { nivel = ImpactLevel.CONTACT; marcador = "pii-field"; }
        else return new Avaliacao(ImpactLevel.SHOWCASE, List.of(), indicios, plataforma, null);

        return new Avaliacao(nivel, List.of(new ImpactSignal(ImpactSource.FORM, marcador)),
                indicios, plataforma, null);
    }

    /**
     * Por que não dá para afirmar nada sobre a página; nulo quando ela foi lida.
     *
     * O status vem primeiro: o corpo de um 403 é a página do bloqueio, não a do site.
     */
    private ImpactUndetermined motivoIndeterminado(int httpStatus, FormSurfaceResult form) {
        if (httpStatus < 200 || httpStatus >= 300) return ImpactUndetermined.HTTP_STATUS;
        if (form == null || !form.isAnalyzed())    return ImpactUndetermined.EMPTY;
        if (form.isJsRendered())                   return ImpactUndetermined.JS_RENDERED;
        return null;
    }

    /** Sinais do DOMÍNIO, que não dizem o que esta página coleta — ver o javadoc da classe. */
    private List<ImpactSignal> indicios(ScanResult r) {
        List<ImpactSignal> out = new ArrayList<>();
        cookiesDeSessao(r.getCookieIssues()).forEach(nome -> out.add(new ImpactSignal(ImpactSource.COOKIES, nome)));
        primeiros(r.getJwtSecurity(), j -> j.getSource())
                .forEach(s -> out.add(new ImpactSignal(ImpactSource.JWT, s)));
        primeiros(r.getApiDocsExposure(), a -> a.getPath())
                .forEach(p -> out.add(new ImpactSignal(ImpactSource.API_DOCS, p)));
        primeiros(r.getGraphQlIntrospection(), g -> g.getEndpoint())
                .forEach(e -> out.add(new ImpactSignal(ImpactSource.GRAPHQL, e)));
        return out;
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
     * nomes exatos.
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
