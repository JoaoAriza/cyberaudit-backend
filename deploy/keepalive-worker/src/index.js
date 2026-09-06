/**
 * Mantém o Web Service da Render acordado nas horas que importam.
 *
 * O plano gratuito da Render desliga o serviço após 15 minutos SEM TRÁFEGO DE
 * ENTRADA — e o gatilho é esse mesmo: requisição HTTP chegando de fora. Trabalho
 * interno não conta, então nenhum `@Scheduled` do próprio Backend consegue se
 * manter vivo. Pior: dormindo, o processo está parado, e os jobs agendados
 * (scans, retenção de dados) simplesmente não acontecem no horário.
 *
 * Este Worker é o tráfego de fora. Os horários estão no wrangler.toml.
 *
 * ## O que isto NÃO resolve
 *
 * - O cold start depois de cada deploy: a publicação reinicia o ciclo
 * - As horas de instância consumidas na Render enquanto o serviço fica acordado.
 *   É justamente por isso que a janela é seletiva em vez de 24h — ver o
 *   wrangler.toml. Se um dia a cobertura precisar ser integral, o web service
 *   pago faz o mesmo sem cota e sem esta peça no caminho.
 */

/**
 * Medido contra a produção em 06/09/2026: **65,6 s** com o serviço dormindo,
 * **0,84 s** acordado. Uma tentativa anterior nem completou em 100 s — o cold
 * start passa de um minuto e meio quando a Render está lenta para alocar.
 *
 * Timeout generoso porque errar para menos ESCONDE o sucesso: a requisição já
 * chegou à Render e já disparou o boot: abortar do lado do cliente não cancela
 * isso. O serviço acorda de qualquer forma; só o log diria que falhou.
 */
const TIMEOUT_MS = 150_000;

async function acorda(alvo) {
  const inicio = Date.now();

  try {
    const resposta = await fetch(alvo, {
      // cache: "no-store" porque um 200 vindo do cache da borda não seria
      // tráfego chegando à Render — e é o tráfego que impede o desligamento.
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "User-Agent": "cyberaudit-keepalive/1.0" },
    });

    const ms = Date.now() - inicio;
    // Corte em 10s: acordado a produção responde em ~0,8s e dormindo em ~65s.
    // A distância é de quase cem vezes, então qualquer valor no meio separa os
    // dois casos sem ambiguidade. É o dado que diz se a janela de horários está
    // cobrindo o uso real ou deixando buracos.
    return {
      ok: resposta.ok,
      status: resposta.status,
      ms,
      acordouAgora: ms > 10_000,
    };
  } catch (erro) {
    // Falha aqui NÃO significa que o serviço continuou dormindo: a requisição
    // já chegou à Render e o boot já começou. O próximo ping pega ele de pé.
    return { ok: false, status: 0, ms: Date.now() - inicio, erro: String(erro) };
  }
}

export default {
  async scheduled(event, env, ctx) {
    // waitUntil mantém o Worker vivo durante a espera. Sem ele, o runtime pode
    // encerrar a invocação antes de a Render terminar de subir — o ping sairia,
    // mas o resultado nunca apareceria no log, e um cold start falho passaria
    // despercebido.
    ctx.waitUntil(
      acorda(env.ALVO).then((r) => {
        console.log(JSON.stringify({ cron: event.cron, ...r }));
      })
    );
  },

  /**
   * Mesma checagem, sob demanda: abrir a URL do Worker no navegador dispara um
   * ping e mostra o resultado. Serve para conferir a configuração sem esperar o
   * próximo horário — e para medir um cold start de propósito.
   */
  async fetch(request, env) {
    const resultado = await acorda(env.ALVO);
    return new Response(JSON.stringify(resultado, null, 2), {
      status: resultado.ok ? 200 : 503,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  },
};
