package com.joao.cyberaudit.model;

import com.joao.cyberaudit.service.ScanProgress;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class AsyncScanStatus {

    public enum State { PENDING, RUNNING, DONE, ERROR }

    private String scanId;
    private State state;
    private ScanResult result;
    private String errorMessage;

    /**
     * Código estruturado do erro, quando há um (ex.: "OWNERSHIP_REQUIRED"). Sem isto
     * o cliente só tinha o texto livre de errorMessage para decidir se mostra o card
     * de verificação de posse ou um erro genérico — e o polling nunca checava esse
     * texto, então o card nunca aparecia para erros que só acontecem dentro do scan
     * assíncrono (ownership ao vivo, ver ScanOrchestrator).
     */
    private String errorCode;

    /** Host a que errorCode se refere, quando aplicável (ex.: para pré-preencher o card). */
    private String errorHost;

    /**
     * As verificações e o estado de cada uma agora.
     *
     * Preenchida na LEITURA, não guardada com o resto: os rótulos são traduzidos no
     * locale de quem perguntou, e o estado muda a cada instante. Ver
     * {@link ScanProgress#instantaneo()}.
     */
    private List<ScanProgress.Etapa> progress;

    public AsyncScanStatus(String scanId, State state, ScanResult result, String errorMessage) {
        this(scanId, state, result, errorMessage, null, null, List.of());
    }

    public AsyncScanStatus(String scanId, State state, ScanResult result, String errorMessage,
                           String errorCode, String errorHost) {
        this(scanId, state, result, errorMessage, errorCode, errorHost, List.of());
    }
}
