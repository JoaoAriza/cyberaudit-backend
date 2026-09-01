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
     * As verificações e o estado de cada uma agora.
     *
     * Preenchida na LEITURA, não guardada com o resto: os rótulos são traduzidos no
     * locale de quem perguntou, e o estado muda a cada instante. Ver
     * {@link ScanProgress#instantaneo()}.
     */
    private List<ScanProgress.Etapa> progress;

    public AsyncScanStatus(String scanId, State state, ScanResult result, String errorMessage) {
        this(scanId, state, result, errorMessage, List.of());
    }
}
