package com.joao.cyberaudit.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Política mínima de senha, aplicada em TODO caminho que cria credencial.
 *
 * O mínimo de 8 caracteres existia só no auto-registro: o setup do primeiro
 * OWNER e o aceite de convite aceitavam qualquer coisa, inclusive senha de um
 * caractere — justamente nas contas com mais privilégio.
 */
public final class PasswordPolicy {

    private PasswordPolicy() {}

    public static final int MIN_LENGTH = 8;

    /**
     * BCrypt ignora tudo além de 72 bytes; aceitar entrada ilimitada só serve para
     * gastar CPU de hash à toa.
     */
    public static final int MAX_LENGTH = 128;

    /**
     * Nome e e-mail não tinham teto: acima de 255 chars a inserção estourava na
     * coluna e o cliente recebia um 500 em vez de um 400 claro.
     */
    public static void validateIdentity(String name, String email) {
        if (name != null && name.strip().length() > 120) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nome muito longo. Máximo 120 caracteres.");
        }
        if (email != null && email.strip().length() > 254) {
            // 254 é o limite prático de endereço de e-mail (RFC 5321).
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "E-mail muito longo. Máximo 254 caracteres.");
        }
    }

    public static void validate(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Senha deve ter pelo menos " + MIN_LENGTH + " caracteres.");
        }
        if (password.length() > MAX_LENGTH) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Senha deve ter no máximo " + MAX_LENGTH + " caracteres.");
        }
        if (password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Senha não pode ser composta apenas de espaços.");
        }
    }
}
