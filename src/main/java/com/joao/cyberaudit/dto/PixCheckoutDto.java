package com.joao.cyberaudit.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.UUID;

/**
 * Resposta de POST /billing/checkout/pix — o front renderiza o QR code (ou usa o
 * copia-e-cola) e faz polling de GET /billing/subscription até o status virar
 * AUTHORIZED (confirmado só pelo webhook de payment, nunca por esta resposta).
 */
@Getter
@Builder
public class PixCheckoutDto {

    private UUID subscriptionId;

    /** id do payment no Mercado Pago — mesmo id que chega no webhook (topic=payment). */
    private String paymentId;

    /** Sempre "pending" na criação — Pix não aprova na hora da chamada. */
    private String status;

    /** Copia-e-cola — string para colar no app do banco. */
    private String qrCode;

    /** Imagem do QR code em base64 (sem o prefixo data:image/...;base64,). */
    private String qrCodeBase64;

    /** Link alternativo para abrir o pagamento fora do app do banco. */
    private String ticketUrl;
}
