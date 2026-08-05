package com.joao.cyberaudit.service;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.Iterator;
import java.util.Optional;

/**
 * Validação do logo de marca antes de ele chegar ao PDFBox.
 *
 * O único limite existente era o tamanho da string base64 (280 KB). Isso não
 * impede uma **bomba de descompressão**: um PNG de poucos KB pode declarar
 * 50000×50000 px e, ao ser decodificado para bitmap na geração do relatório,
 * pedir dezenas de GB de heap. Como o logo é gravado uma vez e usado em toda
 * exportação de PDF da conta, bastaria um PUT para derrubar o processo a cada
 * relatório gerado.
 *
 * A checagem lê só o CABEÇALHO da imagem (ImageReader.getWidth/getHeight não
 * decodificam os pixels), então é barata.
 */
public final class BrandLogoValidator {

    private BrandLogoValidator() {}

    /** ~200 KB de imagem depois do base64. */
    public static final int MAX_BASE64_LENGTH = 280_000;

    /** Teto de bytes da imagem decodificada. */
    public static final int MAX_DECODED_BYTES = 220_000;

    /** Um logo de cabeçalho de relatório não precisa passar disso. */
    public static final int MAX_DIMENSION = 4_000;

    /** Total de pixels — barra formatos "finos e compridos" (ex.: 1×50.000.000). */
    public static final long MAX_PIXELS = 8_000_000L;

    public record Result(boolean valid, String reason, byte[] bytes) {
        static Result ok(byte[] bytes)     { return new Result(true, null, bytes); }
        static Result fail(String reason)  { return new Result(false, reason, null); }
    }

    /**
     * Decodifica e valida um logo em base64 (com ou sem prefixo data URI).
     * Nunca lança — devolve o motivo da recusa para o chamador decidir.
     */
    public static Result validate(String base64) {
        if (base64 == null || base64.isBlank()) {
            return Result.ok(null); // limpar o logo é válido
        }
        if (base64.length() > MAX_BASE64_LENGTH) {
            return Result.fail("Logo muito grande. Máximo 200 KB após base64.");
        }

        String payload = base64;
        int comma = payload.indexOf(',');
        if (payload.startsWith("data:") && comma > 0) {
            payload = payload.substring(comma + 1);
        }

        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(payload.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            return Result.fail("Logo inválido: conteúdo não é base64 válido.");
        }

        if (bytes.length == 0)                  return Result.fail("Logo vazio.");
        if (bytes.length > MAX_DECODED_BYTES)   return Result.fail("Logo muito grande. Máximo 200 KB.");
        if (!isPngOrJpeg(bytes))                return Result.fail("Logo inválido: use PNG ou JPEG.");

        Optional<int[]> dimensions = readDimensions(bytes);
        if (dimensions.isEmpty()) {
            return Result.fail("Logo inválido: não foi possível ler a imagem.");
        }
        int width = dimensions.get()[0], height = dimensions.get()[1];
        if (width <= 0 || height <= 0) {
            return Result.fail("Logo inválido: dimensões inconsistentes.");
        }
        if (width > MAX_DIMENSION || height > MAX_DIMENSION
                || (long) width * height > MAX_PIXELS) {
            return Result.fail("Logo com dimensões excessivas (" + width + "x" + height
                    + "). Máximo " + MAX_DIMENSION + "x" + MAX_DIMENSION + " px.");
        }

        return Result.ok(bytes);
    }

    /** Assinatura de arquivo — não confia na extensão nem no prefixo data URI. */
    private static boolean isPngOrJpeg(byte[] b) {
        if (b.length >= 8
                && (b[0] & 0xFF) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G'
                && (b[4] & 0xFF) == 0x0D && (b[5] & 0xFF) == 0x0A
                && (b[6] & 0xFF) == 0x1A && (b[7] & 0xFF) == 0x0A) {
            return true;
        }
        return b.length >= 3
                && (b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF;
    }

    /** Lê largura/altura do cabeçalho, sem decodificar os pixels. */
    private static Optional<int[]> readDimensions(byte[] bytes) {
        try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            if (in == null) return Optional.empty();
            Iterator<ImageReader> readers = ImageIO.getImageReaders(in);
            if (!readers.hasNext()) return Optional.empty();

            ImageReader reader = readers.next();
            try {
                reader.setInput(in);
                return Optional.of(new int[]{ reader.getWidth(0), reader.getHeight(0) });
            } finally {
                reader.dispose();
            }
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
