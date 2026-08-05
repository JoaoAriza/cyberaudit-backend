package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrandLogoValidatorTest {

    private static String pngBase64(int width, int height) throws Exception {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    @Test
    @DisplayName("PNG pequeno é aceito e devolve os bytes decodificados")
    void aceitaPngPequeno() throws Exception {
        var result = BrandLogoValidator.validate(pngBase64(200, 80));

        assertTrue(result.valid(), result.reason());
        assertNotNull(result.bytes());
    }

    @Test
    @DisplayName("aceita prefixo data URI")
    void aceitaDataUri() throws Exception {
        var result = BrandLogoValidator.validate("data:image/png;base64," + pngBase64(120, 60));

        assertTrue(result.valid(), result.reason());
    }

    @Test
    @DisplayName("logo vazio/nulo é válido — significa limpar a marca")
    void vazioLimpaLogo() {
        assertTrue(BrandLogoValidator.validate(null).valid());
        assertTrue(BrandLogoValidator.validate("").valid());
        assertNull(BrandLogoValidator.validate(null).bytes());
    }

    /**
     * PNG mínimo (~60 bytes) cujo IHDR DECLARA dimensões enormes. É a forma real do
     * ataque: o arquivo passa folgado em qualquer limite de tamanho, e só quem lê o
     * cabeçalho percebe que a decodificação pediria dezenas de GB.
     */
    private static String tinyPngDeclaring(int width, int height) {
        byte[] ihdr = new byte[13];
        ihdr[0] = (byte) (width >>> 24);  ihdr[1] = (byte) (width >>> 16);
        ihdr[2] = (byte) (width >>> 8);   ihdr[3] = (byte) width;
        ihdr[4] = (byte) (height >>> 24); ihdr[5] = (byte) (height >>> 16);
        ihdr[6] = (byte) (height >>> 8);  ihdr[7] = (byte) height;
        ihdr[8]  = 8; // bit depth
        ihdr[9]  = 2; // color type: truecolor
        ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

        ByteArrayOutputStream png = new ByteArrayOutputStream();
        png.writeBytes(new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A});
        writeChunk(png, "IHDR", ihdr);
        writeChunk(png, "IEND", new byte[0]);
        return Base64.getEncoder().encodeToString(png.toByteArray());
    }

    private static void writeChunk(ByteArrayOutputStream out, String type, byte[] data) {
        int len = data.length;
        out.writeBytes(new byte[]{
                (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len});
        byte[] typeBytes = type.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        out.writeBytes(typeBytes);
        out.writeBytes(data);

        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(typeBytes);
        crc.update(data);
        long c = crc.getValue();
        out.writeBytes(new byte[]{
                (byte) (c >>> 24), (byte) (c >>> 16), (byte) (c >>> 8), (byte) c});
    }

    @Test
    @DisplayName("bomba de descompressão é recusada pelas dimensões, não pelo tamanho do arquivo")
    void recusaBombaDeDescompressao() {
        // 50000x50000 px = 2,5 bilhões de pixels. Como bitmap RGB, ~7,5 GB de heap.
        String bomb = tinyPngDeclaring(50_000, 50_000);

        assertTrue(bomb.length() < 200,
                "o ataque depende de o arquivo ser minúsculo — aqui tem " + bomb.length() + " chars");

        var result = BrandLogoValidator.validate(bomb);

        assertFalse(result.valid(), "deveria recusar pelas dimensões");
        assertTrue(result.reason().contains("dimensões"), result.reason());
    }

    @Test
    @DisplayName("imagem fina e comprida também é recusada (limite de pixels totais)")
    void recusaImagemFinaEComprida() {
        // 1x50.000.000: nenhuma dimensão passa de MAX_DIMENSION sozinha se olhada
        // isoladamente — quem barra é o teto de pixels totais.
        var result = BrandLogoValidator.validate(tinyPngDeclaring(2, 50_000_000));

        assertFalse(result.valid());
        assertTrue(result.reason().contains("dimensões"), result.reason());
    }

    @Test
    @DisplayName("conteúdo que não é PNG/JPEG é recusado mesmo em base64 válido")
    void recusaNaoImagem() {
        String svg = Base64.getEncoder().encodeToString(
                "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"
                        .getBytes());

        var result = BrandLogoValidator.validate(svg);

        assertFalse(result.valid());
        assertTrue(result.reason().contains("PNG ou JPEG"), result.reason());
    }

    @Test
    @DisplayName("base64 malformado é recusado sem lançar")
    void recusaBase64Invalido() {
        var result = BrandLogoValidator.validate("isto-nao-e-base64!!!###");

        assertFalse(result.valid());
        assertNotNull(result.reason());
    }

    @Test
    @DisplayName("string base64 acima do teto é recusada antes de decodificar")
    void recusaBase64Gigante() {
        var result = BrandLogoValidator.validate("A".repeat(BrandLogoValidator.MAX_BASE64_LENGTH + 1));

        assertFalse(result.valid());
        assertTrue(result.reason().contains("200 KB"), result.reason());
    }
}
