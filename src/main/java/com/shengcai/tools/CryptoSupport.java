package com.shengcai.tools;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.regex.Pattern;

/** 与本次 DEX 样本对应的密码参数。书籍 key/iv 始终由调用者提供。 */
final class CryptoSupport {
    // classes4.dex: com.shengcai.util.RSAResquest.g / h
    private static final byte[] RESPONSE_KEY = "1a2s3d%*".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_IV = "%*1a2s3d".getBytes(StandardCharsets.UTF_8);
    private static final Pattern HTML_TAG = Pattern.compile("<(?:html|body)(?:\\s|>)", Pattern.CASE_INSENSITIVE);

    private CryptoSupport() { }

    static String readResponseArgument(String argument) throws IOException {
        final int limit = 8 * 1024 * 1024;
        if ("-".equals(argument)) {
            return utf8(readLimited(System.in, limit));
        }
        if (argument.startsWith("@")) {
            try (InputStream in = Files.newInputStream(Paths.get(argument.substring(1)))) {
                return utf8(readLimited(in, limit));
            }
        }
        return argument;
    }

    static String decryptResponse(String base64) throws GeneralSecurityException, IOException {
        // 允许抓包文本中的换行、空格和 UTF-8 BOM；其他非法字符会明确报错。
        String normalized = base64.replace("\uFEFF", "").replaceAll("\\s+", "");
        byte[] encrypted;
        try {
            encrypted = Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("响应不是有效的 Base64；请只传入 HTTP 响应体。", e);
        }
        if (encrypted.length == 0 || encrypted.length % 8 != 0) {
            throw new IllegalArgumentException("DES 密文长度必须为非零的 8 字节整数倍。");
        }
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(RESPONSE_KEY)),
                new IvParameterSpec(RESPONSE_IV));
        return utf8(cipher.doFinal(encrypted));
    }

    static byte[] decryptChapter(byte[] encrypted, byte[] key, byte[] iv)
            throws GeneralSecurityException {
        if (encrypted.length == 0 || encrypted.length % 16 != 0) {
            throw new IllegalArgumentException("章节密文长度不是非零的 16 字节整数倍。");
        }
        // Android 写 PKCS7Padding；标准 JDK 的 AES/PKCS5Padding 实现相同的 16 字节填充。
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    static boolean looksLikeHtml(byte[] bytes) {
        try {
            return HTML_TAG.matcher(utf8(bytes)).find();
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    static String utf8(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
    }

    static byte[] readLimited(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) != -1) {
            if (n > limit - out.size()) {
                throw new IOException("单个输入超过 " + limit + " 字节限制。");
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
