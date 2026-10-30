package com.shengcai.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** 入口二：解密 EPUB 中的原始 AES 章节密文，并重打包成新的 EPUB。 */
public final class EpubDecryptMain {
    private static final int MAX_CHAPTER_BYTES = 64 * 1024 * 1024;
    private static final byte[] MIMETYPE = "application/epub+zip".getBytes(StandardCharsets.US_ASCII);

    private EpubDecryptMain() { }

    public static void main(String[] args) {
        args=new String[4];
        args[0]="";//input
        args[1]="";//output
        args[2]="";//key
        args[3]="";//iv




        if (args.length == 1 && "--help".equals(args[0])) {
            usage();
            return;
        }
        if (args.length != 4) {
            usage();
            System.exit(2);
        }
        Path temporary = null;
        try {
            Path input = Paths.get(args[0]).toAbsolutePath().normalize();
            Path output = Paths.get(args[1]).toAbsolutePath().normalize();
            if (!Files.isRegularFile(input)) {
                throw new IOException("输入 EPUB 不存在或不是普通文件: " + input);
            }
            if (input.equals(output) || Files.exists(output)) {
                throw new IOException("请指定一个尚不存在的输出路径；不会覆盖输入或已有文件。");
            }
            byte[] key = args[2].getBytes(StandardCharsets.UTF_8);
            byte[] iv = args[3].getBytes(StandardCharsets.UTF_8);
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw new IllegalArgumentException("AES key 的 UTF-8 字节长度必须为 16、24 或 32；不要做十六进制解码。");
            }
            if (iv.length != 16) {
                throw new IllegalArgumentException("AES IV 的 UTF-8 字节长度必须为 16；不要做十六进制解码。");
            }
            temporary = Files.createTempFile(output.getParent(), ".epub-decrypt-", ".tmp");
            int[] counts = decryptArchive(input, temporary, key, iv);
            // 未指定 REPLACE_EXISTING：如果目标已出现则失败，不覆盖。
            Files.move(temporary, output);
            temporary = null;
            System.out.println("完成: " + output);
            System.out.printf("ZIP 条目: %d，解密 HTML: %d，原有明文 HTML: %d%n", counts[0], counts[1], counts[2]);
            if (counts[1] == 0) {
                System.out.println("未发现需要解密的 HTML；输入可能已经是明文 EPUB。");
            }
        } catch (Exception e) {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException cleanupError) {
                    System.err.println("临时文件清理失败: " + temporary);
                }
            }
            System.err.println("EPUB 解密失败: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    private static int[] decryptArchive(Path input, Path output, byte[] key, byte[] iv) throws Exception {
        int total = 1;
        int decrypted = 0;
        int plain = 0;
        try (ZipFile source = new ZipFile(input.toFile(), StandardCharsets.UTF_8)) {
            ZipEntry originalMime = source.getEntry("mimetype");
            if (originalMime == null) {
                throw new IOException("缺少 mimetype 条目，输入不是预期的 EPUB。");
            }
            try (InputStream in = source.getInputStream(originalMime)) {
                if (!Arrays.equals(CryptoSupport.readLimited(in, 1024), MIMETYPE)) {
                    throw new IOException("mimetype 内容不是 application/epub+zip。");
                }
            }
            try (ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(output), StandardCharsets.UTF_8)) {
                if (source.getComment() != null) {
                    target.setComment(source.getComment());
                }
                // EPUB 要求 mimetype 为首个条目，使用 STORED，不附加 extra 字段。
                writeBytes(target, originalMime, MIMETYPE, true);
                Enumeration<? extends ZipEntry> entries = source.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if ("mimetype".equals(entry.getName())) {
                        continue;
                    }
                    total++;
                    if (!entry.isDirectory() && isHtmlName(entry.getName())) {
                        byte[] bytes;
                        try (InputStream in = source.getInputStream(entry)) {
                            bytes = CryptoSupport.readLimited(in, MAX_CHAPTER_BYTES);
                        }
                        if (CryptoSupport.looksLikeHtml(bytes)) {
                            plain++;
                        } else {
                            try {
                                bytes = CryptoSupport.decryptChapter(bytes, key, iv);
                                if (!CryptoSupport.looksLikeHtml(bytes)) {
                                    throw new IOException("解密结果不是可识别的 UTF-8 HTML。");
                                }
                            } catch (Exception e) {
                                throw new IOException("章节 " + entry.getName()
                                        + " 解密失败，请检查 key/iv 与书籍是否匹配。原因: "
                                        + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                            }
                            decrypted++;
                        }
                        writeBytes(target, entry, bytes, false);
                    } else {
                        // 图片、CSS、字体、OPF、NCX 等直接复制未压缩内容，不整本加载到内存。
                        ZipEntry copied = copyMetadata(entry);
                        if (entry.getMethod() == ZipEntry.STORED) {
                            copied.setSize(entry.getSize());
                            copied.setCompressedSize(entry.getSize());
                            copied.setCrc(entry.getCrc());
                        }
                        target.putNextEntry(copied);
                        try (InputStream in = source.getInputStream(entry)) {
                            transfer(in, target);
                        }
                        target.closeEntry();
                    }
                }
            }
        }
        return new int[] {total, decrypted, plain};
    }

    private static boolean isHtmlName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith(".html") || lower.endsWith(".htm") || lower.endsWith(".xhtml");
    }

    private static ZipEntry copyMetadata(ZipEntry original) {
        ZipEntry result = new ZipEntry(original.getName());
        if (original.getTime() >= 0) {
            result.setTime(original.getTime());
        }
        if (original.getComment() != null) {
            result.setComment(original.getComment());
        }
        result.setMethod(original.getMethod());
        // 不复制原压缩长度或 ZIP64 extra，避免替换内容后留下过期字段。
        return result;
    }

    private static void writeBytes(ZipOutputStream out, ZipEntry original, byte[] bytes, boolean mime)
            throws IOException {
        ZipEntry entry = copyMetadata(original);
        if (mime) {
            entry.setMethod(ZipEntry.STORED);
            // 固定为 ZIP DOS 时间，避免自动生成额外时间字段。
            entry.setTime(315532800000L + 2L * 24 * 60 * 60 * 1000);
        }
        if (entry.getMethod() == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(bytes);
            entry.setSize(bytes.length);
            entry.setCompressedSize(bytes.length);
            entry.setCrc(crc.getValue());
        }
        out.putNextEntry(entry);
        out.write(bytes);
        out.closeEntry();
    }

    private static void transfer(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[32768];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
    }

    private static void usage() {
        System.err.println("用法: java -cp <jar或classes目录> com.shengcai.tools.EpubDecryptMain <输入.epub> <输出.epub> <key字符串> <iv字符串>");
        System.err.println("key/iv 直接按 UTF-8 字符串使用；任一章节失败则终止，不留下不完整的输出 EPUB。");
    }
}
