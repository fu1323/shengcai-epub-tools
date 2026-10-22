package com.shengcai.tools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/** 入口一：Base64 响应体 -> DES 解密 -> UTF-8 JSON。 */
public final class ResponseDecryptMain {
    private ResponseDecryptMain() { }

    public static void main(String[] args) {
        if (args.length == 1 && "--help".equals(args[0])) {
            usage();
            return;
        }
        if (args.length < 1 || args.length > 2) {
            usage();
            System.exit(2);
        }
        try {
            String plain = CryptoSupport.decryptResponse(CryptoSupport.readResponseArgument(args[0]));
            if (args.length == 2) {
                Files.write(Paths.get(args[1]), plain.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            }
            // 显式 UTF-8，保证重定向输出到文件时也使用 UTF-8。
            System.out.write(plain.getBytes(StandardCharsets.UTF_8));
            System.out.write('\n');
            System.out.flush();
        } catch (Exception e) {
            System.err.println("响应解密失败: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.err.println("用法: java -cp <jar或classes目录> com.shengcai.tools.ResponseDecryptMain <Base64|@文件|-> [输出.json]");
        System.err.println("- 从标准输入读取；@文件 读取 UTF-8 响应体；输出文件已存在时拒绝覆盖。");
    }
}
