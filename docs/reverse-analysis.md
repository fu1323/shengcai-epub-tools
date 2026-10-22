# 圣才 Android EPUB 解密逆向分析笔记

分析日期：2026-10-22。依据：本次提供的 5 个 DEX、`libtobEmbedEncrypt.so`、EPUB 和抓包响应。结论针对这些样本；没有向服务端发送请求。

## 1. 最终结论

下载文件是普通 EPUB/ZIP，里面的部分 HTML 另行使用 AES-CBC 加密。App 从目录文件中取得 token，向 `GetKey` 接口请求书籍 key/iv；响应本身使用固定 DES 密钥加密。响应解开后，再用其中的 AES key/iv 解章节。

本次抓包和书籍匹配：47 个加密 HTML 全部解密成功。业务调用链在 DEX 中可以闭合，不需要调用提供的 `libtobEmbedEncrypt.so`。这不表示整个 App 都未使用该 SO，也不限定系统 JCE Provider 的底层实现语言。

## 2. 三组对称密钥分别藏在哪里

| 用途 | 位置 | Key | IV | 输入格式 |
| --- | --- | --- | --- | --- |
| 接口响应解密 | `classes4.dex` → `com.shengcai.util.RSAResquest.g / h` | `1a2s3d%*` | `%*1a2s3d` | Base64 文本 → DES 密文 |
| 当前书籍章节解密 | `GetKey` 返回 JSON → `BookUtil.R()` 局部变量；也可能来自本地缓存 | `dc891b08f0344a0b` | `11fbce122f994c93` | HTML 条目的原始字节 |
| App 固定本地缓存 | `classes4.dex` → `com.shengcai.util.BookUtil.e / f` | `1a2s3d%*1a2s3d%*` | `%*1a2s3d%*1a2s3d` | Base64 文本 → AES 密文 |

表中的值全部按字符串字节使用。响应 key/iv 各 8 字节；当前书籍与固定缓存的 key/iv 各 16 字节。IV 是初始化向量，与 key 是不同参数。

**响应密钥直接写在 DEX 的静态字符串字段里。书籍密钥由服务器下发，不是拿响应密钥重复两遍就能得到。** 重复两遍得到的固定 AES 参数只用于另一条缓存分支。当前书籍密钥看起来像十六进制字符串，但源码调用 `getBytes("UTF-8")`：例如开头 `dc` 是 `0x64 0x63` 两个字节，不能合并成 `0xdc`。

另有 `RSAResquest.f`，它是请求加密用的 X.509 编码 RSA 公钥。注意 `RSAResquest.f` 与 `BookUtil.f` 属于不同类，后者是缓存 AES 的 IV。客户端 RSA 公钥不是响应 DES 密钥，也不是书籍 AES 密钥。

“动态”在这里指从接口/缓存取得。未分析服务端，不能断言密钥是否按用户变化、定期轮换，或由 token 通过何种算法生成。

## 3. 定位入口：从文件与密码 API 双向追踪

### 3.1 先确认 EPUB 的哪一层加密

原始文件 `a4ce98a1a68647db80dfd18694449721.epub` 大小 8,323,494 字节。

| 检查项 | 结果 | 含义 |
| --- | --- | --- |
| 文件头 | `50 4B 03 04` | ZIP 容器 |
| ZIP 条目数 | 1278 | 可直接列出并读取内容 |
| ZIP 加密标志 | 0 个条目置位 | 当前样本没有 ZIP 层密码保护 |
| `mimetype` | `application/epub+zip`，STORED | 标准 EPUB 类型标记 |
| OPF | `OEBPS/content.opf` | 由 `META-INF/container.xml` 指向 |
| HTML | 47 个 `.html` 为二进制；2 个 `.htm` 为明文 | 加密在部分内容条目内部 |
| 密文长度 | 47 个均为 16 字节整数倍 | 与 AES 分组长度一致，但单凭此不能确定算法 |

两份明文是 `OEBPS/all.htm`、`OEBPS/shidu.htm`。图片、CSS、字体和 XML 元数据也可直接读取。书名为《陈敏恒〈化工原理〉（第4版）笔记和课后习题（含考研真题）详解》。

### 3.2 搜索字符串，再跟踪调用

在 JADX / DEX 字符串中先搜：

```text
AES/CBC/PKCS7Padding
DES/CBC/PKCS5Padding
GetKey
EbookAes
章节内容获取失败
本地解密失败
```

这些字符串把范围收敛到 `BookUtil`、`RSAResquest`、`HttpUtil`、`URL`。再沿 `key` / `iv` 的来源和 `Cipher.doFinal()` 的输入反向跟踪，而不是只找到一个固定字符串就认定它是书籍密钥。

可复现的定向反编译命令（以 JADX 1.5.3 为例）：

```bash
jadx -r --single-class com.shengcai.util.BookUtil --single-class-output BookUtil.java --no-replace-consts classes4.dex
jadx -r --single-class com.shengcai.util.RSAResquest --single-class-output RSAResquest.java --no-replace-consts classes4.dex
jadx -r --single-class com.school.utils.StorageUtil --single-class-output StorageUtil.java --no-replace-consts classes3.dex
```

方法名是样本中保留/混淆后的名称。反编译局部变量名和行号不稳定，复盘时以完整类名、方法、调用指令和字符串常量定位。本次还对关键方法做了 DEX 指令核对。

## 4. 请求书籍密钥

### 4.1 路径和请求体

`classes4.dex` 的 `com.shengcai.util.URL.S5`：

```text
http://service.sc.zzstep.com/EbookAes/Handler.ashx?method=GetKey
```

```http
POST /EbookAes/Handler.ashx?method=GetKey HTTP/1.1
Host: service.sc.zzstep.com
```

发起位置：`BookUtil.R()` → `HttpUtil.k(context, URL.S5, json)`。

加密前的逻辑 JSON：

```json
{
  "token": "从目录文件取得的 token",
  "ebookId": "业务层书籍 ID",
  "userId": "SharedUtil.Z(activity) 返回值",
  "osType": "android_加设备型号"
}
```

`HttpUtil.k()` 使用 `HttpPost`，正文是 `RSAResquest.e(json)` 返回的 Base64 文本。`RSAResquest.e()` 先补上字符串字段 `"des":"1"`，序列化 JSON，再用 `RSAResquest.f` 中的公钥执行 `RSA/ECB/PKCS1Padding`，最后 Base64 编码。实际 HTTP 正文并非上述明文 JSON。

URL 会经过 `ToolsUtil.w3()`。核对 DEX 后，该方法的代理替换针对 `service.100eshu.com`，不会改写当前常量中的 `service.sc.zzstep.com`。运行时流量仍应以抓包为准。

### 4.2 token 的来源

`ToolsUtil.L2(context, ncxPath)` 读取目录文件，通过 Jsoup 查找 `encrypt` 元素并取其文本。本次 `OEBPS/toc.ncx` 包含：

```xml
<encrypt>IZDUYEDtpV3jwnPlu21hK3hM5LPAtLElEUWXfSOZlaRPclIlrAVfRZwtiIynNOwJ</encrypt>
```

它作为请求中的 token 使用，不能直接当作 AES key。NCX 还出现 `dtb:uid=178_0`，但没有证据可将它直接等同于请求的业务 `ebookId`。

## 5. 解接口响应：固定 DES

定位：`classes4.dex` → `com.shengcai.util.RSAResquest`。

字段与方法核心代码（整理自反编译结果）：

```java
public static String g = "1a2s3d%*";
public static String h = "%*1a2s3d";

// b(byte[] responseBody)
byte[] ciphertext = Base64.decode(responseBody, 2);
SecretKey secretKey = c(g); // DESKeySpec + SecretKeyFactory.getInstance("DES")
Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(h.getBytes()));
byte[] plaintext = cipher.doFinal(ciphertext);
```

调用方向为 `HttpUtil.k()` 收到 HTTP 200 → `RSAResquest.b()` → 按 UTF-8 解码 JSON。原实现解密异常时会返回原始字节，可能使后面的 JSON 解析错误掩盖真正的密码错误；本工程选择明确报错。

本次抓到的响应：

```text
6/TvC9WFRwnJWb54RId9J8+12eJLEPEhD4kR4NOnDRJXjshp1H3m/PzrEYTmBHFSHa85BwUkum69wnsIwODx7Q==
```

Base64 解码为 64 字节 DES 密文，解密去填充后得到：

```json
{"result":1,"key":"dc891b08f0344a0b","iv":"11fbce122f994c93"}
```

工程对应入口：`ResponseDecryptMain`。固定响应参数位于 `CryptoSupport.RESPONSE_KEY`、`RESPONSE_IV`。

## 6. 解书籍章节：接口返回的 AES key/iv

定位：`classes4.dex` → `com.shengcai.util.BookUtil.R(Activity, String, String, String)`。

四个参数按使用方式分别为 `activity`、`ebookId`、`token`、`chapterPath`。主要逻辑：

1. token 非空时，先通过 `SharedUtil.o0(activity, URL.S5 + ebookId)` 读取已缓存的 JSON。
2. 取 JSON 的 `key` / `iv`。任一为空就请求 `GetKey`。
3. 请求成功后调用 `SharedUtil.T2()` 保存 token/key/iv。
4. 若仍缺 key/iv，返回“查询密钥失败”错误。
5. 读取章节原始字节，用 AES-CBC 解密；转 UTF-8，再调用 `BookUtil.i()` 做渲染前处理。

核心代码：

```java
byte[] ciphertext = FileUtil.c(chapterPath);
SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
cipher.init(Cipher.DECRYPT_MODE, secretKey,
            new IvParameterSpec(iv.getBytes("UTF-8")));
String html = new String(cipher.doFinal(ciphertext), "UTF-8");
```

**这里没有对章节做 Base64 解码。** 是取 ZIP 解压出的原始密文字节。若 token 为空，或者动态 AES 解密抛异常，则代码会尝试 `BookUtil.Q()` 的固定本地缓存分支；但请求密钥失败且 key/iv 为空时，会先返回接口错误。

Android 代码写 `PKCS7Padding`；标准 JDK 中本工程使用 `AES/CBC/PKCS5Padding`。JDK 对 AES 实际按 16 字节分组执行这种填充，两者在本格式中兼容，无需引入 Bouncy Castle。这个兼容性已用真实章节和独立实现逐字节验证。

工程对应入口：`EpubDecryptMain`。逐条读取 ZIP，保留现有明文 HTML，解密其他 HTML，再写入新的 EPUB。它不复现 `BookUtil.i()` 的显示处理，不重写 HTML、OPF 或 NCX。

## 7. 书籍 key/iv 的本地缓存

### 7.1 写入链

```java
// classes4.dex: SharedUtil.T2(context, ebookId, token, key, iv)
StorageUtil.p(context, URL.S5 + ebookId,
    jsonOf(token, key, iv).toString(), true);
```

这里的 `jsonOf` 是说明用伪代码，实际代码使用 `JsonUtil.p(new BaseKeyValue(...), ...)`。

`StorageUtil` 位于 **classes3.dex**，完整类名是 `com.school.utils.StorageUtil`。`p()` 中：

- 缓存文件名前缀是 `MD5Util.e(URL.S5 + ebookId)`，即 UTF-8 的完整 32 位小写 MD5；拼接处不额外加分隔符。
- `true` 分支将 JSON 交给 `BookUtil.b()` 加密，文件名追加 `_encrypt`。
- 写入目录名为 `jR7o6RILzltpcN7r`。

因此通常是：

```text
<external-files-dir>/jR7o6RILzltpcN7r/<md5(URL.S5 + ebookId)>_encrypt
```

常见外部路径形态：

```text
/storage/emulated/0/Android/data/<实际包名>/files/jR7o6RILzltpcN7r/<32位md5>_encrypt
```

代码在外部存储不可用的对应分支改用 `context.getFilesDir()` 下同名子目录。实际根路径和包名需按设备确认。

不要误用 `MD5Util.c()`：它返回中间 16 位；这里用的是 `MD5Util.e()` 的完整 32 位。

### 7.2 缓存内容如何加密

`BookUtil.e / f` 是固定参数：

```java
public static String e = "1a2s3d%*1a2s3d%*";
public static String f = "%*1a2s3d%*1a2s3d";
```

`BookUtil.b()`：JSON UTF-8 → AES/CBC/PKCS5Padding → Base64 文本。

`BookUtil.Q()`：Base64 解码 → AES/CBC/PKCS5Padding → UTF-8。

读取链为 `SharedUtil.o0()` → `StorageUtil.g()` → `StorageUtil.i(..., true)` → `BookUtil.Q()`。`StorageUtil.g()` 会先查没有 `_encrypt` 后缀的明文缓存，找不到再查带后缀的加密缓存。

缓存解开后的内容形如：

```json
{"token":"...","key":"dc891b08f0344a0b","iv":"11fbce122f994c93"}
```

所以书籍密钥在网络响应中出现，也会以加密缓存形式落盘；缓存的保护参数本身仍在 DEX 中。

## 8. 容易误判的线索

| 线索 | 实际作用 / 边界 |
| --- | --- |
| `libtobEmbedEncrypt.so` | 提供 `com.byakv.z.TTEncryptUtils` 相关 JNI 接口；本次 EPUB 解密调用链没有用它 |
| `ZipUitl.b()` 中的 `shengcai123` | ZIP 密码分支中的字符串；当前样本没有 ZIP 加密，不能把它当章节 AES 密钥 |
| `BookUtil.e/f` 固定 AES 参数 | 用于缓存及对应本地读取分支；不是当前下载章节的 key/iv |
| `toc.ncx` 的 `<encrypt>` | 获取密钥请求的 token；不是直接用于 `SecretKeySpec` 的值 |
| `RSAResquest.f` | 出站请求的 RSA 公钥；不是对响应或 EPUB 使用的对称密钥 |
| 下载完成即“解密整书” | 代码主要在读章节时解密；下载器写入字节与 ZIP 解压本身不是章节 AES 解密 |

`BookUtil.d()` 还会对符合条件的明文 `<body>` 加入 `<confound>` 内容和隐藏样式，再用固定 AES 参数保存。因此从 App 私有缓存取得的文件，可能与原始下载 EPUB 的章节格式不同。本次 Java 解书入口面向原始 EPUB，不自动猜测或混用缓存格式。

## 9. 本次复现验证

使用提供的真实响应、原始 EPUB，在 OpenJDK 17.0.20 上运行工程；编译使用 `--release 8`。

| 验证 | 结果 |
| --- | --- |
| 响应以命令行字符串、`@文件`、标准输入三种方式输入 | 均得到相同 JSON |
| 真实 EPUB 解密 | 47 个 HTML 成功，2 个现有明文 HTML 保留 |
| 独立 Python AES 实现交叉验证 | 47 份 Java 输出与独立解密结果逐字节相同 |
| 未改动条目 | 1231 个条目未压缩内容逐字节相同 |
| ZIP 校验 | 条目名称/顺序一致、CRC 通过、mimetype 为首条 STORED 且无 extra |
| 错误书籍 key | 报错、没有生成目标 EPUB、清理临时文件 |
| 已有输出文件 | 拒绝覆盖，已有文件哈希不变 |
| 非法 Base64 响应 | 明确失败 |

本次没有执行服务端请求、EPUBCheck 或阅读器视觉检查。填充/UTF-8/HTML 检查有助于发现错密钥，但 CBC 本身没有完整性认证，不能把这些检查当作 MAC 或签名。

## 10. 以后复盘的操作顺序

1. 先检查容器结构，分清 ZIP 密码、条目内部密文、Base64 缓存。
2. 全 DEX 搜密码 API 和业务错误文本，定位实际解密方法。
3. 对 `Cipher.init()` 的 key/iv 逐层追来源，确认是常量、服务端返回还是本地缓存。
4. 对 `doFinal()` 输入追读取方式，确认原始字节或 Base64；对 `getBytes()` 确认编码。
5. 跟到请求 URL、请求体包装和响应解码，不把请求 RSA 与响应 DES 混淆。
6. 用一份真实响应和真实章节验证，再扩展至全部条目；对未改内容做字节比较。
7. 将实测结果与未验证事项分开记录，保留样本哈希便于对应版本。

## 附：样本 SHA-256

```text
a4ce98a1a68647db80dfd18694449721.epub
2cd8c88351eea73164e5ed369a86087ad0733cc74fbea3f519c05c984adb4d07

classes(1).dex
69a8981554696d1708479f12b3d2be2b64d06712e25bdba7f5cbd6e045c96c87

classes2.dex
b71a7527ef8e23a90b9c15b0d4f85fa64f6843ee2d040529a752ed94f2b5aaf4

classes3.dex
4082b47eb925d95168e40d176d9798ea929b831e51f3c062a33f19650c191d71

classes4.dex
0202e7687bb61188127ce036abcfe75e3195e74844f4d62e16541b2c9fc76dfc

classes5.dex
67835ae69062b694f120ad0ae68570ff6f0d490411729a73b37c0bf1047eb626

libtobEmbedEncrypt.so
a8c580843b9cf8c4e93e2d1088b021b9b697792e081e374026414686f4795e43
```
