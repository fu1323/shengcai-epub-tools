# 某才 EPUB 解密复现工程
# 尊重版权 严禁滥用 本文为学习安卓逆向而做，感谢ChatGPT
两个 `main`，对应两项独立操作：

| 入口类 | 输入 | 输出 |
| --- | --- | --- |
| `com.shengcai.tools.ResponseDecryptMain` | 抓到的 Base64 响应体 | 解密后的 UTF-8 JSON |
| `com.shengcai.tools.EpubDecryptMain` | 原始 EPUB、书籍 key、iv | 解密章节后的新 EPUB |


## 1. 直接运行随附 JAR

进入解压后的 `shengcai-epub-tools` 目录。以下命令均从该目录执行。

### 解响应

```bash
```

输出：

```json
{"result":1,"key":"dc891b08f0344a0b","iv":"11fbce122f994c93"}
```

也可以从文件读取；加第二个参数会同时保存 JSON：

```bash
```

或者从标准输入读取：

```bash
```

传入完整 HTTP 响应的**正文**，不要混入状态行、请求头或 JSON 引号。允许 Base64 中有空格、换行和 BOM。输出文件存在时拒绝覆盖。

### 解书

将原始 EPUB 放在工程目录，或使用它的绝对路径：

```bash
```

路径含空格时，加双引号。上面这组 key/iv 对应本次提供的书；换书时应传入相应响应解出的值。

预期统计：

```text
ZIP 条目: 1278，解密 HTML: 47，原有明文 HTML: 2
```

`key`、`iv` 都直接按 UTF-8 字符串转字节。当前各为 16 字节，**不要按十六进制解码**。章节是原始二进制密文，也不要先对章节做 Base64 解码。

## 2. 在 IntelliJ IDEA 中运行

1. 打开工程目录或 `pom.xml`，选一个 JDK。
2. 打开 `ResponseDecryptMain.java`，运行配置的 Program arguments 填入 `@examples/response.b64`，Working directory 设为工程目录。
3. 打开 `EpubDecryptMain.java`，Program arguments 填入 `输入.epub 输出.epub key iv`。

工程中恰好这两个类包含 `public static void main(String[] args)`。`CryptoSupport` 是共用辅助类。

## 3. 从源码编译

macOS / Linux：

```bash
sh build.sh
```

Windows：

```bat
build.cmd
```

两者都会生成 `target/shengcai-epub-tools-1.0.0.jar`。也可以使用标准 Maven 工程构建：

```bash
mvn package
```

Maven 首次运行可能需要下载自身的构建插件；`build.sh` / `build.cmd` 只调用本地 JDK。

## 4. 解书程序的行为

- 识别 `.html`、`.htm`、`.xhtml`，已有 UTF-8 HTML 原样保留，其余按指定 AES key/iv 解密。
- 对解密结果检查填充、UTF-8 和 HTML 标记。任一章节失败就终止，删除临时输出。
- 保留 ZIP 条目名称；图片、CSS、字体、OPF、NCX 等未压缩内容原样复制。
- `mimetype` 放在首条，使用 STORED，不附加 extra 字段。其他条目可能重新压缩，因此新旧 EPUB 的整体哈希会不同。
- 目标文件已存在时拒绝覆盖。程序不会修改输入 EPUB。
- 图片等资源流式复制；一次最多读取一个章节，单章上限 64 MiB。

此入口处理本次定位的“普通 ZIP 容器 + 章节原始 AES 密文”格式。App 私有目录里的固定密钥 Base64 缓存、ZIP 密码保护或其他 EPUB 加密格式不属于该入口支持范围。

程序保留 NCX 中的自定义 `<encrypt>` 标签和原有 OPF/HTML 内容，不做排版、目录或 EPUB 标准兼容性修复，也不执行 App 的 `BookUtil.i()` 渲染前处理。复包和解密成功不等同于通过 EPUBCheck；本次未做阅读器视觉测试。

## 5. 密钥位置与复盘

详细说明见 [docs/reverse-analysis.md](README.md)。要点：

- 响应 DES key/iv：`classes4.dex` 的 `com.shengcai.util.RSAResquest.g/h`，硬编码字符串。
- 书籍 AES key/iv：`GetKey` 响应中的 `key` / `iv`；`BookUtil.R()` 取出使用。
- 固定缓存 AES key/iv：`classes4.dex` 的 `BookUtil.e/f`，用于缓存，不能代替当前书籍的动态密钥。
- 当前 EPUB 业务解密链不需要 `libtobEmbedEncrypt.so`。

工程包含抓包测试向量和预编译 JAR，不包含原始 DEX、SO 或整本书。
