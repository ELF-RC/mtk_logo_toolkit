# MTK LOGO ToolKit

[English](README.md) | 中文

一个 Rust 工具链，用于解包、编辑、重新打包和签名 MediaTek（MTK）开机 logo 镜像。利用 CERT2 证书验证漏洞（CVE-2023-20696 / CVE-2025-20730）绕过 logo 分区的签名校验，允许在支持的 MTK 设备上刷入自定义开机 logo。

## 功能

- **解包（unpack）** — 将 `logo.bin` 镜像中的所有 chunk 提取为 PNG 文件（已知分辨率）或 `.rgba` 文件（未知分辨率）
- **打包（pack）** — 从编辑后的 PNG/BMP/JPEG/GIF/TGA/PNM/WebP 文件重建 logo 镜像，自动适配分辨率
- **注入（install）** — 注入伪造 CERT2 证书以绕过签名验证（支持传统和现代两种模式）
- **构建（build）** — 打包 + 注入一步完成，直接产出可刷入的镜像
- **验证（verify）** — 自动检测并验证注入的证书和哈希值

### 支持的绕过模式

| 模式 | CVE | 参数 | 原理 |
|------|-----|------|------|
| **传统模式**（默认） | CVE-2023-20696 | *（无）* | 在 CERT2 blob 前添加 `BIT_STRING(原始DER) + 0xA0(哈希覆盖)`。旧版 libsec（`bypass_mode=1`）进入 BIT STRING payload 查找原始 `0x30` SEQUENCE。 |
| **现代模式** | CVE-2025-20730 | `--modern` | 在原始 CERT2 DER 前添加 `0xA0(哈希覆盖)` 作为顶层 sibling。新版 libsec 直接读取覆盖块。 |

两种模式均为**幂等操作** — 对已签名的镜像重复执行 `install` 会先剥离旧注入再重新注入。

### 支持的图片格式

| 输入（打包时） | 输出（解包时） |
|---|---|
| PNG、JPEG、BMP、GIF、TGA、PNM、WebP、RGBA | PNG（已知分辨率）、`.rgba`（未知分辨率） |

所有像素数据以 **BGRA32**（每像素 4 字节）格式处理，与新版 MTK 设备使用的格式一致。任意分辨率的输入图片会自动居中裁剪和/或不透明黑边填充以适配目标 chunk 尺寸 — **不进行缩放**。

## 编译

```bash
cargo build --release
```

编译产物位于 `target/release/mtk-logo-toolkit`。

## 用法

### 解包

从 logo 镜像中提取所有 chunk：

```bash
mtk-logo-toolkit unpack logo.bin -o 输出目录/
```

文件命名为 `NN_WxH.png`（如 `14_57x64.png`），其中 `NN` 为 chunk 索引号。

### 打包

从编辑后的图片重建 logo 镜像：

```bash
mtk-logo-toolkit pack 输出目录/ logo.bin -o logo.packed.bin
```

仅匹配 `NN_*.ext` 的文件用作替换。未提供替换文件的 chunk 保留模板中的原始数据。

### 注入

注入伪造证书（默认传统模式）：

```bash
mtk-logo-toolkit install logo.bin -o logo.signed.bin
```

现代模式：

```bash
mtk-logo-toolkit install logo.bin --modern -o logo.signed.bin
```

### 构建（一步完成）

打包 + 注入一步完成：

```bash
mtk-logo-toolkit build 输出目录/ logo.bin -o logo.signed.bin
```

使用现代绕过：

```bash
mtk-logo-toolkit build 输出目录/ logo.bin --modern -o logo.signed.bin
```

### 验证

自动检测并验证注入的证书：

```bash
mtk-logo-toolkit verify logo.signed.bin
```

## 项目结构

```
src/
├── main.rs          — CLI 入口（clap derive）
├── part_header.rs   — part_hdr_t 二进制格式解析与重打包
├── asn1_der.rs     — ASN.1 DER TLV 编解码（纯 Rust 实现）
├── image_codec.rs   — 图像加载、PNG 写入、BGRA↔RGBA 转换、zlib 压缩、分辨率适配
├── logo_payload.rs  — Logo payload 解包/打包操作
└── cert_inject.rs   — CERT2 伪造证书注入与验证
```

## 技术细节

### 镜像结构

一个 `logo.bin` 文件是 `part_hdr_t` 分区的线性链。每个分区以 512 字节头部（magic `0x58881688`）开始，后跟分区数据，按对齐边界填充。典型镜像包含三个分区：

| 分区 | 内容 | `img_type` |
|------|------|------------|
| `logo` | zlib 压缩的 logo 数据块（BGRA32 像素数据） | `0x00000000` |
| `cert1` | ASN.1 DER 证书（RSA-PSS 签名） | `0x02000000` |
| `cert2` | ASN.1 DER 证书（镜像哈希 + 签名） | `0x02000002` |

### Logo Payload 结构

`logo` 分区的数据内部布局如下：

```
[count: u32] [total: u32] [offsets: u32 × count] [zlib BGRA 数据块...]
```

- **`count`**（u32 LE）— logo chunk 数量
- **`total`**（u32 LE）— payload 总大小（头部 + 所有 chunk 数据）
- **`offsets[N]`**（每个 u32 LE）— 各 chunk 在 payload 中的字节偏移
- **`chunk[i]`** — 一个 zlib 流，解压后为 `W × H × 4` 字节的 BGRA 像素数据

### 色彩模式：BGRA32

所有像素数据以 **BGRA32** 格式（每像素 4 字节）存储：Blue、Green、Red、Alpha 各 8 位。这是新版 MTK 引导程序（MT6765 及更新）使用的原生格式。

> **注意：** 旧版 MTK 设备（MT6580/MT6739 及更早）使用 **RGB565** 格式（每像素 2 字节，R5G6B5）。本工具目前不支持 RGB565。

### 压缩：zlib Level 9

每个 logo chunk 独立使用 **zlib deflate level 9**（最高压缩率）压缩，与标准 MTK 构建流程（`zpipe -l 9`）一致。由于 logo 图像以纯色背景和简单图形为主，压缩率极高 — 通常在 2% 以下。

### 分辨率适配

当输入图片的分辨率与目标 chunk 不匹配时，使用**居中裁剪 + 黑边填充**方式适配（不进行缩放）：

1. 将源图片解码为 RGBA
2. 如果大于目标尺寸：居中裁剪至 `目标宽 × 目标高`
3. 如果小于目标尺寸：放在 `目标宽 × 目标高` 的画布中央，四周填充不透明黑色（B=0, G=0, R=0, A=255）
4. 将 RGBA 转为 BGRA 并压缩

这保证了每个 chunk 解压后的大小严格等于 `目标宽 × 目标高 × 4`。

### CERT2 绕过原理

CERT2 blob 是一个 ASN.1 DER 编码的证书，包含镜像头哈希和镜像内容哈希字段（由 OID `2.16.886.2454.2.4` 和 `2.16.886.2454.2.1` 标识）。注入操作在原始 DER 前添加一个构造的 `0xA0` 块，其中包含 OID + BIT STRING 对，值为当前镜像内容重新计算的哈希，使 preloader 的 DER 解析器读取注入的哈希而非原始哈希。

## 已知分辨率

| 字节数 | 分辨率 | 用途 |
|--------|--------|------|
| 18,432,000 | 1440×3200 | QHD+ 手机 |
| 17,971,200 | 1440×3120 | QHD+ 手机 |
| 17,510,400 | 1440×3040 | QHD+ 手机 |
| 17,049,600 | 1440×2960 | QHD+ 手机 |
| 16,588,800 | 1440×2880 | QHD+ 手机 |
| 14,745,600 | 1440×2560 | QHD 手机 |
| 10,886,400 | 1080×2520 | FHD+ 手机 |
| 10,368,000 | 1080×2400 | FHD+ 手机 |
| 10,108,800 | 1080×2340 | FHD+ 手机 |
| 9,849,600 | 1080×2280 | FHD+ 手机 |
| 9,331,200 | 1080×2160 | FHD+ 手机 |
| 8,294,400 | 1080×1920 | FHD 手机 |
| 4,608,000 | 720×1600 | HD+ 手机 |
| 4,492,800 | 720×1560 | HD+ 手机 |
| 4,377,600 | 720×1520 | HD+ 手机 |
| 4,147,200 | 720×1440 | HD+ 手机 |
| 3,686,400 | 720×1280 | HD 手机 |
| 249,200 | 178×350 | 开机 logo |
| 49,444 | 263×47 | Fastboot logo |
| 36,864 | 72×128 | 小图标 |
| 14,592 | 57×64 | 中图标 |
| 11,520 | 45×64 | 小图标 |
| 2,104 | 263×2 | 进度条 |

## 致谢

- [pwnage24mtk](https://github.com/kasnria001/pwnage24mtk) — CERT2 注入逻辑启发（独立 Rust 重写）
- [cannon_logo_maker](https://github.com/ELF-RC/mtk_logo_toolkit/tree/stop-maintenance) — Logo 解包/打包管线（同一作者，前代 Python 项目）

详见 [NOTICE](NOTICE)。

## 许可证

Copyright (C) 2025 ELF-RC。基于 GNU General Public License v3.0 或更高版本授权。完整许可证文本见 [COPYING](COPYING)。