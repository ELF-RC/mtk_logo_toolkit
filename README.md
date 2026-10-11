# MTK LOGO ToolKit

English | [中文](README_zh.md)

A Rust toolchain for unpacking, editing, repacking, and signing MediaTek (MTK) boot logo images. Exploits the CERT2 certificate verification vulnerability (CVE-2023-20696 / CVE-2025-20730) to bypass signature checks on the logo partition, allowing custom boot logos to be flashed onto supported MTK devices.

## Features

- **Unpack** — Extract all logo chunks from a `logo.bin` image to PNG files (known resolutions) or `.rgba` files (unknown resolutions)
- **Pack** — Rebuild a logo image from edited PNG/BMP/JPEG/GIF/TGA/PNM/WebP files with automatic resolution fitting
- **Install** — Inject a fake CERT2 certificate to bypass signature verification (legacy & modern modes)
- **Build** — Pack + install in one step, producing a ready-to-flash image
- **Verify** — Auto-detect and verify the injected certificate and hash values

### Supported Bypass Modes

| Mode | CVE | Flag | Mechanism |
|------|-----|------|-----------|
| **Legacy** (default) | CVE-2023-20696 | *(none)* | `BIT_STRING(original_DER) + 0xA0(hash_override)` prepended before CERT2 blob. Old libsec (`bypass_mode=1`) enters the BIT STRING payload to find the original `0x30` SEQUENCE. |
| **Modern** | CVE-2025-20730 | `--modern` | `0xA0(hash_override)` prepended as a top-level sibling before the original CERT2 DER. New libsec reads the override block directly. |

Both modes are **idempotent** — re-running `install` on an already-signed image strips the previous injection and re-injects cleanly.

### Supported Image Formats

| Input (pack) | Output (unpack) |
|---|---|
| PNG, JPEG, BMP, GIF, TGA, PNM, WebP, RGBA | PNG (known resolution), `.rgba` (unknown) |

All pixel data is processed as **BGRA32** (4 bytes/pixel), matching the format used by modern MTK devices. Input images of any resolution are automatically center-cropped and/or padded with opaque black to fit the target chunk size — **no scaling**.

## Build

```bash
cargo build --release
```

The binary will be at `target/release/mtk-logo-toolkit`.

## Usage

### Unpack

Extract all chunks from a logo image:

```bash
mtk-logo-toolkit unpack logo.bin -o output_dir/
```

Files are named `NN_WxH.png` (e.g. `14_57x64.png`) where `NN` is the chunk index.

### Pack

Rebuild a logo image from edited chunks:

```bash
mtk-logo-toolkit pack output_dir/ logo.bin -o logo.packed.bin
```

Only files matching `NN_*.ext` are used as replacements. Chunks without a replacement file are kept verbatim from the template.

### Install

Inject a fake certificate (legacy mode by default):

```bash
mtk-logo-toolkit install logo.bin -o logo.signed.bin
```

Modern mode:

```bash
mtk-logo-toolkit install logo.bin --modern -o logo.signed.bin
```

### Build (one-step)

Pack + install in a single command:

```bash
mtk-logo-toolkit build output_dir/ logo.bin -o logo.signed.bin
```

With modern bypass:

```bash
mtk-logo-toolkit build output_dir/ logo.bin --modern -o logo.signed.bin
```

### Verify

Auto-detect and verify the injected certificate:

```bash
mtk-logo-toolkit verify logo.signed.bin
```

## Project Structure

```
src/
├── main.rs          — CLI entry point (clap derive)
├── part_header.rs   — part_hdr_t binary format parsing & rebuilding
├── asn1_der.rs      — ASN.1 DER TLV encoding/decoding (pure Rust)
├── image_codec.rs   — Image loading, PNG writing, BGRA↔RGBA, zlib, fit
├── logo_payload.rs  — Logo payload unpack/pack operations
└── cert_inject.rs   — CERT2 fake certificate injection & verification
```

## Technical Details

### Image Structure

A `logo.bin` file is a linear chain of `part_hdr_t` partitions. Each partition starts with a 512-byte header (magic `0x58881688`) followed by its data, padded to the alignment boundary. A typical image contains three partitions:

| Partition | Content | `img_type` |
|-----------|---------|-------------|
| `logo` | zlib-compressed logo chunks (BGRA32 pixel data) | `0x00000000` |
| `cert1` | ASN.1 DER certificate blob (RSA-PSS signature) | `0x02000000` |
| `cert2` | ASN.1 DER certificate blob (image hashes + signature) | `0x02000002` |

### Logo Payload Structure

The `logo` partition's data has this internal layout:

```
[count: u32] [total: u32] [offsets: u32 × count] [zlib BGRA blocks...]
```

- **`count`** (u32 LE) — number of logo chunks
- **`total`** (u32 LE) — total payload size (header + all chunk data)
- **`offsets[N]`** (u32 LE each) — byte offset of each chunk within the payload
- **`chunk[i]`** — a zlib stream that decompresses to `W × H × 4` bytes of BGRA pixel data

### Color Mode: BGRA32

All pixel data is stored in **BGRA32** format (4 bytes/pixel): Blue, Green, Red, Alpha — each 8 bits. This is the native format used by modern MTK bootloaders (MT6765 and newer).

> **Note:** Older MTK devices (MT6580/MT6739 and earlier) use **RGB565** (2 bytes/pixel, R5G6B5). This tool does not currently support RGB565.

### Compression: zlib Level 9

Each logo chunk is independently compressed with **zlib deflate at level 9** (best compression), matching the standard MTK build pipeline (`zpipe -l 9`). Logo images are highly compressible due to solid-color backgrounds and simple graphics — typical compression ratios are under 2%.

### Resolution Fitting

When an input image does not match the target chunk resolution, it is adapted using **center-crop + black-pad** (no scaling):

1. Decode the source image to RGBA
2. If larger than target: center-crop to `target_w × target_h`
3. If smaller than target: center on a `target_w × target_h` canvas, padded with opaque black (B=0, G=0, R=0, A=255)
4. Convert RGBA → BGRA and compress

This guarantees every chunk's decompressed size is exactly `target_w × target_h × 4`.

### CERT2 Bypass Mechanism

The CERT2 blob is an ASN.1 DER-encoded certificate containing image header hash and image content hash fields (identified by OIDs `2.16.886.2454.2.4` and `2.16.886.2454.2.1`). The injection prepends a crafted `0xA0` block containing OID + BIT STRING pairs with recomputed hashes for the current image content, causing the preloader's DER parser to read the injected hashes instead of the original ones.

## Known Resolutions

| Bytes | Resolution | Use Case |
|-------|------------|-----------|
| 18,432,000 | 1440×3200 | QHD+ phone |
| 17,971,200 | 1440×3120 | QHD+ phone |
| 17,510,400 | 1440×3040 | QHD+ phone |
| 17,049,600 | 1440×2960 | QHD+ phone |
| 16,588,800 | 1440×2880 | QHD+ phone |
| 14,745,600 | 1440×2560 | QHD phone |
| 10,886,400 | 1080×2520 | FHD+ phone |
| 10,368,000 | 1080×2400 | FHD+ phone |
| 10,108,800 | 1080×2340 | FHD+ phone |
| 9,849,600 | 1080×2280 | FHD+ phone |
| 9,331,200 | 1080×2160 | FHD+ phone |
| 8,294,400 | 1080×1920 | FHD phone |
| 4,608,000 | 720×1600 | HD+ phone |
| 4,492,800 | 720×1560 | HD+ phone |
| 4,377,600 | 720×1520 | HD+ phone |
| 4,147,200 | 720×1440 | HD+ phone |
| 3,686,400 | 720×1280 | HD phone |
| 249,200 | 178×350 | Boot logo |
| 49,444 | 263×47 | Fastboot logo |
| 36,864 | 72×128 | Small icon |
| 14,592 | 57×64 | Medium icon |
| 11,520 | 45×64 | Small icon |
| 2,104 | 263×2 | Progress bar |

## Acknowledgments

- [pwnage24mtk](https://github.com/kasnria001/pwnage24mtk) — CERT2 injection logic inspiration (independent Rust rewrite)
- [cannon_logo_maker](https://github.com/ELF-RC/mtk_logo_toolkit/tree/stop-maintenance) — Logo unpack/pack pipeline (same author, predecessor Python project)

See [NOTICE](NOTICE) for details.

## License

Copyright (C) 2025 ELF-RC. Licensed under the GNU General Public License v3.0 or later. See [COPYING](COPYING) for the full license text.