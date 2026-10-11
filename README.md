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

A `logo.bin` file is a linear chain of `part_hdr_t` partitions. Each partition has a 512-byte header (80 bytes of fields + 432 bytes of zero padding) followed by the partition data, padded to the alignment boundary.

```
┌──────────────────────────────────────────────────────────────┐
│  Partition 0 (logo)                                           │
│  ┌──────────────────┐  ┌──────────────────────────────────┐  │
│  │  part_hdr_t (512B) │  │  zlib-compressed logo payload   │  │
│  └──────────────────┘  └──────────────────────────────────┘  │
│  ←─── padding to align_sz boundary ───→                       │
├──────────────────────────────────────────────────────────────┤
│  Partition 1 (cert1)                                          │
│  ┌──────────────────┐  ┌──────────────────────────────────┐  │
│  │  part_hdr_t (512B) │  │  CERT1 DER blob                 │  │
│  └──────────────────┘  └──────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│  Partition 2 (cert2)                                          │
│  ┌──────────────────┐  ┌──────────────────────────────────┐  │
│  │  part_hdr_t (512B) │  │  CERT2 DER blob                 │  │
│  └──────────────────┘  └──────────────────────────────────┘  │
│  is_list_end = 1 (last partition)                             │
└──────────────────────────────────────────────────────────────┘
```

### part_hdr_t Header Layout (80 bytes core, 512 bytes total)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `0x58881688` — identifies a valid header |
| 4 | 4 | `dsize` | Unpadded data size in bytes |
| 8 | 32 | `name` | Partition name, NUL-terminated (e.g. `"logo"`, `"cert2"`) |
| 40 | 4 | `maddr` | Load address (informational) |
| 44 | 4 | `mode` | Mode flags (informational) |
| 48 | 4 | `ext_magic` | Extended magic `0x58891689` |
| 52 | 4 | `hdr_sz` | Header size (always 512) |
| 56 | 4 | `hdr_ver` | Header version (typically 1) |
| 60 | 4 | `img_type` | Image type (`0x00000000`=logo, `0x02000000`=cert1, `0x02000002`=cert2) |
| 64 | 4 | `is_list_end` | Non-zero marks the last header in the chain |
| 68 | 4 | `align_sz` | Data alignment boundary (typically 16) |
| 72 | 4 | `dsize_ext` | Upper 32 bits of data size (always 0 for <4 GiB) |
| 76 | 4 | `maddr_ext` | Upper 32 bits of load address (always 0) |

Bytes 80–511 are zero-padding. The padded data size is `round_up(dsize, align_sz)`.

### Logo Payload Structure

The `logo` partition's data (`dsize` bytes) has this internal layout:

```
┌────────────────────────────────────────────────────┐
│  Payload Header                                    │
│  ┌───────────┬───────────┬──────────────────────┐ │
│  │ count:u32  │ total:u32 │ offsets:u32 × count │ │
│  └───────────┴───────────┴──────────────────────┘ │
│  Header size = 8 + count × 4 bytes                 │
├────────────────────────────────────────────────────┤
│  Chunk Data                                        │
│  ┌──────────┬──────────┬─────┬──────────┐         │
│  │ chunk[0] │ chunk[1] │ ... │ chunk[N] │         │
│  └──────────┴──────────┴─────┴──────────┘         │
│  Each chunk = one zlib-compressed BGRA block       │
└────────────────────────────────────────────────────┘
```

- **`count`** (u32 LE) — number of logo chunks
- **`total`** (u32 LE) — total payload size (header + all chunk data)
- **`offsets[N]`** (u32 LE each) — byte offset of each chunk within the payload
- **`chunk[i]`** — a zlib stream that decompresses to `W × H × 4` bytes of BGRA pixel data

### Color Mode: BGRA32

All pixel data is stored in **BGRA32** format (also called BGRA8888):

| Byte offset | Channel | Bits |
|-------------|---------|------|
| 0 | Blue | 8 |
| 1 | Green | 8 |
| 2 | Red | 8 |
| 3 | Alpha | 8 |

This is the native pixel format used by modern MTK bootloaders (MT6765 and newer). Each pixel occupies 4 bytes; a 1080×2340 image requires 10,108,800 bytes of raw BGRA data.

> **Note:** Older MTK devices (MT6580/MT6739 and earlier) use **RGB565** (2 bytes/pixel, R5G6B5). This tool does not currently support RGB565.

### Compression: zlib Level 9

Each logo chunk is independently compressed with **zlib deflate at level 9** (best compression). The standard MTK build pipeline uses `zpipe -l 9`, which corresponds to the same level. The Rust implementation uses `flate2` with `Compression::best()` (= level 9).

Logo images are highly compressible due to solid-color backgrounds and simple graphics. Typical compression ratios:

| Chunk Type | Decompressed Size | Compressed Size | Ratio |
|------------|-------------------|------------------|-------|
| Full-screen logo (1080×2340) | 10,108,800 bytes | ~18,000 bytes | ~0.18% |
| Boot logo (178×350) | 249,200 bytes | ~4,600 bytes | ~1.8% |
| Progress bar (263×2) | 2,104 bytes | ~150 bytes | ~7% |

### Resolution Fitting

When an input image does not match the target chunk resolution, it is adapted using **center-crop + black-pad** (no scaling):

1. The source image is decoded to RGBA
2. If larger than target: center-crop to `target_w × target_h`
3. If smaller than target: center on a canvas of `target_w × target_h`, padded with opaque black (B=0, G=0, R=0, A=255)
4. RGBA is converted to BGRA and compressed

This guarantees that every chunk's decompressed size is exactly `target_w × target_h × 4`, regardless of input image dimensions.

### CERT2 Bypass Mechanism

The CERT2 blob is an ASN.1 DER-encoded certificate containing image header hash and image content hash fields (identified by OIDs `2.16.886.2454.2.4` and `2.16.886.2454.2.1`). The injection prepends a crafted `0xA0` block containing OID + BIT STRING pairs with recomputed hashes for the current image content, causing the preloader's DER parser to read the injected hashes instead of the original ones.

### Example: Real logo.bin Breakdown

Below is a real-world `logo.bin` from a Cannon MTK device:

```
Total image size: 1,294,976 bytes (1.23 MB)

Partitions (3):
  [0] logo      dsize=1,290,753  padded=1,290,768  img_type=0x00000000  align=16
  [1] cert1     dsize=     1,709  padded=     1,712  img_type=0x02000000  align=16
  [2] cert2     dsize=       957  padded=       960  img_type=0x02000002  align=16

Logo payload:
  Chunks:               42
  Payload header:       176 bytes (8 + 42×4)
  Total compressed:     1,290,577 bytes
  Total decompressed:   243,666,816 bytes (232.5 MB)
  Compression ratio:    0.53%

Unique chunk sizes (decompressed):
    2,104 bytes  →  263×2     (progress bar)
   11,520 bytes  →  45×64     (small icon)
   14,592 bytes  →  57×64     (medium icon)
   36,864 bytes  →  72×128    (small icon)
   49,444 bytes  →  263×47    (fastboot logo)
  249,200 bytes  →  178×350   (boot logo)
10,108,800 bytes  →  1080×2340 (full-screen logo, ×2 chunks)
```

## Known Resolutions

| Bytes | Resolution | Use Case |
|-------|------------|-----------|
| 10,368,000 | 1080×2400 | FHD+ phone |
| 10,108,800 | 1080×2340 | FHD+ phone |
| 4,608,000 | 720×1600 | HD+ phone |
| 3,686,400 | 720×1280 | HD phone |
| 249,200 | 178×350 | Boot logo |
| 49,444 | 263×47 | Fastboot logo |
| 36,864 | 72×128 | Small icon |
| 14,592 | 57×64 | Medium icon |
| 11,520 | 45×64 | Small icon |
| 2,104 | 263×2 | Progress bar |

## Acknowledgments

- [pwnage24mtk](https://github.com/kasnria001/pwnage24mtk) — CERT2 injection logic inspiration (independent Rust rewrite)
- [cannon_logo_maker](https://github.com/ELF-RC/cannon_logo_maker) — Logo unpack/pack pipeline (same author)

See [NOTICE](NOTICE) for details.

## License

Copyright (C) 2025 ELF-RC. Licensed under the GNU General Public License v3.0 or later. See [COPYING](COPYING) for the full license text.