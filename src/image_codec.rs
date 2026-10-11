// SPDX-License-Identifier: GPL-3.0-or-later
// mtk-logo-toolkit - MTK logo image toolchain
// Copyright (C) 2025 ELF-RC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Image loading, PNG writing, pixel format conversion, and zlib compression.
//!
//! - **Decoding**: uses the `image` crate for PNG, JPEG, GIF, BMP, TGA, PNM, WebP.
//! - **PNG encoding**: hand-written to guarantee exact RGBA output and to
//!   match the Python reference implementation byte-for-byte (modulo zlib stream).
//! - **Zlib**: uses `flate2` at compression level 9 (= best).

use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;

/// Lookup table: decompressed byte count → (width, height) for known MTK
/// logo chunk resolutions. All entries assume 4 bytes/pixel (BGRA32).
pub fn known_sizes() -> &'static [(usize, (u32, u32))] {
    &[
        // 2K (QHD)
        (18_432_000, (1440, 3200)),
        (17_971_200, (1440, 3120)),
        (17_510_400, (1440, 3040)),
        (17_049_600, (1440, 2960)),
        (16_588_800, (1440, 2880)),
        (14_745_600, (1440, 2560)),
        // 1080P (FHD/FHD+)
        (10_886_400, (1080, 2520)),
        (10_368_000, (1080, 2400)),
        (10_108_800, (1080, 2340)),
        (9_849_600,  (1080, 2280)),
        (9_331_200,  (1080, 2160)),
        (8_294_400,  (1080, 1920)),
        // 720P (HD/HD+)
        (4_608_000,  (720, 1600)),
        (4_492_800,  (720, 1560)),
        (4_377_600,  (720, 1520)),
        (4_147_200,  (720, 1440)),
        (3_686_400,  (720, 1280)),
        // Small logos / icons
        (249_200,    (178, 350)),
        (49_444,     (263, 47)),
        (36_864,     (72, 128)),
        (14_592,     (57, 64)),
        (11_520,     (45, 64)),
        (2_104,      (263, 2)),
    ]
}

/// Look up (width, height) for a given decompressed byte count.
/// Returns `None` if the size is not in the known table.
pub fn lookup_dimensions(byte_count: usize) -> Option<(u32, u32)> {
    known_sizes()
        .iter()
        .find(|(size, _)| *size == byte_count)
        .map(|(_, dims)| *dims)
}

/// Load an image file and return `(width, height, RGBA pixel data)`.
///
/// Supports all formats decoded by the `image` crate: PNG, JPEG, GIF, BMP,
/// TGA, PNM, and WebP. Raw `.rgba` files are handled directly by the caller
/// (see `pack_logo` in `logo_payload.rs`), not through this function.
pub fn load_image_file(path: &Path) -> anyhow::Result<(u32, u32, Vec<u8>)> {
    let img = image::open(path)
        .map_err(|e| anyhow::anyhow!("failed to decode image {}: {}", path.display(), e))?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    Ok((width, height, rgba.into_raw()))
}

/// Write a PNG file (8-bit RGBA, non-interlaced, filter type = None).
///
/// The output is a minimal valid PNG: signature + IHDR + IDAT + IEND.
pub fn write_png(path: &Path, rgba: &[u8], width: u32, height: u32) -> anyhow::Result<()> {
    // Build raw scanlines, each prefixed with filter byte 0 (None).
    let mut raw_scanlines = Vec::with_capacity((width as usize * 4 + 1) * height as usize);
    for row in 0..height as usize {
        raw_scanlines.push(0u8); // filter: none
        let start = row * width as usize * 4;
        let end = start + width as usize * 4;
        raw_scanlines.extend_from_slice(&rgba[start..end]);
    }

    // Compress the raw scanline data with zlib (level 9).
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&raw_scanlines)?;
    let compressed = encoder.finish()?;

    let mut file = File::create(path)?;
    // PNG signature
    file.write_all(b"\x89PNG\r\n\x1a\n")?;

    // IHDR chunk
    let ihdr_data = [
        (width >> 24) as u8, (width >> 16) as u8, (width >> 8) as u8, width as u8,
        (height >> 24) as u8, (height >> 16) as u8, (height >> 8) as u8, height as u8,
        8,  // bit depth
        6,  // color type: RGBA
        0,  // compression method
        0,  // filter method
        0,  // interlace: none
    ];
    write_png_chunk(&mut file, b"IHDR", &ihdr_data)?;
    // IDAT chunk
    write_png_chunk(&mut file, b"IDAT", &compressed)?;
    // IEND chunk
    write_png_chunk(&mut file, b"IEND", &[])?;

    Ok(())
}

/// Write a single PNG chunk: `length(4) + type(4) + data + crc(4)`.
fn write_png_chunk<W: Write>(writer: &mut W, chunk_type: &[u8; 4], data: &[u8]) -> anyhow::Result<()> {
    let length = data.len() as u32;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(chunk_type)?;
    writer.write_all(data)?;
    // CRC is computed over chunk type + data.
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    let crc = crc32_ieee(&crc_input);
    writer.write_all(&crc.to_be_bytes())?;
    Ok(())
}

/// CRC-32 using the IEEE 802.3 polynomial (same as PNG/zlib spec).
fn crc32_ieee(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = 0xEDB8_8320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            t[i as usize] = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Convert RGBA pixel data to BGRA (swap red and blue channels).
pub fn rgba_to_bgra(rgba: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; rgba.len()];
    let pixel_count = rgba.len() / 4;
    for i in 0..pixel_count {
        let offset = i * 4;
        out[offset]     = rgba[offset + 2]; // B ← R
        out[offset + 1] = rgba[offset + 1]; // G
        out[offset + 2] = rgba[offset];     // R ← B
        out[offset + 3] = rgba[offset + 3]; // A
    }
    out
}

/// Convert BGRA pixel data to RGBA (swap red and blue channels).
/// This is the same operation as `rgba_to_bgra` since it's a symmetric swap.
pub fn bgra_to_rgba(bgra: &[u8]) -> Vec<u8> {
    rgba_to_bgra(bgra)
}

/// Fit source RGBA (`src_width × src_height`) into a destination buffer of
/// `dest_width × dest_height` by center-cropping and/or padding with opaque
/// black (R=0, G=0, B=0, A=255). No scaling is performed.
pub fn fit_to_canvas(
    src: &[u8],
    src_width: u32,
    src_height: u32,
    dest_width: u32,
    dest_height: u32,
) -> Vec<u8> {
    let dw = dest_width as usize;
    let dh = dest_height as usize;
    let sw = src_width as usize;
    let sh = src_height as usize;
    let mut dst = vec![0u8; dw * dh * 4];
    // Fill with opaque black.
    for pixel in dst.chunks_exact_mut(4) {
        pixel[0] = 0; pixel[1] = 0; pixel[2] = 0; pixel[3] = 255;
    }
    let crop_w = sw.min(dw);
    let crop_h = sh.min(dh);
    let src_x = (sw - crop_w) / 2;
    let src_y = (sh - crop_h) / 2;
    let dst_x = (dw - crop_w) / 2;
    let dst_y = (dh - crop_h) / 2;
    for row in 0..crop_h {
        let src_offset = ((src_y + row) * sw + src_x) * 4;
        let dst_offset = ((dst_y + row) * dw + dst_x) * 4;
        dst[dst_offset..dst_offset + crop_w * 4].copy_from_slice(&src[src_offset..src_offset + crop_w * 4]);
    }
    dst
}

/// Decompress zlib data.
pub fn zlib_decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Compress data with zlib at level 9 (best compression).
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}