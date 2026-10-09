//! Image loading, PNG writing, and pixel format conversion.
//!
//! Uses the `image` crate for decoding (PNG, JPEG, GIF, BMP, TGA, PNM).
//! PNG encoding is done manually to ensure BGRA-compatible output.

use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;

/// Decompressed size -> (width, height). 4 bytes per pixel (BGRA).
pub fn size_map() -> &'static [(usize, (u32, u32))] {
    &[
        (10368000, (1080, 2400)),
        (10108800, (1080, 2340)),
        (249200,   (178, 350)),
        (49444,    (263, 47)),
        (36864,    (72, 128)),
        (14592,    (57, 64)),
        (11520,    (45, 64)),
        (2104,     (263, 2)),
    ]
}

pub fn lookup_size(byte_len: usize) -> Option<(u32, u32)> {
    size_map().iter().find(|(s, _)| *s == byte_len).map(|(_, wh)| *wh)
}

/// Load an image and return (width, height, RGBA bytes).
pub fn load_image(path: &Path) -> anyhow::Result<(u32, u32, Vec<u8>)> {
    // Try .rgba first
    if path.extension().and_then(|e| e.to_str()) == Some("rgba") {
        let data = std::fs::read(path)?;
        // We don't know dimensions from raw rgba alone; caller handles this
        // by not going through load_image for .rgba files
        return Ok((0, 0, data));
    }
    let img = image::open(path)
        .map_err(|e| anyhow::anyhow!("failed to decode image {}: {}", path.display(), e))?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    Ok((w, h, rgba.into_raw()))
}

/// Write a PNG file (8-bit RGBA, non-interlaced).
pub fn png_write(path: &Path, rgba: &[u8], w: u32, h: u32) -> anyhow::Result<()> {
    // Build raw scanlines with filter type 0 (None)
    let mut raw = Vec::with_capacity((w as usize * 4 + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0u8); // filter: none
        let start = y * w as usize * 4;
        let end = start + w as usize * 4;
        raw.extend_from_slice(&rgba[start..end]);
    }

    // Compress IDAT
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&raw)?;
    let compressed = encoder.finish()?;

    // Build PNG manually
    let mut out = File::create(path)?;
    // Signature
    out.write_all(b"\x89PNG\r\n\x1a\n")?;

    // IHDR
    let ihdr_data = [
        (w >> 24) as u8, (w >> 16) as u8, (w >> 8) as u8, w as u8, // width
        (h >> 24) as u8, (h >> 16) as u8, (h >> 8) as u8, h as u8, // height
        8,  // bit depth
        6,  // color type: RGBA
        0,  // compression
        0,  // filter
        0,  // interlace: none
    ];
    write_chunk(&mut out, b"IHDR", &ihdr_data)?;
    // IDAT
    write_chunk(&mut out, b"IDAT", &compressed)?;
    // IEND
    write_chunk(&mut out, b"IEND", &[])?;

    Ok(())
}

fn write_chunk<W: Write>(w: &mut W, chunk_type: &[u8; 4], data: &[u8]) -> anyhow::Result<()> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(chunk_type)?;
    w.write_all(data)?;
    // CRC over type + data
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    let crc = crc32(&crc_input);
    w.write_all(&crc.to_be_bytes())?;
    Ok(())
}

/// CRC-32 (IEEE 802.3 polynomial, same as PNG/zlib).
fn crc32(data: &[u8]) -> u32 {
    // Use flate2's CRC by computing it via a simple table-based implementation
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            t[i as usize] = c;
        }
        t
    });
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

/// Convert RGBA to BGRA (swap R and B channels).
pub fn rgba_to_bgra(rgba: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; rgba.len()];
    let n = rgba.len() / 4;
    for i in 0..n {
        let o = i * 4;
        out[o] = rgba[o + 2];     // B <- R
        out[o + 1] = rgba[o + 1]; // G
        out[o + 2] = rgba[o];     // R <- B
        out[o + 3] = rgba[o + 3]; // A
    }
    out
}

/// Convert BGRA to RGBA (swap R and B channels).
pub fn bgra_to_rgba(bgra: &[u8]) -> Vec<u8> {
    // Same operation as rgba_to_bgra since it just swaps R and B
    rgba_to_bgra(bgra)
}

/// Fit source RGBA (sw x sh) into (dw x dh) by center-cropping and/or
/// padding with opaque black. No scaling.
pub fn fit_rgba(src: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) -> Vec<u8> {
    let dw = dw as usize;
    let dh = dh as usize;
    let sw = sw as usize;
    let sh = sh as usize;
    let mut dst = vec![0u8; dw * dh * 4];
    // Fill with opaque black: B=0 G=0 R=0 A=255
    for px in dst.chunks_exact_mut(4) {
        px[0] = 0; px[1] = 0; px[2] = 0; px[3] = 255;
    }
    let cw = sw.min(dw);
    let ch = sh.min(dh);
    let sx = (sw - cw) / 2;
    let sy = (sh - ch) / 2;
    let dx = (dw - cw) / 2;
    let dy = (dh - ch) / 2;
    for y in 0..ch {
        let s_off = ((sy + y) * sw + sx) * 4;
        let d_off = ((dy + y) * dw + dx) * 4;
        dst[d_off..d_off + cw * 4].copy_from_slice(&src[s_off..s_off + cw * 4]);
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

/// Compress data with zlib (level 9).
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}
