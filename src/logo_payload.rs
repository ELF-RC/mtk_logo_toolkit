//! Logo payload unpack/pack operations.
//!
//! The logo partition's data has this structure:
//! ```text
//! [chunk_count: u32]
//! [total_payload_size: u32]
//! [chunk_offsets: u32 × chunk_count]
//! [zlib-compressed BGRA blocks, one per chunk]
//! ```
//! Each block decompresses to `width × height × 4` bytes of BGRA pixel data.

use std::path::Path;
use std::fs;
use std::collections::HashMap;

use crate::part_header;
use crate::image_codec::{
    lookup_dimensions, bgra_to_rgba, rgba_to_bgra,
    fit_to_canvas, write_png, load_image_file,
    zlib_decompress, zlib_compress,
};

/// Parse the logo payload header into (chunk_count, total_size, offsets).
fn parse_payload_header(payload: &[u8]) -> (u32, u32, Vec<u32>) {
    let chunk_count = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let total_size  = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let offsets: Vec<u32> = (0..chunk_count)
        .map(|i| u32::from_le_bytes(
            payload[8 + i as usize * 4..12 + i as usize * 4].try_into().unwrap()
        ))
        .collect();
    (chunk_count, total_size, offsets)
}

/// Unpack a logo image: extract all chunks as PNG or `.rgba` files.
///
/// Chunks whose decompressed size matches a known resolution in the size map
/// are written as PNG. Others are written as `.rgba` (raw BGRA bytes).
pub fn unpack_logo(image_path: &Path, output_dir: Option<&str>) -> anyhow::Result<()> {
    let out_dir = match output_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let stem = image_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            std::path::PathBuf::from(format!("{}_out", stem))
        }
    };
    fs::create_dir_all(&out_dir)?;

    let image_data = fs::read(image_path)?;
    let parts = part_header::parse_all_parts(&image_data);
    let logo_index = parts.iter().position(|p| p.header.name == "logo");
    let logo_index = match logo_index {
        Some(i) => i,
        None => {
            println!("[ERROR] no logo part found");
            std::process::exit(1);
        }
    };
    let payload = &parts[logo_index].data;
    let (chunk_count, total_size, offsets) = parse_payload_header(payload);
    println!(
        "Image: {}  parts={}  logo chunks={}  payload={}",
        image_path.file_name().unwrap().to_string_lossy(),
        parts.len(), chunk_count, payload.len()
    );

    let mut unknown_sizes = Vec::new();
    for i in 0..chunk_count as usize {
        let end = if i + 1 < chunk_count as usize {
            offsets[i + 1] as usize
        } else {
            total_size as usize
        };
        let compressed = &payload[offsets[i] as usize..end];
        let decompressed = match zlib_decompress(compressed) {
            Ok(d) => d,
            Err(e) => {
                println!("[{:02}] decompress error: {}", i, e);
                continue;
            }
        };
        match lookup_dimensions(decompressed.len()) {
            Some((width, height)) => {
                let rgba = bgra_to_rgba(&decompressed);
                let filename = out_dir.join(format!("{:02}_{}x{}.png", i, width, height));
                write_png(&filename, &rgba, width, height)?;
                println!(
                    "[{:02}] {}x{}  comp={} dec={} -> {}",
                    i, width, height, compressed.len(), decompressed.len(),
                    filename.file_name().unwrap().to_string_lossy()
                );
            }
            None => {
                let filename = out_dir.join(format!("{:02}_{}.rgba", i, decompressed.len()));
                fs::write(&filename, &decompressed)?;
                unknown_sizes.push((i, decompressed.len()));
                println!(
                    "[{:02}] UNKNOWN size={} px={} -> {}",
                    i, decompressed.len(), decompressed.len() / 4,
                    filename.file_name().unwrap().to_string_lossy()
                );
            }
        }
    }
    println!("\n[OK] {} chunks -> {}", chunk_count, out_dir.display());
    if !unknown_sizes.is_empty() {
        println!("Unknown sizes (saved as .rgba, repacked verbatim if untouched):");
        for (i, size) in unknown_sizes {
            println!("  [{:02}] {} bytes", i, size);
        }
    }
    Ok(())
}

/// Supported image file extensions for pack input.
const SUPPORTED_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tga",
    ".ppm", ".pgm", ".pbm", ".webp", ".rgba",
];

/// Collect replacement images from `src_dir`, indexed by chunk number.
///
/// Files must be named `NN_description.ext` where `NN` is the zero-padded
/// chunk index. Only the first matching file per chunk index is used.
fn collect_replacement_images(
    src_dir: &Path,
    chunk_count: u32,
) -> HashMap<usize, (String, std::path::PathBuf)> {
    let mut sources: HashMap<usize, (String, std::path::PathBuf)> = HashMap::new();

    let mut entries: Vec<_> = fs::read_dir(src_dir)
        .unwrap_or_else(|_| {
            eprintln!("[ERROR] cannot read directory: {}", src_dir.display());
            std::process::exit(2);
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ext_with_dot = format!(".{}", ext);
        if !SUPPORTED_EXTENSIONS.contains(&ext_with_dot.as_str()) { continue; }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let prefix = name.split('_').next().unwrap_or("");
        let index: usize = match prefix.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if index as u32 >= chunk_count { continue; }
        if sources.contains_key(&index) { continue; }
        sources.insert(index, (ext_with_dot, path));
    }
    sources
}

/// Pack images from `src_dir` into a copy of the template MKIMG.
///
/// For each chunk:
/// - If a replacement image is provided, decode it, fit to the target
///   resolution, convert to BGRA, and compress with zlib.
/// - If no replacement is provided, the original compressed block is kept.
///
/// Returns the complete rebuilt image bytes.
pub fn pack_logo(src_dir: &Path, template_path: &Path) -> anyhow::Result<Vec<u8>> {
    let image_data = fs::read(template_path)?;
    let mut parts = part_header::parse_all_parts(&image_data);
    let logo_index = parts.iter().position(|p| p.header.name == "logo");
    let logo_index = match logo_index {
        Some(i) => i,
        None => anyhow::bail!("no logo part in template"),
    };
    let original_payload = parts[logo_index].data.clone();
    let (chunk_count, total_size, offsets) = parse_payload_header(&original_payload);
    let replacements = collect_replacement_images(src_dir, chunk_count);
    println!(
        "Template: {}  chunks={}  provided={}",
        template_path.file_name().unwrap().to_string_lossy(),
        chunk_count, replacements.len()
    );

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut replaced_count = 0u32;

    for i in 0..chunk_count as usize {
        let end = if i + 1 < chunk_count as usize {
            offsets[i + 1] as usize
        } else {
            total_size as usize
        };
        let original_block = original_payload[offsets[i] as usize..end].to_vec();

        let replacement = replacements.get(&i);
        match replacement {
            None => {
                blocks.push(original_block); // keep original compressed data
            }
            Some((ext, path)) => {
                if ext == ".rgba" {
                    let raw_bgra = fs::read(path)?;
                    blocks.push(zlib_compress(&raw_bgra));
                    replaced_count += 1;
                    println!(
                        "[{:02}] <- {} (rgba)  comp={}",
                        i, path.file_name().unwrap().to_string_lossy(),
                        blocks.last().unwrap().len()
                    );
                    continue;
                }
                // Decode the replacement image.
                let original_decompressed = match zlib_decompress(&original_block) {
                    Ok(d) => d,
                    Err(e) => {
                        println!(
                            "[{:02}] template chunk decompress error: {}; keeping original",
                            i, e
                        );
                        blocks.push(original_block);
                        continue;
                    }
                };
                let (target_w, target_h) = match lookup_dimensions(original_decompressed.len()) {
                    Some(dims) => dims,
                    None => {
                        println!(
                            "[{:02}] target size unknown (dec={}); keeping original",
                            i, original_decompressed.len()
                        );
                        blocks.push(original_block);
                        continue;
                    }
                };
                let (src_w, src_h, src_rgba) = match load_image_file(path) {
                    Ok(v) => v,
                    Err(e) => {
                        println!(
                            "[{:02}] failed to load {}: {}; keeping original",
                            i, path.display(), e
                        );
                        blocks.push(original_block);
                        continue;
                    }
                };
                let final_rgba = if (src_w, src_h) != (target_w, target_h) {
                    println!(
                        "[{:02}] fit {}x{} -> {}x{}  ({})",
                        i, src_w, src_h, target_w, target_h,
                        path.file_name().unwrap().to_string_lossy()
                    );
                    fit_to_canvas(&src_rgba, src_w, src_h, target_w, target_h)
                } else {
                    src_rgba
                };
                let final_bgra = rgba_to_bgra(&final_rgba);
                blocks.push(zlib_compress(&final_bgra));
                replaced_count += 1;
                println!(
                    "[{:02}] <- {}  comp={}",
                    i, path.file_name().unwrap().to_string_lossy(),
                    blocks.last().unwrap().len()
                );
            }
        }
    }
    println!("Replaced {}/{} chunks", replaced_count, chunk_count);

    // Rebuild payload: [count][total][offsets][blocks]
    let header_size = 8 + chunk_count as usize * 4;
    let mut current_offset = header_size;
    let mut new_offsets = Vec::with_capacity(chunk_count as usize);
    let mut block_data = Vec::new();
    for block in &blocks {
        new_offsets.push(current_offset);
        current_offset += block.len();
        block_data.extend_from_slice(block);
    }
    let mut new_payload = Vec::with_capacity(header_size + block_data.len());
    new_payload.extend_from_slice(&chunk_count.to_le_bytes());
    new_payload.extend_from_slice(&(current_offset as u32).to_le_bytes());
    for offset in &new_offsets {
        new_payload.extend_from_slice(&(*offset as u32).to_le_bytes());
    }
    new_payload.extend_from_slice(&block_data);

    parts[logo_index].data = new_payload.clone();
    parts[logo_index].header.data_size = new_payload.len() as u32;
    println!(
        "New logo payload: {} bytes (was {})",
        new_payload.len(), original_payload.len()
    );

    Ok(part_header::rebuild_image(&parts))
}