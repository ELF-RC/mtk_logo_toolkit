//! Logo payload unpack/pack operations.

use std::path::Path;
use crate::mkimg;
use crate::image_io::{lookup_size, bgra_to_rgba, rgba_to_bgra, fit_rgba, png_write, load_image, zlib_decompress, zlib_compress};
use std::fs;

/// Parse logo payload header: [count:u32][total:u32][offsets:u32...]
fn parse_logo_payload(pay: &[u8]) -> (u32, u32, Vec<u32>) {
    let cnt = u32::from_le_bytes(pay[0..4].try_into().unwrap());
    let total = u32::from_le_bytes(pay[4..8].try_into().unwrap());
    let offs: Vec<u32> = (0..cnt)
        .map(|i| u32::from_le_bytes(pay[8 + i as usize * 4..12 + i as usize * 4].try_into().unwrap()))
        .collect();
    (cnt, total, offs)
}

/// Unpack a logo image: extract all chunks as PNG or .rgba files.
pub fn unpack_image(image_path: &Path, out_dir: Option<&str>) -> anyhow::Result<()> {
    let out_dir = match out_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let stem = image_path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            std::path::PathBuf::from(format!("{}_out", stem))
        }
    };
    fs::create_dir_all(&out_dir)?;

    let data = fs::read(image_path)?;
    let parts = mkimg::parse_parts(&data);
    let li = parts.iter().position(|p| p.hdr.name == "logo");
    let li = match li {
        Some(i) => i,
        None => {
            println!("[ERROR] no logo part found");
            std::process::exit(1);
        }
    };
    let pay = &parts[li].data;
    let (cnt, total, offs) = parse_logo_payload(pay);
    println!(
        "Image: {}  parts={}  logo chunks={}  payload={}",
        image_path.file_name().unwrap().to_string_lossy(),
        parts.len(), cnt, pay.len()
    );

    let mut unknown = Vec::new();
    for i in 0..cnt as usize {
        let end = if i + 1 < cnt as usize {
            offs[i + 1] as usize
        } else {
            total as usize
        };
        let raw = &pay[offs[i] as usize..end];
        let dec = match zlib_decompress(raw) {
            Ok(d) => d,
            Err(e) => {
                println!("[{:02}] decompress error: {}", i, e);
                continue;
            }
        };
        match lookup_size(dec.len()) {
            Some((w, h)) => {
                let rgba = bgra_to_rgba(&dec);
                let fn_ = out_dir.join(format!("{:02}_{}x{}.png", i, w, h));
                png_write(&fn_, &rgba, w, h)?;
                println!("[{:02}] {}x{}  comp={} dec={} -> {}", i, w, h, raw.len(), dec.len(), fn_.file_name().unwrap().to_string_lossy());
            }
            None => {
                let fn_ = out_dir.join(format!("{:02}_{}.rgba", i, dec.len()));
                fs::write(&fn_, &dec)?;
                unknown.push((i, dec.len()));
                println!("[{:02}] UNKNOWN size={} px={} -> {}", i, dec.len(), dec.len() / 4, fn_.file_name().unwrap().to_string_lossy());
            }
        }
    }
    println!("\n[OK] {} chunks -> {}", cnt, out_dir.display());
    if !unknown.is_empty() {
        println!("Unknown sizes (saved as .rgba, repacked verbatim if untouched):");
        for (i, sz) in unknown {
            println!("  [{:02}] {} bytes", i, sz);
        }
    }
    Ok(())
}

/// Collect pack sources: files with 2-digit prefix matching chunk index.
fn collect_pack_sources(src_dir: &Path, cnt: u32) -> std::collections::HashMap<usize, (String, std::path::PathBuf)> {
    let img_exts: &[&str] = &[".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tga", ".ppm", ".pgm", ".pbm", ".webp", ".rgba"];
    let mut sources: std::collections::HashMap<usize, (String, std::path::PathBuf)> = std::collections::HashMap::new();

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
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let ext_with_dot = format!(".{}", ext);
        if !img_exts.contains(&ext_with_dot.as_str()) { continue; }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let prefix = name.split('_').next().unwrap_or("");
        let idx: usize = match prefix.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if idx as u32 >= cnt { continue; }
        if sources.contains_key(&idx) { continue; }
        sources.insert(idx, (ext_with_dot, path));
    }
    sources
}

/// Pack images from src_dir into the template MKIMG; return new image bytes.
pub fn pack_image(src_dir: &Path, template: &Path) -> anyhow::Result<Vec<u8>> {
    let data = fs::read(template)?;
    let mut parts = mkimg::parse_parts(&data);
    let li = parts.iter().position(|p| p.hdr.name == "logo");
    let li = match li {
        Some(i) => i,
        None => anyhow::bail!("no logo part in template"),
    };
    let pay = parts[li].data.clone();
    let (cnt, total, offs) = parse_logo_payload(&pay);
    let sources = collect_pack_sources(src_dir, cnt);
    println!("Template: {}  chunks={}  provided={}", template.file_name().unwrap().to_string_lossy(), cnt, sources.len());

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut replaced = 0u32;

    for i in 0..cnt as usize {
        let end = if i + 1 < cnt as usize {
            offs[i + 1] as usize
        } else {
            total as usize
        };
        let raw = pay[offs[i] as usize..end].to_vec();

        let src = sources.get(&i);
        match src {
            None => {
                blocks.push(raw); // keep original
            }
            Some((ext, path)) => {
                if ext == ".rgba" {
                    let bgra = fs::read(path)?;
                    blocks.push(zlib_compress(&bgra));
                    replaced += 1;
                    println!("[{:02}] <- {} (rgba)  comp={}", i, path.file_name().unwrap().to_string_lossy(), blocks.last().unwrap().len());
                    continue;
                }
                // image: decode, fit to target, convert to BGRA
                let dec = match zlib_decompress(&raw) {
                    Ok(d) => d,
                    Err(e) => {
                        println!("[{:02}] template chunk decompress error: {}; keeping original", i, e);
                        blocks.push(raw);
                        continue;
                    }
                };
                let (dw, dh) = match lookup_size(dec.len()) {
                    Some(wh) => wh,
                    None => {
                        println!("[{:02}] target size unknown (dec={}); keeping original", i, dec.len());
                        blocks.push(raw);
                        continue;
                    }
                };
                let (sw, sh, rgba) = match load_image(path) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("[{:02}] failed to load {}: {}; keeping original", i, path.display(), e);
                        blocks.push(raw);
                        continue;
                    }
                };
                let rgba_final = if (sw, sh) != (dw, dh) {
                    println!("[{:02}] fit {}x{} -> {}x{}  ({})", i, sw, sh, dw, dh, path.file_name().unwrap().to_string_lossy());
                    fit_rgba(&rgba, sw, sh, dw, dh)
                } else {
                    rgba
                };
                let bgra = rgba_to_bgra(&rgba_final);
                blocks.push(zlib_compress(&bgra));
                replaced += 1;
                println!("[{:02}] <- {}  comp={}", i, path.file_name().unwrap().to_string_lossy(), blocks.last().unwrap().len());
            }
        }
    }
    println!("Replaced {}/{} chunks", replaced, cnt);

    // Rebuild payload: [count][total][offsets][blocks]
    let head = 8 + cnt as usize * 4;
    let mut cur = head;
    let mut noff = Vec::with_capacity(cnt as usize);
    let mut body = Vec::new();
    for b in &blocks {
        noff.push(cur);
        cur += b.len();
        body.extend_from_slice(b);
    }
    let mut newpay = Vec::with_capacity(head + body.len());
    newpay.extend_from_slice(&cnt.to_le_bytes());
    newpay.extend_from_slice(&(cur as u32).to_le_bytes());
    for o in &noff {
        newpay.extend_from_slice(&(*o as u32).to_le_bytes());
    }
    newpay.extend_from_slice(&body);

    parts[li].data = newpay.clone();
    parts[li].hdr.dsize = newpay.len() as u32;
    println!("New logo payload: {} bytes (was {})", newpay.len(), pay.len());

    Ok(mkimg::rebuild_parts(&parts))
}
