//! ASN.1 DER (Distinguished Encoding Rules) TLV encoding and decoding.
//!
//! Pure Rust, zero external dependencies. Used for parsing and forging
//! the CERT2 certificate blob embedded in MTK boot images.
//!
//! Key concepts:
//! - **Tag**: identifies the data type (e.g. 0x06 = OID, 0x03 = BIT STRING)
//! - **Length**: encoded as 1 byte (short form) or multiple bytes (long form)
//! - **Value**: the actual payload
//! - **TLV**: Tag-Length-Value triple, the fundamental unit of DER

/// OID for the image content hash field inside CERT2.
pub const OID_IMAGE_HASH: &str = "2.16.886.2454.2.1";
/// OID for the image header hash field inside CERT2.
pub const OID_IMAGE_HEADER_HASH: &str = "2.16.886.2454.2.4";

// ---------------------------------------------------------------------------
// Length
// ---------------------------------------------------------------------------

/// Encode an integer length in DER format (short or long form).
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let trimmed = &bytes[start..];
        let mut out = Vec::with_capacity(1 + trimmed.len());
        out.push(0x80 | trimmed.len() as u8);
        out.extend_from_slice(trimmed);
        out
    }
}

/// Decode a DER length at `offset` in `data`.
/// Returns `(value, bytes_consumed)`.
pub fn read_length(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() { return Err("truncated length".into()); }
    let first_byte = data[offset];
    if first_byte & 0x80 == 0 {
        return Ok((first_byte as usize, 1));
    }
    let num_bytes = (first_byte & 0x7F) as usize;
    if num_bytes == 0 { return Err("indefinite length not supported".into()); }
    if offset + 1 + num_bytes > data.len() { return Err("truncated length bytes".into()); }
    let mut value = 0usize;
    for i in 0..num_bytes {
        value = (value << 8) | data[offset + 1 + i] as usize;
    }
    Ok((value, 1 + num_bytes))
}

// ---------------------------------------------------------------------------
// Tag
// ---------------------------------------------------------------------------

/// Decode a DER tag byte at `offset`.
/// Returns `(tag_class, is_constructed, tag_number, bytes_consumed)`.
pub fn read_tag(data: &[u8], offset: usize) -> Result<(u8, bool, u32, usize), String> {
    if offset >= data.len() { return Err("truncated tag".into()); }
    let first_byte = data[offset];
    let tag_class    = (first_byte & 0xC0) >> 6;
    let constructed  = first_byte & 0x20 != 0;
    let tag_number   = first_byte & 0x1F;
    let mut tag_len  = 1;
    let mut full_tag = tag_number as u32;

    if tag_number == 0x1F {
        // Long-form tag number
        full_tag = 0;
        let mut i = offset + 1;
        loop {
            if i >= data.len() { return Err("truncated long-form tag".into()); }
            let b = data[i];
            full_tag = (full_tag << 7) | (b & 0x7F) as u32;
            i += 1;
            tag_len += 1;
            if b & 0x80 == 0 { break; }
        }
    }
    Ok((tag_class, constructed, full_tag, tag_len))
}

// ---------------------------------------------------------------------------
// OID encoding/decoding
// ---------------------------------------------------------------------------

/// Encode an OID string (e.g. "2.16.886.2454.2.1") to DER content bytes.
pub fn encode_oid(oid: &str) -> Vec<u8> {
    let components: Vec<u64> = oid.split('.').map(|s| s.parse::<u64>().unwrap()).collect();
    let mut out = vec![40 * components[0] as u8 + components[1] as u8];
    for &component in &components[2..] {
        if component == 0 {
            out.push(0);
            continue;
        }
        let mut chunks = Vec::new();
        let mut value = component;
        while value > 0 {
            chunks.insert(0, (value & 0x7F) as u8);
            value >>= 7;
        }
        for (i, &chunk) in chunks.iter().enumerate() {
            if i != chunks.len() - 1 {
                out.push(0x80 | chunk);
            } else {
                out.push(chunk);
            }
        }
    }
    out
}

/// Decode OID content bytes back to a string (e.g. "2.16.886.2454.2.1").
pub fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let first = bytes[0] as u64;
    let mut parts: Vec<u64> = vec![first / 40, first % 40];
    let mut value = 0u64;
    for &byte in &bytes[1..] {
        value = (value << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

// ---------------------------------------------------------------------------
// TLV builders
// ---------------------------------------------------------------------------

/// Build a complete OID TLV: `06 <len> <oid_bytes>`.
pub fn build_oid_tlv(oid: &str) -> Vec<u8> {
    let content = encode_oid(oid);
    let mut out = vec![0x06];
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}

/// Build a complete BIT STRING TLV: `03 <len> 00 <payload>`.
/// The `0x00` prefix indicates zero unused bits.
pub fn build_bit_string_tlv(payload: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // 0 unused bits
    content.extend_from_slice(payload);
    let mut out = vec![0x03];
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}

// ---------------------------------------------------------------------------
// DER tree (arena-based parser)
// ---------------------------------------------------------------------------

/// A parsed DER node in an arena-style tree.
#[derive(Debug, Clone)]
pub struct DerNode {
    /// Tag class: 0=universal, 1=application, 2=context, 3=private.
    pub tag_class: u8,
    /// Whether this is a constructed (container) node.
    pub is_constructed: bool,
    /// The tag number.
    pub tag_number: u32,
    /// Size of the tag+length prefix (header overhead).
    pub header_len: usize,
    /// Length of the value field.
    pub content_len: usize,
    /// Primitive value (for non-constructed nodes).
    pub raw_value: Option<Vec<u8>>,
    /// Children (for constructed nodes).
    pub children: Option<Vec<DerNode>>,
}

/// Parse a flat byte sequence into a tree of DER nodes.
pub fn parse_der_tree(data: &[u8]) -> Vec<DerNode> {
    let mut nodes = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let (tag_class, is_constructed, tag_number, tag_len) = match read_tag(data, offset) {
            Ok(v) => v,
            Err(_) => break,
        };
        let (length, len_len) = match read_length(data, offset + tag_len) {
            Ok(v) => v,
            Err(_) => break,
        };
        let header_len = tag_len + len_len;
        let value_offset = offset + header_len;
        let value_end = value_offset + length;
        if value_end > data.len() { break; }
        let value_slice = &data[value_offset..value_end];
        let children = if is_constructed {
            Some(parse_der_tree(value_slice))
        } else {
            None
        };
        let raw_value = if is_constructed { None } else { Some(value_slice.to_vec()) };
        nodes.push(DerNode {
            tag_class, is_constructed, tag_number, header_len,
            content_len: length, raw_value, children,
        });
        offset = value_end;
    }
    nodes
}

// ---------------------------------------------------------------------------
// High-level lookups
// ---------------------------------------------------------------------------

/// Find the BIT STRING value (including unused-bits prefix) that immediately
/// follows a given OID anywhere in the DER tree.
pub fn find_bit_string_after_oid(der: &[u8], oid: &str) -> Option<Vec<u8>> {
    let root_nodes = parse_der_tree(der);

    fn walk(nodes: &[DerNode], oid: &str) -> Option<Vec<u8>> {
        for (i, node) in nodes.iter().enumerate() {
            // Is this an OID node matching our target?
            if node.tag_class == 0 && node.tag_number == 6 {
                if let Some(ref value) = node.raw_value {
                    if decode_oid(value) == oid {
                        // Look at subsequent siblings for a BIT STRING
                        for j in (i + 1)..nodes.len() {
                            if let Some(bs) = find_bit_string_in_subtree(&nodes[j]) {
                                return Some(bs);
                            }
                        }
                        return None;
                    }
                }
            }
            // Recurse into children
            if let Some(ref children) = node.children {
                if let Some(bs) = walk(children, oid) {
                    return Some(bs);
                }
            }
        }
        None
    }

    fn find_bit_string_in_subtree(node: &DerNode) -> Option<Vec<u8>> {
        if node.tag_class == 0 && node.tag_number == 3 {
            if let Some(ref value) = node.raw_value {
                return Some(value.clone());
            }
        }
        if let Some(ref children) = node.children {
            for child in children {
                if let Some(bs) = find_bit_string_in_subtree(child) {
                    return Some(bs);
                }
            }
        }
        None
    }

    walk(&root_nodes, oid)
}

/// Parsed first TLV at offset 0.
/// Returns `(tag_class, is_constructed, tag_number, value_offset, value_end)`.
pub fn parse_first_tlv(data: &[u8]) -> Option<(u8, bool, u32, usize, usize)> {
    if data.is_empty() { return None; }
    let (tag_class, is_constructed, tag_number, tag_len) = read_tag(data, 0).ok()?;
    let (length, len_len) = read_length(data, tag_len).ok()?;
    let value_offset = tag_len + len_len;
    let value_end = value_offset + length;
    if value_end > data.len() { return None; }
    Some((tag_class, is_constructed, tag_number, value_offset, value_end))
}

/// A top-level TLV entry with absolute offsets.
pub struct TopLevelTlv {
    pub start: usize,
    pub end: usize,
    pub tag_class: u8,
    pub is_constructed: bool,
    pub tag_number: u32,
    pub value_offset: usize,
}

/// Iterate all top-level TLVs in `data`.
pub fn iter_top_level_tlvs(data: &[u8]) -> Vec<TopLevelTlv> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let first = match parse_first_tlv(&data[offset..]) {
            Some(f) => f,
            None => break,
        };
        let (tag_class, is_constructed, tag_number, val_off, val_end) = first;
        out.push(TopLevelTlv {
            start: offset,
            end: offset + val_end,
            tag_class,
            is_constructed,
            tag_number,
            value_offset: offset + val_off,
        });
        offset += val_end;
    }
    out
}

/// Locate the original CERT2 DER SEQUENCE (tag 0x30) in the blob.
/// Returns `(der_bytes, relative_offset)`.
pub fn find_original_cert2_sequence(der: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    for node in iter_top_level_tlvs(der) {
        if node.tag_class == 0 && node.is_constructed && node.tag_number == 0x10 {
            return Ok((&der[node.start..node.end], node.start));
        }
    }
    anyhow::bail!("original CERT2 DER SEQUENCE (0x30) not found")
}

/// Strip any previous injection's prefix, making re-install idempotent.
///
/// Handles two cases:
/// 1. **Legacy BIT STRING wrapper**: top-level BIT STRING → strip it, then
///    continue stripping any following 0xA0 blocks.
/// 2. **Top-level 0xA0 override** (modern sibling): strip it, then continue
///    to check if there's a BIT STRING or another 0xA0 after it.
///
/// Both cases are handled by the same loop since both are top-level TLVs.
/// Returns a sub-slice of the input (zero-copy).
pub fn strip_injection(der: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let mut data = der;
    loop {
        let first = match parse_first_tlv(data) {
            Some(f) => f,
            None => break,
        };
        let is_bit_string = first.0 == 0 && first.2 == 3;          // universal BIT STRING
        let is_override   = first.0 == 2 && first.1 && first.2 == 0; // ctx constructed tag 0
        if is_bit_string || is_override {
            data = &data[first.4..];
        } else {
            break;
        }
    }
    std::borrow::Cow::Borrowed(data)
}