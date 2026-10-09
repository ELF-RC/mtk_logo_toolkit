//! ASN.1 DER TLV encoding and decoding (pure Rust, minimal).

pub const OID_IMAGE_HASH: &str = "2.16.886.2454.2.1";
pub const OID_IMAGE_HEADER_HASH: &str = "2.16.886.2454.2.4";

// ---- length ----

pub fn encode_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let s = n.to_be_bytes();
        // trim leading zeros
        let start = s.iter().position(|&b| b != 0).unwrap_or(s.len() - 1);
        let trimmed = &s[start..];
        let mut out = Vec::with_capacity(1 + trimmed.len());
        out.push(0x80 | trimmed.len() as u8);
        out.extend_from_slice(trimmed);
        out
    }
}

pub fn read_length(data: &[u8], off: usize) -> Result<(usize, usize), String> {
    if off >= data.len() { return Err("truncated length".into()); }
    let b = data[off];
    if b & 0x80 == 0 {
        return Ok((b as usize, 1));
    }
    let num = (b & 0x7F) as usize;
    if num == 0 { return Err("indefinite length not supported".into()); }
    if off + 1 + num > data.len() { return Err("truncated length bytes".into()); }
    let mut val = 0usize;
    for i in 0..num {
        val = (val << 8) | data[off + 1 + i] as usize;
    }
    Ok((val, 1 + num))
}

// ---- tag ----

pub fn read_tag(data: &[u8], off: usize) -> Result<(u8, bool, u32, usize), String> {
    if off >= data.len() { return Err("truncated tag".into()); }
    let b0 = data[off];
    let tag_class = (b0 & 0xC0) >> 6;
    let constructed = b0 & 0x20 != 0;
    let tagnum = b0 & 0x1F;
    let mut tag_len = 1;
    let mut tagnum_full = tagnum as u32;
    if tagnum == 0x1F {
        tagnum_full = 0;
        let mut i = off + 1;
        loop {
            if i >= data.len() { return Err("truncated long-form tag".into()); }
            let b = data[i];
            tagnum_full = (tagnum_full << 7) | (b & 0x7F) as u32;
            i += 1;
            tag_len += 1;
            if b & 0x80 == 0 { break; }
        }
    }
    Ok((tag_class, constructed, tagnum_full, tag_len))
}

// ---- OID ----

pub fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid.split('.').map(|s| s.parse::<u64>().unwrap()).collect();
    let mut out = vec![40 * parts[0] as u8 + parts[1] as u8];
    for &p in &parts[2..] {
        if p == 0 {
            out.push(0);
            continue;
        }
        let mut chunks = Vec::new();
        let mut v = p;
        while v > 0 {
            chunks.insert(0, (v & 0x7F) as u8);
            v >>= 7;
        }
        for (i, &c) in chunks.iter().enumerate() {
            if i != chunks.len() - 1 {
                out.push(0x80 | c);
            } else {
                out.push(c);
            }
        }
    }
    out
}

pub fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let first = bytes[0] as u64;
    let mut parts: Vec<u64> = vec![first / 40, first % 40];
    let mut val = 0u64;
    for &b in &bytes[1..] {
        val = (val << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            parts.push(val);
            val = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

// ---- TLV builders ----

pub fn build_oid_tlv(oid: &str) -> Vec<u8> {
    let b = encode_oid(oid);
    let mut out = vec![0x06];
    out.extend(encode_length(b.len()));
    out.extend(b);
    out
}

pub fn build_bitstring_tlv(payload: &[u8]) -> Vec<u8> {
    let mut val = vec![0x00]; // 0 unused bits
    val.extend_from_slice(payload);
    let mut out = vec![0x03];
    out.extend(encode_length(val.len()));
    out.extend(val);
    out
}

// ---- DER tree (arena-based) ----

#[derive(Debug, Clone)]
pub struct DerNode {
    pub tag_class: u8,
    pub constructed: bool,
    pub tagnum: u32,
    pub hdr_len: usize,
    pub length: usize,
    pub val: Option<Vec<u8>>,
    pub children: Option<Vec<DerNode>>,
}

pub fn parse_tlv_tree(data: &[u8]) -> Vec<DerNode> {
    let mut nodes = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let (tag_class, constructed, tagnum, tag_len) = match read_tag(data, off) {
            Ok(v) => v,
            Err(_) => break,
        };
        let (length, len_len) = match read_length(data, off + tag_len) {
            Ok(v) => v,
            Err(_) => break,
        };
        let hdr_len = tag_len + len_len;
        let val_off = off + hdr_len;
        let val_end = val_off + length;
        if val_end > data.len() { break; }
        let val_slice = &data[val_off..val_end];
        let children = if constructed {
            Some(parse_tlv_tree(val_slice))
        } else {
            None
        };
        let val = if constructed { None } else { Some(val_slice.to_vec()) };
        nodes.push(DerNode {
            tag_class, constructed, tagnum, hdr_len, length, val, children,
        });
        off = val_end;
    }
    nodes
}

/// Find the BIT STRING value (including unused-bits prefix) following a given OID
/// anywhere in the DER tree.
pub fn find_oid_bitstring(der: &[u8], oid_str: &str) -> Option<Vec<u8>> {
    let root_nodes = parse_tlv_tree(der);
    fn walk(nodes: &[DerNode], oid_str: &str) -> Option<Vec<u8>> {
        for (i, node) in nodes.iter().enumerate() {
            if node.tag_class == 0 && node.tagnum == 6 {
                if let Some(ref val) = node.val {
                    if decode_oid(val) == oid_str {
                        // look at subsequent siblings
                        for j in (i + 1)..nodes.len() {
                            if let Some(bs) = find_bitstring_in_node(&nodes[j]) {
                                return Some(bs);
                            }
                        }
                        return None;
                    }
                }
            }
            if let Some(ref children) = node.children {
                if let Some(bs) = walk(children, oid_str) {
                    return Some(bs);
                }
            }
        }
        None
    }
    fn find_bitstring_in_node(node: &DerNode) -> Option<Vec<u8>> {
        if node.tag_class == 0 && node.tagnum == 3 {
            if let Some(ref val) = node.val {
                return Some(val.clone());
            }
        }
        if let Some(ref children) = node.children {
            for ch in children {
                if let Some(bs) = find_bitstring_in_node(ch) {
                    return Some(bs);
                }
            }
        }
        None
    }
    walk(&root_nodes, oid_str)
}

/// Parse the first TLV at offset 0; return (tag_class, constructed, tagnum, val_off, val_end).
pub fn find_first_tlv(data: &[u8]) -> Option<(u8, bool, u32, usize, usize)> {
    if data.is_empty() { return None; }
    let (tag_class, constructed, tagnum, tag_len) = read_tag(data, 0).ok()?;
    let (length, len_len) = read_length(data, tag_len).ok()?;
    let val_off = tag_len + len_len;
    let val_end = val_off + length;
    if val_end > data.len() { return None; }
    Some((tag_class, constructed, tagnum, val_off, val_end))
}

/// Iterate top-level TLVs, returning (off, end, tag_class, constructed, tagnum, val_off).
pub struct TopTlv {
    pub off: usize,
    pub end: usize,
    pub tag_class: u8,
    pub constructed: bool,
    pub tagnum: u32,
    pub val_off: usize,
}

pub fn iter_top_level_tlvs(data: &[u8]) -> Vec<TopTlv> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let first = match find_first_tlv(&data[off..]) {
            Some(f) => f,
            None => break,
        };
        let (tag_class, constructed, tagnum, val_off, val_end) = first;
        out.push(TopTlv {
            off,
            end: off + val_end,
            tag_class,
            constructed,
            tagnum,
            val_off: off + val_off,
        });
        off += val_end;
    }
    out
}

/// Locate the original CERT2 DER SEQUENCE (0x30) in the blob.
/// Returns (der_bytes, rel_offset).
pub fn find_original_cert2_der(der: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    for node in iter_top_level_tlvs(der) {
        if node.tag_class == 0 && node.constructed && node.tagnum == 0x10 {
            return Ok((&der[node.off..node.end], node.off));
        }
    }
    anyhow::bail!("original CERT2 DER SEQUENCE (0x30) not found")
}

/// Strip any legacy BIT STRING wrapper and 0xA0 override block prepended by a
/// previous install, so re-installing is idempotent.
pub fn recover_original_der(der: &[u8]) -> &[u8] {
    let mut data = der;
    loop {
        let first = match find_first_tlv(data) {
            Some(f) => f,
            None => break,
        };
        let is_bitstring = first.0 == 0 && first.2 == 3; // universal BIT STRING
        let is_override = first.0 == 2 && first.1 && first.2 == 0; // ctx cons tag 0 (0xA0)
        if is_bitstring || is_override {
            data = &data[first.4..];
        } else {
            break;
        }
    }
    data
}
