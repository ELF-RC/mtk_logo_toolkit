//! MKIMG part_hdr_t binary format parsing and rebuilding.

pub const PART_MAGIC: u32 = 0x58881688;
pub const PART_HDR_SIZE: usize = 512;
pub const IMG_TYPE_GROUP_CERT: u32 = 0x02 << 24;
pub const IMG_TYPE_CERT2: u32 = IMG_TYPE_GROUP_CERT | 0x02;

/// 80-byte part_hdr_t core fields (the full header is 512 bytes).
/// Format: `<II32sIIIIIIIIII` = 4+4+32+4*11 = 80 bytes
#[derive(Debug, Clone)]
pub struct PartHdr {
    pub magic: u32,
    pub dsize: u32,
    pub name: String,
    pub maddr: u32,
    pub mode: u32,
    pub ext_magic: u32,
    pub hdr_sz: u32,
    pub hdr_ver: u32,
    pub img_type: u32,
    pub img_list_end: u32,
    pub align_sz: u32,
    pub dsize_extend: u32,
    pub maddr_extend: u32,
    pub raw: Vec<u8>, // full 512-byte header
}

impl PartHdr {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 80 {
            anyhow::bail!("short part_hdr_t: got {} bytes", data.len());
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let dsize = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let name_bytes = &data[8..40];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let maddr = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let mode = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let ext_magic = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let hdr_sz = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let hdr_ver = u32::from_le_bytes(data[56..60].try_into().unwrap());
        let img_type = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let img_list_end = u32::from_le_bytes(data[64..68].try_into().unwrap());
        let align_sz = u32::from_le_bytes(data[68..72].try_into().unwrap());
        let dsize_extend = u32::from_le_bytes(data[72..76].try_into().unwrap());
        let maddr_extend = u32::from_le_bytes(data[76..80].try_into().unwrap());

        let raw = data[..PART_HDR_SIZE.min(data.len())].to_vec();

        Ok(Self {
            magic, dsize, name, maddr, mode, ext_magic, hdr_sz, hdr_ver,
            img_type, img_list_end, align_sz, dsize_extend, maddr_extend, raw,
        })
    }

    pub fn padded_data_size(&self) -> usize {
        roundup(self.dsize as usize, self.align_sz as usize)
    }
}

pub fn roundup(value: usize, align: usize) -> usize {
    if align == 0 { return value; }
    ((value + align - 1) / align) * align
}

/// One parsed part in the image: header + raw data (unpadded).
#[derive(Clone)]
pub struct Part {
    pub hdr: PartHdr,
    pub off: usize,
    pub data_off: usize,
    pub data: Vec<u8>,
}

/// Parse all part_hdr_t entries from image bytes.
pub fn parse_parts(data: &[u8]) -> Vec<Part> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + PART_HDR_SIZE <= data.len() {
        let hdr = match PartHdr::parse(&data[off..]) {
            Ok(h) => h,
            Err(_) => break,
        };
        if hdr.magic != PART_MAGIC { break; }
        let data_off = off + PART_HDR_SIZE;
        let padded = hdr.padded_data_size();
        if data_off + hdr.dsize as usize > data.len() { break; }
        let data = data[data_off..data_off + hdr.dsize as usize].to_vec();
        out.push(Part { hdr, off, data_off, data });
        off = data_off + padded;
        if out.last().unwrap().hdr.img_list_end != 0 { break; }
    }
    out
}

/// Rebuild the complete MKIMG from parts, updating dsize in each header.
pub fn rebuild_parts(parts: &[Part]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        let mut hraw = p.hdr.raw.clone();
        // update dsize at offset 4
        hraw[4..8].copy_from_slice(&(p.hdr.dsize).to_le_bytes());
        out.extend_from_slice(&hraw);
        out.extend_from_slice(&p.data);
        let pad = roundup(p.hdr.dsize as usize, p.hdr.align_sz as usize) - p.data.len();
        out.extend(std::iter::repeat(0u8).take(pad));
    }
    out
}
