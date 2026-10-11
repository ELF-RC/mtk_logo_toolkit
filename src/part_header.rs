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

//! MKIMG part_hdr_t binary format: parsing and rebuilding.
//!
//! Each MTK image partition starts with a 512-byte `part_hdr_t` header
//! (80 bytes of meaningful fields + padding). The header is followed by
//! the partition data, padded to `align_sz` boundaries.

/// Magic number identifying a valid `part_hdr_t`.
pub const PART_MAGIC: u32 = 0x5888_1688;
/// Total size of a single part header (including padding).
pub const PART_HEADER_SIZE: usize = 512;
/// Image type flag for certificate-group partitions.
pub const IMAGE_TYPE_GROUP_CERT: u32 = 0x02 << 24;
/// Image type for CERT2 (the second certificate chain stage).
pub const IMAGE_TYPE_CERT2: u32 = IMAGE_TYPE_GROUP_CERT | 0x02;

/// 80-byte `part_hdr_t` core fields. The full on-disk header is 512 bytes;
/// the remaining bytes are zero-padding and are stored in `raw`.
///
/// Binary layout: `<II32sIIIIIIIIII` = 4+4+32+4*11 = 80 bytes.
#[derive(Debug, Clone)]
pub struct PartHeader {
    /// Magic number, must be `PART_MAGIC`.
    pub magic: u32,
    /// Unpadded data size in bytes.
    pub data_size: u32,
    /// Partition name (NUL-terminated, max 32 bytes).
    pub name: String,
    /// Load address (informational, not used for packing).
    pub load_addr: u32,
    /// Mode flags (informational).
    pub mode: u32,
    /// Extended magic number for newer header versions.
    pub ext_magic: u32,
    /// Size of this header struct on disk (should be 512).
    pub header_size: u32,
    /// Header format version.
    pub header_version: u32,
    /// Image type (e.g. logo=0, cert2=0x02000002).
    pub image_type: u32,
    /// Non-zero marks the last header in the chain.
    pub is_list_end: u32,
    /// Alignment boundary for data padding (typically 16).
    pub align_size: u32,
    /// Upper 32 bits of data size (for >4 GiB images; always 0 here).
    pub data_size_ext: u32,
    /// Upper 32 bits of load address (always 0 here).
    pub load_addr_ext: u32,
    /// Full 512-byte raw header, preserved verbatim.
    pub raw: Vec<u8>,
}

impl PartHeader {
    /// Parse a `part_hdr_t` from the start of `data`.
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 80 {
            anyhow::bail!("short part_hdr_t: got {} bytes", data.len());
        }
        let magic         = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let data_size     = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let name_bytes    = &data[8..40];
        let name_end      = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name          = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let load_addr     = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let mode          = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let ext_magic     = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let header_size   = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let header_version= u32::from_le_bytes(data[56..60].try_into().unwrap());
        let image_type    = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let is_list_end   = u32::from_le_bytes(data[64..68].try_into().unwrap());
        let align_size    = u32::from_le_bytes(data[68..72].try_into().unwrap());
        let data_size_ext = u32::from_le_bytes(data[72..76].try_into().unwrap());
        let load_addr_ext = u32::from_le_bytes(data[76..80].try_into().unwrap());

        let raw = data[..PART_HEADER_SIZE.min(data.len())].to_vec();

        Ok(Self {
            magic, data_size, name, load_addr, mode, ext_magic,
            header_size, header_version, image_type, is_list_end,
            align_size, data_size_ext, load_addr_ext, raw,
        })
    }

    /// Padded data size: `data_size` rounded up to `align_size`.
    pub fn padded_data_size(&self) -> usize {
        round_up(self.data_size as usize, self.align_size as usize)
    }
}

/// Round `value` up to the next multiple of `align`.
pub fn round_up(value: usize, align: usize) -> usize {
    if align == 0 { return value; }
    ((value + align - 1) / align) * align
}

/// One parsed partition: header + raw (unpadded) data + bookkeeping offsets.
#[derive(Clone)]
pub struct ParsedPart {
    pub header: PartHeader,
    /// Offset of this header within the full image.
    pub header_offset: usize,
    /// Offset of the data (header_offset + 512) within the full image.
    pub data_offset: usize,
    /// Unpadded partition data.
    pub data: Vec<u8>,
}

/// Parse all `part_hdr_t` entries from image bytes.
pub fn parse_all_parts(image: &[u8]) -> Vec<ParsedPart> {
    let mut parts = Vec::new();
    let mut offset = 0usize;
    while offset + PART_HEADER_SIZE <= image.len() {
        let header = match PartHeader::parse(&image[offset..]) {
            Ok(h) => h,
            Err(_) => break,
        };
        if header.magic != PART_MAGIC { break; }
        let data_offset = offset + PART_HEADER_SIZE;
        if data_offset + header.data_size as usize > image.len() { break; }
        let data = image[data_offset..data_offset + header.data_size as usize].to_vec();
        parts.push(ParsedPart {
            header, header_offset: offset, data_offset, data,
        });
        offset = data_offset + parts.last().unwrap().header.padded_data_size();
        if parts.last().unwrap().header.is_list_end != 0 { break; }
    }
    parts
}

/// Rebuild the complete MKIMG from parsed parts, updating `data_size` in each header.
pub fn rebuild_image(parts: &[ParsedPart]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        let mut header_raw = part.header.raw.clone();
        // Update data_size at offset 4 (little-endian u32).
        header_raw[4..8].copy_from_slice(&(part.header.data_size).to_le_bytes());
        out.extend_from_slice(&header_raw);
        out.extend_from_slice(&part.data);
        let padding = round_up(part.header.data_size as usize, part.header.align_size as usize) - part.data.len();
        out.extend(std::iter::repeat(0u8).take(padding));
    }
    out
}