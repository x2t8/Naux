//! Minimal, bounded PE resource reader for the canonical NAUX Learn icon.
//!
//! This avoids hashing the raw `.rsrc` section: resource directory entries
//! contain image-layout RVAs, so a harmless code-size change can alter that
//! section. Instead we reconstruct the semantic ICO from RT_GROUP_ICON and
//! RT_ICON payloads and compare its bytes with the canonical source ICO.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::core::encoding::sha256;

const PE_MAX_BYTES: u64 = 32 * 1024 * 1024;
const RESOURCE_MAX_BYTES: usize = 1024 * 1024;
const SECTION_MAX_COUNT: usize = 96;
const ICON_MAX_COUNT: usize = 32;
const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsIconError {
    message: String,
}

impl WindowsIconError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WindowsIconError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WindowsIconError {}

#[derive(Clone, Copy, Debug)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

#[derive(Clone, Copy, Debug)]
struct ResourceEntry {
    id: u32,
    target: u32,
    is_directory: bool,
}

pub fn verify_windows_icon_resource(
    executable: &Path,
    canonical_icon: &Path,
) -> Result<String, WindowsIconError> {
    let executable_bytes = read_bounded(executable, PE_MAX_BYTES, "Windows executable")?;
    let icon_bytes = read_bounded(
        canonical_icon,
        RESOURCE_MAX_BYTES as u64,
        "canonical Windows icon",
    )?;
    let reconstructed = reconstruct_icon(&executable_bytes)?;
    if reconstructed != icon_bytes {
        return Err(WindowsIconError::new(
            "Windows executable icon resource differs from the canonical ICO",
        ));
    }
    Ok(hex_encode(&sha256(&reconstructed)))
}

fn reconstruct_icon(bytes: &[u8]) -> Result<Vec<u8>, WindowsIconError> {
    if bytes.len() < 64 || &bytes[..2] != b"MZ" {
        return Err(WindowsIconError::new(
            "Windows executable has invalid DOS magic",
        ));
    }
    let pe_offset = u32_at(bytes, 0x3c)? as usize;
    if slice(bytes, pe_offset, 4)? != b"PE\0\0" {
        return Err(WindowsIconError::new(
            "Windows executable has invalid PE magic",
        ));
    }
    let coff = pe_offset
        .checked_add(4)
        .ok_or_else(|| WindowsIconError::new("PE header offset overflow"))?;
    let section_count = u16_at(bytes, coff + 2)? as usize;
    if section_count == 0 || section_count > SECTION_MAX_COUNT {
        return Err(WindowsIconError::new(
            "PE section count is outside the admitted bound",
        ));
    }
    let optional_size = u16_at(bytes, coff + 16)? as usize;
    let optional = coff + 20;
    if u16_at(bytes, optional)? != 0x20b || optional_size < 160 {
        return Err(WindowsIconError::new(
            "Windows executable is not a bounded PE32+ image",
        ));
    }
    let directory_count = u32_at(bytes, optional + 108)?;
    if directory_count <= 2 {
        return Err(WindowsIconError::new(
            "PE resource data directory is missing",
        ));
    }
    let resource_rva = u32_at(bytes, optional + 112 + 2 * 8)?;
    let resource_size = u32_at(bytes, optional + 112 + 2 * 8 + 4)? as usize;
    if resource_rva == 0 || resource_size == 0 || resource_size > RESOURCE_MAX_BYTES {
        return Err(WindowsIconError::new(
            "PE resource directory is empty or exceeds its bound",
        ));
    }

    let section_table = optional
        .checked_add(optional_size)
        .ok_or_else(|| WindowsIconError::new("PE section table offset overflow"))?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table
            .checked_add(index * 40)
            .ok_or_else(|| WindowsIconError::new("PE section table overflow"))?;
        slice(bytes, offset, 40)?;
        sections.push(Section {
            virtual_size: u32_at(bytes, offset + 8)?,
            virtual_address: u32_at(bytes, offset + 12)?,
            raw_size: u32_at(bytes, offset + 16)?,
            raw_offset: u32_at(bytes, offset + 20)?,
        });
    }
    let resource_base = rva_to_offset(resource_rva, resource_size, &sections, bytes.len())?;
    slice(bytes, resource_base, resource_size)?;

    let root = directory_entries(bytes, resource_base, 0, resource_size)?;
    let group_type = exact_id(&root, RT_GROUP_ICON, true, "RT_GROUP_ICON")?;
    let icon_type = exact_id(&root, RT_ICON, true, "RT_ICON")?;
    let group_names = directory_entries(
        bytes,
        resource_base,
        group_type.target as usize,
        resource_size,
    )?;
    if group_names.len() != 1 || !group_names[0].is_directory {
        return Err(WindowsIconError::new(
            "NAUX PE must contain exactly one icon group name",
        ));
    }
    let group_languages = directory_entries(
        bytes,
        resource_base,
        group_names[0].target as usize,
        resource_size,
    )?;
    if group_languages.len() != 1 || group_languages[0].is_directory {
        return Err(WindowsIconError::new(
            "NAUX PE icon group must contain exactly one language payload",
        ));
    }
    let group = resource_data(
        bytes,
        resource_base,
        group_languages[0].target as usize,
        resource_size,
        &sections,
    )?;

    let icon_names = directory_entries(
        bytes,
        resource_base,
        icon_type.target as usize,
        resource_size,
    )?;
    let mut icons = BTreeMap::new();
    for name in icon_names {
        if !name.is_directory || icons.contains_key(&name.id) {
            return Err(WindowsIconError::new(
                "PE RT_ICON name tree is noncanonical",
            ));
        }
        let languages =
            directory_entries(bytes, resource_base, name.target as usize, resource_size)?;
        if languages.len() != 1 || languages[0].is_directory {
            return Err(WindowsIconError::new(
                "each PE icon must contain exactly one language payload",
            ));
        }
        let data = resource_data(
            bytes,
            resource_base,
            languages[0].target as usize,
            resource_size,
            &sections,
        )?;
        icons.insert(name.id, data);
    }

    reconstruct_ico(group, &icons)
}

fn reconstruct_ico(
    group: &[u8],
    icons: &BTreeMap<u32, &[u8]>,
) -> Result<Vec<u8>, WindowsIconError> {
    if group.len() < 6 || u16_at(group, 0)? != 0 || u16_at(group, 2)? != 1 {
        return Err(WindowsIconError::new("PE icon group header is invalid"));
    }
    let count = u16_at(group, 4)? as usize;
    if count == 0 || count > ICON_MAX_COUNT || group.len() != 6 + count * 14 {
        return Err(WindowsIconError::new(
            "PE icon group count or length is noncanonical",
        ));
    }
    if icons.len() != count {
        return Err(WindowsIconError::new(
            "PE icon group does not reference the complete RT_ICON set",
        ));
    }

    let data_start = 6_usize
        .checked_add(count * 16)
        .ok_or_else(|| WindowsIconError::new("ICO directory length overflow"))?;
    let mut result = Vec::new();
    result.extend_from_slice(&[0, 0, 1, 0]);
    result.extend_from_slice(&(count as u16).to_le_bytes());
    let mut images = Vec::with_capacity(count);
    let mut image_offset = data_start;
    for index in 0..count {
        let entry = 6 + index * 14;
        let declared_size = u32_at(group, entry + 8)? as usize;
        let icon_id = u16_at(group, entry + 12)? as u32;
        let image = icons
            .get(&icon_id)
            .ok_or_else(|| WindowsIconError::new("PE icon group references a missing icon ID"))?;
        if declared_size != image.len() || image_offset > u32::MAX as usize {
            return Err(WindowsIconError::new(
                "PE icon group size or reconstructed offset is invalid",
            ));
        }
        result.extend_from_slice(slice(group, entry, 8)?);
        result.extend_from_slice(&(declared_size as u32).to_le_bytes());
        result.extend_from_slice(&(image_offset as u32).to_le_bytes());
        image_offset = image_offset
            .checked_add(image.len())
            .ok_or_else(|| WindowsIconError::new("ICO image length overflow"))?;
        if image_offset > RESOURCE_MAX_BYTES {
            return Err(WindowsIconError::new("reconstructed ICO exceeds its bound"));
        }
        images.push(*image);
    }
    for image in images {
        result.extend_from_slice(image);
    }
    Ok(result)
}

fn directory_entries(
    bytes: &[u8],
    base: usize,
    relative: usize,
    resource_size: usize,
) -> Result<Vec<ResourceEntry>, WindowsIconError> {
    let directory = resource_offset(base, relative, 16, resource_size)?;
    let named = u16_at(bytes, directory + 12)? as usize;
    let ids = u16_at(bytes, directory + 14)? as usize;
    if named != 0 {
        return Err(WindowsIconError::new(
            "NAUX icon resources must use numeric directory IDs",
        ));
    }
    let count = named
        .checked_add(ids)
        .filter(|count| *count <= ICON_MAX_COUNT + 16)
        .ok_or_else(|| WindowsIconError::new("PE resource directory entry count exceeds bound"))?;
    let table_size = count
        .checked_mul(8)
        .ok_or_else(|| WindowsIconError::new("PE resource entry table overflow"))?;
    let table_relative = relative
        .checked_add(16)
        .ok_or_else(|| WindowsIconError::new("PE resource entry table offset overflow"))?;
    let table = resource_offset(base, table_relative, table_size, resource_size)?;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = table + index * 8;
        let name = u32_at(bytes, offset)?;
        if name & 0x8000_0000 != 0 {
            return Err(WindowsIconError::new(
                "NAUX icon resources must not use named entries",
            ));
        }
        let target = u32_at(bytes, offset + 4)?;
        entries.push(ResourceEntry {
            id: name,
            target: target & 0x7fff_ffff,
            is_directory: target & 0x8000_0000 != 0,
        });
    }
    Ok(entries)
}

fn exact_id<'a>(
    entries: &'a [ResourceEntry],
    id: u32,
    directory: bool,
    label: &str,
) -> Result<&'a ResourceEntry, WindowsIconError> {
    let mut matches = entries
        .iter()
        .filter(|entry| entry.id == id && entry.is_directory == directory);
    let found = matches
        .next()
        .ok_or_else(|| WindowsIconError::new(format!("PE resource tree is missing {label}")))?;
    if matches.next().is_some() {
        return Err(WindowsIconError::new(format!(
            "PE resource tree duplicates {label}"
        )));
    }
    Ok(found)
}

fn resource_data<'a>(
    bytes: &'a [u8],
    base: usize,
    relative: usize,
    resource_size: usize,
    sections: &[Section],
) -> Result<&'a [u8], WindowsIconError> {
    let entry = resource_offset(base, relative, 16, resource_size)?;
    let data_rva = u32_at(bytes, entry)?;
    let size = u32_at(bytes, entry + 4)? as usize;
    if size == 0 || size > RESOURCE_MAX_BYTES {
        return Err(WindowsIconError::new(
            "PE icon resource data size is invalid",
        ));
    }
    let offset = rva_to_offset(data_rva, size, sections, bytes.len())?;
    slice(bytes, offset, size)
}

fn resource_offset(
    base: usize,
    relative: usize,
    size: usize,
    resource_size: usize,
) -> Result<usize, WindowsIconError> {
    let end = relative
        .checked_add(size)
        .filter(|end| *end <= resource_size)
        .ok_or_else(|| WindowsIconError::new("PE resource-relative offset exceeds directory"))?;
    let _ = end;
    base.checked_add(relative)
        .ok_or_else(|| WindowsIconError::new("PE resource file offset overflow"))
}

fn rva_to_offset(
    rva: u32,
    size: usize,
    sections: &[Section],
    file_len: usize,
) -> Result<usize, WindowsIconError> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.saturating_add(span);
        if rva >= section.virtual_address && rva < end {
            let relative = (rva - section.virtual_address) as usize;
            if relative
                .checked_add(size)
                .filter(|end| *end <= section.raw_size as usize)
                .is_none()
            {
                return Err(WindowsIconError::new(
                    "PE resource payload exceeds section raw data",
                ));
            }
            let offset = (section.raw_offset as usize)
                .checked_add(relative)
                .ok_or_else(|| WindowsIconError::new("PE resource file offset overflow"))?;
            slice_len(file_len, offset, size)?;
            return Ok(offset);
        }
    }
    Err(WindowsIconError::new(
        "PE resource RVA does not map to a section",
    ))
}

fn read_bounded(path: &Path, max: u64, label: &str) -> Result<Vec<u8>, WindowsIconError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        WindowsIconError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max {
        return Err(WindowsIconError::new(format!(
            "{label} must be a regular non-symlink file no larger than {max} bytes"
        )));
    }
    fs::read(path).map_err(|error| {
        WindowsIconError::new(format!("cannot read {label} `{}`: {error}", path.display()))
    })
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, WindowsIconError> {
    let data: [u8; 2] = slice(bytes, offset, 2)?
        .try_into()
        .expect("bounded two-byte slice");
    Ok(u16::from_le_bytes(data))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, WindowsIconError> {
    let data: [u8; 4] = slice(bytes, offset, 4)?
        .try_into()
        .expect("bounded four-byte slice");
    Ok(u32::from_le_bytes(data))
}

fn slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], WindowsIconError> {
    let end = slice_len(bytes.len(), offset, size)?;
    Ok(&bytes[offset..end])
}

fn slice_len(file_len: usize, offset: usize, size: usize) -> Result<usize, WindowsIconError> {
    offset
        .checked_add(size)
        .filter(|end| *end <= file_len)
        .ok_or_else(|| WindowsIconError::new("PE structure exceeds executable bounds"))
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
