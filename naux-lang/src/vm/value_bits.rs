//! NaN-tagged value helpers for JIT/typed VM.

pub const QNAN_MASK: u64 = 0x7ff8_0000_0000_0000;
pub const TAG_SHIFT: u64 = 48;
pub const TAG_MASK: u64 = 0x0007_0000_0000_0000;
pub const PAYLOAD_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

pub const TAG_LIST: u64 = 1;
pub const TAG_TEXT: u64 = 2;
pub const TAG_MAP: u64 = 3;
pub const TAG_NULL: u64 = 4;
pub const TAG_TEXT_SMALL: u64 = 5; // 5-bit (len<=8)
pub const TAG_TEXT_SMALL6: u64 = 6; // 6-bit (len<=7)

pub const SMALL_TEXT_MAX_LEN: usize = 8;

pub fn is_tagged(bits: u64) -> bool {
    (bits & QNAN_MASK) == QNAN_MASK
}

pub fn tag_of(bits: u64) -> Option<u64> {
    if is_tagged(bits) {
        Some((bits & TAG_MASK) >> TAG_SHIFT)
    } else {
        None
    }
}

pub fn payload(bits: u64) -> u64 {
    bits & PAYLOAD_MASK
}

pub fn tag_ptr(ptr: u64, tag: u64) -> u64 {
    QNAN_MASK | ((tag & 0x7) << TAG_SHIFT) | (ptr & PAYLOAD_MASK)
}

pub fn is_text_tag(tag: u64) -> bool {
    tag == TAG_TEXT || tag == TAG_TEXT_SMALL || tag == TAG_TEXT_SMALL6
}

pub fn is_text(bits: u64) -> bool {
    tag_of(bits).map(is_text_tag).unwrap_or(false)
}

pub fn tag_small_text(payload: u64) -> u64 {
    QNAN_MASK | ((TAG_TEXT_SMALL & 0x7) << TAG_SHIFT) | (payload & PAYLOAD_MASK)
}

pub fn tag_small_text6(payload: u64) -> u64 {
    QNAN_MASK | ((TAG_TEXT_SMALL6 & 0x7) << TAG_SHIFT) | (payload & PAYLOAD_MASK)
}

fn encode_small_text5(s: &str) -> Option<u64> {
    if s.len() > SMALL_TEXT_MAX_LEN {
        return None;
    }
    let mut payload: u64 = (s.len() as u64) & 0xF;
    let mut shift = 4u64;
    for b in s.bytes() {
        let code = if b.is_ascii_lowercase() {
            (b - b'a') as u64
        } else if (b'0'..=b'5').contains(&b) {
            26 + (b - b'0') as u64
        } else {
            return None;
        };
        payload |= (code & 0x1F) << shift;
        shift += 5;
    }
    Some(tag_small_text(payload))
}

fn encode_small_text6(s: &str) -> Option<u64> {
    if s.len() > 7 {
        return None;
    }
    let mut payload: u64 = (s.len() as u64) & 0xF;
    let mut shift = 4u64;
    for b in s.bytes() {
        let code = if b.is_ascii_lowercase() {
            (b - b'a') as u64
        } else if b.is_ascii_uppercase() {
            26 + (b - b'A') as u64
        } else if b.is_ascii_digit() {
            52 + (b - b'0') as u64
        } else if b == b'_' {
            62
        } else if b == b'.' {
            63
        } else {
            return None;
        };
        payload |= (code & 0x3F) << shift;
        shift += 6;
    }
    Some(tag_small_text6(payload))
}

pub fn encode_small_text(s: &str) -> Option<u64> {
    encode_small_text6(s).or_else(|| encode_small_text5(s))
}

fn decode_small_text5(bits: u64) -> Option<String> {
    let payload_bits = payload(bits);
    let len = (payload_bits & 0xF) as usize;
    if len > SMALL_TEXT_MAX_LEN {
        return None;
    }
    let mut out = String::with_capacity(len);
    for i in 0..len {
        let shift = 4 + (i as u64) * 5;
        let code = ((payload_bits >> shift) & 0x1F) as u8;
        let ch = if code < 26 {
            (b'a' + code) as char
        } else if code < 32 {
            (b'0' + (code - 26)) as char
        } else {
            return None;
        };
        out.push(ch);
    }
    Some(out)
}

fn decode_small_text6(bits: u64) -> Option<String> {
    let payload_bits = payload(bits);
    let len = (payload_bits & 0xF) as usize;
    if len > 7 {
        return None;
    }
    let mut out = String::with_capacity(len);
    for i in 0..len {
        let shift = 4 + (i as u64) * 6;
        let code = ((payload_bits >> shift) & 0x3F) as u8;
        let ch = if code < 26 {
            (b'a' + code) as char
        } else if code < 52 {
            (b'A' + (code - 26)) as char
        } else if code < 62 {
            (b'0' + (code - 52)) as char
        } else if code == 62 {
            '_'
        } else if code == 63 {
            '.'
        } else {
            return None;
        };
        out.push(ch);
    }
    Some(out)
}

pub fn decode_small_text(bits: u64) -> Option<String> {
    match tag_of(bits) {
        Some(tag) if tag == TAG_TEXT_SMALL => decode_small_text5(bits),
        Some(tag) if tag == TAG_TEXT_SMALL6 => decode_small_text6(bits),
        _ => None,
    }
}

pub fn small_text_len(bits: u64) -> Option<usize> {
    match tag_of(bits) {
        Some(tag) if tag == TAG_TEXT_SMALL => {
            let payload_bits = payload(bits);
            let len = (payload_bits & 0xF) as usize;
            if len > SMALL_TEXT_MAX_LEN {
                None
            } else {
                Some(len)
            }
        }
        Some(tag) if tag == TAG_TEXT_SMALL6 => {
            let payload_bits = payload(bits);
            let len = (payload_bits & 0xF) as usize;
            if len > 7 {
                None
            } else {
                Some(len)
            }
        }
        _ => None,
    }
}

pub fn tag_null() -> u64 {
    QNAN_MASK | ((TAG_NULL & 0x7) << TAG_SHIFT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_text6_roundtrip() {
        let s = "name_1";
        let bits = encode_small_text(s).expect("encode");
        assert!(is_text(bits));
        let decoded = decode_small_text(bits).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn small_text5_roundtrip_len8() {
        let s = "abcdefgh";
        let bits = encode_small_text(s).expect("encode");
        let decoded = decode_small_text(bits).expect("decode");
        assert_eq!(decoded, s);
    }
}
