//! RFC 8216 attribute-list helpers (quoted-string aware).
//!
//! RFC 8216 §4.2 attribute lists are comma-separated `NAME=value`
//! pairs where the value is a quoted-string (no escaping — a
//! quoted-string cannot contain `"`), a hexadecimal-sequence, a
//! decimal-floating-point, a signed-decimal or an enum. The splitter
//! here is the lenient superset used by real-world packs: split on
//! commas **outside** double quotes, then split each item on the first
//! `=`, strip surrounding double quotes from the value. Attribute
//! names are matched case-sensitively (the RFC fixes uppercase).

/// One parsed attribute (`name`, `value` with quotes stripped).
pub(crate) struct Attr<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Split an attribute list (the text after `#EXT-…:`), preserving
/// commas inside quoted values. Malformed items (no `=`) are skipped,
/// not fatal — callers decide which attributes are REQUIRED.
pub(crate) fn parse_attr_list(input: &str) -> Vec<Attr<'_>> {
    let mut out = Vec::new();
    for item in split_attr_items(input) {
        if let Some(eq) = item.find('=') {
            let name = item[..eq].trim();
            let mut value = item[eq + 1..].trim();
            if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                value = &value[1..value.len() - 1];
            }
            out.push(Attr { name, value });
        }
    }
    out
}

/// Look one attribute up (last occurrence wins, as consumers of
/// duplicate attributes usually re-apply).
pub(crate) fn attr<'a>(list: &'a [Attr<'_>], name: &str) -> Option<&'a str> {
    let mut found = None;
    for a in list {
        if a.name == name {
            found = Some(a.value);
        }
    }
    found
}

/// Split on commas that are not inside a quoted value.
fn split_attr_items(input: &str) -> impl Iterator<Item = &str> {
    let mut parts = Vec::new();
    let mut depth_quote = false;
    let mut start = 0;
    for (i, ch) in input.char_indices() {
        match ch {
            '"' => depth_quote = !depth_quote,
            ',' if !depth_quote => {
                parts.push(&input[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts.into_iter()
}

/// Parse `IV=0x…` into 16 bytes (32 hex digits, optional `0x`/`0X`
/// prefix, case-insensitive digits).
pub(crate) fn parse_hex_iv(value: &str) -> Option<[u8; 16]> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut iv = [0u8; 16];
    for (i, byte) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (byte[0] as char).to_digit(16);
        let lo = (byte[1] as char).to_digit(16);
        iv[i] = ((hi.unwrap_or(0) << 4) | lo.unwrap_or(0)) as u8;
    }
    Some(iv)
}

/// Parse `RESOLUTION=<W>x<H>` (both limbs required, decimal).
pub(crate) fn parse_resolution(value: &str) -> Option<(u32, u32)> {
    let (w, h) = value.split_once('x')?;
    let w = w.trim().parse::<u32>().ok()?;
    let h = h.trim().parse::<u32>().ok()?;
    Some((w, h))
}

/// Parse the `<n>[@<o>]` byte-range form used by the EXT-X-BYTERANGE
/// tag and the EXT-X-MAP `BYTERANGE` attribute: returns
/// `(length, offset?)`. A zero-length sub-range is rejected (it names
/// no bytes — fuzz-found degenerate form).
pub(crate) fn parse_byterange(value: &str) -> Option<(u64, Option<u64>)> {
    let (len, off) = match value.split_once('@') {
        Some((l, o)) => (l, Some(o.trim().parse::<u64>().ok()?)),
        None => (value, None),
    };
    let len = len.trim().parse::<u64>().ok()?;
    (len > 0).then_some((len, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(input: &str, name: &str) -> Option<String> {
        attr(&parse_attr_list(input), name).map(str::to_owned)
    }

    #[test]
    fn splits_outside_quotes() {
        let list = parse_attr_list(
            r#"METHOD=AES-128,URI="https://k.example/?a=1,b=2",IV=0X00112233445566778899aabbccddeeff"#,
        );
        assert_eq!(list.len(), 3);
        assert_eq!(values(r#"URI="a,b",X=1"#, "URI").as_deref(), Some("a,b"));
    }

    #[test]
    fn iv_and_resolution_and_range_forms() {
        assert_eq!(
            parse_hex_iv("0x00112233445566778899aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert_eq!(parse_hex_iv("0x1234"), None);
        assert_eq!(parse_resolution("1920x1080"), Some((1920, 1080)));
        assert_eq!(parse_resolution("1920"), None);
        assert_eq!(parse_byterange("720@0"), Some((720, Some(0))));
        assert_eq!(parse_byterange("720"), Some((720, None)));
        assert_eq!(parse_byterange("x@y"), None);
    }
}
