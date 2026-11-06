//! Client identification: peer_id prefix table + ext handshake `v` field
//! string matching -> [`PeerClient`]. Pure types, no IO.
//!
//! # Authority (BEP text > libtorrent > aria2)
//!
//! peer_id prefix semantics = the **Azureus-style convention** of BEP 20
//! (Peer ID Conventions): "first byte of the peer id is a `-` character
//! (0x2D hexadecimal), followed by two characters for the client id, four
//! ascii digits for the version number, followed by a `-`" (sample shape
//! `-AZ2060-...`). The built-in prefix table cites its source per entry.
//!
//! - `XL` -> Xunlei: BEP 20 Azureus-style table `'XL' - Xunlei`;
//! - `QD` -> QQDownload: BEP 20 table (libtorrent `identify_client.cpp`
//! `{"QD", "QQDownload"}` agrees);
//! - `FG` -> FlashGet: BEP 20 note "FlashGet uses Azureus style with FG
//! but without the trailing -" (i.e. `-FG0180...` with **no trailing
//! `-`** — this table matches the literal prefix, naturally compatible);
//! libtorrent `identify_client.cpp` `{0, "-FG", "FlashGet"}` agrees;
//! - `TT` -> TuoTu, `VG` -> Vagaa: BEP 20 tables;
//! - `SD` -> Xunlei: libtorrent `identify_client.cpp` `{"SD", "Xunlei"}`;
//! the two-character name table covers both the Az form `-SD0100-` and
//! the Shadow-style form `SD0100--`, so both prefixes are listed;
//! - `XF` -> Xfplay, `XS` -> XSwifter: libtorrent
//! `identify_client.cpp`;
//! - `QVOD` -> Qvod: libtorrent `identify_client.cpp` `{0, "QVOD",
//! "Qvod"}` (non-Az form, offset-0 literal prefix).
//!
//! `v` field matching = a case-insensitive **product name** substring of
//! what the peer self-reports in the BEP10 ext handshake `v` (client
//! name); the product names are the ones cited above. No aliases/variants
//! absent from a source are introduced (e.g. the `-XUNLEI` prefix: no
//! public peer_id table lists that form; per the no-invented-samples rule
//! it is not added — users can extend via the `client_ban_prefixes`
//! configuration).
//!
//! # Identification != banning
//!
//! This module only answers "who is the peer" (unknown ->
//! [`PeerClient::Unknown`], never guessed). Whether to refuse/disconnect
//! is entirely configuration-driven (`IpGuard::client_blocks` consumes
//! `client_ban_prefixes`; the default empty list bans no client).

/// Identified BT clients (built-in table hits; unknown ->
/// [`PeerClient::Unknown`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerClient {
    /// Unidentified (unknown prefix / not self-reported — never guessed).
    Unknown,
    /// Xunlei (Thunder).
    Xunlei,
    /// Tencent QQ Download.
    QQDownload,
    /// FlashGet.
    FlashGet,
    /// TuoTu.
    TuoTu,
    /// Vagaa.
    Vagaa,
    /// Xfplay.
    Xfplay,
    /// XSwifter.
    XSwifter,
    /// Qvod.
    Qvod,
}

impl PeerClient {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerClient::Unknown => "Unknown",
            PeerClient::Xunlei => "Xunlei",
            PeerClient::QQDownload => "QQDownload",
            PeerClient::FlashGet => "FlashGet",
            PeerClient::TuoTu => "TuoTu",
            PeerClient::Vagaa => "Vagaa",
            PeerClient::Xfplay => "Xfplay",
            PeerClient::XSwifter => "XSwifter",
            PeerClient::Qvod => "Qvod",
        }
    }
}

/// peer_id prefix table (literal byte prefixes; sources in the module
/// docs, per-entry `(prefix, client)`). The specific prefix (`-SD`)
/// precedes the loose one (`SD`).
const PEER_ID_PREFIXES: &[(&str, PeerClient)] = &[
    ("-XL", PeerClient::Xunlei),     // BEP 20 'XL' - Xunlei
    ("-SD", PeerClient::Xunlei),     // libtorrent identify_client.cpp (Azureus-style)
    ("SD", PeerClient::Xunlei),      // same, Shadow-style form (SD0100--)
    ("-QD", PeerClient::QQDownload), // BEP 20 'QD'; libtorrent
    ("-FG", PeerClient::FlashGet),   // BEP 20 (no trailing `-` note); libtorrent
    ("-TT", PeerClient::TuoTu),      // BEP 20 'TT' - TuoTu
    ("-VG", PeerClient::Vagaa),      // BEP 20 'VG' - Vagaa
    ("-XF", PeerClient::Xfplay),     // libtorrent
    ("-XS", PeerClient::XSwifter),   // libtorrent
    ("QVOD", PeerClient::Qvod),      // libtorrent (non-Az form, literal prefix)
];

/// ext handshake `v` field match strings (lowercased product names; same
/// sources as the prefix table).
const V_TOKENS: &[(&str, PeerClient)] = &[
    ("xunlei", PeerClient::Xunlei),
    ("qqdownload", PeerClient::QQDownload),
    ("flashget", PeerClient::FlashGet),
    ("tuotu", PeerClient::TuoTu),
    ("vagaa", PeerClient::Vagaa),
    ("xfplay", PeerClient::Xfplay),
    ("xswifter", PeerClient::XSwifter),
    ("qvod", PeerClient::Qvod),
];

/// Identify the peer's client (peer_id prefix first, `v` field fallback;
/// neither -> [`PeerClient::Unknown`]). Both inputs may be absent (peer_id
/// always exists during the handshake; `v` only becomes available after
/// the ext handshake — the function is decoupled from their availability).
pub fn identify_client(peer_id: Option<&[u8; 20]>, v: Option<&str>) -> PeerClient {
    if let Some(id) = peer_id
        && let Some((_, client)) = PEER_ID_PREFIXES
            .iter()
            .find(|(prefix, _)| id.starts_with(prefix.as_bytes()))
    {
        return *client;
    }
    if let Some(v) = v {
        let lower = v.to_ascii_lowercase();
        if let Some((_, client)) = V_TOKENS.iter().find(|(token, _)| lower.contains(token)) {
            return *client;
        }
    }
    PeerClient::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector construction note (honesty): the BEP 20 / libtorrent public
    /// tables document the **prefix codes** and shapes (`-` + 2-char code +
    /// 4 version digits + `-`), not full 20B samples; the prefix segments
    /// below are the documented shapes and the tails are harmless padding
    /// (identification consumes only the prefix segment) — the test target
    /// is the matcher's conformance to the **source formats**, not a
    /// reproduction of wild captures.
    #[test]
    fn peer_id_prefix_vector_table_with_sources() {
        // Xunlei -XL (BEP 20 'XL' - Xunlei; -XL####- Az form).
        assert_eq!(
            identify_client(Some(b"-XL0011-0123456789AB"), None),
            PeerClient::Xunlei
        );
        // Xunlei -SD (libtorrent identify_client.cpp).
        assert_eq!(
            identify_client(Some(b"-SD2010-0123456789AB"), None),
            PeerClient::Xunlei
        );
        // Xunlei SD Shadow-style form (SD0100--; covered by the same
        // two-char name table).
        assert_eq!(
            identify_client(Some(b"SD0100--0123456789AB"), None),
            PeerClient::Xunlei
        );
        // QQDownload -QD (BEP 20 'QD' - QQDownload).
        assert_eq!(
            identify_client(Some(b"-QD0011-0123456789AB"), None),
            PeerClient::QQDownload
        );
        // FlashGet -FG without the trailing `-` (BEP 20 "without the
        // trailing -" note; libtorrent identify_client.cpp).
        assert_eq!(
            identify_client(Some(b"-FG0188@0123456789AB"), None),
            PeerClient::FlashGet
        );
        // TuoTu -TT / Vagaa -VG (BEP 20 tables).
        assert_eq!(
            identify_client(Some(b"-TT1010-0123456789AB"), None),
            PeerClient::TuoTu
        );
        assert_eq!(
            identify_client(Some(b"-VG0000-0123456789AB"), None),
            PeerClient::Vagaa
        );
        // Xfplay -XF / XSwifter -XS (libtorrent identify_client.cpp).
        assert_eq!(
            identify_client(Some(b"-XF1010-0123456789AB"), None),
            PeerClient::Xfplay
        );
        assert_eq!(
            identify_client(Some(b"-XS1010-0123456789AB"), None),
            PeerClient::XSwifter
        );
        // Qvod non-Az form (libtorrent identify_client.cpp offset-0 literal
        // prefix).
        assert_eq!(
            identify_client(Some(b"QVOD00000123456789AB"), None),
            PeerClient::Qvod
        );
    }

    /// Unknown stays Unknown: unlisted clients and blank inputs all yield
    /// Unknown; known clients are not re-judged via the `v` path (peer_id
    /// wins).
    #[test]
    fn unknown_inputs_yield_unknown() {
        // A well-known client not in the built-in table (the table focuses
        // on the mainland-China anti-leech set) -> Unknown.
        assert_eq!(
            identify_client(Some(b"-qB4550-0123456789AB"), None),
            PeerClient::Unknown,
            "qBittorrent not in table -> Unknown (no guessing)"
        );
        assert_eq!(
            identify_client(Some(b"-TR4060-0123456789AB"), None),
            PeerClient::Unknown
        );
        // All-zero / all-blank peer_id.
        assert_eq!(identify_client(Some(&[0u8; 20]), None), PeerClient::Unknown);
        // No inputs.
        assert_eq!(identify_client(None, None), PeerClient::Unknown);
        // A peer_id hit wins over the `v` fallback.
        assert_eq!(
            identify_client(Some(b"-XL0011-0123456789AB"), Some("QQDownload 1.0")),
            PeerClient::Xunlei
        );
    }

    /// The `v` field path (product-name substring, case-insensitive; names
    /// share the prefix table's sources).
    #[test]
    fn v_field_product_name_tokens() {
        assert_eq!(
            identify_client(None, Some("Xunlei 5.0.1.2")),
            PeerClient::Xunlei
        );
        assert_eq!(
            identify_client(None, Some("thunder (xunlei)")),
            PeerClient::Xunlei
        );
        assert_eq!(
            identify_client(None, Some("QQDownload/2.1")),
            PeerClient::QQDownload
        );
        assert_eq!(
            identify_client(None, Some("FlashGet 3.7")),
            PeerClient::FlashGet
        );
        assert_eq!(identify_client(None, Some("QVOD player")), PeerClient::Qvod);
        // Not self-reported / a name not in the table -> Unknown.
        assert_eq!(
            identify_client(None, Some("qBittorrent v4.2.5")),
            PeerClient::Unknown
        );
        assert_eq!(identify_client(None, Some("")), PeerClient::Unknown);
    }

    /// Display names are stable (ban reasons / log surface).
    #[test]
    fn display_names_are_stable() {
        assert_eq!(PeerClient::Unknown.as_str(), "Unknown");
        assert_eq!(PeerClient::Xunlei.as_str(), "Xunlei");
        assert_eq!(PeerClient::QQDownload.as_str(), "QQDownload");
        assert_eq!(PeerClient::Qvod.as_str(), "Qvod");
    }
}
