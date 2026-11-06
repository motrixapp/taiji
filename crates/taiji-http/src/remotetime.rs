//! `--remote-time`: set the file mtime from the remote Last-Modified
//! after download.
//!
//! Parses RFC 9110 §5.6.7 HTTP-date: IMF-fixdate is the field form;
//! the obsolete RFC 850 and asctime spellings are accepted (tolerant
//! parsing). Parse/mtime failure → None/Err: the caller warns and
//! skips, never failing the task (aria2 `HttpResponseCommand` is
//! likewise best-effort, logging only). Hand-rolled (no httpdate/
//! chrono/time deps); the day↔unix-seconds conversion uses Hinnant's
//! public-domain civil-date algorithms with pinned vectors.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::HttpError;

/// Parse an HTTP-date → unix seconds (UTC). The three spec forms:
/// - IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT` (preferred form);
/// - RFC 850: `Sunday, 06-Nov-94 08:49:37 GMT`;
/// - asctime: `Sun Nov 6 08:49:37 1994`.
pub fn parse_http_date(value: &str) -> Option<i64> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(s) = parse_imf_fixdate(v) {
        return Some(s);
    }
    if let Some(s) = parse_rfc850(v) {
        return Some(s);
    }
    parse_asctime(v)
}

/// Month name → 1..=12 (standard three-letter abbreviations, case
/// insensitive). Non-ASCII input is always None (the HTTP date grammar
/// is pure ASCII — a fuzz fix: with multibyte UTF-8, `&name[..3]` can
/// slice inside a character boundary = panic).
fn month_of(name: &str) -> Option<u32> {
    let m = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    if !name.is_ascii() {
        return None;
    }
    m.iter()
        .position(|s| name.len() >= 3 && s.eq_ignore_ascii_case(&name[..3]))
        .map(|i| i as u32 + 1)
}

struct DateTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
}

/// Civil datetime → unix seconds (days_from_civil: H. Hinnant's
/// algorithm, handles era wraps and leap years).
fn unix_seconds(dt: &DateTime) -> Option<i64> {
    let (y, m) = if dt.month <= 2 {
        (dt.year - 1, dt.month + 9)
    } else {
        (dt.year, dt.month - 3)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let d = (153 * i64::from(m) + 2) / 5 + i64::from(dt.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + d;
    let days = era * 146_097 + doe - 719_468; // days since 1970-01-01
    Some(days * 86_400 + i64::from(dt.hour) * 3600 + i64::from(dt.min) * 60 + i64::from(dt.sec))
}

/// "HH:MM:SS" parsing (shared by IMF/RFC 850).
fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.trim().split(':');
    let h: u32 = it.next()?.trim().parse().ok()?;
    let m: u32 = it.next()?.trim().parse().ok()?;
    let sec: u32 = it.next()?.trim().parse().ok()?;
    if h > 23 || m > 59 || sec > 60 {
        return None; // 60 allowed for leap-second forms (tolerant; added as-is).
    }
    Some((h, m, sec))
}

/// IMF-fixdate: `Tue, 01 Sep 2026 12:00:00 GMT` (the weekday and GMT
/// do not enter the conversion — validated then ignored per spec).
fn parse_imf_fixdate(v: &str) -> Option<i64> {
    let rest = v.split_once(", ").map(|(_, r)| r).unwrap_or(v);
    let mut it = rest.split_ascii_whitespace();
    let day: u32 = it.next()?.parse().ok()?;
    let month = month_of(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    let (h, m, s) = parse_hms(it.next()?)?;
    if !(1..=31).contains(&day) {
        return None;
    }
    // Fuzz fix: the year field is 4 digits (RFC 9110 IMF-fixdate =
    // 4DIGIT) — an unbounded year (e.g. 2000000) yields absurd
    // timestamps (far-future mtimes).
    if !(0..=9999).contains(&year) {
        return None;
    }
    unix_seconds(&DateTime {
        year,
        month,
        day,
        hour: h,
        min: m,
        sec: s,
    })
}

/// RFC 850: `Tuesday, 06-Nov-94 08:49:37 GMT` (two-digit year →
/// window mapping 00-69 = 2000-2069, 70-99 = 1970-1999, per the
/// RFC 9110 §5.6.7 note).
fn parse_rfc850(v: &str) -> Option<i64> {
    let rest = v.split_once(", ")?.1;
    let mut it = rest.splitn(3, '-');
    let day: u32 = it.next()?.parse().ok()?;
    let month = month_of(it.next()?)?;
    // "94 08:49:37 GMT": two-digit year + space-separated time.
    let mut it2 = it.next()?.split_ascii_whitespace();
    let yy: i64 = it2.next()?.parse().ok()?;
    let (h, m, s) = parse_hms(it2.next()?)?;
    // Fuzz fix: RFC 850 year = 2DIGIT (0..=99) — unbounded yy (e.g.
    // "9433777771777") yields absurd timestamps via 1900+yy.
    if !(0..=99).contains(&yy) {
        return None;
    }
    let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
    unix_seconds(&DateTime {
        year,
        month,
        day,
        hour: h,
        min: m,
        sec: s,
    })
}

/// asctime: `Sun Nov 6 08:49:37 1994` (space-padded two-digit day).
fn parse_asctime(v: &str) -> Option<i64> {
    let mut it = v.split_ascii_whitespace();
    let _dow = it.next()?; // weekday (not used in the conversion)
    let month = month_of(it.next()?)?;
    let day: u32 = it.next()?.parse().ok()?;
    let (h, m, s) = parse_hms(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    // Fuzz fix: the year field is 4 digits (asctime year = 4DIGIT).
    if !(0..=9999).contains(&year) {
        return None;
    }
    unix_seconds(&DateTime {
        year,
        month,
        day,
        hour: h,
        min: m,
        sec: s,
    })
}

/// RFC 3659 §2.3 MDTM reply time value (`213 YYYYMMDDhhmmss[.sss]`,
/// UTC) → an IMF-fixdate string — the FTP probe's `last_modified`
/// exits in the same format as the HTTP Last-Modified, so resume
/// validation and `--remote-time` share the single [`parse_http_date`]
/// parser. Takes the last token of the reply line; fractional seconds
/// (`.sss`) do not enter the second-level conversion (same exit
/// precision as HTTP-date); out-of-range/unparseable → None (the
/// caller silently skips; not a probe failure).
pub fn mdtm_http_date(reply: &str) -> Option<String> {
    let token = reply.split_ascii_whitespace().next_back()?;
    let digits = token.split('.').next()?;
    if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |lo: usize, hi: usize| -> Option<u32> { digits.get(lo..hi)?.parse().ok() };
    let (year, month, day) = (i64::from(num(0, 4)?), num(4, 6)?, num(6, 8)?);
    let (hour, min, sec) = (num(8, 10)?, num(10, 12)?, num(12, 14)?);
    // Same range rules as parse_imf_fixdate/parse_hms (sec <= 60
    // allows leap-second forms).
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let unix = unix_seconds(&DateTime {
        year,
        month,
        day,
        hour,
        min,
        sec,
    })?;
    Some(format_http_date(unix))
}

/// Unix seconds → IMF-fixdate (`Thu, 01 Jan 2026 12:00:00 GMT`, the
/// RFC 9110 §5.6.7 preferred form). The date goes through
/// civil_from_days (the inverse of days_from_civil); the weekday is
/// derived mod 7 from the 1970-01-01 = Thursday anchor.
fn format_http_date(unix: i64) -> String {
    const DOW: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTH: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs_of_day = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DOW[days.rem_euclid(7) as usize],
        d,
        MONTH[(m - 1) as usize],
        y,
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60
    )
}

/// Days (since 1970-01-01) → (year, month, day). civil_from_days:
/// H. Hinnant's algorithm (the inverse of [`unix_seconds`]'s
/// days_from_civil, public domain), handles era wraps and leap years.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// SystemTime ← unix seconds (negative/overflow → None).
fn system_time(unix: i64) -> Option<SystemTime> {
    if unix >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(unix as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(unix.unsigned_abs()))
    }
}

/// Set the file mtime from the remote Last-Modified (the
/// `--remote-time` executor).
///
/// Best-effort: parse or mtime failure = `Err` (the caller warns and
/// continues, not a task failure — aria2 `HttpResponseCommand` is
/// likewise best-effort). The blocking part runs in spawn_blocking.
pub async fn apply_remote_mtime(path: &Path, last_modified: &str) -> Result<(), HttpError> {
    let unix = parse_http_date(last_modified).ok_or_else(|| {
        HttpError::Transport(format!(
            "remote-time: unparseable Last-Modified {last_modified:?}"
        ))
    })?;
    let mtime = system_time(unix).ok_or_else(|| {
        HttpError::Transport("remote-time: Last-Modified out of system range".into())
    })?;
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        // The OS open goes through the winpath conversion (identity
        // off Windows; errors report the original path).
        let f = std::fs::File::options()
            .write(true)
            .open(taiji_io::winpath::to_fs_path(&p))
            .map_err(|e| HttpError::Disk(format!("remote-time open {}: {e}", p.display())))?;
        f.set_modified(mtime)
            .map_err(|e| HttpError::Disk(format!("remote-time set_modified {}: {e}", p.display())))
    })
    .await
    .map_err(|e| HttpError::Disk(format!("remote-time join: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IMF-fixdate vectors (anchors: epoch/leap day/century
    /// midpoint/future date).
    #[test]
    fn imf_fixdate_vectors() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Tue, 01 Sep 2026 12:00:00 GMT"),
            Some(1_788_264_000)
        );
        assert_eq!(
            parse_http_date("Fri, 29 Feb 2008 23:59:59 GMT"),
            Some(1_204_329_599)
        );
        assert_eq!(
            parse_http_date("Wed, 15 Dec 1999 08:30:00 GMT"),
            Some(945_246_600)
        );
    }

    /// The three forms are equivalent (RFC 9110 §5.6.7 spellings of
    /// the same instant).
    #[test]
    fn three_formats_represent_same_instant() {
        let want = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(want, Some(784111777));
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), want);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), want);
        // Two-digit year window mapping: 69 → 2069, 70 → 1970.
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-69 08:49:37 GMT"),
            parse_http_date("Sun, 06 Nov 2069 08:49:37 GMT")
        );
    }

    /// Tolerant: lowercase month names / missing weekday. Rejecting:
    /// garbage/empty/out-of-range day/out-of-range hour.
    #[test]
    fn tolerant_and_rejecting_edges() {
        assert_eq!(
            parse_http_date("tue, 01 sep 2026 12:00:00 gmt"),
            Some(1_788_264_000)
        );
        assert_eq!(
            parse_http_date("01 Sep 2026 12:00:00 GMT"),
            Some(1_788_264_000)
        );
        // Garbage forms → None (the caller skips setting the time).
        for bad in [
            "",
            "not a date",
            "Tue, 32 Sep 2026 12:00:00 GMT",
            "Tue, 01 Sep 2026 25:00:00 GMT",
            "Tue, 01 Xxx 2026 12:00:00 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad:?} must not parse");
        }
    }

    /// MDTM time-value parsing (RFC 3659 §2.3): a `213` reply line
    /// (with status prefix) → IMF-fixdate, reading back to the same
    /// instant via [`parse_http_date`] (exit-format round trip);
    /// fractional seconds truncated; out-of-range/garbage → None.
    #[test]
    fn mdtm_reply_parses_to_http_date_exit_format() {
        // 2026-01-01T12:00:00Z (`date -u` cross-check = 1767268800).
        let lm = mdtm_http_date("213 20260101120000").unwrap_or_else(|| panic!("mdtm must parse"));
        assert_eq!(lm, "Thu, 01 Jan 2026 12:00:00 GMT");
        assert_eq!(parse_http_date(&lm), Some(1_767_268_800));
        // Fractional seconds (.sss) truncate to seconds; a bare time
        // value (no status prefix) parses too.
        assert_eq!(
            mdtm_http_date("213 19941106084937.123").as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        assert_eq!(
            mdtm_http_date("20260101120000").as_deref(),
            Some("Thu, 01 Jan 2026 12:00:00 GMT")
        );
        // Rejects: not 14 digits, non-digits, out-of-range
        // month/day/hour.
        for bad in [
            "213 2026010112000",    // 13 digits
            "213 2026010112000000", // 16 digits
            "213 20261301120000",   // month 13
            "213 20260101240000",   // hour 24
            "213 20260132120000",   // day 32
            "213 2026-01-01 12:00", // not a time-value shape
            "213",                  // no time value
            "",
        ] {
            assert_eq!(mdtm_http_date(bad), None, "{bad:?} must not parse");
        }
    }

    /// Executor: a valid Last-Modified writes the mtime; an invalid
    /// value is an explicit Err.
    #[tokio::test]
    async fn apply_remote_mtime_sets_file_time() {
        let dir = std::env::temp_dir().join(format!("tj-rtime-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let p = dir.join("f.bin");
        std::fs::write(&p, b"x").unwrap_or_else(|e| panic!("write: {e}"));

        apply_remote_mtime(&p, "Tue, 01 Sep 2026 12:00:00 GMT")
            .await
            .unwrap_or_else(|e| panic!("apply: {e}"));
        let got = std::fs::metadata(&p)
            .unwrap_or_else(|e| panic!("stat: {e}"))
            .modified()
            .unwrap_or_else(|e| panic!("mtime: {e}"));
        let expect = system_time(1_788_264_000).unwrap_or_else(|| panic!("anchor"));
        assert_eq!(got, expect, "mtime == Last-Modified");

        assert!(apply_remote_mtime(&p, "garbage").await.is_err());
        assert!(
            apply_remote_mtime(&dir.join("missing.bin"), "Tue, 01 Sep 2026 12:00:00 GMT")
                .await
                .is_err(),
            "missing file = Err (no pretending success)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod p5_fuzz_fixes {
    use super::*;

    /// Fuzz-fix anchors (artifacts from libFuzzer crash inputs):
    /// (a) multibyte UTF-8 month names do not panic and give None;
    /// (b) IMF/asctime year is a 4-digit field (2000000 → None);
    /// (c) RFC 850 year is a 2-digit field (9433777771777 → None);
    /// (d) the three legal forms still parse.
    #[test]
    fn http_date_domain_guards_hold() {
        // (a) Non-ASCII month: before the fix `&name[..3]` sliced
        // inside a multibyte character and panicked.
        assert_eq!(month_of("O��t"), None, "non-ASCII month -> None");
        assert_eq!(parse_http_date("Wed, 21 O��t 2015 07:28:00 GMT"), None);
        // (b) Unbounded year.
        assert_eq!(parse_http_date("Wed, 21 Oct 2000000 07:28:00 GMT"), None);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 2000000"), None);
        // (c) RFC 850 year beyond 2 digits.
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-9433777771777 08:49:37 GMT"),
            None
        );
        // (d) Legal forms still parse.
        assert!(parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT").is_some());
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_some());
        assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_some());
        // Legal timestamps stay sane in magnitude (year <= 9999 →
        // |ts| < 2^40).
        if let Some(ts) = parse_http_date("Wed, 21 Oct 9999 23:59:59 GMT") {
            assert!(ts.abs() < (1i64 << 40));
        }
    }
}
