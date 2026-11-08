//! `--load-cookies`: Netscape cookie file parsing, a per-domain cookie
//! jar, and the per-task cookie store (self-contained parser, fuzzed).
//!
//! # File format (curl Netscape cookie file; same face as aria2
//! `--load-cookies`)
//!
//! 7 tab-separated fields per line: `domain include_subdomains path
//! secure expiry(unix secs) name value`; lines starting with `#` are
//! comments, with the `#HttpOnly_` prefix exception (strip the prefix
//! and parse normally; the HttpOnly flag itself is not consumed by
//! this crate). `expiry = 0` or unparseable = session cookie (never
//! expires within the jar lifetime).
//!
//! # Parsing discipline (tolerant + injection-proof)
//!
//! Bad lines are skipped, not fatal (curl behavior): wrong field
//! count, invalid domain/path, control characters or `;` `,` in
//! name/value (Cookie header injection face), and domain cookies whose
//! domain is a single-label public-suffix shape (`.com`/`com`) or a
//! generated multi-label public suffix (`.co.uk` exact /
//! `foo.kawasaki.jp` wildcard — tail-match would send that cookie to
//! any .com/.co.uk site, see [`MULTI_LABEL_PUBLIC_SUFFIXES`]) all drop
//! the line (exception rules such as `www.ck` are registrable domains
//! and pass). Duplicate `(name, domain, path)` lines: the later line
//! replaces the earlier (RFC 6265 §5.3 step 11 new-value replacement).
//! File-level cap of 1MiB errors out explicitly.
//!
//! # Task cookie store ([`CookieStore`])
//!
//! One instance per task: absorbs response `Set-Cookie` during the
//! download (RFC 6265 §5.2/§5.3 reduced form: domain/path/Secure/
//! Max-Age/Expires handling + same-key merge) and resends on later
//! requests per domain/path/Secure (§5.4). Layered apart from
//! cross-host credential stripping (client layer).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// Path-reference revision: `reqwest::Url` became `url::Url` —
// the same type (reqwest 0.13's `Url` IS the `url` crate's re-export);
// the vocabulary crate takes the small direct dependency instead of
// the whole HTTP client stack.
use url::Url;

use crate::error::HttpError;

/// `--load-cookies` file size cap: 1MiB.
pub const MAX_COOKIE_FILE_BYTES: u64 = 1024 * 1024;

/// Cap on runtime-ingested ([`CookieStore::absorb`]) entries. A
/// malicious server can inject any number of `Set-Cookie` headers per
/// response; unbounded, memory grows without limit (DoS). The file
/// parse path already has a 1MiB size cap ([`MAX_COOKIE_FILE_BYTES`]);
/// this closes the runtime face. At the cap, new-key insertion evicts
/// the least recently active entry; same-key updates only refresh
/// recency — not new entries, never triggering eviction.
pub const MAX_RUNTIME_COOKIE_ENTRIES: usize = 4096;

/// Generated multi-label public suffix table module: the tables live
/// in `cookies_psl_generated.rs`, a committed file produced by
/// `scripts/gen_psl.py` from the official PSL (publicsuffix.org) —
/// three tables: exact (ICANN + PRIVATE + legacy curated segments,
/// 8672 entries), wildcards (`*.tail` normalized form, 311),
/// exceptions (`!` rules minus the prefix, 8). The single-label-rule
/// exclusion criteria are documented in that file's header. The
/// generator does not run at build time (no build.rs, no network
/// fetch — builds stay offline and deterministic); the table ships
/// with the source and refreshing it means re-running the script.
#[path = "cookies_psl_generated.rs"]
mod cookies_psl_generated;

use cookies_psl_generated::{
    MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS, MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS,
    MULTI_LABEL_PUBLIC_SUFFIXES,
};

/// Whether a domain is a multi-label public suffix (PSL decision, same
/// shape as libpsl). Caller contract: input must be normalized
/// (lowercase, no leading/trailing dots); single-label domains (`com`)
/// are not decided here — the caller's "contains no dot" check rejects
/// them first. Three steps (the order is semantic: exceptions beat
/// the other two):
/// 1. Exception table (`!rule` minus the `!`) hit -> NOT a public
///    suffix — exception entries are themselves registrable domains
///    (`www.ck` beats `*.ck`, `city.kawasaki.jp` beats
///    `*.kawasaki.jp`);
/// 2. Exact table hit -> yes (`co.uk`/`github.io`);
/// 3. Wildcard table (`*.tail` normalized form): strip the leftmost
///    label from the candidate and probe `*.{tail}`; a hit -> yes.
///    `*` matches exactly one label: `foo.kawasaki.jp` is a public
///    suffix (rejected), `bar.foo.kawasaki.jp` is a registrable
///    domain (allowed); single-label tails behave the same (`*.ck` =>
///    `foo.ck` rejected / `a.b.ck` allowed — the wildcard eats one
///    layer: candidate `foo.ck` minus its leftmost label is `ck`, and
///    probe `*.ck` hits).
///    All three tables carry a strict-alphabetical-order invariant
///    (locked by self-check tests), which makes `binary_search` O(log n)
///    — at 8600+/311/8 entries a linear `contains` would degrade every
///    property resolution to an O(n) full scan.
fn is_multi_label_public_suffix(domain: &str) -> bool {
    // 1. Exceptions beat exact/wildcard: the entry itself is registrable.
    if MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS
        .binary_search(&domain)
        .is_ok()
    {
        return false;
    }
    // 2. Exact table.
    if MULTI_LABEL_PUBLIC_SUFFIXES.binary_search(&domain).is_ok() {
        return true;
    }
    // 3. Wildcard: candidate = `<single label>.tail` <=> probe
    // `*.{minus leftmost label}` is in the wildcard table. A candidate
    // without a dot makes split_once None (outside the caller
    // contract); fall back to not-a-suffix.
    let Some((_, tail)) = domain.split_once('.') else {
        return false;
    };
    let probe = format!("*.{tail}");
    MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS
        .binary_search(&probe.as_str())
        .is_ok()
}

/// One parsed cookie (RFC 6265 storage shape; Netscape file field
/// mapping).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetscapeCookie {
    /// Domain (canonical: no leading/trailing `.`, lowercase — the DNS
    /// absolute-form trailing dot is stripped, same normalization as
    /// the `Domain` attribute).
    pub domain: String,
    /// Host-only (Netscape field 2 FALSE or no leading dot): exact
    /// domain matches only.
    pub host_only: bool,
    /// Path (RFC 6265 §5.1.4 path-match input).
    pub path: String,
    /// HTTPS-only sending (Secure flag, field 4).
    pub secure: bool,
    /// Expiry as unix seconds; `None` = session cookie (expiry=0 or
    /// unparseable in the file).
    pub expires: Option<i64>,
    /// Cookie name (non-empty, no control characters).
    pub name: String,
    /// Cookie value (no control characters, `;`, `,` — Cookie header
    /// injection guard).
    pub value: String,
}

/// Per-domain cookie jar: holds parsed results and synthesizes the
/// `Cookie` header at send time per RFC 6265 §5.4 selection.
/// Cross-host redirect credential stripping does not depend on this
/// jar (the jar matches by domain and is naturally cross-domain safe;
/// explicit credential headers (Authorization/Cookie/Basic) are
/// stripped in the client layer).
#[derive(Clone, Debug, Default)]
pub struct CookieJar {
    cookies: Vec<NetscapeCookie>,
}

impl CookieJar {
    /// Empty jar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses Netscape text (bad lines skipped tolerantly; the size
    /// cap is the caller's job). Duplicate `(name, domain, path)`
    /// lines: the later line wins (RFC 6265 §5.3 step 11).
    pub fn parse_netscape(text: &str) -> Self {
        let mut cookies: Vec<NetscapeCookie> = Vec::new();
        let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
        for line in text.lines() {
            // HttpOnly prefix exception: strip the prefix, parse normally (curl semantics).
            let rest = line.strip_prefix("#HttpOnly_").unwrap_or(line);
            if rest.is_empty() || rest.starts_with('#') {
                continue;
            }
            if let Some(c) = parse_line(rest) {
                let key = (c.name.clone(), c.domain.clone(), c.path.clone());
                match seen.get(&key) {
                    Some(&i) => cookies[i] = c,
                    None => {
                        seen.insert(key, cookies.len());
                        cookies.push(c);
                    }
                }
            }
        }
        Self { cookies }
    }

    /// Parses bytes (<= [`MAX_COOKIE_FILE_BYTES`], over-limit errors;
    /// non-UTF-8 bytes go through lossy conversion then tolerant
    /// parsing).
    pub fn from_netscape_bytes(bytes: &[u8]) -> Result<Self, HttpError> {
        if bytes.len() as u64 > MAX_COOKIE_FILE_BYTES {
            return Err(HttpError::CookieFileTooLarge {
                max_bytes: MAX_COOKIE_FILE_BYTES,
            });
        }
        Ok(Self::parse_netscape(&String::from_utf8_lossy(bytes)))
    }

    /// Reads a file (<= 1MiB; disk IO runs on `spawn_blocking`).
    pub async fn load_netscape_file(path: &Path) -> Result<Self, HttpError> {
        let owned = path.to_path_buf();
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            use std::io::Read;
            // OS open goes through the winpath conversion (identity off Windows).
            let file = std::fs::File::open(taiji_io::winpath::to_fs_path(&owned))?;
            let mut buf = Vec::new();
            // take(cap+1): at the cap the byte count read is itself
            // the over-limit evidence, avoiding reading a whole large
            // file.
            file.take(MAX_COOKIE_FILE_BYTES + 1).read_to_end(&mut buf)?;
            Ok(buf)
        })
        .await
        .map_err(|e| HttpError::CookieFile(format!("cookie load join: {e}")))?
        .map_err(|e| HttpError::CookieFile(format!("cookie file read: {e}")))?;
        Self::from_netscape_bytes(&bytes)
    }

    /// Parsed-result read face (injection seam): after a `load-cookies`
    /// file loads, entries are extracted in order to pre-fill the task
    /// [`CookieStore`] (`seed`).
    pub fn cookies(&self) -> &[NetscapeCookie] {
        &self.cookies
    }

    /// Number of parsed cookies.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Empty-jar check.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Synthesizes the `Cookie` header value for a target URL (RFC
    /// 6265 §5.4: domain match, path match, Secure and not-expired
    /// checks); `None` when nothing matches. Output looks like
    /// `name=value; name=value` — the parse discipline guarantees no
    /// control characters/`;`.
    pub fn header_for(&self, url: &Url) -> Option<String> {
        cookie_header(&self.cookies, url)
    }
}

/// RFC 6265 §5.4 send selection (domain/path/Secure/not expired) ->
/// `Cookie` header value; shared by [`CookieJar`] and [`CookieStore`].
fn cookie_header(cookies: &[NetscapeCookie], url: &Url) -> Option<String> {
    let host = request_host(url)?;
    let now = unix_now();
    let mut parts: Vec<String> = Vec::new();
    for c in cookies {
        if c.secure && url.scheme() != "https" {
            continue;
        }
        if let Some(exp) = c.expires
            && now >= exp
        {
            continue;
        }
        if !domain_match(&host, c) || !path_match(url.path(), &c.path) {
            continue;
        }
        parts.push(format!("{}={}", c.name, c.value));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Request host (IPv6 literals have brackets stripped before matching;
/// lowercased; the DNS absolute-form trailing dot is stripped — the
/// url parser preserves the trailing-dot form, and normalizing both
/// sides the same way as the `Domain` attribute/cookie domain stops
/// trailing-dot URL forms from bypassing domain matching and the
/// public-suffix tables).
fn request_host(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.trim_end_matches('.');
    Some(host.to_ascii_lowercase())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses one line; any failed check returns `None` (skip the line; tolerant discipline).
fn parse_line(line: &str) -> Option<NetscapeCookie> {
    // value is field 7; splitn(7) folds tabs inside the value into
    // the value (which the control-character check then rejects).
    let mut fields = line.splitn(7, '\t');
    let domain_raw = fields.next()?.trim();
    let subdomains = fields.next()?.trim();
    let path_raw = fields.next()?.trim();
    let secure_raw = fields.next()?.trim();
    let expiry_raw = fields.next()?.trim();
    let name_raw = fields.next()?.trim();
    let value_raw = fields.next()?.trim();

    if domain_raw.is_empty() {
        return None;
    }
    // Field 2 TRUE = includeSubdomains (domain cookie); no leading dot
    // and FALSE = host-only (curl/aria2 Netscape shape).
    let domain_cookie = subdomains.eq_ignore_ascii_case("true");
    let host_only = !domain_cookie && !domain_raw.starts_with('.');
    // Domain normalization (lowercase; DNS absolute-form dots stripped
    // on both ends — same treatment as the request-host side, so
    // trailing-dot forms cannot bypass the public-suffix tables and
    // tail-match).
    let domain = domain_raw.trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    // Public-suffix baseline defense: a domain cookie (subdomains
    // included) whose domain is single-label (`.com`/`com` shape) or a
    // generated multi-label public suffix (`.co.uk` exact /
    // `foo.kawasaki.jp` wildcard) rejects the whole line — tail-match
    // would send that cookie to any .com/.co.uk site. Host-only
    // single-label domains (localhost) and exact domains (co.uk as its
    // own site) are unaffected; exception-rule entries (`www.ck` and
    // other registrable domains) pass. Table criteria registered at
    // [`MULTI_LABEL_PUBLIC_SUFFIXES`].
    if !host_only && (!domain.contains('.') || is_multi_label_public_suffix(&domain)) {
        return None;
    }
    // path must start with '/' (Netscape shape contract); empty path falls back to "/".
    let path = if path_raw.is_empty() {
        "/".to_string()
    } else if path_raw.starts_with('/') {
        path_raw.to_string()
    } else {
        return None;
    };
    let secure = secure_raw.eq_ignore_ascii_case("true");
    let expires = expiry_raw.parse::<i64>().ok().filter(|e| *e > 0);
    let name = name_raw.to_string();
    let value = value_raw.to_string();
    if !valid_pair(&name) || !valid_pair(&value) {
        return None;
    }
    Some(NetscapeCookie {
        domain,
        host_only,
        path,
        secure,
        expires,
        name,
        value,
    })
}

/// name/value injection guard: non-empty, no control characters (CTL), no `;` `,`.
fn valid_pair(s: &str) -> bool {
    !s.is_empty()
        && !s
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b';' || b == b',')
}

/// RFC 6265 §5.1.3 domain match: exact equality, or (domain cookies)
/// host ends with `.domain`; IP hosts match only exactly.
fn domain_match(host: &str, c: &NetscapeCookie) -> bool {
    if host == c.domain {
        return true;
    }
    !c.host_only && domain_tail_match(host, &c.domain)
}

/// Domain tail-match (host-only bit aside): host == domain, or host
/// ends with `.domain`; IP hosts only allow exact equality (§5.1.3).
fn domain_tail_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    host.strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// RFC 6265 §5.1.4 path-match.
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/')
            || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/'))
}

/// RFC 6265 §5.1.4 default-path: the prefix before the last `/` in
/// the request path (excluding it); root/empty shapes fall back to
/// `/`.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

/// Store internal state: the entry vector plus a parallel activity
/// sequence (invariant: `stamps` and `cookies` are the same length
/// and order; every insert/remove must update both vectors). The
/// activity sequence increases monotonically: new-key inserts and
/// same-key updates both take the next stamp (writing refreshes
/// recency); eviction takes the minimum stamp. Entry vector position
/// = storage order (snapshot/resend order), decoupled from activity
/// order — under the cap, storage-order behavior stays field-for-field
/// identical to the uncapped behavior.
#[derive(Clone, Debug, Default)]
struct StoreState {
    cookies: Vec<NetscapeCookie>,
    stamps: Vec<u64>,
    next_stamp: u64,
}

impl StoreState {
    /// Next activity stamp (u64, monotonically increasing; exhaustion unreachable).
    fn next_stamp(&mut self) -> u64 {
        self.next_stamp = self.next_stamp.wrapping_add(1);
        self.next_stamp
    }

    /// New-key insertion (the only entry-growing path): when full, the
    /// least active (oldest) entry is evicted before inserting —
    /// runtime ingestion is thereby capped
    /// ([`MAX_RUNTIME_COOKIE_ENTRIES`], the DoS bound). Same-key
    /// updates do not pass through here: the count is unchanged and
    /// eviction never triggers.
    fn push_capped(&mut self, c: NetscapeCookie) {
        if self.cookies.len() >= MAX_RUNTIME_COOKIE_ENTRIES
            && let Some(oldest) = self
                .stamps
                .iter()
                .enumerate()
                .min_by_key(|&(_, s)| *s)
                .map(|(i, _)| i)
        {
            self.cookies.remove(oldest);
            self.stamps.remove(oldest);
        }
        let stamp = self.next_stamp();
        self.cookies.push(c);
        self.stamps.push(stamp);
    }
}

/// Task cookie store: one instance per task; absorbs response
/// `Set-Cookie` during the download and resends on later requests per
/// RFC 6265 domain/path/Secure. Layered apart from cross-host
/// credential stripping: stored cookies are naturally constrained by
/// domain matching and are not stripped along with explicit credential
/// headers (Secure cookies are not sent on an https->http downgrade).
///
/// Interior mutability via `Arc<Mutex<..>>`: multiple workers and
/// redirect hops of one task share one store (`Clone` shares the
/// handle; `PartialEq` compares content snapshots). Runtime ingestion
/// is capped at [`MAX_RUNTIME_COOKIE_ENTRIES`] (except the `seed`
/// injection seam, whose call sources — Netscape files / structured
/// direct passing — are bounded on their own).
#[derive(Clone, Debug, Default)]
pub struct CookieStore {
    state: Arc<Mutex<StoreState>>,
}

impl PartialEq for CookieStore {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot() == other.snapshot()
    }
}

impl Eq for CookieStore {}

impl CookieStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.state.lock().map(|s| s.cookies.len()).unwrap_or(0)
    }

    /// Empty-store check.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Content snapshot (persistence/reconciliation/test face; in storage order).
    pub fn snapshot(&self) -> Vec<NetscapeCookie> {
        self.state
            .lock()
            .map(|s| s.cookies.clone())
            .unwrap_or_default()
    }

    /// Synthesizes the `Cookie` header value for a target URL (the
    /// same §5.4 selection face as [`CookieJar::header_for`]).
    pub fn header_for(&self, url: &Url) -> Option<String> {
        let state = self.state.lock().ok()?;
        cookie_header(&state.cookies, url)
    }

    /// Pre-fill (injection seam): the only bulk entry into the task
    /// store, from `--load-cookies` file entries or `addUriWithCookies`
    /// structured direct passing.
    ///
    /// Difference from [`CookieStore::absorb`]: no request-host
    /// constraint (Netscape file / direct-pass shapes carry their own
    /// domain; the caller validates the scheme at the source) — resend
    /// domain matching is naturally constrained by the §5.4 selection
    /// face ([`CookieStore::header_for`]). Same `(name, domain, path)`
    /// key: the later writer wins (RFC 6265 §5.3 step 11 merge
    /// discipline, same rule as duplicate lines in the parse face). No
    /// [`MAX_RUNTIME_COOKIE_ENTRIES`] cap: the call sources are
    /// bounded themselves (the 1MiB file cap / structured direct
    /// passing), and a cap would silently drop the caller's explicit
    /// injection set.
    pub fn seed(&self, cookies: impl IntoIterator<Item = NetscapeCookie>) {
        let Ok(mut state) = self.state.lock() else {
            return; // poisoned lock: drop the injection set rather than amplify the failure.
        };
        for c in cookies {
            match state
                .cookies
                .iter()
                .position(|s| s.name == c.name && s.domain == c.domain && s.path == c.path)
            {
                Some(i) => {
                    // Same key, later wins: replace in place
                    // (storage order unchanged); the write refreshes
                    // the activity stamp.
                    let stamp = state.next_stamp();
                    state.stamps[i] = stamp;
                    state.cookies[i] = c;
                }
                None => {
                    let stamp = state.next_stamp();
                    state.cookies.push(c);
                    state.stamps.push(stamp);
                }
            }
        }
    }

    /// Whole-set replacement (the `setTaskCookies` runtime override;
    /// direct translation of fork `RequestGroup::setTaskCookieStorage`
    /// — RpcMethodImpl.cc): clears, then lands the new set under the
    /// same discipline as [`CookieStore::seed`]. Expired entries are
    /// dropped by the caller (fork parseRpcCookies same rule: expired
    /// records are legal input but do not enter the active store —
    /// RpcCookie.cc).
    pub fn replace_with(&self, cookies: impl IntoIterator<Item = NetscapeCookie>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.cookies.clear();
        state.stamps.clear();
        drop(state);
        self.seed(cookies);
    }

    /// Absorbs one `Set-Cookie` (RFC 6265 §5.2/§5.3 reduced form).
    ///
    /// - Domain: the `Domain` attribute is normalized (lowercase, dots
    ///   stripped) and validated by tail-match before landing as a
    ///   domain cookie (single-label and generated multi-label public
    ///   suffix shapes — exact/wildcard hits — are rejected; exception
    ///   entries are registrable domains and pass,
    ///   [`MULTI_LABEL_PUBLIC_SUFFIXES`]); no attribute = host-only;
    ///   IP hosts are always host-only.
    /// - Path: a `Path` attribute not starting with `/` falls back to
    ///   the default-path algorithm.
    /// - Secure: only a resend gate (not resent over non-https); the
    ///   accept face does not reject it.
    /// - Expiry: `Max-Age` wins over `Expires`; already expired =
    ///   delete the same-key stored entry.
    /// - Merge: the same `(name, domain, path)` is replaced in place
    ///   (§5.3 step 11), refreshing the activity stamp (recency) — not
    ///   a new entry, never triggering eviction.
    /// - Cap: a new-key insert at the [`MAX_RUNTIME_COOKIE_ENTRIES`]
    ///   limit first evicts the least recently active entry (runtime
    ///   ingestion DoS bound; the file path already has the 1MiB size
    ///   cap).
    pub fn absorb(&self, url: &Url, set_cookie: &str) {
        let Some(host) = request_host(url) else {
            return;
        };
        let (pair, attrs_raw) = match set_cookie.split_once(';') {
            Some((p, a)) => (p, a),
            None => (set_cookie, ""),
        };
        let Some((name_raw, value_raw)) = pair.split_once('=') else {
            return; // a pair without '=' is dropped entirely (§5.2 step 2).
        };
        let name = name_raw.trim();
        let value = value_raw.trim();
        // Name non-empty and no CTL; the value may be empty (§5.2) but
        // carries no CTL/';'/',' (resend injection face).
        if !valid_pair(name)
            || value
                .bytes()
                .any(|b| b < 0x20 || b == 0x7f || b == b';' || b == b',')
        {
            return;
        }

        let mut domain_attr: Option<String> = None;
        let mut path_attr: Option<String> = None;
        let mut secure = false;
        let mut expires: Option<i64> = None;
        for attr in attrs_raw.split(';') {
            let (k, v) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (attr.trim(), ""),
            };
            match k.to_ascii_lowercase().as_str() {
                "domain" => {
                    // Domain attribute normalization (lowercase; DNS
                    // absolute-form dots stripped on both ends — same
                    // normalization on both sides as request_host, so
                    // a `Domain=co.uk.` trailing-dot form cannot
                    // bypass a public-suffix table hit).
                    let d = v.trim_matches('.').to_ascii_lowercase();
                    if !d.is_empty() {
                        domain_attr = Some(d);
                    }
                }
                "path" => path_attr = Some(v.to_string()),
                "secure" => secure = true,
                // Max-Age wins over Expires (§5.3 step 3).
                "max-age" => {
                    if let Ok(secs) = v.parse::<i64>() {
                        expires = Some(unix_now().saturating_add(secs.max(0)));
                    }
                }
                "expires" => {
                    if let Some(t) = parse_cookie_date(v) {
                        expires.get_or_insert(t);
                    }
                }
                _ => {} // HttpOnly/SameSite/Partitioned etc.: not consumed here
            }
        }

        let now = unix_now();
        let expired = matches!(expires, Some(t) if t <= now);

        // Domain normalization and acceptance (§5.3 steps 5-6 + the
        // public-suffix baseline defense): a domain attribute that does
        // not tail-match the request host rejects the whole cookie; a
        // normalized hit on a single-label or generated multi-label
        // public suffix (exact/wildcard, exceptions pass) rejects the
        // same way.
        let (cookie_domain, host_only) = match domain_attr {
            Some(d) => {
                if !d.contains('.') {
                    return; // single-label public-suffix shape rejected
                }
                if is_multi_label_public_suffix(&d) {
                    return; // multi-label public-suffix shape rejected (PSL generated tables)
                }
                if domain_tail_match(&host, &d) {
                    if host == d { (host, true) } else { (d, false) }
                } else {
                    return;
                }
            }
            None => (host, true),
        };
        let cookie_path = match path_attr {
            Some(p) if p.starts_with('/') => p,
            _ => default_path(url.path()),
        };

        let Ok(mut state) = self.state.lock() else {
            return; // poisoned lock: lose one cookie rather than amplify the failure.
        };
        let same_key = |c: &NetscapeCookie| {
            c.name == name && c.domain == cookie_domain && c.path == cookie_path
        };
        if expired {
            // Delete face: same-key entries are removed together with
            // their activity stamps (retain semantics; the loop
            // defensively covers multiple hits), keeping the
            // stamps/cookies parallel invariant.
            while let Some(pos) = state.cookies.iter().position(same_key) {
                state.cookies.remove(pos);
                state.stamps.remove(pos);
            }
            return;
        }
        if let Some(pos) = state.cookies.iter().position(same_key) {
            // Same-key update: replace in place (storage order
            // unchanged; under the cap, identical to the uncapped
            // behavior) and refresh the activity stamp; the count is
            // unchanged, no eviction.
            let stamp = state.next_stamp();
            let c = &mut state.cookies[pos];
            c.value = value.to_string();
            c.secure = secure;
            c.expires = expires;
            state.stamps[pos] = stamp;
        } else {
            state.push_capped(NetscapeCookie {
                domain: cookie_domain,
                host_only,
                path: cookie_path,
                secure,
                expires,
                name: name.to_string(),
                value: value.to_string(),
            });
        }
    }
}

/// RFC 6265 §5.1.1 cookie-date reduced parse: tokenize on delimiters,
/// then claim time/day-of-month/month/year in order (common superset
/// of IMF-fixdate/RFC 850/asctime); any missing group or year < 1601
/// -> `None` (the caller falls back to a session cookie).
fn parse_cookie_date(value: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let mut time: Option<(u32, u32, u32)> = None;
    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<i64> = None;
    // RFC 6265 §5.1.1 delimiter set: TAB/%x20-2F/%x3B-40/%x5B-60/
    // %x7B-7E — note that `:` (0x3A) is NOT a delimiter (time tokens
    // pair on it).
    for token in value.split(is_cookie_date_delimiter) {
        if token.is_empty() {
            continue;
        }
        if time.is_none()
            && let Some(hms) = parse_hms(token)
        {
            time = Some(hms);
            continue;
        }
        if day.is_none()
            && let Ok(d) = token.parse::<u32>()
            && (1..=31).contains(&d)
        {
            day = Some(d);
            continue;
        }
        if month.is_none() {
            let lower = token.to_ascii_lowercase();
            if let Some(i) = MONTHS.iter().position(|m| lower.starts_with(m)) {
                month = Some(i as u32 + 1);
                continue;
            }
        }
        if year.is_none()
            && token.len() == 2
            && token.bytes().all(|b| b.is_ascii_digit())
            && let Ok(y) = token.parse::<i64>()
        {
            // §5.1.1 step 5: two-digit years 70-99 -> 1900+, 0-69 -> 2000+.
            year = Some(if y >= 70 { y + 1900 } else { y + 2000 });
            continue;
        }
        if year.is_none() && (token.len() == 4) && token.bytes().all(|b| b.is_ascii_digit()) {
            year = token.parse::<i64>().ok();
            continue;
        }
    }
    let (h, mi, s) = time?;
    let d = day?;
    let mo = month?;
    let y = year?;
    if !(1601..=9999).contains(&y) || !(1..=12).contains(&mo) || d as u64 > days_in_month(y, mo) {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some(days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s))
}

/// `hh:mm:ss` (hours <= 23, minutes/seconds <= 59).
fn parse_hms(token: &str) -> Option<(u32, u32, u32)> {
    let mut it = token.split(':');
    let h = it.next()?.parse::<u32>().ok()?;
    let m = it.next()?.parse::<u32>().ok()?;
    let s = it.next()?.parse::<u32>().ok()?;
    if it.next().is_some() || h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some((h, m, s))
}

/// RFC 6265 §5.1.1 cookie-date delimiter predicate.
fn is_cookie_date_delimiter(c: char) -> bool {
    matches!(
        c,
        '\t' | '\u{20}'..='\u{2f}'
            | '\u{3b}'..='\u{40}'
            | '\u{5b}'..='\u{60}'
            | '\u{7b}'..='\u{7e}'
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil` proleptic Gregorian algorithm
/// (civil-date -> unix days without a chrono dependency;
/// 1970-01-01 = 0).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from(m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Netscape HTTP Cookie File
#HttpOnly_.example.com\tTRUE\t/\tTRUE\t4102444800\tsid\tabc123
.example.com\tTRUE\t/deep\tFALSE\t0\tdomaincookie\tv1
host.example.com\tFALSE\t/\tFALSE\t4102444800\thostcookie\thv
bad.example.com\tFALSE\tnoslash\tFALSE\t0\tbad\tskip
short.example.com\tNOTABS
bad.example.com\tTRUE\t/\tFALSE\tnotanumber\texp\tkept-as-session
evil.example.com\tTRUE\t/\tFALSE\t0\tinj\twith\ttab
evil.example.com\tTRUE\t/\tFALSE\t0\tinj2\tbad;value
.\tTRUE\t/\tFALSE\t0\tdotless\tx
";

    #[test]
    fn parses_and_skips_bad_lines() {
        let jar = CookieJar::parse_netscape(SAMPLE);
        // 4 valid: HttpOnly_sid, domaincookie, hostcookie, exp (bad
        // expiry number -> session cookie). Bad lines: noslash path,
        // too few fields, value with tab (CTL), value with ';', empty
        // domain.
        assert_eq!(jar.len(), 4);
    }

    #[test]
    fn domain_and_host_only_matching() {
        let jar = CookieJar::parse_netscape(SAMPLE);
        let url: Url = "https://www.example.com/deep/file"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar
            .header_for(&url)
            .unwrap_or_else(|| panic!("no cookie header"));
        // Domain cookie (subdomains included) matches; host-only host.example.com misses www.
        assert!(header.contains("sid=abc123"), "{header}");
        assert!(header.contains("domaincookie=v1"), "{header}");
        assert!(!header.contains("hostcookie"), "{header}");

        let exact: Url = "https://host.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar
            .header_for(&exact)
            .unwrap_or_else(|| panic!("no cookie"));
        assert!(header.contains("hostcookie=hv"), "{header}");
        assert!(header.contains("sid=abc123"), "{header}");
        // The /deep domain cookie is not sent to the / path (path-match boundary).
        assert!(!header.contains("domaincookie"), "{header}");
    }

    #[test]
    fn path_match_rfc6265_examples() {
        assert!(path_match("/foo", "/foo"));
        assert!(path_match("/foo/bar", "/foo"));
        assert!(!path_match("/foobar", "/foo")); // no / boundary
        assert!(path_match("/foo/bar", "/foo/"));
        assert!(!path_match("/foo", "/foo/bar"));
    }

    #[test]
    fn secure_cookie_https_only() {
        let jar = CookieJar::parse_netscape(SAMPLE);
        let http: Url = "http://www.example.com/deep/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&http).unwrap_or_default();
        // sid is Secure and must not appear over http; the non-Secure
        // /deep domain cookie goes out normally.
        assert!(!header.contains("sid="), "{header}");
        assert!(header.contains("domaincookie=v1"), "{header}");
    }

    #[test]
    fn expired_cookies_dropped_session_sent() {
        let jar = CookieJar::parse_netscape(SAMPLE);
        let url: Url = "https://bad.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        // The bad domain only has exp (bad expiry -> session cookie);
        // the noslash path line was skipped.
        let header = jar.header_for(&url).unwrap_or_default();
        assert!(header.contains("exp=kept-as-session"), "{header}");
        assert!(!header.contains("bad=skip"), "{header}");
    }

    #[test]
    fn injection_values_rejected() {
        // Lines whose value carries CTL/';' must be dropped entirely,
        // guarding Cookie header injection (domain cookies stay valid
        // for subdomains; the injection pair must not appear).
        let jar = CookieJar::parse_netscape(SAMPLE);
        let url: Url = "https://evil.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        if let Some(h) = jar.header_for(&url) {
            assert!(!h.contains("inj"), "{h}");
        }
    }

    #[test]
    fn byte_cap_enforced() {
        let big = vec![b'a'; MAX_COOKIE_FILE_BYTES as usize + 1];
        assert!(matches!(
            CookieJar::from_netscape_bytes(&big),
            Err(HttpError::CookieFileTooLarge {
                max_bytes: MAX_COOKIE_FILE_BYTES
            })
        ));
        let ok = vec![b'a'; MAX_COOKIE_FILE_BYTES as usize];
        assert!(CookieJar::from_netscape_bytes(&ok).is_ok());
    }

    #[test]
    fn header_output_is_header_safe() {
        let jar = CookieJar::parse_netscape(SAMPLE);
        let url: Url = "https://www.example.com/deep/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        if let Some(h) = jar.header_for(&url) {
            assert!(!h.bytes().any(|b| b < 0x20 || b == 0x7f), "{h}");
        }
    }

    /// Expired cookies (expiry earlier than now) are not sent; session cookies are unaffected.
    #[test]
    fn expired_timestamp_suppressed() {
        let text = "a.example.com\tFALSE\t/\tFALSE\t1\told\tv\n\
                    a.example.com\tFALSE\t/\tFALSE\t0\tsession\tv\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 2);
        let url: Url = "https://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&url).unwrap_or_default();
        assert!(!header.contains("old="), "{header}");
        assert!(header.contains("session=v"), "{header}");
    }

    /// Public-suffix baseline defense: a domain cookie (subdomains
    /// included) whose domain is single-label (`.com`/`com` shape)
    /// rejects the whole line — otherwise tail-match would send that
    /// cookie to any .com site. Host-only single-label domains
    /// (localhost) are unaffected.
    #[test]
    fn public_suffix_domain_cookie_rejected() {
        let text = ".com\tTRUE\t/\tFALSE\t4102444800\tsid\tx\n\
                    com\tTRUE\t/\tFALSE\t4102444800\tsid2\ty\n\
                    localhost\tFALSE\t/\tFALSE\t0\tlocal\tok\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 1, "only host-only localhost survives");

        let evil: Url = "https://evil.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            jar.header_for(&evil).is_none(),
            "no cookie for any .com site"
        );

        let local: Url = "http://localhost/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&local).unwrap_or_default();
        assert!(header.contains("local=ok"), "{header}");
    }

    /// Multi-label public-suffix defense (Netscape file parse face,
    /// same rule as the Set-Cookie face): a domain cookie whose domain
    /// is a generated multi-label public suffix (`.co.uk` shape)
    /// rejects the whole line — tail-match would send it to any
    /// *.co.uk site; host-only exact co.uk lines are unaffected.
    #[test]
    fn multi_label_public_suffix_domain_cookie_line_rejected() {
        let text = ".co.uk\tTRUE\t/\tFALSE\t4102444800\tsid\tx\n\
                    co.uk\tTRUE\t/\tFALSE\t4102444800\tsid2\ty\n\
                    co.uk\tFALSE\t/\tFALSE\t0\thostonly\tok\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 1, "only host-only co.uk line survives");
        assert_eq!(jar.cookies()[0].name, "hostonly");

        let bank: Url = "https://bank.co.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            jar.header_for(&bank).is_none(),
            "no cookie for sibling .co.uk site"
        );

        let exact: Url = "http://co.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&exact).unwrap_or_default();
        assert!(header.contains("hostonly=ok"), "{header}");
    }

    /// File face (same rule as the Set-Cookie face): added-segment
    /// (me.uk/uk.com/com.gr/punycode Chinese segment) and trailing-dot
    /// (`.co.uk.`/`co.uk.`) domain-cookie lines reject the whole line
    /// — before normalization a trailing-dot domain missed the tables
    /// while tail-match against a trailing-dot host still held;
    /// host-only lines are unaffected; victim sites (including
    /// trailing-dot URL forms) get no resend.
    #[test]
    fn added_suffix_and_trailing_dot_netscape_lines_rejected() {
        let text = ".me.uk\tTRUE\t/\tFALSE\t0\tsid\tx\n\
                    .uk.com\tTRUE\t/\tFALSE\t0\tsid2\ty\n\
                    .com.gr\tTRUE\t/\tFALSE\t0\tsid3\tz\n\
                    .xn--55qx5d.cn\tTRUE\t/\tFALSE\t0\tsid4\tu\n\
                    .co.uk.\tTRUE\t/\tFALSE\t0\tsid5\tw\n\
                    co.uk.\tTRUE\t/\tFALSE\t0\tsid6\tv\n\
                    host.me.uk\tFALSE\t/\tFALSE\t0\thostonly\tok\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 1, "only host-only line survives");
        assert_eq!(jar.cookies()[0].name, "hostonly");
        // Trailing-dot siblings and added-segment victim sites get no
        // resend (after host-side normalization no un-stripped domain
        // can match).
        let bank: Url = "https://bank.co.uk./"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            jar.header_for(&bank).is_none(),
            "no cookie for trailing-dot sibling"
        );
        let bank2: Url = "https://bank.me.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(jar.header_for(&bank2).is_none());
        // Host-only lines resend normally.
        let host: Url = "https://host.me.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&host).unwrap_or_default();
        assert!(header.contains("hostonly=ok"), "{header}");
    }

    /// Generated-table self-check invariants: strict alphabetical
    /// order (the [`is_multi_label_public_suffix`] binary_search
    /// precondition — a mis-sorted regeneration or misplaced hand edit
    /// surfaces immediately), entries all in normalized form
    /// (lowercase/digits/hyphen-dot — punycode entries legally contain
    /// digits and hyphens; no leading/trailing dots) and no duplicates
    /// — the normalization contract (strip edge dots/lowercase, then
    /// exact hit) relies on this; the size floor anchors against
    /// accidental truncation/empty replacement; spot checks cover
    /// well-known suffixes (ICANN and PRIVATE segments share hosted
    /// domains) and legacy curated segment representatives, and the
    /// anti-overblock anchor confirms ordinary domains (including site
    /// subdomains under suffixes) do not hit.
    #[test]
    fn multi_label_public_suffix_set_invariants() {
        for pair in MULTI_LABEL_PUBLIC_SUFFIXES.windows(2) {
            assert!(
                pair[0] < pair[1],
                "strict sort violated (binary_search precondition): {} vs {}",
                pair[0],
                pair[1]
            );
        }
        let mut seen = std::collections::HashSet::new();
        for e in MULTI_LABEL_PUBLIC_SUFFIXES {
            assert!(
                e.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
                "non-normalized entry: {e}"
            );
            assert!(e.contains('.'), "must be multi-label: {e}");
            assert!(!e.starts_with('.') && !e.ends_with('.'), "dot-fringe: {e}");
            assert!(seen.insert(*e), "duplicate entry: {e}");
        }
        // Size floor: official PSL multi-label ~8.6k entries + legacy
        // segments (8672 at last regeneration); a large drop = table
        // truncated or source anomaly.
        assert!(seen.len() >= 8_000, "generated set shrank: {}", seen.len());
        for probe in [
            "co.uk",
            "ac.uk",
            "co.jp",
            "com.au",
            "com.br",
            "com.cn",
            "com.hk",
            "com.tw",
            "com.sg",
            "co.in",
            "co.nz",
            "com.mx",
            "com.ar",
            "co.za",
            "com.tr",
            "com.ua",
            "co.il",
            "co.id",
            "com.vn",
            "co.th",
            "com.ru",
            "gob.pe",
            "gub.uy",
            "gob.bo",
            "com.pr",
            // Added-segment representatives (UK additions/AT/GR/PT/RO/HU/CentralNic/punycode).
            "me.uk",
            "sch.uk",
            "co.at",
            "com.gr",
            "com.pt",
            "com.ro",
            "co.hu",
            "uk.com",
            "gb.com",
            "us.com",
            "de.com",
            "eu.com",
            "jp.net",
            "cn.com",
            "ru.com",
            "br.com",
            "za.net",
            "xn--55qx5d.cn",
            "xn--io0a7i.cn",
            // Generated-table additions: PRIVATE segment shared hosted
            // domains (the harvest face existed there too — a
            // registration gap in the earlier hand-curated table).
            "github.io",
            "appspot.com",
            "herokuapp.com",
            "pages.dev",
        ] {
            assert!(is_multi_label_public_suffix(probe), "missing: {probe}");
        }
        // Anti-overblock anchor: ordinary domains / ordinary multi-label
        // domains (including site subdomains under added-segment and
        // PRIVATE suffixes) must not hit — the table only blocks "a
        // public suffix itself as the Domain".
        for benign in [
            "example.com",
            "example.co",
            "www.co.uk",
            "co.uk.example.com",
            "a.b",
            "evil.me.uk",
            "example.me.uk",
            // github.io is a public suffix; registrable domains under it (user sites) are not.
            "example.github.io",
        ] {
            assert!(
                !is_multi_label_public_suffix(benign),
                "over-blocked: {benign}"
            );
        }
    }

    /// Wildcard/exception table self-check invariants: strict
    /// alphabetical order (the [`is_multi_label_public_suffix`]
    /// three-step binary_search precondition), normalized form
    /// (wildcard entries `*.` prefix + trailing lowercase dot-separated
    /// punycode — the tail may be single-label (`*.ck`); exception
    /// entries multi-label normalized), no duplicates; size anchors
    /// track the current data (official list: 311 wildcard rules,
    /// exactly 8 exception rules — www.ck + 7 Japanese cities); spot
    /// checks cover single-label tails, geographic multi-label tails,
    /// the official wildcard shape in the legacy segment (`*.sch.uk`,
    /// complementary to the exact-table legacy entry `sch.uk`) and
    /// PRIVATE segment cloud-hosting tails; exception entries must not
    /// overlap the exact table (otherwise step 1 running first would
    /// wrongly pass an exact public suffix).
    #[test]
    fn psl_wildcard_and_exception_set_invariants() {
        // Wildcard table: strict order + normalized form + dedup.
        for pair in MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "wildcard strict sort violated: {} vs {}",
                pair[0],
                pair[1]
            );
        }
        let mut seen = std::collections::HashSet::new();
        for e in MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS {
            let tail = e
                .strip_prefix("*.")
                .unwrap_or_else(|| panic!("wildcard entry without `*.` prefix: {e}"));
            assert!(
                !tail.is_empty() && !tail.starts_with('.') && !tail.ends_with('.'),
                "bad wildcard tail: {e}"
            );
            assert!(
                tail.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
                "non-normalized wildcard tail: {e}"
            );
            assert!(seen.insert(*e), "duplicate wildcard entry: {e}");
        }
        // Size anchor: officially 311 entries at the moment, slow drift
        // of +-10 allowed; a large drop = table truncated or source
        // anomaly.
        assert!(
            (301..=321).contains(&seen.len()),
            "wildcard set size drifted: {}",
            seen.len()
        );
        for probe in [
            "*.ck",
            "*.jm",
            "*.kawasaki.jp",
            "*.sch.uk",
            "*.nom.br",
            "*.compute.amazonaws.com",
        ] {
            assert!(
                MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS
                    .binary_search(&probe)
                    .is_ok(),
                "missing wildcard: {probe}"
            );
        }
        // Anti-overblock anchor: ordinary domains are not wildcard
        // rules (co.uk/github.io are exact rules).
        for absent in ["*.example.com", "*.co.uk", "*.github.io"] {
            assert!(
                MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS
                    .binary_search(&absent)
                    .is_err(),
                "unexpected wildcard: {absent}"
            );
        }

        // Exception table: strict order + multi-label normalized form + dedup + exactly 8.
        for pair in MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "exception strict sort violated: {} vs {}",
                pair[0],
                pair[1]
            );
        }
        let mut seen_exc = std::collections::HashSet::new();
        for e in MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS {
            assert!(e.contains('.'), "exception must be multi-label: {e}");
            assert!(
                e.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
                "non-normalized exception: {e}"
            );
            assert!(seen_exc.insert(*e), "duplicate exception: {e}");
            // Exceptions beat the exact table (decision step 1 runs
            // first): an entry also in the exact table would wrongly
            // pass an exact public suffix — no such conflict in the
            // current data; locked.
            assert!(
                MULTI_LABEL_PUBLIC_SUFFIXES.binary_search(e).is_err(),
                "exception also in exact table: {e}"
            );
        }
        assert_eq!(seen_exc.len(), 8, "exception set size changed");
        for probe in ["www.ck", "city.kawasaki.jp", "city.yokohama.jp"] {
            assert!(
                MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS
                    .binary_search(&probe)
                    .is_ok(),
                "missing exception: {probe}"
            );
        }
    }

    /// Wildcard/exception decision table (libpsl-shaped): `*` matches
    /// exactly one label (candidate = `<single label>.tail` is a
    /// public suffix; one more layer is a registrable domain);
    /// exceptions beat wildcards (the entry itself is a registrable
    /// domain, its subdomains likewise); existing exact-table behavior
    /// does not regress.
    #[test]
    fn multi_label_public_suffix_wildcard_decision_table() {
        // Wildcard hits (rejection face).
        for suffix in [
            "foo.kawasaki.jp", // *.kawasaki.jp (multi-label tail)
            "foo.ck",          // *.ck (single-label tail)
            "foo.jm",          // *.jm (single-label tail)
            "hoge.sch.uk",     // *.sch.uk (official wildcard shape of legacy exact entry sch.uk)
            // PRIVATE segment cloud-hosting wildcard.
            "hoge.compute.amazonaws.com",
            // punycode shape of a non-ASCII source: `*` eats one label regardless.
            "xn--zckzah.kawasaki.jp",
        ] {
            assert!(
                is_multi_label_public_suffix(suffix),
                "should be public suffix: {suffix}"
            );
        }
        // A wildcard eats one layer: one more layer = registrable domain (allow face).
        for registrable in [
            "bar.foo.kawasaki.jp",
            // *.ck eats one layer: b.ck is the public suffix, a.b.ck is a registrable domain.
            "a.b.ck",
            "a.b.jm",
            "a.hoge.sch.uk",
            "a.hoge.compute.amazonaws.com",
        ] {
            assert!(
                !is_multi_label_public_suffix(registrable),
                "should be registrable: {registrable}"
            );
        }
        // Exceptions beat wildcards: the entry itself is a registrable domain.
        for exc in [
            "www.ck",           // !www.ck beats *.ck
            "city.kawasaki.jp", // !city.kawasaki.jp beats *.kawasaki.jp
            "city.sendai.jp",
        ] {
            assert!(
                !is_multi_label_public_suffix(exc),
                "exception entry is registrable: {exc}"
            );
        }
        // Siblings/subdomains of an exception are unaffected: sibling
        // x.ck is still a public suffix (*.ck); subdomains under an
        // exception domain are registrable.
        assert!(is_multi_label_public_suffix("x.ck"));
        assert!(!is_multi_label_public_suffix("sub.www.ck"));
        assert!(!is_multi_label_public_suffix("sub.city.kawasaki.jp"));
        // Existing exact-table behavior does not regress.
        assert!(is_multi_label_public_suffix("co.uk"));
        assert!(is_multi_label_public_suffix("github.io"));
        assert!(!is_multi_label_public_suffix("example.github.io"));
        assert!(!is_multi_label_public_suffix("example.com"));
    }

    /// Wildcard/exception semantics on the Set-Cookie face (same path
    /// as the existing `Domain=co.uk` defense): a wildcard-hit Domain
    /// attribute (a public suffix itself) rejects the whole cookie
    /// with no sibling leak; registrable domains one layer under the
    /// wildcard and exception entries are accepted normally.
    #[test]
    fn absorb_wildcard_public_suffix_and_exception_semantics() {
        let store = CookieStore::new();
        // *.kawasaki.jp => foo.kawasaki.jp is a public suffix: a
        // subsite setting Domain=foo.kawasaki.jp would harvest all
        // *.foo.kawasaki.jp — rejected.
        let evil: Url = "http://evil.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&evil, "sid=x; Domain=foo.kawasaki.jp; Path=/");
        store.absorb(&evil, "sid2=y; Domain=.foo.kawasaki.jp; Path=/");
        assert!(
            store.is_empty(),
            "wildcard public-suffix Domain attrs rejected: {:?}",
            store.snapshot()
        );
        let bank: Url = "https://bank.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            store.header_for(&bank).is_none(),
            "no cookie leaked to *.foo.kawasaki.jp sibling"
        );

        // A wildcard eats one layer: bar.foo.kawasaki.jp is a
        // registrable domain — the same-domain Domain attribute is
        // accepted and resends to its subdomains.
        let reg: Url = "http://www.bar.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&reg, "k=v; Domain=bar.foo.kawasaki.jp; Path=/");
        assert_eq!(store.len(), 1, "{:?}", store.snapshot());
        let sibling: Url = "http://x.bar.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert_eq!(store.header_for(&sibling).unwrap_or_default(), "k=v");

        // *.ck: foo.ck rejected; a.b.ck (registrable domain) accepted.
        let ck_store = CookieStore::new();
        let ck_evil: Url = "http://evil.foo.ck/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        ck_store.absorb(&ck_evil, "s=v; Domain=foo.ck; Path=/");
        assert!(ck_store.is_empty(), "{:?}", ck_store.snapshot());
        let ck_reg: Url = "http://site.a.b.ck/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        ck_store.absorb(&ck_reg, "r=v; Domain=a.b.ck; Path=/");
        assert_eq!(ck_store.len(), 1, "{:?}", ck_store.snapshot());

        // Exceptions beat wildcards: www.ck / city.kawasaki.jp are
        // registrable — accepted and resent.
        let exc_store = CookieStore::new();
        let www_ck: Url = "http://www.ck/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        exc_store.absorb(&www_ck, "e=v; Domain=www.ck; Path=/");
        let city: Url = "http://sub.city.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        exc_store.absorb(&city, "c=v; Domain=city.kawasaki.jp; Path=/");
        assert_eq!(exc_store.len(), 2, "{:?}", exc_store.snapshot());
        assert_eq!(exc_store.header_for(&www_ck).unwrap_or_default(), "e=v");
        assert_eq!(exc_store.header_for(&city).unwrap_or_default(), "c=v");
    }

    /// Wildcard/exception semantics on the Netscape file face (same
    /// rule as the Set-Cookie face): domain-cookie lines whose domain
    /// is a wildcard-hit suffix (`.foo.kawasaki.jp`/`foo.ck`/punycode
    /// label shapes) reject the whole line; exception entries
    /// (`www.ck`/`city.kawasaki.jp`) and registrable domains under the
    /// wildcard (`bar.foo.kawasaki.jp`) are kept and resent.
    #[test]
    fn wildcard_public_suffix_netscape_lines_rejected() {
        let text = ".foo.kawasaki.jp\tTRUE\t/\tFALSE\t0\tsid\tx\n\
                    foo.ck\tTRUE\t/\tFALSE\t0\tsid2\ty\n\
                    xn--zckzah.kawasaki.jp\tTRUE\t/\tFALSE\t0\tpuny\tdrop\n\
                    www.ck\tTRUE\t/\tFALSE\t0\texcept1\tok\n\
                    city.kawasaki.jp\tTRUE\t/\tFALSE\t0\texcept2\tok2\n\
                    bar.foo.kawasaki.jp\tTRUE\t/\tFALSE\t0\treg\tok3\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 3, "{:?}", jar.cookies());

        // Wildcard public-suffix lines dropped: *.foo.kawasaki.jp
        // siblings get no resend at all.
        let bank: Url = "https://bank.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            jar.header_for(&bank).is_none(),
            "no cookie for wildcard-suffix sibling"
        );
        // Exception and registrable lines resend normally (domain cookies apply to subdomains).
        let www_ck: Url = "http://www.ck/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert_eq!(
            jar.header_for(&www_ck).unwrap_or_default(),
            "except1=ok",
            "exception entry kept and sent"
        );
        let sub: Url = "http://x.bar.foo.kawasaki.jp/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&sub).unwrap_or_default();
        assert!(header.contains("reg=ok3"), "{header}");
        // city.kawasaki.jp's cookie does not apply to
        // bar.foo.kawasaki.jp subdomains (two independent registrable
        // domains under the wildcard *.kawasaki.jp).
        assert!(
            !header.contains("except2=ok2"),
            "city cookie does not cross registrable domains: {header}"
        );
    }

    /// (name, domain, path) duplicate-line dedup: the later line
    /// overwrites the earlier (RFC 6265 §5.3 step 11: same key, new
    /// value replaces old); no duplicate Cookie pairs may be
    /// synthesized.
    #[test]
    fn duplicate_name_domain_path_last_wins() {
        let text = "a.example.com\tFALSE\t/\tFALSE\t4102444800\tk\told\n\
                    a.example.com\tFALSE\t/\tFALSE\t4102444800\tk\tnew\n";
        let jar = CookieJar::parse_netscape(text);
        assert_eq!(jar.len(), 1);

        let url: Url = "https://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&url).unwrap_or_default();
        assert_eq!(header, "k=new", "{header}");
    }

    /// IPv6 literals: the request URL host has brackets stripped before domain matching.
    #[test]
    fn ipv6_literal_host_matches_without_brackets() {
        let jar = CookieJar::parse_netscape("::1\tFALSE\t/\tFALSE\t0\ts6\tv\n");
        let url: Url = "http://[::1]:8080/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = jar.header_for(&url).unwrap_or_default();
        assert!(header.contains("s6=v"), "{header}");
    }

    // ---------- Task cookie store (absorb/resend) ----------

    #[test]
    fn absorb_host_only_default_path_and_resent() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/deep/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "sid=abc");
        assert_eq!(store.len(), 1);
        let c = &store.snapshot()[0];
        assert_eq!(c.domain, "a.example.com");
        assert!(c.host_only, "no Domain attr = host-only");
        assert_eq!(c.path, "/deep", "default-path of /deep/x");
        assert!(!c.secure);

        // Subpaths under the path resend; outside the path nothing is sent.
        let under: Url = "http://a.example.com/deep/y"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = store.header_for(&under).unwrap_or_default();
        assert_eq!(header, "sid=abc");
        let other: Url = "http://a.example.com/other"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(store.header_for(&other).is_none());
    }

    #[test]
    fn absorb_domain_attr_tail_match_and_reject() {
        let store = CookieStore::new();
        let url: Url = "http://www.a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "k=v; Domain=a.example.com; Path=/");
        assert_eq!(store.len(), 1);

        // Domain cookies resend to subdomains.
        let sub: Url = "http://x.a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(store.header_for(&sub).is_some());

        // A domain not tail-matching the request host rejects the
        // whole cookie (§5.3 step 6).
        store.absorb(&url, "evil=1; Domain=other.com; Path=/");
        // Single-label public-suffix shape rejected (the .com harvest face).
        store.absorb(&url, "ps=1; Domain=com; Path=/");
        assert_eq!(store.len(), 1, "mismatched/public-suffix domains rejected");
        let any: Url = "http://any.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(store.header_for(&any).is_none());
    }

    /// Multi-label public-suffix defense (Set-Cookie Domain
    /// attribute): evil.co.uk answering `Set-Cookie: sid=x;
    /// Domain=co.uk` rejects the whole cookie — otherwise tail-match
    /// would send it to any *.co.uk site (victim bank.co.uk included).
    /// A leading-dot form normalizes to the same rejection;
    /// single-label (com) rejection and normal-domain behavior
    /// (example.com setting Domain=example.com) are preserved.
    #[test]
    fn absorb_multi_label_public_suffix_domain_rejected() {
        let store = CookieStore::new();
        let evil: Url = "http://evil.co.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&evil, "sid=x; Domain=co.uk; Path=/");
        store.absorb(&evil, "sid2=y; Domain=.co.uk; Path=/");
        assert!(
            store.is_empty(),
            "multi-label public-suffix Domain attrs rejected: {:?}",
            store.snapshot()
        );

        // Direct consequence of the rejection: no *.co.uk site
        // (victims included) gets the cookie resent.
        let bank: Url = "https://bank.co.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            store.header_for(&bank).is_none(),
            "no cookie leaked to sibling .co.uk site"
        );

        // Single-label public-suffix rejection preserved (the .com harvest face).
        store.absorb(&evil, "ps=1; Domain=com; Path=/");
        assert!(store.is_empty());

        // Normal-domain behavior preserved: host == Domain attribute
        // (example.com sets Domain=example.com) accepted;
        // parent/child domain cookies are unaffected by the
        // public-suffix defense.
        let exact: Url = "http://example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&exact, "k=v; Domain=example.com; Path=/");
        assert_eq!(store.len(), 1);
        let header = store.header_for(&exact).unwrap_or_default();
        assert_eq!(header, "k=v", "{header}");
    }

    /// (a) Added-segment public-suffix defense — evil.me.uk answering
    /// `Set-Cookie: sid=x; Domain=me.uk` rejects the whole cookie
    /// (me.uk was previously missing from the hand-curated set,
    /// leaving the *.me.uk harvest face alive); bank.me.uk gets no
    /// resend; the same-domain Domain attribute (host == Domain) and
    /// host-only regression anchors are preserved.
    #[test]
    fn absorb_me_uk_public_suffix_domain_rejected() {
        let store = CookieStore::new();
        let evil: Url = "http://evil.me.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&evil, "sid=x; Domain=me.uk; Path=/");
        store.absorb(&evil, "sid2=y; Domain=.me.uk; Path=/");
        assert!(
            store.is_empty(),
            "me.uk Domain attrs rejected: {:?}",
            store.snapshot()
        );
        let bank: Url = "https://bank.me.uk/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            store.header_for(&bank).is_none(),
            "no cookie leaked to sibling .me.uk site"
        );
        // Regression anchor: same-domain Domain attribute and
        // host-only are unaffected by the added segments.
        store.absorb(&evil, "k=v; Domain=evil.me.uk; Path=/");
        store.absorb(&evil, "hostonly=1; Path=/");
        assert_eq!(store.len(), 2, "{:?}", store.snapshot());
        let header = store.header_for(&evil).unwrap_or_default();
        assert_eq!(header, "k=v; hostonly=1", "{header}");
    }

    /// (b) Trailing dot (DNS absolute form) normalization — the url
    /// parser preserves the host's trailing-dot form, and a
    /// trailing-dot Domain previously missed the public-suffix tables
    /// while tail-match against a trailing-dot host still held (the
    /// leak face = the trailing-dot sibling). After the fix:
    /// - `Domain=co.uk.` / `Domain=.co.uk.` normalize to a table hit
    ///   and reject the whole cookie;
    /// - the host side is normalized the same way (request_host strips
    ///   the dot): normal-domain cookies for trailing-dot URLs are
    ///   accepted after both-side normalization, and a dot-stripped
    ///   host also receives resends;
    /// - a dotless host setting a trailing-dot Domain
    ///   (`Domain=example.com.`) is accepted as a normal domain after
    ///   normalization.
    #[test]
    fn absorb_trailing_dot_domain_forms_rejected_and_host_normalized() {
        let store = CookieStore::new();
        // Leak reproduction: evil.co.uk. (trailing-dot URL host)
        // setting a trailing-dot Domain.
        let evil: Url = "http://evil.co.uk./"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&evil, "sid=x; Domain=co.uk.; Path=/");
        store.absorb(&evil, "sid2=y; Domain=.co.uk.; Path=/");
        assert!(
            store.is_empty(),
            "trailing-dot public-suffix Domain rejected: {:?}",
            store.snapshot()
        );
        // Trailing-dot sibling (bank.co.uk.) gets no resend.
        let bank: Url = "https://bank.co.uk./"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(
            store.header_for(&bank).is_none(),
            "no cookie leaked to trailing-dot sibling"
        );
        // Host-side normalization regression anchor: a normal-domain
        // cookie from a trailing-dot URL is accepted, and a
        // dot-stripped host's request also resends (both sides
        // normalized).
        let www: Url = "http://www.example.com./"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&www, "k=v; Domain=example.com; Path=/");
        assert_eq!(store.len(), 1, "{:?}", store.snapshot());
        let stripped: Url = "http://www.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert_eq!(store.header_for(&stripped).unwrap_or_default(), "k=v");
        let exact: Url = "http://example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert_eq!(store.header_for(&exact).unwrap_or_default(), "k=v");
        // Dotless host + trailing-dot Domain attribute: accepted as a
        // normal domain after normalization.
        store.absorb(&stripped, "k2=v2; Domain=example.com.; Path=/");
        assert_eq!(store.len(), 2, "{:?}", store.snapshot());
        assert_eq!(store.header_for(&exact).unwrap_or_default(), "k=v; k2=v2");
    }

    /// (c) Added-segment per-segment coverage — set-level full sweep
    /// (>= 2 entries per segment), absorb-level representatives per
    /// segment (evil.\<suffix\> setting Domain=\<suffix\> -> rejected +
    /// victim sites get no resend); the normal registrable domain
    /// (example.com setting Domain=example.com) regression anchor is
    /// preserved.
    #[test]
    fn absorb_added_public_suffix_segments_rejected() {
        // Set level: added-segment representatives (UK additions/AT/
        // GR/PT/RO/HU/CentralNic/punycode/China provincial/Australia
        // state/Japan-Korea regional/Middle East-Africa/LatAm).
        for probe in [
            "me.uk",
            "net.uk",
            "sch.uk",
            "ltd.uk",
            "plc.uk",
            "co.at",
            "or.at",
            "ac.at",
            "com.gr",
            "net.gr",
            "org.gr",
            "com.pt",
            "org.pt",
            "edu.pt",
            "com.ro",
            "org.ro",
            "shop.ro",
            "co.hu",
            "web.hu",
            "2000.hu",
            "uk.com",
            "gb.com",
            "us.com",
            "de.com",
            "eu.com",
            "jp.net",
            "cn.com",
            "ru.com",
            "br.com",
            "za.org",
            "xn--55qx5d.cn",
            "xn--io0a7i.cn",
            "bj.cn",
            "sh.cn",
            "gd.cn",
            "qld.au",
            "nsw.au",
            "tokyo.jp",
            "osaka.jp",
            "seoul.kr",
            "go.kr",
            "gov.za",
            "co.ir",
            "com.ly",
            "co.tz",
            "com.gt",
            "gov.do",
            "in.ua",
            "ac.vn",
            "com.mk",
            "co.me",
        ] {
            assert!(is_multi_label_public_suffix(probe), "missing: {probe}");
        }
        // Absorb level: representatives per segment (evil.<suffix> sets Domain=<suffix>).
        for suffix in [
            "me.uk",
            "co.at",
            "com.gr",
            "com.pt",
            "com.ro",
            "co.hu",
            "uk.com",
            "cn.com",
            "jp.net",
            "xn--55qx5d.cn",
            "xn--io0a7i.cn",
            "bj.cn",
            "tokyo.jp",
            "gov.za",
        ] {
            let store = CookieStore::new();
            let evil: Url = format!("http://evil.{suffix}/")
                .parse()
                .unwrap_or_else(|e| panic!("url {suffix}: {e}"));
            store.absorb(&evil, &format!("sid=x; Domain={suffix}; Path=/"));
            assert!(
                store.is_empty(),
                "Domain={suffix} rejected: {:?}",
                store.snapshot()
            );
            let bank: Url = format!("https://bank.{suffix}/")
                .parse()
                .unwrap_or_else(|e| panic!("url {suffix}: {e}"));
            assert!(
                store.header_for(&bank).is_none(),
                "no cookie leaked via {suffix}"
            );
        }
        // Regression anchor: a normal registrable domain (example.com
        // sets Domain=example.com) is accepted.
        let store = CookieStore::new();
        let exact: Url = "http://example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&exact, "k=v; Domain=example.com; Path=/");
        assert_eq!(store.len(), 1);
        assert_eq!(store.header_for(&exact).unwrap_or_default(), "k=v");
    }

    #[test]
    fn absorb_ip_host_is_host_only() {
        let store = CookieStore::new();
        let url: Url = "http://127.0.0.1:8080/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        // IP host + different-IP Domain attribute: IPs do not
        // participate in tail-match -> rejected.
        store.absorb(&url, "bad=1; Domain=0.0.0.1; Path=/");
        assert!(store.is_empty());
        // IP host + same-IP Domain attribute: exact equality is a
        // domain match (§5.1.3), equivalent to host-only.
        store.absorb(&url, "same=1; Domain=127.0.0.1; Path=/");
        assert_eq!(store.len(), 1);
        // IP host without a Domain attribute = host-only, accepted.
        store.absorb(&url, "ok=1; Path=/");
        assert_eq!(store.len(), 2);
        assert!(store.snapshot()[1].host_only);
    }

    #[test]
    fn absorb_secure_stored_but_not_sent_over_http() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "s=1; Secure; Path=/");
        assert_eq!(store.len(), 1);
        assert!(store.snapshot()[0].secure);
        // Not resent over non-https (no Secure cookie on an https->http
        // downgrade).
        assert!(store.header_for(&url).is_none());
    }

    #[test]
    fn absorb_max_age_expiry_deletes_same_key() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "k=v; Max-Age=3600; Path=/");
        assert_eq!(store.len(), 1);
        // Already expired (Max-Age=0) -> deletes the same-key entry, no new entry.
        store.absorb(&url, "k=v; Max-Age=0; Path=/");
        assert!(store.is_empty());
        // Invalid Max-Age -> attribute ignored (session cookie fallback).
        store.absorb(&url, "m=v; Max-Age=abc; Path=/");
        assert_eq!(store.len(), 1);
        assert_eq!(store.snapshot()[0].expires, None);
    }

    #[test]
    fn absorb_merge_same_key_replaces_value() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "k=old; Path=/");
        store.absorb(&url, "k=new; Path=/");
        assert_eq!(store.len(), 1);
        let header = store.header_for(&url).unwrap_or_default();
        assert_eq!(header, "k=new");
    }

    #[test]
    fn absorb_expires_http_date() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        // An expired HTTP-date -> delete face (no entry landed).
        store.absorb(&url, "d=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/");
        assert!(store.is_empty());
        // A future HTTP-date -> entry landed, expiry parsed per §5.1.1.
        store.absorb(&url, "d=1; Expires=Wed, 21 Oct 2100 07:28:00 GMT; Path=/");
        assert_eq!(store.len(), 1);
        let exp = store.snapshot()[0].expires;
        assert!(exp.is_some_and(|t| t > unix_now()), "{exp:?}");
        // An unparseable Expires -> session cookie fallback.
        store.absorb(&url, "s=1; Expires=nonsense; Path=/");
        assert_eq!(store.len(), 2);
        assert_eq!(store.snapshot()[1].expires, None);
    }

    #[test]
    fn absorb_rejects_injection_and_missing_pair() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        // A pair without '=' is dropped entirely.
        store.absorb(&url, "novalue");
        // A value with ';' (already isolated by the split), ',' or CTL -> rejected.
        store.absorb(&url, "inj=bad,value");
        store.absorb(&url, "ctl=bad\nvalue");
        // An empty name -> rejected.
        store.absorb(&url, "=anon; Path=/");
        assert!(store.is_empty(), "store: {:?}", store.snapshot());
    }

    /// RFC 6265 §5.1.1 date-form vectors: IMF-fixdate/RFC 850/asctime.
    #[test]
    fn cookie_date_parser_vectors() {
        assert_eq!(
            parse_cookie_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(1445412480)
        );
        assert_eq!(
            parse_cookie_date("Wednesday, 21-Oct-15 07:28:00 GMT"),
            Some(1445412480)
        );
        assert_eq!(
            parse_cookie_date("Sun Nov  6 08:49:37 1994"),
            Some(784111777)
        );
        assert_eq!(parse_cookie_date("not a date"), None);
        // With Max-Age absent, Expires provides year/month/day/time —
        // any missing group -> None.
        assert_eq!(parse_cookie_date("21 Oct"), None);
    }

    /// CookieStore shared-handle semantics: Clone shares content; PartialEq compares snapshots.
    #[test]
    fn cookie_store_clone_shares_and_snapshot_equality() {
        let store = CookieStore::new();
        let clone = store.clone();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "k=v; Path=/");
        assert_eq!(clone.len(), 1, "clone is a shared handle");
        assert_eq!(store, clone);

        let other = CookieStore::new();
        other.absorb(&url, "k=v; Path=/");
        assert_eq!(store, other, "equality is by snapshot content");
        other.absorb(&url, "k=v2; Path=/");
        assert_ne!(store, other);
    }

    /// seed injection seam: Netscape file parse results pour straight
    /// into the task store, same key later wins; injected entries
    /// resend per §5.4 domain/path/Secure.
    #[test]
    fn seed_prefills_store_from_jar_last_wins() {
        let jar = CookieJar::parse_netscape(
            "a.example.com\tFALSE\t/\tFALSE\t4102444800\tsid\told\n\
             a.example.com\tTRUE\t/\tFALSE\t0\tdom\tv\n",
        );
        let store = CookieStore::new();
        // Same key (name, domain, path): the later one wins (§5.3 step 11).
        store.seed(jar.cookies().iter().cloned());
        store.seed(std::iter::once(NetscapeCookie {
            domain: "a.example.com".into(),
            host_only: false,
            path: "/".into(),
            secure: false,
            expires: Some(4102444800),
            name: "sid".into(),
            value: "new".into(),
        }));
        assert_eq!(store.len(), 2);
        let url: Url = "https://sub.a.example.com/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        let header = store.header_for(&url).unwrap_or_default();
        assert!(header.contains("sid=new"), "{header}");
        assert!(header.contains("dom=v"), "{header}");
        // The host-only exact domain does not match the subdomain.
        let exact: Url = "https://a.example.com/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        assert!(store.header_for(&exact).is_some());
    }

    /// replace_with override seam (setTaskCookies): whole-set
    /// replacement (clear first, then fill), distinguishable from
    /// seed's merge semantics.
    #[test]
    fn replace_with_clears_before_seeding() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "captured=1; Path=/");
        assert_eq!(store.len(), 1);
        store.replace_with(std::iter::once(NetscapeCookie {
            domain: "a.example.com".into(),
            host_only: true,
            path: "/".into(),
            secure: false,
            expires: None,
            name: "fresh".into(),
            value: "v".into(),
        }));
        assert_eq!(store.len(), 1, "captured=1 overwritten away");
        let header = store.header_for(&url).unwrap_or_default();
        assert_eq!(header, "fresh=v", "{header}");
    }

    /// Runtime ingestion cap: once entries reach
    /// [`MAX_RUNTIME_COOKIE_ENTRIES`], new keys are still accepted and
    /// the least recently active (first inserted) entry is evicted —
    /// the ingestion face is thereby capped (DoS bound).
    #[test]
    fn absorb_caps_entries_and_evicts_oldest() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        for i in 0..MAX_RUNTIME_COOKIE_ENTRIES {
            store.absorb(&url, &format!("k{i}=v; Path=/"));
        }
        assert_eq!(store.len(), MAX_RUNTIME_COOKIE_ENTRIES);
        let newest = format!("k{MAX_RUNTIME_COOKIE_ENTRIES}");
        store.absorb(&url, &format!("{newest}=v; Path=/"));
        assert_eq!(store.len(), MAX_RUNTIME_COOKIE_ENTRIES, "cap holds");
        let snap = store.snapshot();
        // Exactly the oldest k0 was evicted; next-oldest k1 remains
        // (only one evicted); the new key is kept at the back.
        assert!(!snap.iter().any(|c| c.name == "k0"), "oldest evicted");
        assert!(snap.iter().any(|c| c.name == "k1"), "only one evicted");
        let last = snap.last().unwrap_or_else(|| panic!("empty after cap"));
        assert_eq!(last.name, newest, "new entry retained at the back");
        assert_eq!(last.value, "v");
    }

    /// Same-key updates neither grow nor evict: on a full store the
    /// entry is replaced in place (key set and storage order unchanged
    /// bit for bit) and recency refreshed — the updated entry moves
    /// out of eviction order; the next eviction target is the
    /// unrefreshed next-oldest entry.
    #[test]
    fn absorb_same_key_update_at_cap_neither_grows_nor_evicts() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        for i in 0..MAX_RUNTIME_COOKIE_ENTRIES {
            store.absorb(&url, &format!("k{i}=v; Path=/"));
        }
        let before = store.snapshot();
        for r in 0..4 {
            store.absorb(&url, &format!("k7=upd{r}; Path=/"));
        }
        assert_eq!(
            store.len(),
            MAX_RUNTIME_COOKIE_ENTRIES,
            "update not counted as new"
        );
        let after = store.snapshot();
        assert_eq!(before.len(), after.len());
        for (b, a) in before.iter().zip(&after) {
            assert_eq!(
                (b.name.as_str(), b.domain.as_str(), b.path.as_str()),
                (a.name.as_str(), a.domain.as_str(), a.path.as_str()),
                "storage order unchanged by update"
            );
        }
        let Some(k7) = after.iter().find(|c| c.name == "k7") else {
            panic!("k7 missing");
        };
        assert_eq!(k7.value, "upd3");
        // After refreshing the oldest k0's recency and adding a new
        // key: the next-oldest k1 is evicted, not the refreshed k0;
        // one in, one out, the count stays capped.
        store.absorb(&url, "k0=refreshed; Path=/");
        store.absorb(&url, "fresh=v; Path=/");
        assert_eq!(store.len(), MAX_RUNTIME_COOKIE_ENTRIES, "one in, one out");
        let snap = store.snapshot();
        let value_of = |name: &str| {
            snap.iter()
                .find(|c| c.name == name)
                .map(|c| c.value.as_str())
        };
        assert_eq!(value_of("k0"), Some("refreshed"), "updated entry survives");
        assert_eq!(value_of("k1"), None, "next-oldest evicted instead");
        assert_eq!(value_of("k2"), Some("v"), "exactly one entry evicted");
        assert_eq!(value_of("fresh"), Some("v"));
    }

    /// Under-cap behavior is field-for-field identical to the uncapped
    /// status quo: storage order = insertion order; fields
    /// (domain/host_only/path/secure/expires/name/value) and the
    /// resent header are unaffected by the cap; same-key updates keep
    /// their position.
    #[test]
    fn absorb_under_cap_field_by_field_unchanged() {
        let store = CookieStore::new();
        let url: Url = "http://a.example.com/deep/x"
            .parse()
            .unwrap_or_else(|e| panic!("url: {e}"));
        store.absorb(&url, "a=1; Path=/");
        store.absorb(&url, "b=2; Secure; Max-Age=3600; Path=/deep");
        store.absorb(&url, "c=3");
        assert!(store.len() < MAX_RUNTIME_COOKIE_ENTRIES);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].name, "a");
        assert_eq!(snap[0].value, "1");
        assert_eq!(snap[0].domain, "a.example.com");
        assert!(snap[0].host_only);
        assert_eq!(snap[0].path, "/");
        assert!(!snap[0].secure);
        assert_eq!(snap[0].expires, None);
        assert_eq!(snap[1].name, "b");
        assert_eq!(snap[1].path, "/deep");
        assert!(snap[1].secure);
        assert!(snap[1].expires.is_some_and(|t| t > unix_now()));
        assert_eq!(snap[2].name, "c");
        assert_eq!(snap[2].path, "/deep", "default-path of /deep/x");
        // Same-key update: replaced in place (storage order unchanged), only the value refreshed.
        store.absorb(&url, "a=1b; Path=/");
        let snap = store.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].name, "a", "same-key update keeps position");
        assert_eq!(snap[0].value, "1b");
        // The resend face is unaffected by the cap (b is Secure; not
        // resent over http).
        let header = store.header_for(&url).unwrap_or_default();
        assert_eq!(header, "a=1b; c=3");
    }
}
