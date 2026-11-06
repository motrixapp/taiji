//! SSRF defense line for second-order media URLs (the media spec's
//! key-section threat model, extending the product spec's base SSRF
//! posture — the
//! line covers **both** the key URIs and the media-segment/init
//! section URLs, defending against a forged manifest or probe snapshot
//! driving intranet fetches).
//!
//! # Decision shape (pure core + injected resolution)
//!
//! [`decide_uri`] is pure: scheme whitelist → literal-IP/localhost
//! classification → a `NeedsResolve` verdict handed to the caller. The
//! resolved-IP layer runs through the injected [`SsrfResolver`] (the
//! test injection face — the production adapter rides
//! `taiji_io::dns::SharedDns`, the process-level shared resolver, so
//! the decision and the actual connection share one TTL-cached view).
//!
//! * **Scheme whitelist** (always, flag or not): `http`, `https`,
//! `data:` — everything else (`ftp://`, `file://`, …) is denied.
//! * **Literal layer**: `localhost` and restricted IP literals
//! (loopback / RFC1918 private / link-local incl. 169.254.169.254 /
//! ULA / v4-mapped / NAT64 / unspecified / multicast) are denied
//! under the default posture. The classification list mirrors the
//! base crate's `redirect_guard` module (its classifier is
//! `pub(crate)`; the mirror is deliberate and documented — same
//! list, same semantics, media-owned pure function).
//! * **Resolved layer**: any resolved address restricted → denied
//! (**any** rule, conservative side); resolution failure or an empty
//! answer list → denied (fail-closed — the guard query and the
//! connect query are independent, so allowing an unresolvable-now
//! host would open a two-query bypass; the fetch would fail anyway).
//! * **Flag**: `--media-allow-private-key-url` (per the product spec) relaxes
//! the private-address layers for **both faces at once** — one
//! threat model (a forged manifest driving intranet fetches), one
//! escape hatch. The widened scope (the flag name says "key", the
//! line also covers segment URLs) is recorded for the
//! unified-surface registration / difference declaration. With
//! the flag on, resolution is skipped entirely (localhost mock labs
//! need no DNS).
//!
//! # Redirect endpoints
//!
//! The initial-target faces above are media-owned. The **redirect
//! endpoint** coverage rides the base client's redirect IP hygiene
//! (`taiji-http` `redirect_guard`: a non-restricted initial URL plus a
//! restricted hop target is refused with `HttpError::RedirectToRestrictedIp`;
//! a restricted initial — a localhost/LAN media source under the flag —
//! passes every hop). Residual, deliberate (no base fork): with
//! the flag on, a *public* key/segment host redirecting into a private
//! network is still refused by the base guard; the flag's contract is
//! "my media source is on the private network", not "any public host
//! may pivot private mid-chain". Registered for the difference
//! declaration.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures::future::BoxFuture;

use crate::error::MediaError;

/// Allowed URL schemes for second-order media URLs (the media spec's
/// http/https/data: line).
pub const ALLOWED_SCHEMES: &[&str] = &["http", "https", "data"];

/// The SSRF posture: default deny private targets, explicit flag to
/// allow (`--media-allow-private-key-url`; default false =
/// deny private).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SsrfPolicy {
    /// `--media-allow-private-key-url` (default false = deny private).
    pub allow_private: bool,
}

/// Pure decision for one URI (see module docs for the layer order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed outright (scheme whitelisted + `data:`, or the flag is
    /// on and the scheme is whitelisted).
    Allowed,
    /// Denied; the text names the layer that refused (embedded in
    /// `taiji.media.ssrf_blocked`).
    Denied(&'static str),
    /// The literal layer is inconclusive — the host needs resolution
    /// (the caller consults the injected resolver and applies the
    /// any-restricted rule).
    NeedsResolve { host: String },
}

/// Single-address classification (mirrors the base `redirect_guard`
/// list; see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrClass {
    /// Loopback / RFC1918 / link-local / ULA / v4-mapped / NAT64-
    /// embedded / unspecified / multicast.
    Restricted,
    /// Publicly routable.
    Public,
}

/// Classify one address (the mirror of `taiji-http`'s redirect-guard
/// table; the anti-over-blocking red line holds: CGNAT `100.64/10`,
/// documentation ranges and site-local `fec0::/10` stay Public).
pub fn classify_addr(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // v4-mapped ::ffff:0:0/96 → classify the embedded v4.
            if seg[..5].iter().all(|s| *s == 0) && seg[5] == 0xFFFF {
                let v4 = std::net::Ipv4Addr::from(u32::from(seg[6]) << 16 | u32::from(seg[7]));
                return classify_v4(v4);
            }
            // NAT64 64:ff9b::/96 → the embedded v4 (RFC 6052 WKP).
            if seg[0] == 0x64 && seg[1] == 0xFF9B && seg[2..5].iter().all(|s| *s == 0) {
                let v4 = std::net::Ipv4Addr::from(u32::from(seg[6]) << 16 | u32::from(seg[7]));
                return classify_v4(v4);
            }
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xFFC0) == 0xFE80 // link-local fe80::/10
                || (seg[0] & 0xFE00) == 0xFC00
            // ULA fc00::/7
            {
                AddrClass::Restricted
            } else {
                AddrClass::Public
            }
        }
    }
}

fn classify_v4(v4: std::net::Ipv4Addr) -> AddrClass {
    let o = v4.octets();
    if v4.is_loopback()
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254/16 (cloud metadata included)
        || v4.is_unspecified()
        || v4.is_multicast()
        || (o[0] == 0)
    // 0.0.0.0/8 ("this network")
    {
        AddrClass::Restricted
    } else {
        AddrClass::Public
    }
}

/// The host-literal layer: `localhost`, restricted IP literals. A
/// non-literal host returns `None` (the resolver layer decides).
pub fn classify_host_literal(host: &str) -> Option<AddrClass> {
    if host.eq_ignore_ascii_case("localhost") {
        return Some(AddrClass::Restricted);
    }
    // Bracketed v6 form (callers pass `Url::host_str`, which is already
    // unbracketed; accept both defensively).
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match unbracketed.parse::<IpAddr>() {
        Ok(ip) => Some(classify_addr(ip)),
        Err(_) => None,
    }
}

/// Pure first-stage decision for one URI under a policy.
pub fn decide_uri(uri: &str, policy: &SsrfPolicy) -> Decision {
    let Ok(url) = taiji_http::reqwest::Url::parse(uri) else {
        return Decision::Denied("unparseable URL");
    };
    let scheme = url.scheme().to_ascii_lowercase();
    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        return Decision::Denied("scheme outside the http/https/data: whitelist");
    }
    // data: carries no host — scheme-whitelisted is all it needs.
    if scheme == "data" {
        return Decision::Allowed;
    }
    // The flag relaxes the private-address layers (scheme whitelist
    // stays in force above).
    if policy.allow_private {
        return Decision::Allowed;
    }
    let Some(host) = url.host_str().map(str::to_owned) else {
        return Decision::Denied("URL without a host");
    };
    match classify_host_literal(&host) {
        Some(AddrClass::Restricted) => Decision::Denied("loopback/private/link-local literal host"),
        Some(AddrClass::Public) => Decision::Allowed,
        None => Decision::NeedsResolve { host },
    }
}

/// The injected resolution face (the resolved-IP layer). Production
/// adapter: [`ProductionSsrfResolver`] over the process-shared DNS
/// service; tests inject stubs (the taiji-io test-DNS ban — no real
/// resolution in tests).
pub trait SsrfResolver: Send + Sync {
    /// Resolve one hostname to its address list; an error or an empty
    /// list is fail-closed at the decision layer.
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>>;
}

/// Production resolver: the process-level shared DNS service (the same
/// resolver the base's redirect guard and the transports share — one
/// TTL-cached view; `resolve_for_transport`'s literal-IP passthrough is
/// unreachable here because the literal layer already classified).
#[derive(Default)]
pub struct ProductionSsrfResolver;

impl SsrfResolver for ProductionSsrfResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            let shared = taiji_io::dns::SharedDns::shared_default();
            let addrs = shared
                .resolve_for_transport(host, 0)
                .await
                .map_err(|e| e.to_string())?;
            Ok(addrs.into_iter().map(|a| a.ip()).collect())
        })
    }
}

/// Apply the resolved-IP layer to a `NeedsResolve` decision: **any**
/// restricted address denies; resolution failure or an empty list
/// denies (fail-closed).
pub fn decide_resolved(host: &str, addrs: &[IpAddr]) -> Result<(), MediaError> {
    if addrs.is_empty() {
        return Err(blocked(host, "resolution returned no addresses"));
    }
    if addrs
        .iter()
        .any(|ip| classify_addr(*ip) == AddrClass::Restricted)
    {
        return Err(blocked(host, "resolved into a restricted address space"));
    }
    Ok(())
}

/// One host's judgment outcome in a driver's plan scope: the verdict
/// plus — when the resolved layer produced it — the **connection
/// pin** (the address the judgment saw — the fetch
/// transport is pinned to it so the connection cannot land on a
/// rebinding answer the judgment never saw; the judgment query and
/// the connect query are otherwise independent DNS lookups).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostVerdict {
    /// The verdict (a cached deny short-circuits later URIs on the
    /// host without re-resolution).
    pub allowed: bool,
    /// `(ip, port)` the judgment resolved — `None` for the
    /// literal/flag paths (they never resolve). The port comes from
    /// the first judged URI on the host (`port_or_known_default`); a
    /// URL with an explicit port wins over the pin's port at connect
    /// time (the base client's pinned-resolve semantics).
    pub pin: Option<SocketAddr>,
}

impl HostVerdict {
    fn denied() -> Self {
        Self {
            allowed: false,
            pin: None,
        }
    }

    fn allowed_resolved(pin: SocketAddr) -> Self {
        Self {
            allowed: true,
            pin: Some(pin),
        }
    }
}

/// The first resolved address of a passing judgment, socketed with
/// the judged URI's port (the pin the driver hands the transport).
fn pin_of(uri: &str, addrs: &[IpAddr]) -> Option<SocketAddr> {
    let ip = *addrs.first()?;
    let port = taiji_http::reqwest::Url::parse(uri)
        .ok()
        .and_then(|u| u.port_or_known_default())?;
    Some(SocketAddr::new(ip, port))
}

fn blocked(uri: &str, why: &str) -> MediaError {
    // The failing URI enters the error face redacted (query
    // stripped — signed key/segment URLs must not leak through errors).
    MediaError::SsrfBlocked(format!("{} ({why})", crate::m3u8::strip_query(uri)))
}

/// Check one URI end-to-end under a policy + resolver, with a
/// per-driver verdict cache (one resolution per distinct hostname —
/// the cache lives in the driver's plan scope; a cached verdict skips
/// re-resolution for later URIs on the same host). A passing
/// resolved-layer judgment records its **connection pin** in the
/// cache ([`HostVerdict::pin`] — the driver pins the fetch transport
/// to it; the judgment and the connect must not be two different DNS
/// answers, the rebinding TOCTOU).
pub async fn check_uri(
    uri: &str,
    policy: &SsrfPolicy,
    resolver: &dyn SsrfResolver,
    cache: &mut HostVerdictCache,
) -> Result<(), MediaError> {
    match decide_uri(uri, policy) {
        Decision::Allowed => Ok(()),
        Decision::Denied(why) => Err(blocked(uri, why)),
        Decision::NeedsResolve { host } => {
            if let Some(verdict) = cache.get(&host) {
                return if verdict.allowed {
                    Ok(())
                } else {
                    Err(blocked(
                        uri,
                        "host previously resolved into a restricted space",
                    ))
                };
            }
            let verdict = match resolver.resolve(&host).await {
                Ok(addrs) => match decide_resolved(uri, &addrs) {
                    Ok(()) => {
                        HostVerdict::allowed_resolved(pin_of(uri, &addrs).unwrap_or_else(|| {
                            SocketAddr::new(
                                // Unreachable in practice (NeedsResolve
                                // implies a parseable http/https URI with a
                                // defaultable port); fail-safe as an
                                // unpinnable allowed verdict.
                                IpAddr::from([0, 0, 0, 0]),
                                0,
                            )
                        }))
                    }
                    Err(e) => {
                        cache.insert(host.clone(), HostVerdict::denied());
                        return Err(e);
                    }
                },
                Err(e) => {
                    let err = blocked(uri, &format!("resolution failed: {e}"));
                    cache.insert(host.clone(), HostVerdict::denied());
                    return Err(err);
                }
            };
            cache.insert(host, verdict);
            Ok(())
        }
    }
}

/// Convenience alias for the cache type threaded through a driver's
/// plan phase (host -> judgment + connection pin).
pub type HostVerdictCache = HashMap<String, HostVerdict>;

/// A resolver for tests: a fixed host→addresses map (the injection
/// face the SSRF matrix uses; no real DNS is touched).
pub struct MapResolver(pub HashMap<String, Vec<IpAddr>>);

impl SsrfResolver for MapResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| format!("MapResolver: {host} not mapped"))
        })
    }
}

/// A resolver that always fails (the fail-closed matrix row).
pub struct FailingResolver;

impl SsrfResolver for FailingResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move { Err(format!("injected failure for {host}")) })
    }
}

/// `Arc<dyn SsrfResolver>` default helper (production resolver when
/// none is injected).
pub fn default_resolver() -> Arc<dyn SsrfResolver> {
    Arc::new(ProductionSsrfResolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny() -> SsrfPolicy {
        SsrfPolicy::default()
    }

    fn allow() -> SsrfPolicy {
        SsrfPolicy {
            allow_private: true,
        }
    }

    /// Scheme whitelist: http/https/data: pass the scheme gate; ftp://
    /// and friends are denied **regardless of the flag**.
    #[test]
    fn scheme_whitelist() {
        assert_eq!(
            decide_uri("http://cdn.example/s.ts", &deny()),
            Decision::NeedsResolve {
                host: "cdn.example".to_string()
            }
        );
        assert_eq!(
            decide_uri("https://cdn.example/s.ts", &deny()),
            Decision::NeedsResolve {
                host: "cdn.example".to_string()
            }
        );
        assert_eq!(decide_uri("data:,hello", &deny()), Decision::Allowed);
        for bad in ["ftp://host/f", "file:///etc/passwd", "gopher://h/x"] {
            assert_eq!(
                decide_uri(bad, &deny()),
                Decision::Denied("scheme outside the http/https/data: whitelist"),
                "{bad}"
            );
            // The flag does not relax the scheme layer.
            assert_eq!(
                decide_uri(bad, &allow()),
                Decision::Denied("scheme outside the http/https/data: whitelist"),
                "{bad} under the flag"
            );
        }
        // Unparseable.
        assert_eq!(
            decide_uri("not a url at all", &deny()),
            Decision::Denied("unparseable URL")
        );
    }

    /// Literal layer matrix: loopback/private/link-local literals (incl.
    /// the cloud metadata address), localhost, v6 forms — denied by
    /// default, allowed under the flag; public literals allowed.
    #[test]
    fn literal_layer_matrix() {
        for denied in [
            "http://127.0.0.1/k",
            "http://127.1.2.3/k",
            "http://10.0.0.5/k",
            "http://172.16.1.1/k",
            "http://172.31.255.255/k",
            "http://192.168.1.4/k",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.0.1/k",
            "http://localhost/k",
            "http://LOCALHOST:8080/k",
            "http://[::1]/k",
            "http://[fe80::1]/k",
            "http://[fc00::5]/k",
            "http://[::ffff:127.0.0.1]/k",
            "http://0.0.0.0/k",
            "http://224.0.0.1/k",
        ] {
            assert_eq!(
                decide_uri(denied, &deny()),
                Decision::Denied("loopback/private/link-local literal host"),
                "{denied} must be denied by default"
            );
            assert_eq!(
                decide_uri(denied, &allow()),
                Decision::Allowed,
                "{denied} flag"
            );
        }
        // Public literals pass the literal layer without resolution.
        for ok in [
            "http://8.8.8.8/k",
            "https://1.1.1.1/k",
            "http://[2001:db8::1]/k",
            // CGNAT + documentation ranges stay Public (the
            // anti-over-blocking red line, base mirror).
            "http://100.64.0.1/k",
            "http://192.0.2.1/k",
        ] {
            assert_eq!(decide_uri(ok, &deny()), Decision::Allowed, "{ok}");
        }
    }

    /// Resolved layer: any restricted address denies; mixed lists deny;
    /// all-public lists pass; empty and failing resolutions are
    /// fail-closed.
    #[tokio::test]
    async fn resolved_layer_matrix() {
        let v = |s: &str| s.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let mut m = HashMap::new();
        m.insert("pub.example".to_string(), vec![v("93.184.216.34")]);
        m.insert(
            "private.example".to_string(),
            vec![v("93.184.216.34"), v("10.1.2.3")],
        );
        m.insert("meta.example".to_string(), vec![v("169.254.169.254")]);
        m.insert("empty.example".to_string(), vec![]);
        let resolver = MapResolver(m);

        let mut cache = HostVerdictCache::new();
        check_uri("http://pub.example/s.ts", &deny(), &resolver, &mut cache)
            .await
            .unwrap_or_else(|e| panic!("public host: {e}"));
        // Cached verdict: a second URI on the same host passes without
        // re-resolution (the failing resolver proves no query is made).
        check_uri(
            "http://pub.example/other.ts",
            &deny(),
            &FailingResolver,
            &mut cache,
        )
        .await
        .unwrap_or_else(|e| panic!("cached public verdict: {e}"));
        for bad in [
            "http://private.example/s.ts",
            "http://meta.example/k.bin",
            "http://empty.example/s.ts",
        ] {
            let e = check_uri(bad, &deny(), &resolver, &mut cache)
                .await
                .err()
                .unwrap_or_else(|| panic!("{bad} must be denied"));
            assert_eq!(e.code(), "taiji.media.ssrf_blocked", "{bad}");
            assert!(
                !e.to_string().contains('?'),
                "the failing URI enters the error face query-stripped: {e}"
            );
        }
        // Fail-closed on a failing resolver.
        let e = check_uri(
            "http://unknown.example/s.ts",
            &deny(),
            &FailingResolver,
            &mut cache,
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("failing resolver must deny"));
        assert_eq!(e.code(), "taiji.media.ssrf_blocked");
        // Under the flag the same hosts skip resolution entirely.
        check_uri(
            "http://private.example/s.ts",
            &allow(),
            &FailingResolver,
            &mut cache,
        )
        .await
        .unwrap_or_else(|e| panic!("flag bypasses resolution: {e}"));

        // decide_resolved direct matrix.
        assert!(decide_resolved("h", &[v("8.8.8.8")]).is_ok());
        assert!(decide_resolved("h", &[v("8.8.8.8"), v("2001:4860::8888")]).is_ok());
        assert!(decide_resolved("h", &[]).is_err());
        assert!(decide_resolved("h", &[v("8.8.8.8"), v("192.168.0.1")]).is_err());
    }

    /// The address-class mirror spot-check against the base list (v6
    /// wrappers classify as their embedded v4).
    #[test]
    fn addr_class_mirror() {
        let v = |s: &str| s.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        for r in [
            "127.0.0.1",
            "10.0.0.1",
            "172.20.3.4",
            "192.168.5.6",
            "169.254.9.9",
        ] {
            assert_eq!(classify_addr(v(r)), AddrClass::Restricted, "{r}");
        }
        for p in ["8.8.8.8", "100.64.1.1", "203.0.113.9", "198.51.100.1"] {
            assert_eq!(classify_addr(v(p)), AddrClass::Public, "{p}");
        }
        assert_eq!(
            classify_addr(v("::ffff:192.168.0.1")),
            AddrClass::Restricted,
            "v4-mapped classifies as the embedded v4"
        );
        assert_eq!(
            classify_addr(v("64:ff9b::a00:1")),
            AddrClass::Restricted,
            "NAT64-embedded 10.0.0.1 classifies restricted"
        );
        assert_eq!(classify_addr(v("2001:db8::1")), AddrClass::Public);
    }
}
