//! Redirect-target IP hygiene: a redirect-target decision aligned with
//! the **initial-URL policy**.
//!
//! # Defect (before this guard)
//!
//! The manual redirect loop ([`crate::client::HttpClient::execute`])
//! only checked the scheme whitelist / https downgrade / loop detection,
//! never the target IP class — a malicious HTTP source could 302 to
//! `http://169.254.169.254/latest/meta-data/` (cloud metadata) or any
//! intranet host:port (error shape and timing differences reported back
//! through task state = intranet liveness / port probing), and the
//! response body would be written to disk. The FTP surface (the PASV
//! three-state policy [`crate::ftp::PasvAddressPolicy`]) and the BT
//! surface (taiji-engine `addr_hygiene`) already had equivalent
//! defenses; this module closes the HTTP side.
//!
//! # Classification list (restricted = true)
//!
//! - Loopback: v4 `127.0.0.0/8`, v6 `::1` (RFC 1122 §3.2.1.3,
//!   RFC 4291 §2.5.3).
//! - RFC1918 private: v4 `10/8`, `172.16/12`, `192.168/16` (RFC 1918;
//!   same domain as std `is_private`).
//! - Link-local: v4 `169.254.0.0/16`, v6 `fe80::/10` (RFC 3927,
//!   RFC 4291 §2.5.6; the cloud-metadata endpoint 169.254.169.254 sits
//!   in the v4 range).
//! - ULA: v6 `fc00::/7` (RFC 4193).
//! - v4-mapped: v6 `::ffff:0:0/96` -> normalized and classified as the
//!   embedded v4 (RFC 4291 §2.5.5.2).
//! - NAT64: v6 `64:ff9b::/96` -> same (the Well-Known Prefix,
//!   RFC 6052 §2.1; the local-use `64:ff9b:1::/48` is not listed —
//!   outside this spec's list).
//! - Unspecified: v4 `0.0.0.0`, v6 `::` (RFC 1122, RFC 4291 §2.5.2).
//! - Multicast: v4 `224.0.0.0/4`, v6 `ff00::/8` (RFC 1112,
//!   RFC 4291 §2.7).
//!
//! Everything else is non-restricted (publicly routable). Deliberately
//! **not** listed (the anti-over-blocking red line): CGNAT `100.64/10`
//! (carrier middle range, not the local intranet), the RFC 5737/3849
//! documentation ranges (test surfaces, no intranet-reachability
//! semantics), and the deprecated site-local `fec0::/10`.
//!
//! # Decision policy (aligned with the initial classification)
//!
//! - The task's initial URL is classified **exactly once** (before the
//!   first hop, [`classify_host_all`]) under the **all** rule: all
//!   resolved addresses must be restricted to form a restricted anchor —
//!   a mixed-family host (public A + restricted AAAA via static DNS
//!   poisoning) must not form one, or the "restricted initial -> allow
//!   all hops" short-circuit branch voids the entire guard.
//! - Each redirect hop: the target is classified via
//!   [`classify_host_any`] under the **any** rule (any resolved address
//!   restricted -> restricted); a restricted target **and** a
//!   non-restricted initial -> abort
//!   ([`HttpError::RedirectToRestrictedIp`]; the payload carries the
//!   target host, not credentials).
//! - A restricted initial (localhost/LAN task) -> every hop passes:
//!   trusted LAN/tunnel topologies (local services, router admin pages,
//!   intranet mirrors) are real usage, in the same spirit as the FTP
//!   surface's "pass when the reply equals the control peer".
//! - Host decision order: `pinned_resolve` pins (reqwest's overrides
//!   layer sits above the injected resolver — the pin address is the
//!   actual connect target, so a decision not matching the connection
//!   would make the pin surface a bypass seam) > literal IP classified
//!   directly (zero resolution) > shared resolver. Pins/literals are
//!   single-address decisions; the any/all rules do not differ at these
//!   two levels.
//! - **Failure surface (fail-closed, differentiated by rule)**: a hop
//!   target whose resolution fails / yields an empty list is rejected
//!   as Restricted — such a hop could not download successfully anyway,
//!   so rejecting costs nothing; and negative results are not cached
//!   (taiji-io dns.rs), so allowing would leave the deterministic
//!   two-query bypass of "answer SERVFAIL to the guard query, answer a
//!   private address to the connect query". An initial anchor whose
//!   resolution fails / yields an empty list counts as Public (the
//!   guard stays armed) — an empty list carries no "all restricted"
//!   evidence, and letting `all` over an empty set (vacuous truth) form
//!   a restricted anchor would disarm the guard on the failure surface
//!   (an opening in the opposite direction of the per-hop fail-closed;
//!   deliberately not taken).
//!
//! # Residuals (registered)
//!
//! - **any/all divergence shapes**: the rules differ only when a
//!   resolver multi-address list is expanded — all-public and
//!   all-restricted lists decide identically under both; a mixed family
//!   is Public as an initial anchor (the tightened side) and Restricted
//!   as a hop target (the existing conservative side). Resulting
//!   over-blocking shape: a legitimate dual-stack host (public A + ULA
//!   AAAA intranet service) as the initial URL arms the guard as
//!   public, so a hop to its intranet target is rejected — the user
//!   resolves this with a literal-IP initial URL or `pinned_resolve`
//!   (single address, no rule ambiguity); a mixed hop target is
//!   rejected when any address is restricted, even if connect path
//!   selection would land on the public address (selection prefers v4
//!   and shares nothing with the decision) — the same conservative
//!   side, security direction first.
//! - **Failure-surface residual**: the guard decision and the
//!   connection are two independent queries (negatives uncached) —
//!   with per-hop fail-closed, the "guard fails + connect succeeds"
//!   direction is closed (reject on failure, no bypass); the "guard
//!   succeeds + the record changed by connect time" direction falls
//!   into the rebinding window (next item).
//! - A DNS rebinding window theoretically exists between the decision
//!   and the actual connection (the domain's record changes after the
//!   decision): the shared resolver's TTL cache makes the decision
//!   result and the transport connection mostly same-source same-value,
//!   narrowing but not eliminating the window (not pin-style
//!   elimination — the same water level as industry-wide redirect
//!   protection). The resolver and the transport share the
//!   [`taiji_io::dns::SharedDns`] process-level instance
//!   ([`taiji_io::dns::SharedDns::shared_default`]).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use taiji_io::dns::SharedDns;

use crate::error::HttpError;

/// Address class (the restricted set is in the module docs' classification list).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IpClass {
    /// Restricted: loopback / RFC1918 / link-local / ULA / mapped /
    /// NAT64-embedded / unspecified / multicast.
    Restricted,
    /// Everything else (publicly routable).
    Public,
}

/// Single-address classification (table in the module docs).
pub(crate) fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            // v4-mapped `::ffff:0:0/96` (RFC 4291 §2.5.5.2): a v4
            // endpoint in v6 wrapping; normalize and classify as the
            // embedded v4 (family consistency — the wrapper must not
            // produce an independent v6 verdict; same as taiji-engine
            // addr_hygiene).
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            // NAT64 WKP `64:ff9b::/96` (RFC 6052 §2.1): the low 32
            // embedded v4 bits classify the same way (a restricted v4 in
            // NAT64 form must not pass because of its v6 carrier).
            if let Some(v4) = nat64_embedded_v4(&v6) {
                return classify_v4(v4);
            }
            if v6.is_loopback()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || v6.is_unspecified()
                || v6.is_multicast()
            {
                IpClass::Restricted
            } else {
                IpClass::Public
            }
        }
    }
}

/// v4 classification (stable std predicates; the ranges map line by
/// line to the classification list).
fn classify_v4(v4: Ipv4Addr) -> IpClass {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
    {
        IpClass::Restricted
    } else {
        IpClass::Public
    }
}

/// Address-list **any** rule (per-hop target decision): any restricted
/// address makes it restricted. An empty list is restricted — the
/// resolver contract never produces an empty `Ok` (defensive: empty and
/// `Err` are the same resolution-failure surface and fail closed with
/// it, see the module docs' failure surface).
fn classify_addrs_any(addrs: &[IpAddr]) -> IpClass {
    if addrs.is_empty() || addrs.iter().any(|a| classify(*a) == IpClass::Restricted) {
        IpClass::Restricted
    } else {
        IpClass::Public
    }
}

/// Address-list **all** rule (initial anchor decision): restricted only
/// when all addresses are restricted. An empty list is non-restricted —
/// `all` over an empty set is vacuously true, and letting it form a
/// restricted anchor would disarm the guard exactly on the resolution
/// failure surface (the opposite direction of the per-hop fail-closed;
/// deliberately resolved toward Public).
fn classify_addrs_all(addrs: &[IpAddr]) -> IpClass {
    if !addrs.is_empty() && addrs.iter().all(|a| classify(*a) == IpClass::Restricted) {
        IpClass::Restricted
    } else {
        IpClass::Public
    }
}

/// The first two levels of host decision (pins > literal): a hit yields
/// a single-address class; if neither level hits, returns `None` (handed
/// to the resolver step). Single-address decisions have no any/all
/// ambiguity — the two rules diverge only on resolver multi-address
/// lists.
fn pinned_or_literal_class(pins: &[(String, SocketAddr)], host: &str) -> Option<IpClass> {
    // (1) Pins first: reqwest's overrides layer sits above the injected
    // resolver (see `build_transport`) — the pin address is the host's
    // actual connect target; a decision ignoring pins would be a bypass
    // seam. Keys match lowercase (reqwest's normalization rule).
    if let Some((_, addr)) = pins.iter().find(|(h, _)| h.eq_ignore_ascii_case(host)) {
        return Some(classify(addr.ip()));
    }
    // (2) Literal IP classified directly (zero resolution; strip the IPv6 bracket form first).
    literal_host_ip(host).map(classify)
}

/// Per-hop target rule (**any**): any resolved restricted address
/// restricts; resolution failure / an empty list rejects as restricted
/// (fail-closed — rationale and residuals in the module docs).
pub(crate) async fn classify_host_any(
    pins: &[(String, SocketAddr)],
    dns: &SharedDns,
    host: &str,
) -> IpClass {
    if let Some(class) = pinned_or_literal_class(pins, host) {
        return class;
    }
    // (3) Hostname via the shared resolver (the rule divergence point: any + failure restricted).
    match dns.resolve_for_transport(host, 0).await {
        Ok(addrs) => classify_addrs_any(&addr_ips(&addrs)),
        Err(_) => IpClass::Restricted,
    }
}

/// Initial anchor rule (**all**): a restricted anchor forms only when
/// all resolved addresses are restricted; resolution failure / an empty
/// list counts as non-restricted (guard stays armed — vacuous truth
/// must not form an anchor).
pub(crate) async fn classify_host_all(
    pins: &[(String, SocketAddr)],
    dns: &SharedDns,
    host: &str,
) -> IpClass {
    if let Some(class) = pinned_or_literal_class(pins, host) {
        return class;
    }
    // (3) Hostname via the shared resolver (the rule divergence point: all + failure armed).
    match dns.resolve_for_transport(host, 0).await {
        Ok(addrs) => classify_addrs_all(&addr_ips(&addrs)),
        Err(_) => IpClass::Public,
    }
}

/// `Vec<SocketAddr>` -> address projection (port 0 is the resolver
/// bridge's synthesized value and takes no part in classification).
fn addr_ips(addrs: &[SocketAddr]) -> Vec<IpAddr> {
    addrs.iter().map(|a| a.ip()).collect()
}

/// Redirect hop decision: (target restricted AND initial
/// non-restricted) -> abort; everything else passes (including the
/// ordinary "restricted initial -> allow all" and "restricted initial
/// hops to a public CDN" shapes).
pub(crate) fn hop_decision(
    initial: IpClass,
    target: IpClass,
    target_host: &str,
) -> Result<(), HttpError> {
    match (initial, target) {
        // Restricted initial (localhost/LAN): aligned with the initial
        // policy, any target passes.
        (IpClass::Restricted, _) => Ok(()),
        // Non-restricted initial + non-restricted target: the ordinary
        // redirect case (public CDN chains) passes.
        (IpClass::Public, IpClass::Public) => Ok(()),
        // Non-restricted initial + restricted target: the SSRF /
        // intranet-probing surface, abort (the payload carries only the
        // target host — no credentials, no path; redact discipline as
        // for transport errors).
        (IpClass::Public, IpClass::Restricted) => Err(HttpError::RedirectToRestrictedIp {
            host: target_host.to_string(),
        }),
    }
}

/// `64:ff9b::/96` (RFC 6052 WKP) low-32-bit embedded v4 extraction: the
/// first 96 bits (segments 0..6) are the equal prefix, the low 32 bits
/// (segments 6..8) are the v4. The local-use `64:ff9b:1::/48` prefix is
/// not listed (see the classification list).
fn nat64_embedded_v4(v6: &std::net::Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let prefix_match =
        s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    if prefix_match {
        Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ))
    } else {
        None
    }
}

/// The literal IP form of a URL host (IPv6 is always bracketed — the
/// serialization normalization of special schemes; parse after
/// stripping the brackets). Domain names / IDN do not parse (failure ->
/// None).
fn literal_host_ip(host: &str) -> Option<IpAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use taiji_io::dns::{HostResolver, ListResolverFuture, ResolverFuture};

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|e| panic!("ip {s}: {e}"))
    }

    fn v6(o: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7],
        ))
    }

    /// Classification vector table (table-driven; per-class rationale in
    /// the module docs' classification list).
    #[test]
    fn classify_vector_table() {
        let restricted: &[(IpAddr, &str)] = &[
            // ---- v4: loopback/RFC1918/link-local/unspecified/multicast ----
            (ip("127.0.0.1"), "v4 loopback"),
            (ip("127.255.0.1"), "inside the v4 loopback block"),
            (ip("10.1.2.3"), "RFC1918 10/8"),
            (ip("172.16.0.9"), "RFC1918 172.16/12 lower edge"),
            (ip("172.31.255.254"), "RFC1918 172.16/12 upper edge"),
            (ip("192.168.1.2"), "RFC1918 192.168/16"),
            (
                ip("169.254.169.254"),
                "link-local = cloud metadata endpoint (attack anchor)",
            ),
            (ip("169.254.0.1"), "link-local block lower edge"),
            (ip("0.0.0.0"), "v4 unspecified"),
            (ip("224.0.0.1"), "v4 multicast"),
            (
                ip("239.255.255.250"),
                "v4 multicast block upper edge (SSDP)",
            ),
            // ---- v6: loopback/link-local/ULA/unspecified/multicast ----
            (ip("::1"), "v6 loopback"),
            (ip("fe80::1"), "link-local fe80::/10"),
            (
                v6([0xfebf, 0xffff, 0, 0, 0, 0, 0, 1]),
                "link-local block upper edge febf::",
            ),
            (ip("fc00::1"), "ULA fc00::/7 lower edge"),
            (ip("fd12:3456::1"), "ULA fd00::/8"),
            (ip("::"), "v6 unspecified"),
            (ip("ff02::1"), "v6 multicast"),
            // ---- v4-mapped: classified as the embedded v4 after normalization ----
            (ip("::ffff:127.0.0.1"), "mapped loopback"),
            (ip("::ffff:10.0.0.1"), "mapped RFC1918"),
            (
                ip("::ffff:169.254.169.254"),
                "mapped link-local (cloud metadata wrapper)",
            ),
            // ---- NAT64 WKP: the embedded v4 classifies the same way ----
            (ip("64:ff9b::a00:1"), "NAT64 embedded 10.0.0.1"),
            (ip("64:ff9b::a9fe:a9fe"), "NAT64 embedded 169.254.169.254"),
        ];
        for (addr, why) in restricted {
            assert_eq!(
                classify(*addr),
                IpClass::Restricted,
                "{addr} must be restricted ({why})"
            );
        }

        let public: &[(IpAddr, &str)] = &[
            (ip("8.8.8.8"), "public v4"),
            (ip("93.184.216.34"), "public v4"),
            // Deliberately unlisted ranges (the anti-over-blocking red
            // line; the module docs' "everything else non-restricted"
            // section):
            (ip("100.64.1.1"), "CGNAT 100.64/10 unlisted"),
            (ip("192.0.2.1"), "RFC5737 documentation block unlisted"),
            (
                ip("172.32.0.1"),
                "adjacent above the RFC1918 172.16/12 block",
            ),
            (
                ip("192.169.1.1"),
                "adjacent above the RFC1918 192.168/16 block",
            ),
            (ip("2606:4700::1111"), "GUA 2000::/3"),
            (ip("2001:db8::1"), "RFC3849 documentation block unlisted"),
            (
                ip("::ffff:8.8.8.8"),
                "mapped public (passes as v4 after normalization)",
            ),
            (
                ip("64:ff9b::808:808"),
                "NAT64 embedded 8.8.8.8 (passes as v4 after normalization)",
            ),
            (
                ip("64:ff9b:1::808:808"),
                "NAT64 local-use 64:ff9b:1::/48 unlisted (not the WKP /96)",
            ),
        ];
        for (addr, why) in public {
            assert_eq!(
                classify(*addr),
                IpClass::Public,
                "{addr} must be non-restricted ({why})"
            );
        }
    }

    /// Hop policy table: (public, restricted) -> reject,
    /// (restricted, restricted) -> pass, (public, public) -> pass.
    #[test]
    fn hop_decision_policy_table() {
        let public = IpClass::Public;
        let restricted = IpClass::Restricted;

        // (public, restricted) -> reject: the error carries the target
        // host, no credentials/path.
        let err = match hop_decision(public, restricted, "169.254.169.254") {
            Err(e) => e,
            Ok(()) => panic!("(public initial, restricted target) must be rejected"),
        };
        assert!(
            matches!(err, HttpError::RedirectToRestrictedIp { ref host } if host == "169.254.169.254"),
            "error shape/payload: {err:?}"
        );
        assert_eq!(err.code(), "taiji.http.redirect_to_restricted_ip");
        assert!(err.to_string().contains("169.254.169.254"));

        // (restricted, restricted) -> pass: a localhost/LAN initial
        // allows all targets (including a hop to the cloud-metadata
        // literal — the task is itself in a trusted intranet topology).
        assert!(
            hop_decision(restricted, restricted, "169.254.169.254").is_ok(),
            "(restricted, restricted) must pass"
        );

        // (public, public) -> pass.
        assert!(
            hop_decision(public, public, "cdn.example").is_ok(),
            "(public, public) must pass"
        );

        // (restricted, public) -> pass: a LAN initial hopping to a public CDN is ordinary.
        assert!(
            hop_decision(restricted, public, "cdn.example").is_ok(),
            "(restricted, public) must pass"
        );

        // Not retryable (a deterministic protocol refusal).
        assert!(!crate::retry::transport_retryable(&err));
    }

    /// Address-list counting stub (real DNS forbidden; unknown hosts -> Err).
    #[derive(Clone)]
    struct GuardStubResolver {
        table: std::collections::HashMap<String, Vec<IpAddr>>,
        queries: Arc<AtomicUsize>,
    }

    impl GuardStubResolver {
        fn new(entries: &[(&str, Vec<IpAddr>)]) -> Self {
            GuardStubResolver {
                table: entries
                    .iter()
                    .map(|(h, list)| ((*h).to_string(), list.clone()))
                    .collect(),
                queries: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn queries(&self) -> usize {
            self.queries.load(AtomicOrdering::SeqCst)
        }
    }

    impl HostResolver for GuardStubResolver {
        fn resolve(&self, host: String) -> ResolverFuture {
            let result = self
                .table
                .get(&host)
                .and_then(|list| list.first().copied())
                .ok_or_else(|| format!("guard stub: unknown host {host}"));
            Box::pin(std::future::ready(result))
        }

        fn resolve_list(&self, host: String) -> ListResolverFuture {
            self.queries.fetch_add(1, AtomicOrdering::SeqCst);
            let result = match self.table.get(&host) {
                Some(list) if !list.is_empty() => Ok(list.clone()),
                _ => Err(format!("guard stub: unknown host {host}")),
            };
            Box::pin(std::future::ready(result))
        }
    }

    /// Both-rules pure-function table (divergence point: any/all diverge
    /// only on multi-address and empty lists; single-element lists judge
    /// the same under both rules).
    #[test]
    fn classify_addrs_any_all_caliber_table() {
        let list = |s: &[&str]| s.iter().map(|a| ip(a)).collect::<Vec<_>>();

        // All public: both rules say Public.
        let pubs = list(&["93.184.216.34", "2606:4700::1111"]);
        assert_eq!(classify_addrs_any(&pubs), IpClass::Public);
        assert_eq!(classify_addrs_all(&pubs), IpClass::Public);

        // All restricted: both rules say Restricted (the list form of the pure-LAN anchor).
        let lan = list(&["10.0.0.5", "192.168.1.7", "fd00::7"]);
        assert_eq!(classify_addrs_any(&lan), IpClass::Restricted);
        assert_eq!(classify_addrs_all(&lan), IpClass::Restricted);

        // Mixed family (public A + ULA AAAA, the attack shape):
        // any = Restricted (hop target rejected), all = non-restricted
        // (no restricted anchor — guard armed).
        let mixed = list(&["93.184.216.34", "fd00::5"]);
        assert_eq!(classify_addrs_any(&mixed), IpClass::Restricted);
        assert_eq!(
            classify_addrs_all(&mixed),
            IpClass::Public,
            "a mixed family must not form a restricted anchor (the all rule)"
        );

        // Single element: both rules agree (literals/pins are single-address, no rule ambiguity).
        let one_pub = list(&["8.8.8.8"]);
        assert_eq!(classify_addrs_any(&one_pub), IpClass::Public);
        assert_eq!(classify_addrs_all(&one_pub), IpClass::Public);
        let one_rst = list(&["169.254.169.254"]);
        assert_eq!(classify_addrs_any(&one_rst), IpClass::Restricted);
        assert_eq!(classify_addrs_all(&one_rst), IpClass::Restricted);

        // Empty list (defensive: the resolver contract never produces an
        // empty Ok): any = Restricted (per-hop fail-closed), all =
        // non-restricted (vacuous truth must not form an anchor).
        let empty: Vec<IpAddr> = Vec::new();
        assert_eq!(
            classify_addrs_any(&empty),
            IpClass::Restricted,
            "an empty list fails closed with the resolution-failure face"
        );
        assert_eq!(
            classify_addrs_all(&empty),
            IpClass::Public,
            "all-rule vacuous truth must not form a restricted anchor \
             (the guard must not be disarmed)"
        );
    }

    /// Literal host surface: direct classification, zero resolution
    /// (mapped/NAT64 wrappers judge the same as the embedded truth;
    /// single-address, no any/all ambiguity — verifies the per-hop rule;
    /// the anchor rule is covered by the pure-LAN anchor test).
    #[tokio::test]
    async fn classify_host_literals_and_embedded_v4() {
        let stub = GuardStubResolver::new(&[]);
        let dns = SharedDns::with_resolver(Arc::new(stub.clone()));

        let restricted_literals = [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "[::1]",
            "[fe80::1]",
            "[::ffff:169.254.169.254]",
            "[64:ff9b::a9fe:a9fe]",
        ];
        for host in restricted_literals {
            assert_eq!(
                classify_host_any(&[], &dns, host).await,
                IpClass::Restricted,
                "literal {host} must be restricted"
            );
        }
        let public_literals = ["93.184.216.34", "[::ffff:8.8.8.8]", "[64:ff9b::808:808]"];
        for host in public_literals {
            assert_eq!(
                classify_host_any(&[], &dns, host).await,
                IpClass::Public,
                "literal {host} must be non-restricted"
            );
        }
        // Short-circuit proof: literal classification makes zero resolver queries.
        assert_eq!(
            stub.queries(),
            0,
            "literal hosts must not touch the resolver"
        );
    }

    /// Resolver surface: the per-hop any rule (any restricted address
    /// rejects) + failure fail-closed + pin precedence (the decision
    /// matches the actual connect target).
    #[tokio::test]
    async fn classify_host_resolver_and_pins() {
        let stub = GuardStubResolver::new(&[
            ("meta-host.example", vec![ip("169.254.169.254")]),
            ("public-host.example", vec![ip("93.184.216.34")]),
            // Dual-stack mix: public A + intranet AAAA -> conservatively rejected per hop.
            ("mixed.example", vec![ip("93.184.216.34"), ip("fd00::5")]),
            ("v6-public.example", vec![ip("2606:4700::1111")]),
        ]);
        let dns = SharedDns::with_resolver(Arc::new(stub.clone()));

        // hostname -> restricted address -> restricted.
        assert_eq!(
            classify_host_any(&[], &dns, "meta-host.example").await,
            IpClass::Restricted,
            "a hostname resolving to any restricted address is restricted"
        );
        // hostname -> public -> non-restricted.
        assert_eq!(
            classify_host_any(&[], &dns, "public-host.example").await,
            IpClass::Public
        );
        assert_eq!(
            classify_host_any(&[], &dns, "v6-public.example").await,
            IpClass::Public
        );
        // Mixed list -> restricted under the per-hop rule (conservative
        // — even if connect path selection might land on the public
        // address).
        assert_eq!(
            classify_host_any(&[], &dns, "mixed.example").await,
            IpClass::Restricted,
            "a mixed A/AAAA set is rejected if any address is restricted (the per-hop any rule)"
        );

        // Resolution failure -> restricted under the per-hop rule
        // (fail-closed: negatives are not cached; allowing would leave
        // the guard-SERVFAIL / connect-answers-private two-query bypass).
        assert_eq!(
            classify_host_any(&[], &dns, "nonexistent.invalid").await,
            IpClass::Restricted,
            "a hop target failing resolution must be rejected as restricted (fail-closed)"
        );

        // Pin precedence: a pin hit classifies by the pin address (the
        // stub's public record is ignored + zero queries); keys are
        // case-insensitive (reqwest's lowercase-matching rule);
        // single-address decisions agree under both rules.
        let pins = [(
            "pinned.example".to_string(),
            SocketAddr::new(ip("169.254.169.254"), 0),
        )];
        let before = stub.queries();
        assert_eq!(
            classify_host_any(&pins, &dns, "PINNED.example").await,
            IpClass::Restricted,
            "the pin address is the actual connect target; the verdict must follow the pin"
        );
        assert_eq!(
            classify_host_all(&pins, &dns, "pinned.example").await,
            IpClass::Restricted,
            "a pinned single address has no rule ambiguity (same verdict under the anchor rule)"
        );
        assert_eq!(
            stub.queries(),
            before,
            "a pin hit must not touch the resolver (the verdict and the connect share one source)"
        );
    }

    // ===== Initial classification rules (mixed-family poisoning + negative resolution) =====

    /// Mixed-family poisoning: an attacker domain's static DNS sets
    /// A=public + AAAA=ULA; the initial classification must not form a
    /// restricted anchor from it — otherwise client.rs's
    /// `initial_ip_class != Restricted` short-circuit branch voids the
    /// whole guard and a malicious source can 302 to intranet /
    /// cloud-metadata targets unimpeded.
    #[tokio::test]
    async fn poc_mixed_family_initial_must_not_form_restricted_anchor() {
        let stub = GuardStubResolver::new(&[
            // Mixed family: public A + ULA AAAA (an attacker-controlled static DNS shape).
            (
                "mixed-poison.example",
                vec![ip("93.184.216.34"), ip("fd00::5")],
            ),
            // Hop target: resolves to the cloud-metadata endpoint.
            ("meta-target.example", vec![ip("169.254.169.254")]),
        ]);
        let dns = SharedDns::with_resolver(Arc::new(stub));

        // The initial anchor must be Public: only an all-restricted
        // address list forms a restricted anchor (the all rule).
        let initial = classify_host_all(&[], &dns, "mixed-poison.example").await;
        assert_eq!(
            initial,
            IpClass::Public,
            "a mixed family (public A + ULA AAAA) must not form a restricted anchor \
             — the any rule would short-circuit the whole guard"
        );
        // Direct guard proof: under this anchor, a hop to a restricted target must be rejected.
        let target = classify_host_any(&[], &dns, "meta-target.example").await;
        assert!(
            hop_decision(initial, target, "meta-target.example").is_err(),
            "under a mixed-family initial anchor, a hop to the cloud metadata \
             target must be rejected by RedirectToRestrictedIp"
        );
    }

    /// Pure-LAN regression anchor: an initial host whose full address
    /// list is restricted still forms a restricted anchor (localhost
    /// literals / pure-LAN scenarios unaffected), and every hop passes.
    #[tokio::test]
    async fn poc_pure_lan_initial_still_forms_restricted_anchor() {
        let stub = GuardStubResolver::new(&[(
            "lan-only.example",
            vec![ip("10.0.0.5"), ip("192.168.1.7")],
        )]);
        let dns = SharedDns::with_resolver(Arc::new(stub.clone()));

        let initial = classify_host_all(&[], &dns, "lan-only.example").await;
        assert_eq!(
            initial,
            IpClass::Restricted,
            "a pure-LAN family's initial must be a restricted anchor"
        );
        // Restricted anchor -> every hop passes (including hops to restricted targets —
        // the trusted-topology semantics).
        assert!(hop_decision(initial, IpClass::Restricted, "169.254.169.254").is_ok());
        assert!(hop_decision(initial, IpClass::Public, "cdn.example").is_ok());
        // localhost literals (zero resolution) classify restricted under
        // the anchor rule too — localhost/LAN tasks are unaffected by
        // the tightening.
        let before = stub.queries();
        assert_eq!(
            classify_host_all(&[], &dns, "127.0.0.1").await,
            IpClass::Restricted
        );
        assert_eq!(
            classify_host_all(&[], &dns, "[::1]").await,
            IpClass::Restricted
        );
        assert_eq!(
            stub.queries(),
            before,
            "literal-anchor verdicts make zero resolver queries \
             (snapshot comparison, excluding the lan-only resolution above)"
        );
    }

    /// Negative resolution: a hop target whose resolution fails
    /// (Err / empty list) must be rejected as restricted (fail-closed) —
    /// attacker DNS can answer SERVFAIL to the guard query and a private
    /// IP to the connect query (negatives uncached = a deterministic
    /// two-query bypass); allowing resolution failure would be pierced
    /// by exactly that shape. Anchor contrast: a failed initial-anchor
    /// resolution counts as Public (the guard stays armed — the failure
    /// surface must not disarm the guard).
    #[tokio::test]
    async fn poc_hop_target_resolution_failure_must_be_rejected() {
        // Unknown host -> resolve_list Err (the SERVFAIL shape).
        let stub = GuardStubResolver::new(&[]);
        let dns = SharedDns::with_resolver(Arc::new(stub));

        let target = classify_host_any(&[], &dns, "nonexistent.invalid").await;
        assert_eq!(
            target,
            IpClass::Restricted,
            "a hop target failing resolution must be treated as restricted \
             (fail-closed, closing the two-query bypass)"
        );
        // Combined decision under a public initial anchor: must reject.
        assert!(hop_decision(IpClass::Public, target, "nonexistent.invalid").is_err());
        // Anchor contrast: a failed initial-anchor resolution counts as
        // Public (armed; the direction is opposite to the per-hop rule —
        // see the module docs' failure surface).
        assert_eq!(
            classify_host_all(&[], &dns, "nonexistent.invalid").await,
            IpClass::Public,
            "a failed initial-anchor resolution must keep the guard armed (no restricted anchor)"
        );
    }
}
