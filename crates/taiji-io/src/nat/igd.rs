//! UPnP IGD client (the rupnp-based approach fixed by SPEC §6.8 — not
//! to be swapped without an ADR).
//!
//! Discovers a gateway over SSDP, fetches and parses its device
//! description, and drives the WAN{IP,PPP}Connection port-mapping SOAP
//! actions (add/query/remove/external-ip), with a 718-conflict fallback
//! to AddAnyPortMapping on v2 services. Protocol facts (UPnP IGD
//! "WANIPConnection:2" spec sections) and upstream anchor mapping:
//! docs/design/io.md.
//!
//! Hard invariants (security-review fixes; rupnp 3.0's control-point
//! HTTP/XML face has no injection point — `device.rs` builds a fresh
//! hyper Client per call and reads bodies with an unbounded `collect()`,
//! `Service::action` is the same shape, and `DeviceSpec::from_xml`
//! recurses into deviceList without a depth guard — so the bounds are
//! owned on this side):
//!
//! - **SSDP protocol face untouched**: discovery still goes through
//! `rupnp::ssdp` (same search arguments as rupnp's discovery); this
//! module only takes over the HTTP/XML carrier of a hit Location.
//! - **Timeouts**: the device-description GET and every SOAP POST are
//! wrapped in the [`HTTP_REQUEST_TIMEOUT`] total budget (connect +
//! response headers + body read, capped as one, via
//! `tokio::time::timeout`), plus a discovery-round budget (SSDP window +
//! the per-request cap) so any number of fake devices inside the
//! window cannot stretch the round.
//! - **Body caps**: a Content-Length precheck rejects fast (not trusted
//! — a lying or missing length is still caught by the
//! [`http_body_util::Limited`] streaming backstop); over-limit aborts
//! as [`SoapError::BodyTooLarge`].
//! - **Parsing isolation**: XML parsing runs inside
//! [`tokio::task::spawn_blocking`] (a pathological input costs one
//! blocking-pool task); the depth precheck ([`precheck_xml_depth`], a
//! flat byte scan) runs **before** roxmltree, whose parse itself
//! recursively aborts on deep nesting; the device tree is walked with
//! an explicit stack (the tag_stack shape of libtorrent
//! `find_control_url`, `upnp.cpp` — no recursive parsing) and rejected
//! per size/depth caps ([`MAX_XML_DEPTH`]).
//! - **Error-string truncation**: attacker-controlled strings (SOAP
//! fault text, raw port values, URLs, ...) are truncated to
//! [`ERROR_STRING_MAX_BYTES`] before entering errors/logs (bounding
//! the second-order amplification of e.g. `InvalidPort(String)`
//! carrying a full attacker string).
//! - **Location host validation** ([`validate_location_host`]): an SSDP
//! Location must point at an RFC 1918 / RFC 3927 link-local IPv4
//! literal (loopback / public / domain names rejected — the SSRF and
//! gateway-hijack face); when the description carries `<URLBase>` its
//! authority passes the same validation. With an explicit gateway
//! configured, the host must also match it.
//! - **Single-error continuation**: one malformed SSDP response or one
//! failed device is logged, counted, and the round continues
//! ([`for_each_ssdp_response`]); AddAnyPortMapping's NewReservedPort
//! of 0 is rejected on read-back.
//! - **fuzz entry points**: `*_for_fuzz` shims expose both parsers to
//! the cross-crate fuzz workspace.
//!
//! SOAP envelope, response parsing, and device required-field semantics
//! are verbatim ports of rupnp 3.0 (sources noted inline); the mapping
//! action semantics are unaffected by this module's bounds.
//!
//! [`IgdClient::from_device_url`] bypasses SSDP and fetches a device
//! description directly — the entry point for mock-IGD (local HTTP/XML)
//! tests; [`IgdClient::discover`] (real SSDP multicast) awaits
//! live-router verification (does not block later milestones). The
//! bounded-face attack paths (slow gateway / body bomb / deep nesting)
//! are covered by the `nat::tests` group.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rupnp::http::uri::PathAndQuery;
use rupnp::http::{Request, StatusCode, Uri};
use rupnp::ssdp::{SearchTarget, URN};
use tracing::debug;

/// tracing target.
const LOG_TARGET: &str = "taiji::io::nat::igd";

/// IGD root device URN v1 (SSDP search target;
/// `urn:schemas-upnp-org:device:InternetGatewayDevice:1` — the
/// advertisement form common to v1/v2 routers).
pub const IGD_DEVICE_V1: URN = URN::device("schemas-upnp-org", "InternetGatewayDevice", 1);

/// IGD root device URN v2 (`...InternetGatewayDevice:2`; for devices
/// advertising only IGD2).
pub const IGD_DEVICE_V2: URN = URN::device("schemas-upnp-org", "InternetGatewayDevice", 2);

/// WANIPConnection service URN v1.
pub const WAN_IP_CONNECTION_V1: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
/// WANIPConnection service URN v2 (preferred; §2.5.17's recommended
/// AddAnyPortMapping is v2-only).
pub const WAN_IP_CONNECTION_V2: URN = URN::service("schemas-upnp-org", "WANIPConnection", 2);
/// WANPPPConnection service URN v1 (the equivalent service face of
/// PPPoE gateways).
pub const WAN_PPP_CONNECTION_V1: URN = URN::service("schemas-upnp-org", "WANPPPConnection", 1);

/// Service lookup priority: v2 (AddAnyPortMapping) → v1 → PPP.
const SERVICE_PRIORITY: [URN; 3] = [
    WAN_IP_CONNECTION_V2,
    WAN_IP_CONNECTION_V1,
    WAN_PPP_CONNECTION_V1,
];

/// Per-request total timeout (connect + response headers + body read,
/// capped as one budget; local value).
///
/// Basis: libtorrent's upnp face uses a 10s SOAP connect completion
/// timeout and a 30s device-description GET (`upnp.cpp`). This crate
/// uses 10s across the board: the NAT actor executes commands serially
/// (the `nat.rs` concurrency discipline), so the longer a single request
/// hangs the deeper Map/Renew/Unmap/Snapshot queue — tighter than the
/// 30s GET, aligned with the 10s control face; a conservative value
/// within the ~5s design order (real gateways answer in sub-seconds,
/// the loopback mock is far faster).
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Response body cap (1MiB; the same value as the spawn_blocking parse
/// threshold). Reference cap anchor = libtorrent
/// `default_max_bottled_buffer_size = 2MiB` (`http_connection.hpp`).
/// IGD device-description documents are typically a few KiB to a few
/// tens of KiB, so 1MiB gives ≥10x headroom; enforced twice by a
/// Content-Length precheck + [`http_body_util::Limited`], never trusting
/// the declared value.
pub const MAX_HTTP_BODY: usize = 1024 * 1024;

/// Device nesting depth cap (no spec-anchored value — IGD topologies
/// are typically root/WANDevice/WANConnectionDevice, three levels
/// (WANIPConnection:2 spec §2.1 device tree); 32 ≈ 10x headroom).
/// Enforced twice: the byte-level precheck ([`precheck_xml_depth`]) and
/// the explicit-stack device-tree walk — the precheck is also crash
/// protection (roxmltree's parse itself recursively aborts on deep
/// nesting, see that function's docs); rupnp's recursive
/// `DeviceSpec::from_xml` (device.rs) is an upstream defect whose ideal
/// fix is an upstream iteration, so this side is a mitigation.
pub const MAX_XML_DEPTH: usize = 32;

/// Truncation width for attacker-controlled error strings (64B; bounds
/// the second-order amplification of e.g. `InvalidPort(String)` carrying
/// a full attacker string into errors/logs).
const ERROR_STRING_MAX_BYTES: usize = 64;

/// Attacker-controlled string truncation (byte-exact; never cuts a
/// UTF-8 sequence mid-character).
fn clip(s: &str) -> String {
    if s.len() <= ERROR_STRING_MAX_BYTES {
        return s.to_owned();
    }
    let mut end = ERROR_STRING_MAX_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// IGD bounded transport/protocol errors (the control-point HTTP/XML
/// face is self-contained here — rupnp 3.0's fetch/parse has no
/// injection point: `device.rs` builds a fresh Client per call with an
/// unbounded collect, and `Service::action` is the same shape — so
/// timeouts, caps, and isolation are implemented on this side).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SoapError {
    /// Response body over the cap (Content-Length precheck or the
    /// Limited stream backstop).
    #[error("igd: gateway response exceeds {limit}B body cap")]
    BodyTooLarge {
        /// Effective cap in bytes ([`MAX_HTTP_BODY`] or a test-injected
        /// value).
        limit: usize,
    },
    /// The gateway did not answer within the total budget (slowloris /
    /// silent carrier).
    #[error("igd: gateway did not respond within {timeout_secs}s")]
    Timeout {
        /// Total budget in seconds ([`HTTP_REQUEST_TIMEOUT`] or a
        /// test-injected value).
        timeout_secs: u64,
    },
    /// Non-200 response (same semantics as rupnp `err_if_not_200`).
    #[error("igd: gateway responded with http status {0}")]
    Status(StatusCode),
    /// Transport-layer failure (hyper client / body read; text
    /// truncated).
    #[error("igd: transport: {0}")]
    Network(String),
    /// SOAP fault (a UPnP error code returned by the gateway, §2.5.23;
    /// text truncated).
    #[error("igd: upnp fault {code}: {description}")]
    UpnpFault {
        /// UPnP error code (e.g. 718/714/606).
        code: u16,
        /// errorDescription verbatim, truncated (attacker-controlled).
        description: String,
    },
    /// Non-UTF-8 response / pathological XML / size-or-depth precheck
    /// rejection (text truncated).
    #[error("igd: xml: {0}")]
    Xml(String),
}

/// Classifies a Limited overrun from the error source chain
/// ([`http_body_util::LengthLimitError`] can be wrapped in a
/// `hyper::Error`; walks down `source()` layer by layer).
fn is_body_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
        || err.source().is_some_and(is_body_limit)
}

/// IGD error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IgdError {
    /// No gateway with a usable WAN connection service found within the
    /// SSDP window/budget (real-router behavior still to be verified
    /// against a live environment).
    #[error("igd: no internet gateway device found within {timeout_secs}s")]
    NotFound {
        /// SSDP search window (seconds).
        timeout_secs: u64,
    },
    /// Device description fetch or parse failure (bounded transport +
    /// scan; text truncated).
    #[error("igd: device description fetch/parse failed: {0}")]
    Description(String),
    /// SOAP network face / unknown action failure (bounded transport
    /// passthrough).
    #[error("igd: {0}")]
    Soap(#[from] SoapError),
    /// SOAP action failure (carries the gateway's UPnP error code,
    /// §2.5.23).
    #[error("igd: action {action} failed: {source}")]
    Action {
        /// The failed action's name.
        action: &'static str,
        /// The bounded transport error chain.
        #[source]
        source: SoapError,
    },
    /// Port conflict (718 ConflictInMappingEntry with no
    /// AddAnyPortMapping fallback).
    #[error("igd: external port {0} conflicts with another client's mapping (718)")]
    Conflict(u16),
    /// Missing/invalid field in the response (valid XML, semantically
    /// incomplete).
    #[error("igd: malformed action response for {0}")]
    MalformedResponse(&'static str),
    /// Port string parse failure (original truncated —
    /// attacker-controlled).
    #[error("igd: invalid port value {0:?}")]
    InvalidPort(String),
}

impl IgdError {
    /// Extracts the gateway's UPnP error code from a SOAP error
    /// (§2.5.23; non-SOAP-fault → None).
    pub fn upnp_code(err: &SoapError) -> Option<u16> {
        match err {
            SoapError::UpnpFault { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// IGD port-mapping request/response view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgdMapping {
    /// Mapping protocol (NewProtocol: TCP/UDP, §2.5.16.2).
    pub protocol: crate::nat::natpmp::Protocol,
    /// Local listening port (NewInternalPort).
    pub internal_port: u16,
    /// Requested external port (NewExternalPort; §2.5.17 note: v2 must
    /// accept wildcard 0).
    pub external_port: u16,
    /// Requested lease in seconds (NewLeaseDuration; always 3600 here,
    /// see the module docs).
    pub lease_secs: u32,
    /// Mapping description (NewPortMappingDescription; a human-readable
    /// label in the aiohttp/miniupnpc style, not part of protocol
    /// matching).
    pub description: String,
}

/// Queried mapping state (a semantic subset of the
/// GetSpecificPortMappingEntry OUT set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingInfo {
    /// Internal port (NewInternalPort).
    pub internal_port: u16,
    /// Internal client (NewInternalClient).
    pub internal_client: Ipv4Addr,
    /// Granted lease in seconds; 0 = permanent (§2.5.16.2 '0'
    /// semantics).
    pub lease_secs: u32,
}

/// Device-description scan result (a semantic projection of rupnp
/// `Device`: root friendly name + all services flattened — lookup
/// follows [`SERVICE_PRIORITY`] order, equivalent in hit set to rupnp's
/// `devices_iter` DFS).
#[derive(Debug, Clone)]
pub(crate) struct DeviceScan {
    /// Root device friendly name (diagnostic log; truncated —
    /// attacker-controlled).
    pub(crate) friendly_name: String,
    /// `<URLBase>` (UDA 1.1 §2.3: the merge base for relative URLs
    /// inside the description; empty text = absent; a non-absolute URI
    /// is rejected — see [`scan_device_description`]).
    pub(crate) url_base: Option<Uri>,
    /// All services in the tree (including nested deviceLists).
    pub(crate) services: Vec<ScannedService>,
}

/// One service description (a semantic projection of rupnp
/// `Service::from_xml`; only the control face is consumed — SCPD/event
/// faces get the same shape of required-field validation only; there is
/// no SCPD/subscription face).
#[derive(Debug, Clone)]
pub(crate) struct ScannedService {
    pub(crate) service_type: URN,
    #[expect(
        dead_code,
        reason = "parsed for description-shape validation; not consumed yet"
    )]
    pub(crate) service_id: String,
    pub(crate) control_url: PathAndQuery,
}

/// IGD client: one parsed device description plus the WAN connection
/// service resolved from it (the merge base for the SOAP control URL =
/// <URLBase>, defaulting to the description URL — UDA 1.1 §2.3; see the
/// [`control_base`] field).
#[derive(Debug, Clone)]
pub struct IgdClient {
    device_url: Uri,
    /// Merge base for the SOAP control URL (the authority source):
    /// <URLBase> when present; otherwise the description fetch URL (UDA
    /// 1.1 §2.3 default base, status quo). Relative paths inside the
    /// description are already merged into
    /// [`ScannedService::control_url`]'s PathAndQuery at the scan layer
    /// ([`resolve_url_text`]).
    control_base: Uri,
    friendly_name: String,
    service: ScannedService,
}

impl IgdClient {
    /// SSDP discovery (real network face; live-environment verification
    /// pending).
    ///
    /// Opens one search each for [`IGD_DEVICE_V1`] and
    /// [`IGD_DEVICE_V2`] (concurrent; each with window `timeout`, the
    /// SSDP stream tries each Location against [`SERVICE_PRIORITY`]);
    /// the first hit wins. The whole round is capped by the
    /// **discovery-round budget** (window + [`HTTP_REQUEST_TIMEOUT`]) —
    /// cutting off the path where any number of fake devices inside the
    /// window drag the round out one by one (the time-based equivalent
    /// of a device-processing cap for the round).
    ///
    /// `gateway` = the explicitly configured NAT-PMP gateway
    /// (`NatConfig::gateway`; None = unconfigured): when present, the
    /// Location host must also match it ([`validate_location_host`];
    /// the host-side equivalent of libtorrent's
    /// `upnp_ignore_nonrouters`, upnp.cpp).
    pub async fn discover(timeout: Duration, gateway: Option<Ipv4Addr>) -> Result<Self, IgdError> {
        let s1 =
            async { Self::discover_one(&SearchTarget::URN(IGD_DEVICE_V1), timeout, gateway).await };
        let s2 =
            async { Self::discover_one(&SearchTarget::URN(IGD_DEVICE_V2), timeout, gateway).await };
        match tokio::join!(s1, s2) {
            (Ok(c), _) | (_, Ok(c)) => Ok(c),
            (Err(_), Err(_)) => Err(IgdError::NotFound {
                timeout_secs: timeout.as_secs(),
            }),
        }
    }

    /// Single-target SSDP search + per-Location validation/bounded
    /// description fetch + service matching.
    ///
    /// Any failure of one SSDP response (stream parse Err, invalid/
    /// rejected Location, description fetch failure) is logged, counted,
    /// and the round **continues** — a single malicious/corrupted device
    /// must not kill the whole discovery round; the budget cap is
    /// unchanged.
    async fn discover_one(
        target: &SearchTarget,
        window: Duration,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Self, IgdError> {
        let budget = window + HTTP_REQUEST_TIMEOUT;
        let round = async {
            // SSDP protocol face: ssdp-client search (rupnp
            // `discovery.rs` args `(target, timeout, mx=3, ttl=None)`;
            // SSDP face untouched).
            let responses = rupnp::ssdp::search(target, window, 3, None)
                .await
                .map_err(|e| IgdError::Description(clip(&e.to_string())))?;
            let mut responses = std::pin::pin!(responses);
            let (skipped, found) = for_each_ssdp_response(&mut responses, |response| async move {
                handle_ssdp_response(response, gateway).await
            })
            .await;
            if let Some(client) = found {
                debug!(target: LOG_TARGET, name = client.friendly_name(), "igd discovered");
                return Ok(client);
            }
            debug!(target: LOG_TARGET, skipped, "ssdp round ended without an igd");
            Err(IgdError::NotFound {
                timeout_secs: window.as_secs(),
            })
        };
        tokio::time::timeout(budget, round)
            .await
            .unwrap_or(Err(IgdError::NotFound {
                timeout_secs: window.as_secs(),
            }))
    }

    /// Constructs directly from a device-description URL (mock test
    /// face; production = the `NatConfig::igd_device_url` deployment
    /// override). Bounded: [`MAX_HTTP_BODY`] + [`HTTP_REQUEST_TIMEOUT`].
    pub async fn from_device_url(url: Uri) -> Result<Self, IgdError> {
        Self::from_device_url_bounded(url, MAX_HTTP_BODY, HTTP_REQUEST_TIMEOUT).await
    }

    /// The parameterized form of [`from_device_url`] (tests inject a
    /// short timeout/small cap, avoiding a 10s real wait; the production
    /// path uses the constants).
    pub(crate) async fn from_device_url_bounded(
        url: Uri,
        limit: usize,
        timeout: Duration,
    ) -> Result<Self, IgdError> {
        let (device_url, scan) = Self::fetch_and_scan(url, limit, timeout).await?;
        Self::from_scan(device_url, scan)
    }

    /// Scan result → client (WAN service matching + SOAP merge-base
    /// resolution).
    fn from_scan(device_url: Uri, scan: DeviceScan) -> Result<Self, IgdError> {
        let service = find_wan_service(&scan.services).ok_or_else(|| {
            IgdError::Description(clip(
                "no WAN{IP,PPP}Connection service in device description",
            ))
        })?;
        // Merge base (UDA 1.1 §2.3): <URLBase> when present (already
        // validated absolute at the scan layer); otherwise the
        // description fetch URL (status quo).
        let control_base = scan.url_base.unwrap_or_else(|| device_url.clone());
        Ok(Self {
            device_url,
            control_base,
            friendly_name: scan.friendly_name,
            service,
        })
    }

    /// Bounded device-description fetch + isolated parsing (error
    /// surface = [`IgdError::Description`] — the same shape as the
    /// existing rupnp `Device::from_url` error passthrough; text
    /// truncated).
    async fn fetch_and_scan(
        url: Uri,
        limit: usize,
        timeout: Duration,
    ) -> Result<(Uri, DeviceScan), IgdError> {
        let request = Request::get(url.clone())
            .body(Full::new(Bytes::new()))
            .map_err(|e| IgdError::Description(clip(&format!("bad request: {e}"))))?;
        let raw = bounded_request(request, limit, timeout)
            .await
            .map_err(|e| IgdError::Description(clip(&e.to_string())))?;
        let scan = parse_off_task(raw, scan_device_description)
            .await
            .map_err(|e| IgdError::Description(clip(&e.to_string())))?;
        Ok((url, scan))
    }

    /// Gateway IP hint (the device-description URL's host; a side
    /// source for NAT-PMP gateway derivation, see
    /// [`crate::nat::NatConfig`]).
    pub fn gateway_hint(&self) -> Option<Ipv4Addr> {
        device_host(&self.device_url)
    }

    /// Device friendly name (diagnostic log; truncated —
    /// attacker-controlled).
    pub fn friendly_name(&self) -> &str {
        &self.friendly_name
    }

    /// Whether the service is WANIPConnection:2 (the AddAnyPortMapping
    /// fallback test).
    fn is_ip_v2(&self) -> bool {
        self.service.service_type == WAN_IP_CONNECTION_V2
    }

    /// GetExternalIPAddress (§2.5.20).
    pub async fn external_ip(&self) -> Result<Ipv4Addr, IgdError> {
        let resp = self.call("GetExternalIPAddress", "").await?;
        let raw = resp
            .get("NewExternalIPAddress")
            .ok_or(IgdError::MalformedResponse("GetExternalIPAddress"))?;
        raw.parse()
            .map_err(|_| IgdError::MalformedResponse("GetExternalIPAddress"))
    }

    /// AddPortMapping (§2.5.16); on a 718 conflict (§2.5.23) a v2
    /// service falls back to AddAnyPortMapping (§2.5.17) and takes
    /// NewReservedPort.
    ///
    /// Returns the externally effective port (regular path = requested
    /// value; fallback path = the gateway's reserved value).
    pub async fn add_mapping(
        &self,
        m: &IgdMapping,
        internal_client: Ipv4Addr,
    ) -> Result<u16, IgdError> {
        let args = add_mapping_args(m, internal_client);
        match self.call("AddPortMapping", &args).await {
            Ok(_) => Ok(m.external_port),
            Err(e) if IgdError::upnp_code(&e) == Some(CODE_CONFLICT) => {
                debug!(target: LOG_TARGET, port = m.external_port, "conflict (718), fallback");
                if !self.is_ip_v2() {
                    return Err(IgdError::Conflict(m.external_port));
                }
                let resp = self.call("AddAnyPortMapping", &args).await?;
                let reserved = resp
                    .get("NewReservedPort")
                    .ok_or(IgdError::MalformedResponse("AddAnyPortMapping"))?;
                let port = reserved
                    .parse::<u16>()
                    .map_err(|_| IgdError::InvalidPort(clip(reserved)))?;
                // NewReservedPort 0 has no mapping semantics (§2.5.17
                // returns a gateway-reserved free port; a 0 port in the
                // announce pollutes the whole swarm) — symmetric
                // read-back validation; 0 is rejected as invalid.
                if port == 0 {
                    return Err(IgdError::InvalidPort(clip(reserved)));
                }
                Ok(port)
            }
            Err(e) => Err(IgdError::Action {
                action: "AddPortMapping",
                source: e,
            }),
        }
    }

    /// GetSpecificPortMappingEntry (§2.5.15); 714 NoSuchEntryInArray →
    /// `Ok(None)` (§2.5.23 Table 2-51).
    pub async fn query_mapping(
        &self,
        protocol: crate::nat::natpmp::Protocol,
        external_port: u16,
    ) -> Result<Option<MappingInfo>, IgdError> {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{}</NewProtocol>",
            protocol_name(protocol),
        );
        match self.call("GetSpecificPortMappingEntry", &args).await {
            Ok(resp) => {
                let port = |k: &str| -> Result<u16, IgdError> {
                    let raw = resp
                        .get(k)
                        .ok_or(IgdError::MalformedResponse("GetSpecificPortMappingEntry"))?;
                    raw.parse::<u16>()
                        .map_err(|_| IgdError::InvalidPort(clip(raw)))
                };
                let client = resp
                    .get("NewInternalClient")
                    .ok_or(IgdError::MalformedResponse("GetSpecificPortMappingEntry"))?;
                let lease = |resp: &std::collections::HashMap<String, String>| {
                    resp.get("NewLeaseDuration")
                        .and_then(|v| v.parse::<u32>().ok())
                        // Missing lease = the gateway did not report it;
                        // treat as permanent (no renewal, no mistaken
                        // deletion)
                        .unwrap_or(0)
                };
                Ok(Some(MappingInfo {
                    internal_port: port("NewInternalPort")?,
                    internal_client: client
                        .parse()
                        .map_err(|_| IgdError::MalformedResponse("GetSpecificPortMappingEntry"))?,
                    lease_secs: lease(&resp),
                }))
            }
            Err(e) if IgdError::upnp_code(&e) == Some(CODE_NO_SUCH_ENTRY) => Ok(None),
            Err(e) => Err(IgdError::Action {
                action: "GetSpecificPortMappingEntry",
                source: e,
            }),
        }
    }

    /// DeletePortMapping (§2.5.18). Deletion is best-effort (cf.
    /// RFC 6886 §3.1 "mapping deletion requests are... advisory");
    /// gateway errors propagate up.
    pub async fn remove_mapping(
        &self,
        protocol: crate::nat::natpmp::Protocol,
        external_port: u16,
    ) -> Result<(), IgdError> {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{}</NewProtocol>",
            protocol_name(protocol),
        );
        self.call("DeletePortMapping", &args)
            .await
            .map(|_| ())
            .map_err(|e| IgdError::Action {
                action: "DeletePortMapping",
                source: e,
            })
    }

    /// SOAP action invocation (bounded: [`HTTP_REQUEST_TIMEOUT`] +
    /// [`MAX_HTTP_BODY`] + isolated parsing; XML argument names follow
    /// §2.5.16 Table 2-39 verbatim).
    async fn call(
        &self,
        action: &'static str,
        payload: &str,
    ) -> Result<std::collections::HashMap<String, String>, SoapError> {
        let envelope = soap_envelope(&self.service.service_type, action, payload);
        let url = replace_url_path(&self.control_base, &self.service.control_url);
        let request = Request::post(url)
            // Header names/values verbatim from rupnp
            // `Service::action` (service.rs).
            .header("CONTENT-TYPE", "text/xml; charset=\"utf-8\"")
            .header(
                "SOAPAction",
                format!("\"{}#{}\"", self.service.service_type, action),
            )
            .body(Full::new(Bytes::from(envelope)))
            .map_err(|e| SoapError::Network(clip(&format!("bad request: {e}"))))?;
        let raw = bounded_request(request, MAX_HTTP_BODY, HTTP_REQUEST_TIMEOUT).await?;
        parse_off_task(raw, move |bytes| parse_action_response(action, bytes)).await
    }
}

/// Conflict error code 718 ConflictInMappingEntry (§2.5.23 Table
/// 2-51).
const CODE_CONFLICT: u16 = 718;
/// 714 NoSuchEntryInArray (§2.5.23 Table 2-51).
const CODE_NO_SUCH_ENTRY: u16 = 714;

// ---------------------------------------------------------------------------
// SSDP stream consumption and Location validation
// ---------------------------------------------------------------------------

/// SSDP stream-consumption skeleton: drives `responses` item by item; a
/// single Err (malformed/truncated message) is logged, counted, and the
/// round continues — the round is not aborted; a callback returning
/// `Some(out)` = gateway found, the round ends early. Returns (number
/// of skipped error items, the hit result).
///
/// The continue-on-error semantics intentionally diverge from rupnp's
/// discover stream, where `parse()?` aborts the whole round on the
/// first error; the rationale is the review fix (one malicious device's
/// malformed message must not deny discovery of the remaining devices),
/// and the round still has a total budget cap
/// ([`IgdClient::discover_one`]).
pub(crate) async fn for_each_ssdp_response<T, E, S, F, Fut, Out>(
    responses: &mut S,
    mut on_response: F,
) -> (u32, Option<Out>)
where
    S: futures::Stream<Item = Result<T, E>> + Unpin,
    E: std::fmt::Display,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Option<Out>>,
{
    let mut skipped = 0u32;
    loop {
        match futures::stream::TryStreamExt::try_next(responses).await {
            Ok(Some(response)) => {
                if let Some(found) = on_response(response).await {
                    return (skipped, Some(found));
                }
            }
            Ok(None) => break,
            Err(e) => {
                skipped = skipped.saturating_add(1);
                debug!(target: LOG_TARGET, error = %clip(&e.to_string()),
                    "ssdp: skipping malformed response （continue)");
            }
        }
    }
    (skipped, None)
}

/// One SSDP response: parse the Location → validate the host → bounded
/// description fetch → WAN service matching. Any step failing only logs
/// and returns None ([`for_each_ssdp_response`] continues the round);
/// `Some(IgdClient)` = hit.
async fn handle_ssdp_response(
    response: rupnp::ssdp::SearchResponse,
    gateway: Option<Ipv4Addr>,
) -> Option<IgdClient> {
    let url: Uri = match response.location().parse() {
        Ok(url) => url,
        Err(e) => {
            debug!(target: LOG_TARGET,
                error = %clip(&format!("bad location: {e}")),
                location = %clip(response.location()),
                "ssdp: skipping response with unparseable location");
            return None;
        }
    };
    if let Err(e) = validate_location_host(&url, gateway) {
        debug!(target: LOG_TARGET, error = %e,
            location = %clip(response.location()),
            "ssdp: skipping response with rejected location host ");
        return None;
    }
    match IgdClient::fetch_and_scan(url, MAX_HTTP_BODY, HTTP_REQUEST_TIMEOUT).await {
        Ok((url, scan)) => {
            let client = match IgdClient::from_scan(url, scan) {
                Ok(client) => client,
                Err(e) => {
                    debug!(target: LOG_TARGET, error = %e,
                        "ssdp: skipping device without usable wan service");
                    return None;
                }
            };
            // Merge-base host validation: when <URLBase> points the
            // SOAP face at another authority, that authority is
            // validated on the same terms as the Location (SSRF/hijack
            // — an equivalent extension of Location validation; the
            // default base is the Location itself, so re-validation is
            // idempotent).
            if let Err(e) = validate_location_host(&client.control_base, gateway) {
                debug!(target: LOG_TARGET, error = %e,
                    "ssdp: skipping device whose url base host is rejected");
                return None;
            }
            Some(client)
        }
        Err(e) => {
            debug!(target: LOG_TARGET, error = %e,
                "ssdp: skipping device with failed description fetch/scan");
            None
        }
    }
}

/// SSDP Location host validation (consumed by
/// [`handle_ssdp_response`]).
///
/// Rules and basis:
///
/// - **The host must be a private/link-local IPv4 literal**: RFC 1918
/// §3 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or
/// RFC 3927 §2.1 link-local (169.254.0.0/16). Basis: SSDP discovery
/// is link-local multicast (UPnP DA §1 — M-SEARCH to
/// 239.255.255.250:1900, ssdp-client default TTL=2), so a legitimate
/// responder's description URL necessarily points at a host reachable
/// on this link; the IGD is itself the LAN-side router
/// (WANIPConnection/WANPPPConnection device definitions). Reference:
/// libtorrent's `upnp_ignore_nonrouters` subnet-matches the SSDP
/// response **source address** with
/// `match_addr_mask(listen, from, netmask)` (upnp.cpp); ssdp-client
/// 2.x's `SearchResponse` does not expose the response source address
/// (search.rs field set), so per-packet source comparison is
/// unreachable and this side uses the Location-host equivalent.
/// - **Rejected**: loopback (127/8 — the localhost SSRF face), public
/// literals, domain names (pointing the description URL at
/// attacker-controlled DNS introduces an off-link trust step), IPv6
/// literals (discovery is v4 multicast; v6 description URLs are out
/// of scope), and unspecified/multicast/reserved ranges (RFC 1112 §4,
/// 224/4, etc.).
/// - **Known trade-off**: the rare topology of a public address hung
/// directly on the LAN is falsely rejected (the review guidance
/// explicitly says "reject ... public"; recorded as-is); an explicit
/// `igd_device_url` deployment override bypasses this check
/// (operator-supplied input, not an SSDP attack surface).
/// - With `gateway` (the explicitly configured NAT-PMP gateway)
/// present, the host must also match it — the configuration already
/// anchors the router's identity, so self-advertisements from other
/// devices on the link are out of the candidate set.
pub(crate) fn validate_location_host(url: &Uri, gateway: Option<Ipv4Addr>) -> Result<(), IgdError> {
    let host = url
        .host()
        .ok_or_else(|| IgdError::Description(clip("location without host is rejected ")))?;
    // Ipv4Addr::parse rejects both domain names and IPv6 literals (the
    // latter in `[]` host form).
    let ip: Ipv4Addr = host.parse().map_err(|_| {
        IgdError::Description(clip(&format!(
            "location host {host:?} is not a private IPv4 literal "
        )))
    })?;
    if !is_private_igd_host(ip) {
        return Err(IgdError::Description(clip(&format!(
            "location host {ip} is outside RFC1918/RFC3927 local-link space "
        ))));
    }
    if let Some(gw) = gateway
        && ip != gw
    {
        return Err(IgdError::Description(clip(&format!(
            "location host {ip} does not match configured gateway {gw} "
        ))));
    }
    Ok(())
}

/// Private/link-local test (RFC 1918 §3 + RFC 3927 §2.1; loopback
/// 127/8, unspecified 0.0.0.0/8, multicast 224/4, reserved 240/4 are
/// all outside the set).
fn is_private_igd_host(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
}

// ---------------------------------------------------------------------------
// fuzz entry points (every parser gets a fuzz target)
//
// The pure-function bodies (scan_device_description /
// parse_action_response) are pub(crate) — fuzz/ is a separate workspace
// unreachable across crates. This section is the minimal visibility
// change: #[doc(hidden)] pub shims forward as-is without widening the
// type surface (they return (); error text is already truncated).
// ---------------------------------------------------------------------------

/// fuzz/cross-crate entry for [`scan_device_description`] (contract =
/// any byte string only Ok/Err, never panics — shares the
/// implementation with the depth precheck, roxmltree, and the
/// explicit-stack walk, so behavior cannot drift).
#[doc(hidden)]
pub fn parse_device_description_for_fuzz(raw: &[u8]) -> Result<(), SoapError> {
    scan_device_description(raw).map(|_| ())
}

/// fuzz/cross-crate entry for [`parse_action_response`] (the SOAP
/// response face is equally fully attacker-controlled). Same contract.
#[doc(hidden)]
pub fn parse_action_response_for_fuzz(action: &str, raw: &[u8]) -> Result<(), SoapError> {
    parse_action_response(action, raw).map(|_| ())
}

// ---------------------------------------------------------------------------
// Bounded HTTP transport
// ---------------------------------------------------------------------------

/// Bounded HTTP round trip: total timeout (connect + headers + body as
/// one cap) → non-200 rejection → Content-Length precheck (fast path,
/// not trusted) → [`http_body_util::Limited`] streaming body backstop
/// (over/under-declared bodies are truncated either way).
///
/// The client shape = rupnp's own per-call fresh `hyper_util` legacy
/// `build_http` (device.rs): HTTP-only (scheme locked; https and other
/// schemes are rejected), no redirects (the hyper client has no
/// redirect semantics — preserved).
async fn bounded_request(
    request: Request<Full<Bytes>>,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, SoapError> {
    let timeout_secs = timeout.as_secs();
    tokio::time::timeout(timeout, async move {
        let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
        let response = client
            .request(request)
            .await
            .map_err(|e| SoapError::Network(clip(&e.to_string())))?;
        if response.status() != StatusCode::OK {
            return Err(SoapError::Status(response.status()));
        }
        if let Some(declared) = response
            .headers()
            .get(rupnp::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            && declared > limit
        {
            return Err(SoapError::BodyTooLarge { limit });
        }
        // Limited's error surface is an erased Box<dyn Error>
        // (http-body-util limited.rs) — the LengthLimitError rides in
        // the source chain; walk down layer by layer to classify.
        let body = Limited::new(response.into_body(), limit);
        let collected = body.collect().await.map_err(|e| {
            let err: &(dyn std::error::Error + 'static) = &*e;
            if is_body_limit(err) {
                SoapError::BodyTooLarge { limit }
            } else {
                SoapError::Network(clip(&e.to_string()))
            }
        })?;
        Ok(collected.to_bytes())
    })
    .await
    .map_err(|_| SoapError::Timeout { timeout_secs })?
}

/// XML parsing isolation boundary: bytes (≤ the cap, already bounded)
/// go into [`tokio::task::spawn_blocking`] — a pathological input costs
/// only one blocking-pool task and never runs third-party parsing on
/// the actor task stack (an abort-face mitigation); this module's own
/// tree walk is explicit-stack iteration ([`scan_device_description`]),
/// no recursion.
async fn parse_off_task<T, F>(raw: Bytes, parse: F) -> Result<T, SoapError>
where
    T: Send + 'static,
    F: FnOnce(&[u8]) -> Result<T, SoapError> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || parse(&raw)).await {
        Ok(result) => result,
        Err(join) => Err(SoapError::Xml(clip(&format!("parse task aborted: {join}")))),
    }
}

// ---------------------------------------------------------------------------
// XML parsing (precheck → isolated parse → explicit-stack walk)
// ---------------------------------------------------------------------------

/// Byte-level depth precheck (a guard **before** parsing — roxmltree
/// 0.20's `Document::parse` itself recurses through the default 2MiB
/// thread stack on deep nesting and aborts at roughly the
/// hundreds-of-levels mark; a 64MiB stack survives 1000 levels), so the
/// depth rejection must precede `Document::parse`, which only ever
/// receives input of ≤ [`MAX_XML_DEPTH`] levels.
///
/// The scanner = a flat byte scan of the same shape as libtorrent
/// `xml_parse` (`xml_parse.cpp`): iterative, no recursion, O(n), no
/// allocation; quote-aware (`</a>`/`>` inside attribute values do not
/// count — prevents forged close tags from deflating depth), and
/// comments/CDATA/PI/DOCTYPE content is skipped wholesale (no element
/// semantics inside; DOCTYPE is always rejected under roxmltree's
/// default `allow_dtd=false`, so there is no hidden-element face).
/// Unbalanced/pathological input is not classified here — roxmltree
/// files it.
pub(crate) fn precheck_xml_depth(text: &str) -> Result<(), SoapError> {
    let b = text.as_bytes();
    let find = |from: usize, needle: &[u8]| -> Result<usize, SoapError> {
        b[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| from + p)
            .ok_or_else(|| SoapError::Xml("unterminated markup".into()))
    };
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &b[i..];
        if rest.starts_with(b"<!--") {
            i = find(i + 4, b"-->")? + 3;
        } else if rest.starts_with(b"<![CDATA[") {
            i = find(i + 9, b"]]>")? + 3;
        } else if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
            i = find(i + 2, b">")? + 1;
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = find(i + 2, b">")? + 1;
        } else {
            // Start tag: quote-aware scan to '>'; self-closing does not
            // deepen.
            depth += 1;
            if depth > MAX_XML_DEPTH {
                return Err(SoapError::Xml("xml nesting exceeds depth cap (32)".into()));
            }
            let mut j = i + 1;
            let mut quote = 0u8;
            let self_closing;
            loop {
                if j >= b.len() {
                    return Err(SoapError::Xml("unterminated start tag".into()));
                }
                let c = b[j];
                if quote != 0 {
                    if c == quote {
                        quote = 0;
                    }
                } else if c == b'"' || c == b'\'' {
                    quote = c;
                } else if c == b'>' {
                    self_closing = b[j - 1] == b'/';
                    break;
                }
                j += 1;
            }
            if self_closing {
                depth -= 1;
            }
            i = j + 1;
        }
    }
    Ok(())
}

/// Device-description scan (pure function; bytes → semantic
/// projection). Depth precheck → roxmltree parse → required-field
/// semantics of the same shape as rupnp `DeviceSpec::from_xml` /
/// `Service::from_xml` (the find_in_xml face of device.rs), with
/// nesting depth rejected up front per [`MAX_XML_DEPTH`].
pub(crate) fn scan_device_description(raw: &[u8]) -> Result<DeviceScan, SoapError> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| SoapError::Xml(clip(&format!("device description utf8: {e}"))))?;
    precheck_xml_depth(text)?;
    let document = roxmltree::Document::parse(text)
        .map_err(|e| SoapError::Xml(clip(&format!("device description xml: {e}"))))?;
    // Root device: the first element named "device" in document order
    // (same semantics as rupnp utils::find_root, device.rs).
    let root = document
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("device"))
        .ok_or_else(|| SoapError::Xml("device description has no <device>".into()))?;

    // <URLBase> (UDA 1.1 §2.3: the merge base for relative URLs inside
    // the description; first in document order, canonical position = a
    // direct child of <root>). Empty text = default base (the
    // description fetch URL); a non-absolute URI (no host) rejects the
    // whole document — the merge base must not be guessed; silently
    // falling back to the description URL would point the SOAP face at
    // the wrong endpoint.
    let url_base = match document
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "URLBase")
        .and_then(|n| n.text())
        .map(str::trim)
    {
        None | Some("") => None,
        Some(raw) => {
            let uri: Uri = raw
                .parse()
                .map_err(|e| SoapError::Xml(clip(&format!("invalid URLBase: {e}"))))?;
            if uri.host().is_none() {
                return Err(SoapError::Xml(clip(
                    "URLBase without authority cannot relativize control URLs",
                )));
            }
            Some(uri)
        }
    };

    // Explicit-stack device-tree walk (no recursion — the tag_stack
    // shape of libtorrent find_control_url, upnp.cpp).
    let mut stack = vec![(root, 1usize)];
    let mut services = Vec::new();
    let mut friendly_name = None;
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_XML_DEPTH {
            return Err(SoapError::Xml(
                "deviceList nesting exceeds depth cap (32)".into(),
            ));
        }
        let is_root = depth == 1;
        let mut device_type = None;
        let mut name = None;
        let mut service_list = None;
        let mut device_list = None;
        for child in node.children().filter(roxmltree::Node::is_element) {
            match child.tag_name().name() {
                "deviceType" => device_type = Some(child),
                "friendlyName" => name = Some(child),
                "serviceList" => service_list = Some(child),
                "deviceList" => device_list = Some(child),
                _ => {}
            }
        }
        // deviceType/friendlyName required (rupnp find_in_xml,
        // non-optional); deviceType is validated as a URN (the
        // parse_node_text::<URN> shape).
        let device_type = required_text(device_type, "deviceType")?;
        device_type
            .parse::<URN>()
            .map_err(|e| SoapError::Xml(clip(&format!("invalid deviceType: {e}"))))?;
        let name = required_text(name, "friendlyName")?;
        if is_root {
            friendly_name = Some(clip(name));
        }
        if let Some(list) = service_list {
            for service in list.children().filter(roxmltree::Node::is_element) {
                services.push(scan_service(&service, url_base.as_ref())?);
            }
        }
        if let Some(list) = device_list {
            for device in list.children().filter(roxmltree::Node::is_element) {
                stack.push((device, depth + 1));
            }
        }
    }
    Ok(DeviceScan {
        friendly_name: friendly_name.unwrap_or_default(),
        url_base,
        services,
    })
}

/// One-service scan (serviceType/serviceId/SCPDURL/controlURL/
/// eventSubURL all required = rupnp `Service::from_xml` verbatim;
/// control is the consumed face, SCPD/event get the same PathAndQuery
/// validation only — URL text goes through [`resolve_url_text`] to
/// merge against <URLBase> (UDA 1.1 §2.3) before validation).
fn scan_service<'a>(
    node: &roxmltree::Node<'a, 'a>,
    url_base: Option<&Uri>,
) -> Result<ScannedService, SoapError> {
    let mut service_type = None;
    let mut service_id = None;
    let mut scpd_url = None;
    let mut control_url = None;
    let mut event_sub_url = None;
    for child in node.children().filter(roxmltree::Node::is_element) {
        match child.tag_name().name() {
            "serviceType" => service_type = Some(child),
            "serviceId" => service_id = Some(child),
            "SCPDURL" => scpd_url = Some(child),
            "controlURL" => control_url = Some(child),
            "eventSubURL" => event_sub_url = Some(child),
            _ => {}
        }
    }
    let service_type: URN = required_text(service_type, "serviceType")?
        .parse()
        .map_err(|e| SoapError::Xml(clip(&format!("invalid serviceType: {e}"))))?;
    let service_id = required_text(service_id, "serviceId")?.to_owned();
    let parse_path = |raw: &str, what: &str| -> Result<PathAndQuery, SoapError> {
        resolve_url_text(url_base, raw)
            .map_err(|e| SoapError::Xml(clip(&format!("invalid {what}: {e}"))))
    };
    let _scpd = parse_path(required_text(scpd_url, "SCPDURL")?, "SCPDURL")?;
    let control = parse_path(required_text(control_url, "controlURL")?, "controlURL")?;
    let _event = parse_path(required_text(event_sub_url, "eventSubURL")?, "eventSubURL")?;
    Ok(ScannedService {
        service_type,
        service_id,
        control_url: control,
    })
}

/// URL text inside the description → PathAndQuery (UDA 1.1 §2.3: when
/// <URLBase> is present it is the base for RFC 3986 relative-reference
/// resolution; the default = an absolute path as-is — authority merging
/// happens in [`replace_url_path`] at call time with the description
/// URL, status quo).
///
/// - Absolute-path reference (`/control`, RFC 3986 §4.2 path-absolute):
/// the base path yields entirely — the scan layer passes it as-is and
/// authority merging is left to the call layer;
/// - Relative-path reference (`control`): RFC 3986 §5.2.3 merge — the
/// base path up to and including the last `/`, then the reference
/// appended. A trailing slash on URLBase (`/root/`) preserves the
/// prefix (→ `/root/control`); without it (`/root`) the last segment
/// yields (→ `/control`) — the merge difference between the two real
/// UDA §2.3 shapes; a URLBase with no path (authority only) defaults
/// the base path to `/`;
/// - dot-segments (`./x`, `../x`) get no §5.2.4 normalization: the
/// device ecosystem does not produce them, and prefix-merge already
/// covers the real shapes;
/// - an empty URL / a relative path with no URLBase: rejected by
/// `PathAndQuery` parsing (the http crate rejects any path not
/// starting with `/` as `PathDoesNotStartWithSlash` — rupnp's
/// required-field validation shape is preserved).
fn resolve_url_text(url_base: Option<&Uri>, raw: &str) -> Result<PathAndQuery, String> {
    if raw.is_empty() {
        return Err("empty url".into());
    }
    if raw.starts_with('/') {
        return raw.parse::<PathAndQuery>().map_err(|e| e.to_string());
    }
    let Some(base) = url_base else {
        // A relative reference with no <URLBase>: no merge base; keep
        // the parse-rejection face.
        return raw.parse::<PathAndQuery>().map_err(|e| e.to_string());
    };
    let base_path = base.path();
    let cut = base_path.rfind('/').map_or(0, |i| i + 1);
    let merged = format!("{}{}", &base_path[..cut], raw);
    merged.parse::<PathAndQuery>().map_err(|e| e.to_string())
}

/// Required element text (missing = `Xml`; the same failure face as
/// rupnp's `XmlMissingElement`). Lifetime = a borrow of the document
/// tree (does not escape the scan function — consumption is the
/// parse/truncate point).
fn required_text<'a>(
    node: Option<roxmltree::Node<'a, 'a>>,
    name: &str,
) -> Result<&'a str, SoapError> {
    let node = node.ok_or_else(|| SoapError::Xml(clip(&format!("missing <{name}>"))))?;
    Ok(node.text().unwrap_or_default())
}

/// SOAP action response parsing (the parse segment of rupnp
/// `Service::action` verbatim: locate Body case-insensitively → first
/// child → a Fault goes to [`parse_fault`], otherwise collect argName →
/// text; same text as service.rs).
fn parse_action_response(
    action: &str,
    raw: &[u8],
) -> Result<std::collections::HashMap<String, String>, SoapError> {
    let text = std::str::from_utf8(raw).map_err(|e| SoapError::Xml(clip(&format!("utf8: {e}"))))?;
    precheck_xml_depth(text)?;
    let document =
        roxmltree::Document::parse(text).map_err(|e| SoapError::Xml(clip(&format!("xml: {e}"))))?;
    let body = document
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("Body"))
        .ok_or_else(|| SoapError::Xml(clip(&format!("missing <Body> for {action}"))))?;
    let response = body
        .first_element_child()
        .ok_or_else(|| SoapError::Xml(clip(&format!("missing <{action}Response> in Body"))))?;
    if response.tag_name().name().eq_ignore_ascii_case("Fault") {
        return Err(parse_fault(&response));
    }
    let values: HashMap<_, _> = response
        .children()
        .filter(roxmltree::Node::is_element)
        .filter_map(|node| {
            node.text()
                .map(|text| (node.tag_name().name().to_string(), text.to_string()))
        })
        .collect();
    Ok(values)
}

/// SOAP fault → [`SoapError::UpnpFault`] (rupnp error.rs
/// `from_fault_node` semantics: the first errorCode under detail
/// decides the code; a missing/invalid errorCode = the Xml failure
/// face, landing in the action error rather than a fault, same as
/// rupnp's XmlMissingElement/InvalidResponse).
fn parse_fault(node: &roxmltree::Node<'_, '_>) -> SoapError {
    let code = node
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("errorCode"))
        .and_then(|n| n.text())
        .and_then(|text| text.trim().parse::<u16>().ok());
    let description = node
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("errorDescription"))
        .and_then(|n| n.text())
        .unwrap_or_default();
    match code {
        Some(code) => SoapError::UpnpFault {
            code,
            description: clip(description),
        },
        None => SoapError::Xml("SOAP fault without valid errorCode".into()),
    }
}

/// SOAP envelope (verbatim from rupnp `Service::action`; UPnP DA §3
/// Control).
fn soap_envelope(service: &URN, action: &str, payload: &str) -> String {
    format!(
        r#"
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:{action} xmlns:u="{service}">
                        {payload}
                    </u:{action}>
                </s:Body>
            </s:Envelope>"#,
        service = service,
        action = action,
        payload = payload
    )
}

/// Merge-base path swap (the skeleton of rupnp service.rs
/// `replace_url_path` + UDA 1.1 §2.3 base parameterization): control
/// URL = the merge base's (<URLBase>, defaulting to the description
/// fetch URL — [`IgdClient::control_base`]) authority + the service
/// controlURL path; when controlURL is a relative-path form its path
/// prefix was already merged against URLBase at the scan layer
/// ([`resolve_url_text`], RFC 3986 §5.2.3), so only the authority
/// application remains here.
fn replace_url_path(url: &Uri, path: &PathAndQuery) -> Uri {
    let mut parts = url.clone().into_parts();
    parts.path_and_query = Some(path.clone());
    // Recombining parts from the same URL cannot actually fail; on
    // failure fall back to the original URL (degrades to hitting the
    // description page, classified by the gateway's 404/non-200 — no
    // panic).
    Uri::from_parts(parts).unwrap_or_else(|_| url.clone())
}

/// Service lookup (priority [`SERVICE_PRIORITY`]; first hit on the
/// flattened set in priority order).
fn find_wan_service(services: &[ScannedService]) -> Option<ScannedService> {
    SERVICE_PRIORITY
        .iter()
        .find_map(|urn| services.iter().find(|s| &s.service_type == urn).cloned())
}

/// NewProtocol string (§2.5.16.2 "PortMappingProtocol is either TCP or
/// UDP").
fn protocol_name(p: crate::nat::natpmp::Protocol) -> &'static str {
    match p {
        crate::nat::natpmp::Protocol::Tcp => "TCP",
        crate::nat::natpmp::Protocol::Udp => "UDP",
    }
}

/// AddPortMapping/AddAnyPortMapping argument XML (§2.5.16 Table 2-39
/// names; an empty NewRemoteHost = wildcard — §2.5.16.2 requires v2
/// gateways to support a wildcard RemoteHost; NewEnabled=1; boolean/
/// port as UPnP ui2/boolean text).
fn add_mapping_args(m: &IgdMapping, internal_client: Ipv4Addr) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{}</NewExternalPort>\
         <NewProtocol>{}</NewProtocol>\
         <NewInternalPort>{}</NewInternalPort>\
         <NewInternalClient>{}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{}</NewPortMappingDescription>\
         <NewLeaseDuration>{}</NewLeaseDuration>",
        m.external_port,
        protocol_name(m.protocol),
        m.internal_port,
        internal_client,
        m.description,
        m.lease_secs,
    )
}

/// Device URL host → Ipv4Addr (a non-IPv4-literal host → None).
fn device_host(url: &Uri) -> Option<Ipv4Addr> {
    url.host()?.parse().ok()
}
