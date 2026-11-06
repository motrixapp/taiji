//! DNS resolution (resolver seam, per-family resolution, whole-list caching,
//! timeout decorator, shared service) lives in the shared layer
//! [`taiji_io::dns`]. This module is a compatibility re-export for the
//! existing `bt::tracker` paths (the tracker actor injection seam
//! `Arc<dyn HostResolver>` and existing tests migrate with zero changes).
//! Design notes and the upstream anchor (aria2 `NameResolveCommand.cc`)
//! are documented in [`taiji_io::dns`].

pub use taiji_io::dns::{
    DNS_TIMEOUT, HOST_CACHE_CAPACITY, HOST_CACHE_TTL, HostResolver, ListResolverFuture,
    ResolveError, ResolveFamily, ResolverFuture, SharedDns, TimeoutResolver, TokioHostResolver,
    box_resolve_error, error_chain_is_dns, pick_addr, pick_addr_family,
};
