//! Per-host connection cap (`--http-max-per-host`, default 64, unit =
//! connections) — a registry shared across tasks.
//!
//! Semantics: the cap scope is engine-global (one [`HostCap`] held by
//! the SessionActor, shared by all HTTP tasks via Arc) — in-flight
//! connections per host are counted across tasks, first come first
//! served; AIMD (dynamic scheduling) decisions also pass through this
//! cap first. Host key = `scheme://host:port` (case/default-port
//! normalized; a protocol+endpoint change is a different host). SFTP
//! tasks count 1 connection (single-connection model). When full,
//! `acquire` waits on `tokio::sync::Notify` — no busy-wait, no
//! unbounded queue. A runtime cap decrease never reclaims existing
//! permits, it only constrains new acquisitions. Holding form: permits
//! are acquired at worker activation and released before parking (see
//! docs/design/http.md).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Notify;

/// Default cap value (`--http-max-per-host` 64; unit = connections;
/// raised from the original 32 after controlled experiments — see
/// docs/design/http.md).
pub const DEFAULT_MAX_PER_HOST: u32 = 64;

/// Permit slot for a single host.
struct Slot {
    active: AtomicU64,
    notify: Notify,
}

impl Slot {
    fn new() -> Slot {
        Slot {
            active: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }
}

struct Inner {
    cap: AtomicU32,
    slots: StdMutex<HashMap<String, Arc<Slot>>>,
}

/// Per-host connection cap registry (cheap Clone; tasks share one Arc).
#[derive(Clone)]
pub struct HostCap {
    inner: Arc<Inner>,
}

impl Default for HostCap {
    fn default() -> Self {
        HostCap::new(DEFAULT_MAX_PER_HOST)
    }
}

impl HostCap {
    /// Build with an initial cap (session-level single instance).
    pub fn new(cap: u32) -> Self {
        HostCap {
            inner: Arc::new(Inner {
                cap: AtomicU32::new(cap.max(1)),
                slots: StdMutex::new(HashMap::new()),
            }),
        }
    }

    /// Adjust the cap at runtime (the changeOption face; clamped >= 1).
    pub fn set_cap(&self, cap: u32) {
        self.inner.cap.store(cap.max(1), Ordering::Relaxed);
        // Wake all waiters to re-evaluate (over-subscribed slots
        // converge as releases happen).
        let slots = crate::lock(&self.inner.slots);
        for slot in slots.values() {
            slot.notify.notify_waiters();
        }
    }

    /// Current cap value.
    pub fn cap(&self) -> u32 {
        self.inner.cap.load(Ordering::Relaxed)
    }

    /// Host connection key (`scheme://host:port`; default port
    /// normalized, host lowercased). Unparseable (non-http(s) URL etc.)
    /// → None (the caller skips the cap check — the cap never blocks
    /// keyless forms).
    pub fn host_key(url: &str) -> Option<String> {
        let u = reqwest::Url::parse(url).ok()?;
        let host = u.host_str()?;
        let port = u.port_or_known_default()?;
        Some(format!(
            "{}://{}:{}",
            u.scheme(),
            host.to_ascii_lowercase(),
            port
        ))
    }

    fn slot_of(&self, host: &str) -> Arc<Slot> {
        let mut slots = crate::lock(&self.inner.slots);
        Arc::clone(
            slots
                .entry(host.to_string())
                .or_insert_with(|| Arc::new(Slot::new())),
        )
    }

    /// Current in-flight connections for this host (observation).
    pub fn active(&self, host: &str) -> u64 {
        crate::lock(&self.inner.slots)
            .get(host)
            .map(|s| s.active.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Acquire a connection permit immediately; full cap → None (no
    /// waiting).
    pub fn try_acquire(&self, host: &str) -> Option<HostPermit> {
        let cap = self.cap();
        let slot = self.slot_of(host);
        loop {
            let cur = slot.active.load(Ordering::Relaxed);
            if cur >= u64::from(cap) {
                return None;
            }
            if slot
                .active
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(HostPermit {
                    slot,
                    released: false,
                });
            }
        }
    }

    /// Acquire a connection permit (waits when the cap is full;
    /// releases/cap changes wake waiters via Notify — Notify's permit
    /// storage semantics close the "notify before await" lost-wakeup
    /// window). Dropping the permit releases it. The wait has no
    /// timeout — cancellation happens by dropping the caller's future
    /// (select/abort).
    pub async fn acquire(&self, host: &str) -> HostPermit {
        let slot = self.slot_of(host);
        loop {
            match self.try_acquire(host) {
                Some(permit) => return permit,
                None => slot.notify.notified().await,
            }
        }
    }
}

/// A per-host connection permit: holds the count +1; Drop returns it
/// and wakes a waiter.
pub struct HostPermit {
    slot: Arc<Slot>,
    released: bool,
}

impl HostPermit {
    /// Current in-flight connections for this host (a read right after
    /// acquisition includes this permit).
    pub fn active_now(&self) -> u64 {
        self.slot.active.load(Ordering::Relaxed)
    }

    /// Release explicitly and early (same semantics as Drop; idempotent).
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        self.slot.active.fetch_sub(1, Ordering::AcqRel);
        self.slot.notify.notify_one();
    }
}

impl Drop for HostPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Host key normalization: case/default-port equivalent; scheme,
    /// port, and path variants differ.
    #[test]
    fn host_key_normalization() {
        assert_eq!(
            HostCap::host_key("http://EXAMPLE.test:80/f.bin"),
            HostCap::host_key("http://example.test/f.bin")
        );
        assert_eq!(
            HostCap::host_key("https://a.test/x"),
            HostCap::host_key("https://a.test:443/y")
        );
        assert_ne!(
            HostCap::host_key("http://a.test/x"),
            HostCap::host_key("https://a.test/x")
        );
        assert_ne!(
            HostCap::host_key("http://a.test:8080/x"),
            HostCap::host_key("http://a.test/x")
        );
        assert_eq!(
            HostCap::host_key("ftp://f.test/x"),
            Some("ftp://f.test:21".into())
        );
        assert_eq!(HostCap::host_key("not a url"), None);
    }

    /// Default cap = 64 (final; see the [`DEFAULT_MAX_PER_HOST`] doc).
    /// Pinned against drift.
    #[test]
    fn default_cap_is_64() {
        assert_eq!(DEFAULT_MAX_PER_HOST, 64);
        assert_eq!(HostCap::default().cap(), 64);
        assert_eq!(
            HostCap::new(0).cap(),
            1,
            "0 clamps to >= 1, semantics unchanged"
        );
    }

    /// Acquire/release counting under the cap; try_acquire refuses
    /// when full.
    #[test]
    fn cap_counts_and_try_acquire_refuses_when_full() {
        let cap = HostCap::new(2);
        let a = cap
            .try_acquire("http://a.test:80")
            .unwrap_or_else(|| panic!("a"));
        assert_eq!(cap.active("http://a.test:80"), 1);
        let b = cap
            .try_acquire("http://a.test:80")
            .unwrap_or_else(|| panic!("b"));
        assert!(
            cap.try_acquire("http://a.test:80").is_none(),
            "a full cap must refuse"
        );
        // Different hosts count independently.
        assert!(cap.try_acquire("http://b.test:80").is_some());
        b.release();
        assert_eq!(cap.active("http://a.test:80"), 1);
        drop(a);
        assert_eq!(cap.active("http://a.test:80"), 0);
    }

    /// Cross-task sharing: two "tasks" (concurrent tokio tasks) share
    /// one registry; the cap counts globally per host — the sum of held
    /// permits never exceeds the cap.
    #[tokio::test]
    async fn cap_is_shared_across_tasks() {
        let cap = HostCap::new(2);
        let cap = Arc::new(cap);
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for _ in 0..6 {
            let cap = Arc::clone(&cap);
            let max_seen = Arc::clone(&max_seen);
            joins.push(tokio::spawn(async move {
                let permit = cap.acquire("http://shared.test/x").await;
                let cur = cap.active("http://shared.test/x") as usize;
                max_seen.fetch_max(cur, Ordering::Relaxed);
                // Hold the permit briefly to create concurrent overlap.
                tokio::time::sleep(Duration::from_millis(10)).await;
                permit.release();
            }));
        }
        for j in joins {
            j.await.unwrap_or_else(|e| panic!("join: {e}"));
        }
        assert!(
            max_seen.load(Ordering::Relaxed) <= 2,
            "cross-task concurrent permits must not exceed the cap: {}",
            max_seen.load(Ordering::Relaxed)
        );
        assert_eq!(
            cap.active("http://shared.test/x"),
            0,
            "all released returns to zero"
        );
    }

    /// acquire waits when full and is granted after release (no
    /// busy-wait deadlock).
    #[tokio::test]
    async fn acquire_waits_until_release() {
        let cap = HostCap::new(1);
        let first = cap
            .try_acquire("http://w.test/")
            .unwrap_or_else(|| panic!("first"));
        let waiter = {
            let cap = cap.clone();
            tokio::spawn(async move { cap.acquire("http://w.test/").await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "the waiter must not already be granted while the cap is full"
        );
        first.release();
        let permit = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap_or_else(|e| panic!("waiter timed out: {e}"))
            .unwrap_or_else(|e| panic!("join: {e}"));
        assert_eq!(permit.active_now(), 1);
    }

    /// Runtime cap decrease/increase takes effect.
    #[tokio::test]
    async fn set_cap_runtime_adjustment() {
        let cap = HostCap::new(32);
        assert_eq!(cap.cap(), 32);
        cap.set_cap(1);
        assert_eq!(cap.cap(), 1);
        let a = cap
            .try_acquire("http://s.test/")
            .unwrap_or_else(|| panic!("a"));
        assert!(cap.try_acquire("http://s.test/").is_none());
        cap.set_cap(4);
        assert!(
            cap.try_acquire("http://s.test/").is_some(),
            "acquirable after the cap is raised"
        );
        let _ = a;
    }
}
