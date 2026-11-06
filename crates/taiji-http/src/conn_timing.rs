//! Connection-establishment timing middleware (the connection-profile
//! observation face).
//!
//! Mounted via [`reqwest::ClientBuilder::connector_layer`]. The
//! connector service only runs on pool misses, so timing and counting
//! here naturally cover new connections only. The success exit feeds
//! [`taiji_io::metrics::HttpMetrics::note_conn_established`]: counter
//! and histogram book the same success event in equal amounts; failed
//! attempts never reach this feed (failure classification stays with
//! `taiji_http_errors_total{class}`); timings cover DNS + TCP + TLS
//! combined (deduction conventions in docs/design/http.md).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use taiji_io::metrics::MetricsRegistry;
use tower_layer::Layer;
use tower_service::Service;

/// Connection-timing layer (cheap clone: only an `Arc` inside).
/// Mounted via [`reqwest::ClientBuilder::connector_layer`]; the layer
/// produces a [`ConnTimingService`] wrapping the inner connector
/// service.
#[derive(Clone, Debug)]
pub(crate) struct ConnTimingLayer {
    metrics: Arc<MetricsRegistry>,
}

impl ConnTimingLayer {
    /// Build bound to a metrics registry (production = the process
    /// default instance at assembly; tests inject an isolated instance
    /// via `HttpClient::with_metrics` — the same registry-injection
    /// pattern; bare globals forbidden).
    pub(crate) fn new(metrics: Arc<MetricsRegistry>) -> Self {
        ConnTimingLayer { metrics }
    }
}

impl<S> Layer<S> for ConnTimingLayer {
    type Service = ConnTimingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnTimingService {
            inner,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Connection-timing service (the [`ConnTimingLayer`] product):
/// requests pass through; the success exit reads the tables (counter
/// +1, histogram observes the combined latency — conventions in the
/// module docs).
#[derive(Clone, Debug)]
pub(crate) struct ConnTimingService<S> {
    inner: S,
    metrics: Arc<MetricsRegistry>,
}

impl<S, Request> Service<Request> for ConnTimingService<S>
where
    S: Service<Request>,
    S::Future: Send + 'static,
    S::Response: 'static,
    S::Error: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // Timing starts when the connector service is called (DNS,
        // TCP, and TLS then happen inside the inner service in order;
        // poll_ready's pool-ready wait is outside the timing domain —
        // the request has not been issued yet).
        let started = Instant::now();
        let fut = self.inner.call(req);
        let metrics = Arc::clone(&self.metrics);
        Box::pin(async move {
            match fut.await {
                Ok(resp) => {
                    metrics.http().note_conn_established(started.elapsed());
                    Ok(resp)
                }
                Err(e) => Err(e),
            }
        })
    }
}
