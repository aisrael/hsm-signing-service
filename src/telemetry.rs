//! OpenTelemetry set-up: ship the `tracing` spans to an OTLP collector.
//!
//! The service is quiet by default. Telemetry is on only if the environment
//! variable `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`)
//! is set. The SDK reads the other standard `OTEL_*` variables itself, for
//! example `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER` and
//! `OTEL_TRACES_SAMPLER_ARG`. The transport is OTLP over gRPC.

use std::time::Duration;

use axum::http::HeaderMap;
use opentelemetry::global;
use opentelemetry::metrics::Meter;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::PeriodicReader;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracer;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The default `service.name`, used if `OTEL_SERVICE_NAME` is not set.
const DEFAULT_SERVICE_NAME: &str = "hsm-signing-service";

/// The name of the tracer (the instrumentation scope).
const TRACER_NAME: &str = env!("CARGO_PKG_NAME");

/// How long to wait for the exporter when the service stops.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the metrics are sent, if `OTEL_METRIC_EXPORT_INTERVAL` is not
/// set. The SDK default is 60 seconds, which is slow for a local check.
const DEFAULT_METRIC_EXPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Owns the tracer provider and the meter provider. Call `shutdown` before the
/// process ends, so the spans in the batch queue and the last metrics are sent.
#[derive(Debug)]
pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl TelemetryGuard {
    /// The meter for the application metrics (see `metrics`).
    pub fn meter(&self) -> Meter {
        self.meter_provider.meter(TRACER_NAME)
    }

    /// Send the spans that wait in the queue and the current metrics, and stop
    /// the exporters. It waits at most a few seconds for each. A failure is
    /// printed, not returned: the service is stopping anyway.
    pub fn shutdown(self) {
        if let Err(err) = self.tracer_provider.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
            eprintln!("Error shutting down tracing: {err}");
        }
        if let Err(err) = self.meter_provider.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
            eprintln!("Error shutting down metrics: {err}");
        }
    }
}

/// Is an OTLP endpoint configured through the environment?
pub fn is_enabled() -> bool {
    [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ]
    .iter()
    .any(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()))
}

/// Build the OTLP exporters, the tracer provider and the meter provider, and
/// set the global propagator (W3C `traceparent`). Return `None` if telemetry
/// is off.
///
/// The caller adds a `tracing_opentelemetry` layer for the returned tracer
/// to the subscriber. This must run inside the Tokio runtime.
pub fn init() -> Result<Option<(TelemetryGuard, SdkTracer)>, opentelemetry_otlp::ExporterBuildError>
{
    if !is_enabled() {
        return Ok(None);
    }

    let span_exporter = SpanExporter::builder().with_tonic().build()?;
    let metric_exporter = MetricExporter::builder().with_tonic().build()?;

    // `Resource::builder` reads `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`.
    let mut resource = Resource::builder();
    if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
        resource = resource.with_service_name(DEFAULT_SERVICE_NAME);
    }
    let resource = resource
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    // The sampler comes from `OTEL_TRACES_SAMPLER` (default: parent based, always on).
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();
    let tracer = tracer_provider.tracer(TRACER_NAME);

    // `PeriodicReader` reads `OTEL_METRIC_EXPORT_INTERVAL`. Only if that is
    // not set, use a shorter interval than the SDK default.
    let mut reader = PeriodicReader::builder(metric_exporter);
    if std::env::var_os("OTEL_METRIC_EXPORT_INTERVAL").is_none() {
        reader = reader.with_interval(DEFAULT_METRIC_EXPORT_INTERVAL);
    }
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(reader.build())
        .with_resource(resource)
        .build();

    global::set_text_map_propagator(TraceContextPropagator::new());
    Ok(Some((
        TelemetryGuard {
            tracer_provider,
            meter_provider,
        },
        tracer,
    )))
}

/// Reads the trace context from the HTTP request headers.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

/// Make `span` a child of the trace in the `traceparent` header, if there is
/// one. Without a valid header the span stays a root span. It does nothing
/// if telemetry is off.
pub fn set_parent_from_headers(span: &Span, headers: &HeaderMap) {
    let parent =
        global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)));
    // Fails only if the span has no OpenTelemetry data (telemetry is off).
    let _ = span.set_parent(parent);
}

#[cfg(test)]
pub mod testing {
    //! A process-wide in-memory exporter for the tests. The tracing subscriber
    //! is global, because `spawn_blocking` threads do not see a thread-local one.
    //! Tests must find their spans by a unique attribute.

    use std::sync::OnceLock;

    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry_sdk::trace::SpanData;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    static EXPORTER: OnceLock<InMemorySpanExporter> = OnceLock::new();

    /// Install the global subscriber (once) and return the exporter.
    pub fn exporter() -> &'static InMemorySpanExporter {
        EXPORTER.get_or_init(|| {
            let exporter = InMemorySpanExporter::default();
            let provider = SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let tracer = provider.tracer("test");
            global::set_text_map_propagator(TraceContextPropagator::new());
            let subscriber = tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(tracer));
            tracing::subscriber::set_global_default(subscriber)
                .expect("a global subscriber is already set");
            exporter
        })
    }

    /// All finished spans so far.
    pub fn finished_spans() -> Vec<SpanData> {
        exporter()
            .get_finished_spans()
            .expect("unable to read the spans")
    }

    /// The string value of an attribute of a span, if it has one.
    pub fn attribute(span: &SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.to_string())
    }
}
