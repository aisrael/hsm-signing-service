//! The application metrics, sent over OTLP together with the traces.
//!
//! There is no scrape endpoint. The metrics go to the same collector as the
//! spans (see `telemetry`). A `Metrics` value holds the instruments. Without
//! telemetry it holds no-op instruments, so the code that uses it needs no
//! `if`.
//!
//! | Metric | Kind | Meaning |
//! | --- | --- | --- |
//! | `hsm_signing.requests.in_flight` | gauge (up-down counter) | Requests in the service, as counted by the admission limit. |
//! | `hsm_signing.pool.sessions_in_use` | gauge (up-down counter) | HSM sessions taken from the pool right now. |
//! | `hsm_signing.pool.size` | gauge | The number of sessions of the pool (a constant). |
//!
//! The queue length is `requests.in_flight - pool.sessions_in_use`.

use opentelemetry::metrics::Meter;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::metrics::NoopMeterProvider;
use opentelemetry::metrics::UpDownCounter;

/// The instruments of the service. It is cheap to clone.
#[derive(Debug, Clone)]
pub struct Metrics {
    meter: Meter,
    requests_in_flight: UpDownCounter<i64>,
    pool_sessions_in_use: UpDownCounter<i64>,
}

impl Metrics {
    /// Make the instruments with `meter`.
    pub fn new(meter: &Meter) -> Self {
        Metrics {
            meter: meter.clone(),
            requests_in_flight: meter
                .i64_up_down_counter("hsm_signing.requests.in_flight")
                .with_description("Requests in the service")
                .with_unit("{request}")
                .build(),
            pool_sessions_in_use: meter
                .i64_up_down_counter("hsm_signing.pool.sessions_in_use")
                .with_description("HSM sessions that are taken from the pool")
                .with_unit("{session}")
                .build(),
        }
    }

    /// Instruments that record nothing. Used when telemetry is off, and in
    /// tests that do not look at metrics.
    pub fn noop() -> Self {
        Metrics::new(&NoopMeterProvider::new().meter(env!("CARGO_PKG_NAME")))
    }

    /// Count one request in the service until the guard is dropped.
    pub fn request_in_flight(&self) -> GaugeGuard {
        GaugeGuard::new(self.requests_in_flight.clone())
    }

    /// Count one session in use until the guard is dropped.
    pub fn session_in_use(&self) -> GaugeGuard {
        GaugeGuard::new(self.pool_sessions_in_use.clone())
    }

    /// Report the (constant) size of the session pool.
    pub fn set_pool_size(&self, size: u32) {
        // The callback runs at every export, so the gauge never goes missing.
        // The instrument stays alive because the meter keeps its callback.
        self.meter
            .u64_observable_gauge("hsm_signing.pool.size")
            .with_description("The number of sessions of the HSM session pool")
            .with_unit("{session}")
            .with_callback(move |observer| observer.observe(u64::from(size), &[]))
            .build();
    }
}

/// Adds 1 to an up-down counter when it is made and subtracts 1 when it is
/// dropped. A guard drops on every path (an error, an early return, a panic),
/// so the gauge cannot drift.
#[derive(Debug)]
#[must_use = "the gauge goes down again when the guard is dropped"]
pub struct GaugeGuard {
    counter: UpDownCounter<i64>,
}

impl GaugeGuard {
    fn new(counter: UpDownCounter<i64>) -> Self {
        counter.add(1, &[]);
        GaugeGuard { counter }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.counter.add(-1, &[]);
    }
}

#[cfg(test)]
pub mod testing {
    //! Read metrics back in tests, with an in-memory exporter and a provider
    //! that is local to the test (no global state).

    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    use opentelemetry_sdk::metrics::PeriodicReader;
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::metrics::data::AggregatedMetrics;
    use opentelemetry_sdk::metrics::data::MetricData;

    use super::*;

    /// A provider whose metrics a test can read.
    pub struct TestMetrics {
        provider: SdkMeterProvider,
        exporter: InMemoryMetricExporter,
        pub metrics: Metrics,
    }

    impl TestMetrics {
        pub fn new() -> Self {
            let exporter = InMemoryMetricExporter::default();
            let reader = PeriodicReader::builder(exporter.clone()).build();
            let provider = SdkMeterProvider::builder().with_reader(reader).build();
            let metrics = Metrics::new(&provider.meter("test"));
            TestMetrics {
                provider,
                exporter,
                metrics,
            }
        }

        /// The current value of the metric. For a gauge with several data
        /// points it is the sum.
        pub fn value(&self, name: &str) -> Option<i64> {
            self.provider.force_flush().expect("unable to flush");
            let finished = self.exporter.get_finished_metrics().unwrap();
            // The last export has the current values.
            let latest = finished.last()?;
            latest
                .scope_metrics()
                .flat_map(|scope| scope.metrics())
                .filter(|metric| metric.name() == name)
                .find_map(|metric| match metric.data() {
                    AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                        Some(sum.data_points().map(|point| point.value()).sum())
                    }
                    AggregatedMetrics::U64(MetricData::Gauge(gauge)) => {
                        Some(gauge.data_points().map(|point| point.value() as i64).sum())
                    }
                    _ => None,
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TestMetrics;

    #[test]
    fn a_guard_counts_up_and_goes_down_when_dropped() {
        let test = TestMetrics::new();

        let first = test.metrics.request_in_flight();
        let second = test.metrics.request_in_flight();
        assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(2));

        drop(first);
        assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(1));
        drop(second);
        assert_eq!(test.value("hsm_signing.requests.in_flight"), Some(0));
    }

    #[test]
    fn a_guard_goes_down_when_the_code_panics() {
        let test = TestMetrics::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = test.metrics.session_in_use();
            panic!("a panic while a session is in use");
        }));

        assert!(result.is_err());
        assert_eq!(test.value("hsm_signing.pool.sessions_in_use"), Some(0));
    }

    #[test]
    fn the_pool_size_is_reported() {
        let test = TestMetrics::new();

        test.metrics.set_pool_size(10);

        assert_eq!(test.value("hsm_signing.pool.size"), Some(10));
    }

    #[test]
    fn noop_metrics_do_nothing_and_do_not_fail() {
        let metrics = super::Metrics::noop();
        let _guard = metrics.request_in_flight();
        metrics.set_pool_size(3);
    }
}
