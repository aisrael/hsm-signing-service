//! This module defines the shared application state for the HSM signing service.

use crate::config::Config;
use crate::errors::Error;
use crate::hsm_backend::HsmBackend;
use crate::metrics::Metrics;

/// The shared application state.
#[derive(Debug)]
pub struct AppState<B: HsmBackend> {
    // Add any shared state here, e.g. database connections, HSM clients, etc.
    pub hsm_backend: B,
    /// The instruments of the application metrics. No-op without telemetry.
    pub metrics: Metrics,
}

impl<B: HsmBackend> AppState<B> {
    pub fn try_new(_config: &Config, hsm_backend: B) -> Result<Self, Error> {
        let app_state = AppState {
            // Initialize shared state here.
            hsm_backend,
            metrics: Metrics::noop(),
        };
        Ok(app_state)
    }

    /// Use these instruments instead of the no-op ones.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }
}
