//! This module defines the shared application state for the HSM signing service.

use crate::config::Config;
use crate::errors::Error;

/// The shared application state.
pub struct AppState {
    // Add any shared state here, e.g. database connections, HSM clients, etc.
}

impl AppState {
    pub fn try_new(config: &Config) -> Result<Self, Error> {
        let app_state = AppState {
            // Initialize shared state here.
        };
        Ok(app_state)
    }
}
