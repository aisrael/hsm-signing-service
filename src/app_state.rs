//! This module defines the shared application state for the HSM signing service.

use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;

use crate::config::Config;
use crate::errors::Error;
use crate::hsm_backend::HsmBackend;

/// The shared application state.
#[derive(Debug)]
pub struct AppState<B: HsmBackend> {
    // Add any shared state here, e.g. database connections, HSM clients, etc.
    pub hsm_backend: B,
    /// Limits the requests in the service. It has one permit for each request
    /// that can use a session, plus one for each request that can wait.
    admission: Semaphore,
}

impl<B: HsmBackend> AppState<B> {
    pub fn try_new(config: &Config, hsm_backend: B) -> Result<Self, Error> {
        // Without a session pool, the service has one session.
        let sessions = config.session_pool_size().unwrap_or(1) as usize;
        let capacity = sessions + config.max_queue() as usize;
        let app_state = AppState {
            // Initialize shared state here.
            hsm_backend,
            admission: Semaphore::new(capacity),
        };
        Ok(app_state)
    }

    /// Take a place in the service for one request, or return `None` if the
    /// service is full. The place is free again when the permit is dropped.
    /// This never waits.
    pub fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        self.admission.try_acquire().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm_backend::MockHsmBackend;

    #[test]
    fn without_a_pool_the_service_admits_one_session_plus_the_queue() {
        let config = Config::for_test("example", "test-pin");
        let state = AppState::try_new(&config, MockHsmBackend::new()).unwrap();

        // 1 session + 20 in the queue
        let permits: Vec<_> = std::iter::from_fn(|| state.try_admit()).collect();

        assert_eq!(permits.len(), 21);
    }

    #[test]
    fn a_place_is_free_again_when_the_permit_is_dropped() {
        let config = Config::for_test("example", "test-pin");
        let state = AppState::try_new(&config, MockHsmBackend::new()).unwrap();
        let permits: Vec<_> = std::iter::from_fn(|| state.try_admit()).collect();
        assert!(state.try_admit().is_none());

        drop(permits);

        assert!(state.try_admit().is_some());
    }
}
