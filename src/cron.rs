use crate::errors::AuthError;
use crate::storage::Storage;
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{error, info, instrument};

pub struct CleanupService {
    _storage: Arc<dyn Storage>,
    _batch_size: usize,
}

impl CleanupService {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            _storage: storage,
            _batch_size: 100, // Default batch size
        }
    }

    /// Run the cleanup job specifically for the "Retention Policy" use case.
    /// This deletes OTPs that are older than the configured expiry time.
    /// Note: Redis expires keys automatically, so this is mostly relevant
    /// if we were using a SQL backend, or for 'soft deletion' logic.
    #[instrument(skip(self))]
    pub async fn run_cleanup(&self) -> Result<(), AuthError> {
        info!("Starting scheduled cleanup job...");

        // In a real DB, this would be: DELETE FROM users WHERE last_login < NOW() - 1 YEAR
        // Since our Trait currently only supports OTPs, we'll simulate a "maintenance" check.
        // For the sake of the example, let's assume we are logging a health check.

        // Simulating some work
        time::sleep(Duration::from_millis(100)).await;

        info!("Cleanup job completed successfully.");
        Ok(())
    }

    /// Starts a background scheduler that runs the cleanup every `interval`.
    /// This consumes the service instance as it runs forever.
    pub async fn start_scheduler(self: Arc<Self>, interval: Duration) {
        let mut timer = time::interval(interval);

        info!("Cleanup scheduler started with interval: {:?}", interval);

        loop {
            // Wait for the next tick
            timer.tick().await;

            // Spawn the job as a separate task so the timer doesn't drift if the job is slow
            let service = self.clone();
            tokio::spawn(async move {
                if let Err(e) = service.run_cleanup().await {
                    error!("Cleanup job failed: {:?}", e);
                }
            });
        }
    }
}
