//! Rate limiting for the webhook handler.
//!
//! Implements a simple in-memory rate limiter using a sliding window algorithm.
//! Rate limiting is applied per source IP address to prevent abuse.
//!
//! # Configuration
//!
//! - `max_requests`: Maximum number of requests allowed in the window
//! - `window_secs`: Size of the sliding window in seconds
//!
//! # Thread Safety
//!
//! The rate limiter is thread-safe using `RwLock` for the internal state.
//! This is required because axum handlers may run concurrently.
//!
//! # Invariant
//!
//! - [INV-WH002] Rate limiter state is thread-safe.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

use super::error::WebhookError;

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the window.
    pub max_requests: u32,

    /// Size of the sliding window in seconds.
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Allow 60 requests per minute by default (reasonable for CI webhooks)
            max_requests: 60,
            window_secs: 60,
        }
    }
}

/// An in-memory rate limiter using a sliding window algorithm.
///
/// The rate limiter tracks request timestamps per IP address and rejects
/// requests that exceed the configured limit within the time window.
pub struct RateLimiter {
    config: RateLimitConfig,
    // Maps IP addresses to a list of request timestamps
    state: RwLock<HashMap<IpAddr, Vec<Instant>>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if a request from the given IP should be allowed.
    ///
    /// If allowed, records the request and returns `Ok(())`.
    /// If rate limited, returns `Err(WebhookError::RateLimitExceeded)`.
    ///
    /// # Arguments
    ///
    /// * `ip` - The source IP address of the request
    ///
    /// # Errors
    ///
    /// Returns `WebhookError::RateLimitExceeded` if the request would exceed
    /// the rate limit.
    pub fn check(&self, ip: IpAddr) -> Result<(), WebhookError> {
        let now = Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_secs);
        let cutoff = now.checked_sub(window_duration).unwrap_or(now);

        // First, try to read and check without write lock
        {
            let state = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(timestamps) = state.get(&ip) {
                let recent_count = timestamps.iter().filter(|&&t| t > cutoff).count();
                if recent_count >= self.config.max_requests as usize {
                    tracing::warn!(
                        ip = %ip,
                        requests = recent_count,
                        max = self.config.max_requests,
                        "rate limit exceeded"
                    );
                    return Err(WebhookError::RateLimitExceeded);
                }
            }
        }

        // If we get here, we need to record the request
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let timestamps = state.entry(ip).or_default();

        // Remove old timestamps outside the window
        timestamps.retain(|&t| t > cutoff);

        // Check again after cleanup (race condition protection)
        if timestamps.len() >= self.config.max_requests as usize {
            tracing::warn!(
                ip = %ip,
                requests = timestamps.len(),
                max = self.config.max_requests,
                "rate limit exceeded"
            );
            return Err(WebhookError::RateLimitExceeded);
        }

        // Record this request
        timestamps.push(now);

        Ok(())
    }

    /// Cleans up old entries from the rate limiter state.
    ///
    /// This should be called periodically to prevent memory growth.
    /// It removes all IP addresses that have no recent requests.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_secs);
        let cutoff = now.checked_sub(window_duration).unwrap_or(now);

        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Remove entries with no recent timestamps
        state.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }

    /// Returns the number of tracked IP addresses.
    ///
    /// Useful for monitoring and debugging.
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn another_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
    }

    #[test]
    fn test_allows_requests_within_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            window_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn test_rejects_when_limit_exceeded() {
        let config = RateLimitConfig {
            max_requests: 3,
            window_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Allow first 3 requests
        for _ in 0..3 {
            assert!(limiter.check(ip).is_ok());
        }

        // 4th request should be rejected
        let result = limiter.check(ip);
        assert!(matches!(result, Err(WebhookError::RateLimitExceeded)));
    }

    #[test]
    fn test_different_ips_tracked_separately() {
        let config = RateLimitConfig {
            max_requests: 2,
            window_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip1 = test_ip();
        let ip2 = another_ip();

        // IP1 uses 2 requests
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(matches!(
            limiter.check(ip1),
            Err(WebhookError::RateLimitExceeded)
        ));

        // IP2 should still have its own quota
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip2).is_ok());
        assert!(matches!(
            limiter.check(ip2),
            Err(WebhookError::RateLimitExceeded)
        ));
    }

    #[test]
    fn test_window_expiration() {
        let config = RateLimitConfig {
            max_requests: 2,
            // Use a very short window for testing
            window_secs: 1,
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Use up the quota
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(matches!(
            limiter.check(ip),
            Err(WebhookError::RateLimitExceeded)
        ));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let config = RateLimitConfig {
            max_requests: 10,
            window_secs: 1,
        };
        let limiter = RateLimiter::new(config);

        // Add entries for multiple IPs
        for i in 0..5 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
            limiter.check(ip).unwrap();
        }

        assert_eq!(limiter.tracked_ips(), 5);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Cleanup should remove all entries
        limiter.cleanup();
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 60);
        assert_eq!(config.window_secs, 60);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let config = RateLimitConfig {
            max_requests: 100,
            window_secs: 60,
        };
        let limiter = Arc::new(RateLimiter::new(config));
        let ip = test_ip();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    for _ in 0..10 {
                        let _ = limiter.check(ip);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // After 100 requests (10 threads * 10 requests), we should be at limit
        // Next request should be rejected
        assert!(matches!(
            limiter.check(ip),
            Err(WebhookError::RateLimitExceeded)
        ));
    }
}
