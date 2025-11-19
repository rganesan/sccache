// Copyright 2025 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Persistent stats storage for sccache
//!
//! This module provides persistent storage for compilation statistics across
//! server restarts and multiple build instances. Currently supports Redis
//! via atomic increment operations.

#[cfg(feature = "redis-stats")]
pub mod redis;

use crate::errors::*;
use crate::server::ServerStats;
use async_trait::async_trait;
use std::sync::Arc;

/// Trait for persistent stats storage backends
#[async_trait]
pub trait StatsStorage: Send + Sync {
    /// Atomically increment stats counters by the given deltas.
    /// This is called periodically to flush local stats changes to the remote store.
    async fn increment_stats(&self, deltas: &ServerStats) -> Result<()>;

    /// Read the current global stats from the storage backend.
    /// Returns the aggregated stats from all instances.
    async fn get_stats(&self) -> Result<ServerStats>;

    /// Reset all stats to zero.
    /// This is called when the user runs `sccache --zero-stats`.
    async fn reset_stats(&self) -> Result<()>;
}

#[cfg(feature = "redis-stats")]
use crate::config::{CacheType, Config};

/// Initialize stats storage from configuration
///
/// Returns Some(stats_storage) if persist_stats is enabled for Redis cache,
/// None otherwise.
#[cfg(feature = "redis-stats")]
pub async fn stats_storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
) -> Result<Option<Arc<dyn StatsStorage>>> {
    if let Some(CacheType::Redis(redis_config)) = &config.cache {
        if redis_config.persist_stats {
            debug!("Initializing Redis stats persistence with key_prefix: {}", redis_config.key_prefix);

            // Build the Redis connection URL
            let redis_url = if let Some(ref endpoint) = redis_config.endpoint {
                // Use endpoint if provided
                let mut url = endpoint.clone();

                // Add authentication if provided
                if let (Some(username), Some(password)) = (&redis_config.username, &redis_config.password) {
                    // Parse and add auth to URL
                    if url.starts_with("redis://") {
                        url = format!("redis://{}:{}@{}", username, password, &url[8..]);
                    } else if url.starts_with("rediss://") {
                        url = format!("rediss://{}:{}@{}", username, password, &url[9..]);
                    }
                }

                // Add database number if not default
                if redis_config.db != 0 {
                    url = format!("{}/?db={}", url, redis_config.db);
                }

                url
            } else if let Some(ref url) = redis_config.url {
                // Fall back to deprecated 'url' field
                url.clone()
            } else {
                bail!("Redis persist_stats is enabled but no endpoint or url is configured");
            };

            // Create redis-client ConnectionManager
            let client = redis_client::Client::open(redis_url.as_str())
                .context("Failed to create Redis client for stats storage")?;

            let connection_manager = pool.block_on(async {
                redis_client::aio::ConnectionManager::new(client).await
            }).context("Failed to create Redis connection manager for stats storage")?;

            // Create RedisStatsStorage
            let stats_storage = redis::RedisStatsStorage::new(
                connection_manager,
                redis_config.key_prefix.clone(),
            ).await?;

            info!("Redis stats persistence enabled with key prefix: {}", redis_config.key_prefix);

            return Ok(Some(Arc::new(stats_storage)));
        }
    }

    Ok(None)
}

#[cfg(not(feature = "redis-stats"))]
pub async fn stats_storage_from_config(
    _config: &crate::config::Config,
    _pool: &tokio::runtime::Handle,
) -> Result<Option<Arc<dyn StatsStorage>>> {
    Ok(None)
}
