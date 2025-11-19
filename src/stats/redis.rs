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

//! Redis-based persistent stats storage

use crate::errors::*;
use crate::server::ServerStats;
use async_trait::async_trait;
use redis_client::aio::ConnectionManager;
use redis_client::{AsyncCommands, Pipeline};
use std::collections::HashMap;
use std::time::Duration;

use super::StatsStorage;

/// Redis-based stats storage using atomic operations
pub struct RedisStatsStorage {
    client: ConnectionManager,
    key_prefix: String,
}

impl RedisStatsStorage {
    /// Create a new Redis stats storage instance
    pub async fn new(client: ConnectionManager, key_prefix: String) -> Result<Self> {
        Ok(Self {
            client,
            key_prefix,
        })
    }

    /// Get the Redis hash key for stats
    fn stats_key(&self) -> String {
        format!("{}:stats", self.key_prefix)
    }

    /// Flatten PerLanguageCount into Redis hash field names
    fn flatten_language_counts(
        &self,
        prefix: &str,
        counts: &crate::server::PerLanguageCount,
    ) -> Vec<(String, i64)> {
        let mut fields = Vec::new();

        // Access the counts and adv_counts HashMaps
        for (lang, count) in counts.counts() {
            fields.push((format!("{}:{}", prefix, lang), *count as i64));
        }
        for (lang, count) in counts.adv_counts() {
            fields.push((format!("{}:adv:{}", prefix, lang), *count as i64));
        }

        fields
    }

    /// Flatten HashMap<String, usize> into Redis hash field names
    fn flatten_hashmap(&self, prefix: &str, map: &HashMap<String, usize>) -> Vec<(String, i64)> {
        map.iter()
            .map(|(key, count)| (format!("{}:{}", prefix, key), *count as i64))
            .collect()
    }
}

#[async_trait]
impl StatsStorage for RedisStatsStorage {
    async fn increment_stats(&self, deltas: &ServerStats) -> Result<()> {
        let key = self.stats_key();
        let mut conn = self.client.clone();

        // Build a pipeline for atomic batch updates
        let mut pipe = Pipeline::new();

        // Simple u64 counters
        if deltas.compile_requests > 0 {
            pipe.hincr(&key, "compile_requests", deltas.compile_requests as i64);
        }
        if deltas.requests_unsupported_compiler > 0 {
            pipe.hincr(&key, "requests_unsupported_compiler", deltas.requests_unsupported_compiler as i64);
        }
        if deltas.requests_not_compile > 0 {
            pipe.hincr(&key, "requests_not_compile", deltas.requests_not_compile as i64);
        }
        if deltas.requests_not_cacheable > 0 {
            pipe.hincr(&key, "requests_not_cacheable", deltas.requests_not_cacheable as i64);
        }
        if deltas.requests_executed > 0 {
            pipe.hincr(&key, "requests_executed", deltas.requests_executed as i64);
        }
        if deltas.cache_timeouts > 0 {
            pipe.hincr(&key, "cache_timeouts", deltas.cache_timeouts as i64);
        }
        if deltas.cache_read_errors > 0 {
            pipe.hincr(&key, "cache_read_errors", deltas.cache_read_errors as i64);
        }
        if deltas.non_cacheable_compilations > 0 {
            pipe.hincr(&key, "non_cacheable_compilations", deltas.non_cacheable_compilations as i64);
        }
        if deltas.forced_recaches > 0 {
            pipe.hincr(&key, "forced_recaches", deltas.forced_recaches as i64);
        }
        if deltas.cache_write_errors > 0 {
            pipe.hincr(&key, "cache_write_errors", deltas.cache_write_errors as i64);
        }
        if deltas.cache_writes > 0 {
            pipe.hincr(&key, "cache_writes", deltas.cache_writes as i64);
        }
        if deltas.compilations > 0 {
            pipe.hincr(&key, "compilations", deltas.compilations as i64);
        }
        if deltas.compile_fails > 0 {
            pipe.hincr(&key, "compile_fails", deltas.compile_fails as i64);
        }
        if deltas.dist_errors > 0 {
            pipe.hincr(&key, "dist_errors", deltas.dist_errors as i64);
        }

        // Duration fields (store as nanoseconds)
        let cache_write_nanos = deltas.cache_write_duration.as_nanos() as i64;
        if cache_write_nanos > 0 {
            pipe.hincr(&key, "cache_write_duration_ns", cache_write_nanos);
        }
        let cache_read_hit_nanos = deltas.cache_read_hit_duration.as_nanos() as i64;
        if cache_read_hit_nanos > 0 {
            pipe.hincr(&key, "cache_read_hit_duration_ns", cache_read_hit_nanos);
        }
        let compiler_write_nanos = deltas.compiler_write_duration.as_nanos() as i64;
        if compiler_write_nanos > 0 {
            pipe.hincr(&key, "compiler_write_duration_ns", compiler_write_nanos);
        }

        // PerLanguageCount fields
        for (field, value) in self.flatten_language_counts("cache_errors", &deltas.cache_errors) {
            if value > 0 {
                pipe.hincr(&key, field, value);
            }
        }
        for (field, value) in self.flatten_language_counts("cache_hits", &deltas.cache_hits) {
            if value > 0 {
                pipe.hincr(&key, field, value);
            }
        }
        for (field, value) in self.flatten_language_counts("cache_misses", &deltas.cache_misses) {
            if value > 0 {
                pipe.hincr(&key, field, value);
            }
        }

        // HashMap fields
        for (field, value) in self.flatten_hashmap("not_cached", &deltas.not_cached) {
            if value > 0 {
                pipe.hincr(&key, field, value);
            }
        }
        for (field, value) in self.flatten_hashmap("dist_compiles", &deltas.dist_compiles) {
            if value > 0 {
                pipe.hincr(&key, field, value);
            }
        }

        // Execute the pipeline atomically
        pipe.query_async::<()>(&mut conn)
            .await
            .context("Failed to increment stats in Redis")?;

        Ok(())
    }

    async fn get_stats(&self) -> Result<ServerStats> {
        let key = self.stats_key();
        let mut conn = self.client.clone();

        // Get all fields from the Redis hash
        let all_fields: HashMap<String, String> = conn
            .hgetall(&key)
            .await
            .context("Failed to get stats from Redis")?;

        // Parse simple u64 counters
        let parse_u64 = |field: &str| -> u64 {
            all_fields
                .get(field)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };

        // Parse Duration fields from nanoseconds
        let parse_duration = |field: &str| -> Duration {
            let nanos = all_fields
                .get(field)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            Duration::from_nanos(nanos)
        };

        // Parse PerLanguageCount from flattened fields
        let parse_language_count = |prefix: &str| -> crate::server::PerLanguageCount {
            let mut counts = HashMap::new();
            let mut adv_counts = HashMap::new();

            for (field, value) in &all_fields {
                if let Some(lang) = field.strip_prefix(&format!("{}:adv:", prefix)) {
                    if let Ok(count) = value.parse::<u64>() {
                        adv_counts.insert(lang.to_string(), count);
                    }
                } else if let Some(lang) = field.strip_prefix(&format!("{}:", prefix)) {
                    if let Ok(count) = value.parse::<u64>() {
                        counts.insert(lang.to_string(), count);
                    }
                }
            }

            crate::server::PerLanguageCount::new_with_counts(counts, adv_counts)
        };

        // Parse HashMap<String, usize> from flattened fields
        let parse_hashmap = |prefix: &str| -> HashMap<String, usize> {
            let mut map = HashMap::new();
            let prefix_with_colon = format!("{}:", prefix);

            for (field, value) in &all_fields {
                if let Some(key) = field.strip_prefix(&prefix_with_colon) {
                    if let Ok(count) = value.parse::<usize>() {
                        map.insert(key.to_string(), count);
                    }
                }
            }

            map
        };

        Ok(ServerStats {
            compile_requests: parse_u64("compile_requests"),
            requests_unsupported_compiler: parse_u64("requests_unsupported_compiler"),
            requests_not_compile: parse_u64("requests_not_compile"),
            requests_not_cacheable: parse_u64("requests_not_cacheable"),
            requests_executed: parse_u64("requests_executed"),
            cache_errors: parse_language_count("cache_errors"),
            cache_hits: parse_language_count("cache_hits"),
            cache_misses: parse_language_count("cache_misses"),
            cache_timeouts: parse_u64("cache_timeouts"),
            cache_read_errors: parse_u64("cache_read_errors"),
            non_cacheable_compilations: parse_u64("non_cacheable_compilations"),
            forced_recaches: parse_u64("forced_recaches"),
            cache_write_errors: parse_u64("cache_write_errors"),
            cache_writes: parse_u64("cache_writes"),
            cache_write_duration: parse_duration("cache_write_duration_ns"),
            cache_read_hit_duration: parse_duration("cache_read_hit_duration_ns"),
            compilations: parse_u64("compilations"),
            compiler_write_duration: parse_duration("compiler_write_duration_ns"),
            compile_fails: parse_u64("compile_fails"),
            not_cached: parse_hashmap("not_cached"),
            dist_compiles: parse_hashmap("dist_compiles"),
            dist_errors: parse_u64("dist_errors"),
        })
    }

    async fn reset_stats(&self) -> Result<()> {
        let key = self.stats_key();
        let mut conn = self.client.clone();

        // Delete the entire hash
        conn.del::<_, ()>(&key)
            .await
            .context("Failed to reset stats in Redis")?;

        Ok(())
    }
}
