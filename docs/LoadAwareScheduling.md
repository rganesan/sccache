# Distributed Compilation Load-Aware Scheduling in sccache

## Architecture Overview

### Communication Flow

```
Client → Scheduler → Server
   ↓         ↓         ↓
1. alloc_job request
            ↓
2.       allocates to best server
                      ↓
3.                  heartbeat (periodic)
```

### Key Components

1. **Client** (`src/dist/http.rs` - client module)
   - Requests job allocation from scheduler
   - Submits toolchain and runs jobs on allocated server

2. **Scheduler** (`src/bin/sccache-dist/main.rs` - `Scheduler` struct)
   - Receives heartbeats from servers
   - Allocates jobs to servers based on load
   - Tracks server health and capacity

3. **Server** (`src/dist/http.rs` - server module)
   - Sends periodic heartbeats to scheduler
   - Executes compilation jobs
   - Reports job state changes

---

## Heartbeat Mechanism

### Server → Scheduler Heartbeat

**Location**: `src/dist/http.rs:935-976`

```rust
let heartbeat_req = HeartbeatServerHttpRequest {
    num_cpus: num_cpus(),  // <-- Currently only CPU count
    jwt_key: jwt_key.clone(),
    server_nonce,
    cert_digest,
    cert_pem: cert_pem.clone(),
};

// Sent periodically in background thread
thread::spawn(move || {
    loop {
        match bincode_req(
            client.post(heartbeat_url.clone())
                .bearer_auth(scheduler_auth.clone())
                .bincode(&heartbeat_req)?
        ) {
            Ok(HeartbeatServerResult { is_new }) => {
                thread::sleep(HEARTBEAT_INTERVAL)  // 30 seconds
            }
            Err(e) => {
                thread::sleep(HEARTBEAT_ERROR_INTERVAL)  // 10 seconds
            }
        }
    }
});
```

**Heartbeat Interval**: 30 seconds (`HEARTBEAT_INTERVAL`)
**Error Retry Interval**: 10 seconds (`HEARTBEAT_ERROR_INTERVAL`)

### Scheduler Heartbeat Handler

**Location**: `src/bin/sccache-dist/main.rs:574-681`

```rust
fn handle_heartbeat_server(
    &self,
    server_id: ServerId,
    server_nonce: ServerNonce,
    num_cpus: usize,  // <-- Only capacity metric currently
    job_authorizer: Box<dyn JobAuthorizer>,
) -> Result<HeartbeatServerResult>
```

**What happens**:
1. Validates `num_cpus > 0`
2. Updates or registers server in `servers: HashMap<ServerId, ServerDetails>`
3. Updates `last_seen` timestamp
4. Prunes stale servers
5. Clears unclaimed jobs after timeout

**ServerDetails Structure** (`src/bin/sccache-dist/main.rs:352-362`):
```rust
struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    jobs_unclaimed: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,  // <-- Currently the only load metric
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
}
```

---

## Job Allocation Logic

### Load Calculation

**Location**: `src/bin/sccache-dist/main.rs:420-432`

```rust
fn load_weight(job_count: usize, core_count: usize) -> f64 {
    // Oversubscribe cores just a little to make up for network and I/O latency
    let cores_plus_slack = core_count + 1 + core_count / 8;

    if job_count >= cores_plus_slack {
        MAX_PER_CORE_LOAD + 1f64  // 3.0 - no new jobs
    } else {
        job_count as f64 / core_count as f64  // Actual load ratio
    }
}
```

**Constants**:
- `MAX_PER_CORE_LOAD = 2.0` - Maximum jobs per core before server is excluded
- Slack formula: `cores + 1 + cores/8` (e.g., 8 cores → 10 slots, 64 cores → 73 slots)

### Server Selection Algorithm

**Location**: `src/bin/sccache-dist/main.rs:444-525`

```rust
// For each server, calculate load
for (&server_id, details) in servers.iter_mut() {
    let load = load_weight(details.jobs_assigned.len(), details.num_cpus);

    // Priority 1: Servers with recent errors (if under max load)
    if let Some(last_error) = details.last_error {
        if load < MAX_PER_CORE_LOAD {
            // Consider if error was long enough ago
            if now.duration_since(last_error) > SERVER_REMEMBER_ERROR_TIMEOUT {
                details.last_error = None;
            }
            // Select oldest error first (give them a chance to recover)
            best_err = Some((server_id, details));
        }
    }

    // Priority 2: Servers without errors, lowest load first
    if details.last_error.is_none() && load < best_load {
        best_load = load;
        best = Some((server_id, details));
    }
}

// Allocation priority:
// 1. Servers with old errors (recovery chance)
// 2. Servers with lowest load (< MAX_PER_CORE_LOAD)
```

**Selection Strategy**:
1. **Error recovery**: Give servers with past errors a chance if their load is acceptable
2. **Load balancing**: Prefer server with lowest `job_count / num_cpus` ratio
3. **Capacity limit**: Exclude servers at or above `MAX_PER_CORE_LOAD`

---

## Current Limitations

### Static Capacity Model
Currently, the scheduler only knows:
- **Static**: `num_cpus` (number of CPU cores)
- **Dynamic**: `jobs_assigned.len()` (number of active jobs)

**Missing**:
- Actual CPU utilization
- Memory pressure
- I/O wait time
- Network saturation
- Disk space
- **Real-time load metrics** (like PSI)

### No Real-Time Load Awareness
The scheduler assumes:
- All CPUs are equal
- All jobs consume similar resources
- Load = job_count / num_cpus

**Reality**:
- Some jobs are CPU-bound, others I/O-bound
- Background processes consume resources
- System load varies independently of job count

---

## Implementing Load-Aware Scheduling with Linux PSI

### Linux PSI (Pressure Stall Information)

PSI provides real-time resource pressure metrics:
- `/proc/pressure/cpu` - CPU contention
- `/proc/pressure/memory` - Memory pressure
- `/proc/pressure/io` - I/O wait pressure

**Format**:
```
some avg10=2.04 avg60=0.75 avg300=0.40 total=58761
full avg10=1.23 avg60=0.58 avg300=0.32 total=38431
```

- `some` - At least one task is stalled
- `full` - All non-idle tasks are stalled
- `avg10` - 10-second average (most relevant for scheduling)

### Proposed Implementation

#### Step 1: Add PSI Metrics to HeartbeatServerHttpRequest

**File**: `src/dist/http.rs:155-161`

```rust
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatServerHttpRequest {
    pub jwt_key: Vec<u8>,
    pub num_cpus: usize,
    pub server_nonce: dist::ServerNonce,
    pub cert_digest: Vec<u8>,
    pub cert_pem: Vec<u8>,

    // NEW: Add load metrics
    #[serde(default)]
    pub load_metrics: Option<ServerLoadMetrics>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerLoadMetrics {
    // PSI metrics (10-second averages, as percentages 0-100)
    pub cpu_pressure_avg10: f32,      // CPU contention
    pub memory_pressure_avg10: f32,   // Memory pressure
    pub io_pressure_avg10: f32,       // I/O wait

    // Additional metrics
    pub active_jobs: usize,            // Current job count
    pub load_average_1min: f32,        // System load average
    pub available_memory_mb: u64,      // Free memory in MB
}
```

#### Step 2: Create PSI Reader Module

**File**: `src/util.rs` (add new function)

```rust
#[cfg(target_os = "linux")]
pub fn read_psi_metrics() -> Result<(f32, f32, f32)> {
    use std::fs;

    fn parse_psi_avg10(path: &str) -> Result<f32> {
        let content = fs::read_to_string(path)?;
        // Parse "some avg10=2.04 avg60=..."
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("some ") {
                for part in rest.split_whitespace() {
                    if let Some(val) = part.strip_prefix("avg10=") {
                        return val.parse::<f32>()
                            .context("Failed to parse PSI avg10 value");
                    }
                }
            }
        }
        bail!("Could not find PSI avg10 value")
    }

    let cpu_pressure = parse_psi_avg10("/proc/pressure/cpu")
        .unwrap_or(0.0);  // Fallback if PSI not available
    let memory_pressure = parse_psi_avg10("/proc/pressure/memory")
        .unwrap_or(0.0);
    let io_pressure = parse_psi_avg10("/proc/pressure/io")
        .unwrap_or(0.0);

    Ok((cpu_pressure, memory_pressure, io_pressure))
}

#[cfg(not(target_os = "linux"))]
pub fn read_psi_metrics() -> Result<(f32, f32, f32)> {
    Ok((0.0, 0.0, 0.0))  // PSI only available on Linux
}
```

#### Step 3: Update Server to Send Load Metrics

**File**: `src/dist/http.rs:935-941`

```rust
// In Server::start()
let heartbeat_req = HeartbeatServerHttpRequest {
    num_cpus: num_cpus(),
    jwt_key: jwt_key.clone(),
    server_nonce,
    cert_digest,
    cert_pem: cert_pem.clone(),

    // NEW: Collect load metrics
    load_metrics: collect_load_metrics(),
};

fn collect_load_metrics() -> Option<ServerLoadMetrics> {
    use crate::util::{read_psi_metrics, read_load_average};

    let (cpu_pressure, memory_pressure, io_pressure) =
        read_psi_metrics().ok()?;

    let load_avg_1min = read_load_average().unwrap_or(0.0);
    let available_memory_mb = read_available_memory().unwrap_or(0);

    Some(ServerLoadMetrics {
        cpu_pressure_avg10: cpu_pressure,
        memory_pressure_avg10: memory_pressure,
        io_pressure_avg10: io_pressure,
        active_jobs: 0,  // Will be updated by scheduler
        load_average_1min: load_avg_1min,
        available_memory_mb,
    })
}
```

#### Step 4: Update Scheduler to Store Load Metrics

**File**: `src/bin/sccache-dist/main.rs:352-362`

```rust
struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    jobs_unclaimed: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,

    // NEW: Add load metrics
    load_metrics: Option<ServerLoadMetrics>,
}
```

**Update handler** (`src/bin/sccache-dist/main.rs:574-681`):

```rust
fn handle_heartbeat_server(
    &self,
    server_id: ServerId,
    server_nonce: ServerNonce,
    num_cpus: usize,
    job_authorizer: Box<dyn JobAuthorizer>,
    load_metrics: Option<ServerLoadMetrics>,  // NEW parameter
) -> Result<HeartbeatServerResult>
```

**Update HTTP handler** (`src/dist/http.rs:814-826`):

```rust
let HeartbeatServerHttpRequest {
    num_cpus,
    jwt_key,
    server_nonce,
    cert_digest,
    cert_pem,
    load_metrics,  // NEW: Extract load metrics
} = heartbeat_server;

let res: HeartbeatServerResult = try_or_500_log!(req_id,
    handler.handle_heartbeat_server(
        server_id,
        server_nonce,
        num_cpus,
        job_authorizer,
        load_metrics  // NEW: Pass to handler
    )
);
```

#### Step 5: Update Load Calculation Algorithm

**File**: `src/bin/sccache-dist/main.rs:420-432`

```rust
fn calculate_server_load(
    jobs_assigned: usize,
    num_cpus: usize,
    load_metrics: Option<&ServerLoadMetrics>,
) -> f64 {
    // Base load: job count ratio
    let job_load = job_count as f64 / num_cpus as f64;

    // If we have real-time metrics, incorporate them
    if let Some(metrics) = load_metrics {
        // PSI pressure values are 0-100 percentages
        // Clamp to valid range to handle malformed data (NaN, infinity, negative)
        let cpu_pressure = metrics.cpu_pressure_avg10.clamp(0.0, 100.0) as f64;
        let mem_pressure = metrics.memory_pressure_avg10.clamp(0.0, 100.0) as f64;
        let io_pressure = metrics.io_pressure_avg10.clamp(0.0, 100.0) as f64;

        // Weight them to influence scheduling decisions
        //
        // For distributed compilation:
        // - Client does preprocessing (reads headers locally)
        // - Server receives preprocessed output and just compiles
        // - Server I/O is minimal: read preprocessed input, write object file
        //
        // Therefore: CPU pressure = Memory pressure >> I/O pressure

        // CPU pressure: most critical - compilation is CPU-intensive
        // Scale: 0% = 1.0x, 50% = 2.0x, 100% = 3.0x multiplier (strong impact)
        let cpu_factor = 1.0 + (cpu_pressure / 50.0);

        // Memory pressure: equally critical - large compilations (e.g., heavy template instantiation)
        // are memory-intensive. Without swap, high memory pressure causes OOM kills affecting both
        // compile jobs and system stability
        // Scale: 0% = 1.0x, 50% = 2.0x, 100% = 3.0x multiplier (strong impact, same as CPU)
        let mem_factor = 1.0 + (mem_pressure / 50.0);

        // I/O pressure: while compilation itself does minimal I/O (only reads preprocessed input
        // and writes object output), high I/O pressure indicates system stress (disk issues, extreme load)
        // Scale: 0% = 1.0x, 100% = 1.5x multiplier (moderate impact)
        let io_factor = 1.0 + (io_pressure / 200.0);

        // Combined load score
        let pressure_load = job_load * cpu_factor * mem_factor * io_factor;

        // Cap at reasonable maximum
        pressure_load.min(MAX_PER_CORE_LOAD + 1.0)
    } else {
        // Fallback to simple job count if no metrics available
        let cores_plus_slack = num_cpus + 1 + num_cpus / 8;
        if jobs_assigned >= cores_plus_slack {
            MAX_PER_CORE_LOAD + 1.0
        } else {
            job_load
        }
    }
}
```

#### Step 6: Update Server Selection

**File**: `src/bin/sccache-dist/main.rs:444-525`

```rust
// In handle_alloc_job()
for (&server_id, details) in servers.iter_mut() {
    // NEW: Use load-aware calculation
    let load = calculate_server_load(
        details.jobs_assigned.len(),
        details.num_cpus,
        details.load_metrics.as_ref(),
    );

    // Rest of selection logic unchanged...
    if load < best_load {
        best_load = load;
        best = Some((server_id, details));
    }
}
```

---

## Benefits of Load-Aware Scheduling

### 1. **Avoid Overloaded Servers**
- Don't send jobs to servers already under pressure
- PSI detects real load, not just job count

### 2. **Better Resource Utilization**
- Distribute to servers with available capacity
- Account for non-compilation workloads

### 3. **Improved Compilation Times**
- Jobs run faster on less-loaded servers
- Avoid memory swapping and I/O contention

### 4. **Adaptive to Mixed Workloads**
- Handles both CPU-intensive and I/O-intensive jobs
- Accounts for background processes

### 5. **Graceful Degradation**
- Falls back to simple job-count logic if PSI unavailable
- Backward compatible with non-Linux servers

---

## Configuration Recommendations

### Pressure Thresholds

```toml
# In scheduler config
[scheduler]
# PSI avg10 thresholds for load calculation
max_cpu_pressure = 80.0      # Consider server loaded at 80% CPU pressure
max_memory_pressure = 50.0   # Memory pressure threshold
max_io_pressure = 75.0       # I/O pressure threshold

# Weight factors for load calculation
cpu_pressure_weight = 2.0    # CPU pressure has highest impact
memory_pressure_weight = 1.5
io_pressure_weight = 1.2
```

### Monitoring

Add metrics endpoint to see load distribution:
```rust
GET /api/v1/scheduler/server_loads

{
  "servers": [
    {
      "server_id": "192.168.1.10:10501",
      "num_cpus": 64,
      "jobs_assigned": 48,
      "job_load": 0.75,
      "cpu_pressure": 45.2,
      "memory_pressure": 12.3,
      "io_pressure": 8.7,
      "effective_load": 1.12,
      "accepting_jobs": true
    }
  ]
}
```

---

## Testing Strategy

1. **Unit Tests**
   - PSI parsing functions
   - Load calculation with various pressure values
   - Server selection with different load scenarios

2. **Integration Tests**
   - Multi-server setup with simulated load
   - Verify jobs go to least-loaded server
   - Test fallback when PSI unavailable

3. **Load Tests**
   - High job volume across multiple servers
   - Monitor job distribution and completion times
   - Compare vs. static job-count scheduling

---

## Migration Path

1. **Phase 1**: Add `load_metrics` as optional field (backward compatible)
2. **Phase 2**: Update servers to send PSI metrics
3. **Phase 3**: Update scheduler to use PSI in load calculation
4. **Phase 4**: Make load-aware scheduling the default
5. **Phase 5**: Add configuration options for tuning thresholds

This ensures zero downtime - old servers continue working while new ones benefit from load awareness.
