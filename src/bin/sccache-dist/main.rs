#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN, scheduler as scheduler_config, server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, HeartbeatServerResult,
    InputsReader, JobAlloc, JobAuthorizer, JobComplete, JobId, JobState, RunJobResult,
    SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult, ServerId, ServerIncoming,
    ServerNonce, ServerOutgoing, SubmitToolchainResult, TcCache, Toolchain, ToolchainReader,
    UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, btree_map};
use std::env;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod token_check;

use cmdline::{AuthSubcommand, Command};

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    target_os = "freebsd"
)))]
fn main() {
    compile_error!("Distributed compilation is only support on Linux/x86_64 and FreeBSD!");
}

// Only supported on x86_64 Linux machines and on FreeBSD
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    target_os = "freebsd"
))]
fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match run(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId::new(server_addr)),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    exp: u64,
    server_id: ServerId,
}
fn create_jwt_server_token(
    server_id: ServerId,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    let key = jwt::EncodingKey::from_secret(key);
    jwt::encode(header, &ServerJwt { exp: 0, server_id }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_server_token(server_token: &str) -> Result<ServerId> {
    let validation = {
        let mut validation = jwt::Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.insecure_disable_signature_validation();
        validation
    };
    let dummy_key = jwt::DecodingKey::from_secret(b"secret");
    jwt::decode::<ServerJwt>(server_token, &dummy_key, &validation)
        .map(|res| res.claims.server_id)
        .map_err(Into::into)
}
fn check_jwt_server_token(
    server_token: &str,
    key: &[u8],
    validation: &jwt::Validation,
) -> Option<ServerId> {
    let key = jwt::DecodingKey::from_secret(key);
    jwt::decode::<ServerJwt>(server_token, &key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            public_addr,
            client_auth,
            server_auth,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
                    Box::new(token_check::ProxyTokenCheck::new(url, cache_secs))
                }
            };

            let check_server_auth: dist::http::ServerAuthCheck = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, token))
                }
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                }
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = BASE64_URL_SAFE_ENGINE
                        .decode(secret_key)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = {
                        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
                        validation.leeway = 0;
                        validation.validate_exp = false;
                        validation.validate_nbf = false;
                        validation
                    };
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &secret_key, &validation)
                    })
                }
            };

            daemonize()?;
            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
            );
            http_scheduler.start()?;
            unreachable!();
        }

        Command::Server(server_config::Config {
            builder,
            cache_dir,
            public_addr,
            bind_address,
            scheduler_url,
            scheduler_auth,
            toolchain_cache_size,
        }) => {
            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir)
                        .context("Overlay builder failed to start")?,
                ),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                ),
                _ => bail!(
                    "Builder type `{}` not supported on this platform",
                    format!("{:?}", builder)
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                ),
            };

            let server_id = ServerId::new(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let server = Server::new(builder, &cache_dir, toolchain_cache_size)
                .context("Failed to create sccache server instance")?;
            let http_server = dist::http::Server::new(
                public_addr,
                bind_address,
                scheduler_url.to_url(),
                scheduler_auth,
                server,
            )
            .context("Failed to create sccache HTTP server instance")?;
            http_server.start()?;
            unreachable!();
        }
    }
}

fn init_logging() {
    if env::var(sccache::LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(sccache::LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}

// Maximum number of jobs per core - only occurs for one core, usually less, see load_weight()
const MAX_PER_CORE_LOAD: f64 = 2f64;
const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    job_count: AtomicUsize,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,
}

struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    // Jobs assigned that haven't seen a state change. Can only be pending
    // or ready.
    jobs_unclaimed: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
    // Load metrics from the server
    load_metrics: Option<sccache::dist::http::ServerLoadMetrics>,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            servers: Mutex::new(HashMap::new()),
        }
    }

    fn prune_servers(
        &self,
        servers: &mut MutexGuard<HashMap<ServerId, ServerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (&server_id, details) in servers.iter_mut() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(server_id);
            }
        }

        for server_id in dead_servers {
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id.addr()
            );
            let server_details = servers
                .remove(&server_id)
                .expect("server went missing from map");
            for job_id in server_details.jobs_assigned {
                warn!(
                    "Non-terminated job {} was cleaned up in server pruning",
                    job_id
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
                }
            }
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

fn calculate_server_load(
    jobs_assigned: usize,
    num_cpus: usize,
    load_metrics: Option<&sccache::dist::http::ServerLoadMetrics>,
) -> f64 {
    // Base load: job count ratio
    let job_load = jobs_assigned as f64 / num_cpus as f64;

    // If we have real-time metrics, incorporate them
    if let Some(metrics) = load_metrics {
        // PSI pressure values should be 0-100 percentages
        // Clamp to valid range to handle out-of-range values
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

        // I/O pressure: while compilation itself does minimal I/O (only reads
        // preprocessed input and writes object output), high I/O pressure indicates
        // system stress (disk issues, extreme load) and should be factored in
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

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut servers = self.servers.lock().unwrap();

            let res = {
                let mut best = None;
                let mut best_err = None;
                let mut best_load: f64 = MAX_PER_CORE_LOAD;
                let now = Instant::now();
                for (&server_id, details) in servers.iter_mut() {
                    let load = calculate_server_load(
                        details.jobs_assigned.len(),
                        details.num_cpus,
                        details.load_metrics.as_ref(),
                    );

                    if let Some(last_error) = details.last_error {
                        if load < MAX_PER_CORE_LOAD {
                            if now.duration_since(last_error) > SERVER_REMEMBER_ERROR_TIMEOUT {
                                details.last_error = None;
                            }
                            match best_err {
                                Some((
                                    _,
                                    &mut ServerDetails {
                                        last_error: Some(best_last_err),
                                        ..
                                    },
                                )) => {
                                    if last_error < best_last_err {
                                        trace!(
                                            "Selected {:?}, its most recent error is {:?} ago",
                                            server_id,
                                            now - last_error
                                        );
                                        best_err = Some((server_id, details));
                                    }
                                }
                                _ => {
                                    trace!(
                                        "Selected {:?}, its most recent error is {:?} ago",
                                        server_id,
                                        now - last_error
                                    );
                                    best_err = Some((server_id, details));
                                }
                            }
                        }
                    } else if load < best_load {
                        best = Some((server_id, details));
                        trace!("Selected {:?} as the server with the best load ({:.2})", server_id, load);
                        best_load = load;
                        if load == 0f64 {
                            break;
                        }
                    }
                }

                // Assign the job to our best choice
                if let Some((server_id, server_details)) = best.or(best_err) {
                    let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
                    let job_id = JobId(job_count);
                    assert!(server_details.jobs_assigned.insert(job_id));
                    assert!(
                        server_details
                            .jobs_unclaimed
                            .insert(job_id, Instant::now())
                            .is_none()
                    );

                    info!(
                        "Job {} created and will be assigned to server {:?}",
                        job_id, server_id
                    );
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    Some((job_id, server_id, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    servers.len()
                );
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, tc, auth.clone())
            .with_context(|| {
                // LOCKS
                let mut servers = self.servers.lock().unwrap();
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_unclaimed.remove(&job_id);
                    if !entry.jobs_assigned.remove(&job_id) {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();

            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
            assert!(
                jobs.insert(job_id, JobDetail { server_id, state })
                    .is_none()
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        num_cpus: usize,
        job_authorizer: Box<dyn JobAuthorizer>,
        load_metrics: Option<sccache::dist::http::ServerLoadMetrics>,
    ) -> Result<HeartbeatServerResult> {
        if num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }

        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;
                details.load_metrics = load_metrics.clone();

                let mut stale_jobs = Vec::new();
                for (&job_id, &last_seen) in details.jobs_unclaimed.iter() {
                    if now.duration_since(last_seen) < UNCLAIMED_READY_TIMEOUT {
                        continue;
                    }
                    if let Some(detail) = jobs.get(&job_id) {
                        match detail.state {
                            JobState::Ready => {
                                stale_jobs.push(job_id);
                            }
                            JobState::Pending => {
                                if now.duration_since(last_seen) > UNCLAIMED_PENDING_TIMEOUT {
                                    stale_jobs.push(job_id);
                                }
                            }
                            state => {
                                warn!("Invalid unclaimed job state for {}: {}", job_id, state);
                            }
                        }
                    } else {
                        warn!("Unknown stale job {}", job_id);
                        stale_jobs.push(job_id);
                    }
                }

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );

                    for job_id in stale_jobs {
                        if !details.jobs_assigned.remove(&job_id) {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if details.jobs_unclaimed.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if jobs.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                    }
                }

                return Ok(HeartbeatServerResult { is_new: false });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.iter() {
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            server_id.addr(),
                            job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", server_id);
        if load_metrics.is_some() {
            debug!("Server {:?} has PSI metrics available", server_id);
        }
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_unclaimed: HashMap::new(),
                num_cpus,
                server_nonce,
                job_authorizer,
                load_metrics,
            },
        );
        Ok(HeartbeatServerResult { is_new: true })
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let now = Instant::now();
            let mut server_details = servers.get_mut(&server_id);
            if let Some(ref mut details) = server_details {
                details.last_seen = now;
            };

            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) => entry.get_mut().state = job_state,
                (JobState::Ready, JobState::Started) => {
                    if let Some(details) = server_details {
                        details.jobs_unclaimed.remove(&job_id);
                    } else {
                        warn!("Job state updated, but server is not known to scheduler")
                    }
                    entry.get_mut().state = job_state
                }
                (JobState::Started, JobState::Complete) => {
                    let (job_id, _) = entry.remove_entry();
                    if let Some(entry) = server_details {
                        assert!(entry.jobs_assigned.remove(&job_id))
                    } else {
                        bail!("Job was marked as finished, but server is not known to scheduler")
                    }
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            bail!("Unknown job")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers.values().map(|v| v.num_cpus).sum(),
            in_progress: jobs.len(),
        })
    }
}

pub struct Server {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    job_toolchains: Mutex<HashMap<JobId, Toolchain>>,
}

impl Server {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
    ) -> Result<Server> {
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Server {
            builder,
            cache: Mutex::new(cache),
            job_toolchains: Mutex::new(HashMap::new()),
        })
    }
}

impl ServerIncoming for Server {
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        assert!(
            self.job_toolchains
                .lock()
                .unwrap()
                .insert(job_id, tc)
                .is_none()
        );
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .context("Updating job state failed")?;
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self.job_toolchains.lock().unwrap().get(&job_id).cloned() {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        let mut cache = self.cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_toolchain(&tc) {
            return Ok(SubmitToolchainResult::Success);
        }
        Ok(cache
            .insert_with(&tc, |mut file| {
                io::copy(&mut { tc_rdr }, &mut file).map(|_| ())
            })
            .map(|_| SubmitToolchainResult::Success)
            .unwrap_or(SubmitToolchainResult::CannotCache))
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        requester
            .do_update_job_state(job_id, JobState::Started)
            .context("Updating job state failed")?;
        let tc = self.job_toolchains.lock().unwrap().remove(&job_id);
        let res = match tc {
            None => Ok(RunJobResult::JobNotFound),
            Some(tc) => {
                match self
                    .builder
                    .run_build(tc, command, outputs, inputs_rdr, &self.cache)
                {
                    Err(e) => Err(e.context("run build failed")),
                    Ok(res) => Ok(RunJobResult::Complete(JobComplete {
                        output: res.output,
                        outputs: res.outputs,
                    })),
                }
            }
        };
        requester
            .do_update_job_state(job_id, JobState::Complete)
            .context("Updating job state failed")?;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_load_metrics(cpu: f32, mem: f32, io: f32) -> sccache::dist::http::ServerLoadMetrics {
        sccache::dist::http::ServerLoadMetrics {
            cpu_pressure_avg10: cpu,
            memory_pressure_avg10: mem,
            io_pressure_avg10: io,
            load_average_1min: 0.0,
        }
    }

    #[test]
    fn test_calculate_server_load_no_metrics() {
        // Fallback to job-count-based calculation when no metrics available
        assert_eq!(calculate_server_load(0, 8, None), 0.0);
        assert_eq!(calculate_server_load(4, 8, None), 0.5);
        assert_eq!(calculate_server_load(8, 8, None), 1.0);

        // Test oversubscription threshold (cores + 1 + cores/8)
        // For 8 cores: 8 + 1 + 1 = 10
        assert_eq!(calculate_server_load(9, 8, None), 1.125);
        assert_eq!(calculate_server_load(10, 8, None), MAX_PER_CORE_LOAD + 1.0); // 3.0
        assert_eq!(calculate_server_load(20, 8, None), MAX_PER_CORE_LOAD + 1.0); // 3.0
    }

    #[test]
    fn test_calculate_server_load_zero_pressure() {
        // Zero pressure should give 1.0x multiplier (no penalty)
        let metrics = mock_load_metrics(0.0, 0.0, 0.0);
        assert_eq!(calculate_server_load(0, 8, Some(&metrics)), 0.0); // 0.0 * 1.0 * 1.0 * 1.0
        assert_eq!(calculate_server_load(4, 8, Some(&metrics)), 0.5); // 0.5 * 1.0 * 1.0 * 1.0
        assert_eq!(calculate_server_load(8, 8, Some(&metrics)), 1.0); // 1.0 * 1.0 * 1.0 * 1.0
    }

    #[test]
    fn test_calculate_server_load_cpu_pressure() {
        // CPU pressure: 0% = 1.0x, 50% = 2.0x, 100% = 3.0x
        let metrics_50 = mock_load_metrics(50.0, 0.0, 0.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics_50)), 1.0); // 0.5 * 2.0 = 1.0

        let metrics_100 = mock_load_metrics(100.0, 0.0, 0.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics_100)), 1.5); // 0.5 * 3.0 = 1.5
    }

    #[test]
    fn test_calculate_server_load_memory_pressure() {
        // Memory pressure: 0% = 1.0x, 50% = 2.0x, 100% = 3.0x (equal to CPU)
        let metrics_50 = mock_load_metrics(0.0, 50.0, 0.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics_50)), 1.0); // 0.5 * 2.0 = 1.0

        let metrics_100 = mock_load_metrics(0.0, 100.0, 0.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics_100)), 1.5); // 0.5 * 3.0 = 1.5
    }

    #[test]
    fn test_calculate_server_load_io_pressure() {
        // I/O pressure: 0% = 1.0x, 100% = 1.5x
        let metrics_100 = mock_load_metrics(0.0, 0.0, 100.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics_100)), 0.75); // 0.5 * 1.5 = 0.75
    }

    #[test]
    fn test_calculate_server_load_combined_pressure() {
        // Test combined pressure: 50% CPU, 50% memory, 100% I/O
        // cpu_factor = 1.0 + 50.0/50.0 = 2.0
        // mem_factor = 1.0 + 50.0/50.0 = 2.0
        // io_factor = 1.0 + 100.0/200.0 = 1.5
        // Total: 0.5 * 2.0 * 2.0 * 1.5 = 3.0
        let metrics = mock_load_metrics(50.0, 50.0, 100.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics)), 3.0);
    }

    #[test]
    fn test_calculate_server_load_extreme_pressure() {
        // Test 100% pressure on all metrics
        // cpu_factor = 1.0 + 100.0/50.0 = 3.0
        // mem_factor = 1.0 + 100.0/50.0 = 3.0
        // io_factor = 1.0 + 100.0/200.0 = 1.5
        // Total: 0.5 * 3.0 * 3.0 * 1.5 = 6.75 (capped at MAX_PER_CORE_LOAD + 1.0 = 3.0)
        let metrics = mock_load_metrics(100.0, 100.0, 100.0);
        assert_eq!(calculate_server_load(4, 8, Some(&metrics)), MAX_PER_CORE_LOAD + 1.0);
    }

    #[test]
    fn test_calculate_server_load_realistic_scenarios() {
        // Lightly loaded server: 10% CPU, 5% memory, 2% I/O
        let light = mock_load_metrics(10.0, 5.0, 2.0);
        let light_load = calculate_server_load(2, 8, Some(&light));
        assert!(light_load < 0.5); // Should be better than no metrics
        assert!(light_load > 0.25); // But not too much better

        // Moderately loaded server: 40% CPU, 30% memory, 20% I/O
        let moderate = mock_load_metrics(40.0, 30.0, 20.0);
        let moderate_load = calculate_server_load(4, 8, Some(&moderate));
        assert!(moderate_load > 0.5); // Should be worse than no pressure
        assert!(moderate_load < 2.0); // But not terrible

        // Heavily loaded server: 80% CPU, 90% memory, 50% I/O
        let heavy = mock_load_metrics(80.0, 90.0, 50.0);
        let heavy_load = calculate_server_load(6, 8, Some(&heavy));
        assert!(heavy_load > 2.0); // Should be significantly worse
    }

    #[test]
    fn test_calculate_server_load_mixed_server_capabilities() {
        // Test that scheduler correctly handles servers with and without PSI metrics

        // Server A: No PSI metrics (old server, non-Linux, or PSI not available)
        // 4 jobs on 8 cores = 0.5 load
        let server_a_load = calculate_server_load(4, 8, None);
        assert_eq!(server_a_load, 0.5);

        // Server B: Has PSI metrics with zero pressure
        // Same 4 jobs on 8 cores, but with PSI showing 0% pressure
        let metrics_zero = mock_load_metrics(0.0, 0.0, 0.0);
        let server_b_load = calculate_server_load(4, 8, Some(&metrics_zero));
        assert_eq!(server_b_load, 0.5); // Same as server A

        // Server C: Has PSI metrics showing moderate pressure
        // Same 4 jobs on 8 cores, but with 30% CPU and memory pressure
        let metrics_moderate = mock_load_metrics(30.0, 30.0, 0.0);
        let server_c_load = calculate_server_load(4, 8, Some(&metrics_moderate));
        // cpu_factor = 1.0 + 30/50 = 1.6
        // mem_factor = 1.0 + 30/50 = 1.6
        // io_factor = 1.0
        // load = 0.5 * 1.6 * 1.6 * 1.0 = 1.28
        assert!((server_c_load - 1.28).abs() < 0.001, "Expected ~1.28, got {}", server_c_load);

        // Verify server selection order: B (PSI zero) = A (no PSI) < C (PSI moderate)
        assert!(server_b_load == server_a_load);
        assert!(server_c_load > server_a_load);
        assert!(server_c_load > server_b_load);
    }

    #[test]
    fn test_calculate_server_load_psi_vs_no_psi_with_pressure() {
        // Scenario: Server with PSI showing heavy load vs server without PSI but fewer jobs

        // Server A: No PSI, 6 jobs on 8 cores
        let server_a_load = calculate_server_load(6, 8, None);
        assert_eq!(server_a_load, 0.75); // Simple ratio

        // Server B: Has PSI showing 80% CPU/memory pressure, but only 4 jobs on 8 cores
        let metrics_heavy = mock_load_metrics(80.0, 80.0, 0.0);
        let server_b_load = calculate_server_load(4, 8, Some(&metrics_heavy));
        // cpu_factor = 1.0 + 80/50 = 2.6
        // mem_factor = 1.0 + 80/50 = 2.6
        // io_factor = 1.0
        // load = 0.5 * 2.6 * 2.6 * 1.0 = 3.38 (capped at 3.0)
        assert_eq!(server_b_load, MAX_PER_CORE_LOAD + 1.0);

        // Even though server B has fewer jobs, it should be avoided due to high pressure
        assert!(server_b_load > server_a_load);
    }

    #[test]
    fn test_calculate_server_load_fallback_consistency() {
        // Verify that servers without PSI metrics use consistent fallback logic

        // Test various job counts with no metrics
        assert_eq!(calculate_server_load(0, 8, None), 0.0);
        assert_eq!(calculate_server_load(4, 8, None), 0.5);
        assert_eq!(calculate_server_load(8, 8, None), 1.0);

        // Test oversubscription threshold: 8 + 1 + 8/8 = 10
        assert_eq!(calculate_server_load(9, 8, None), 1.125);
        assert_eq!(calculate_server_load(10, 8, None), MAX_PER_CORE_LOAD + 1.0);

        // Test with different core counts
        // 16 cores: threshold = 16 + 1 + 16/8 = 19
        assert_eq!(calculate_server_load(18, 16, None), 1.125);
        assert_eq!(calculate_server_load(19, 16, None), MAX_PER_CORE_LOAD + 1.0);

        // 4 cores: threshold = 4 + 1 + 4/8 = 5
        assert_eq!(calculate_server_load(4, 4, None), 1.0);
        assert_eq!(calculate_server_load(5, 4, None), MAX_PER_CORE_LOAD + 1.0);
    }
}
