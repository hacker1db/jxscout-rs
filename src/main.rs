//! `jxscout-rs` command-line entry point.
//!
//! All real logic lives in the library crate (`jxscout`); this file only
//! parses flags, sets up logging, and dispatches subcommands.

use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use jxscout::config::{Config, DiscoveryConfig, FetchConfig, ForwardAuth};
use jxscout::events::{EventBus, LogLayer};
use jxscout::ingest::IngestSource as _;
use jxscout::ingest::har::HarSource;
use jxscout::ingest::server::{ServerConfig, ServerSource, check_bind_addr};
use jxscout::ingest::urls::UrlListSource;
use jxscout::rules::{self, Registry};
use jxscout::scope::Scope;
use jxscout::store::{Db, validate_project_name};
use jxscout::text::clean;
use jxscout::{Pipeline, tui};

#[derive(Parser, Debug)]
#[command(name = "jxscout-rs", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args, Debug, Clone)]
struct GlobalArgs {
    /// Root directory for all projects [default: ~/jxscout].
    #[arg(long, env = "JXSCOUT_OUTPUT_DIR", global = true)]
    output_dir: Option<PathBuf>,
    /// Project folder name (assets go to <output-dir>/<project>).
    #[arg(
        short,
        long,
        env = "JXSCOUT_PROJECT",
        default_value = "default",
        global = true
    )]
    project: String,
    /// Scope patterns, comma-separated; `*` wildcard, `!` prefix excludes.
    #[arg(short, long, value_delimiter = ',', global = true)]
    scope: Vec<String>,
    /// File with one scope pattern per line (`#` comments allowed).
    #[arg(long, global = true)]
    scope_file: Option<PathBuf>,
    /// Verbose logs (also shows why out-of-scope requests were dropped).
    #[arg(long, global = true)]
    debug: bool,

    /// Max concurrent fetches.
    #[arg(long, default_value_t = 5, global = true)]
    fetch_concurrency: usize,
    /// Max tool-initiated requests per second (0 = unlimited).
    #[arg(long, default_value_t = 2, global = true)]
    rate_limit_rps: u32,
    /// Max tool-initiated requests per minute (0 = unlimited).
    #[arg(long, default_value_t = 0, global = true)]
    rate_limit_rpm: u32,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30, global = true)]
    timeout_secs: u64,
    /// Max download size in MiB (decompressed).
    #[arg(long, default_value_t = 20, global = true)]
    max_download_mb: u64,
    /// Retries for transient fetch failures.
    #[arg(long, default_value_t = 2, global = true)]
    retries: u32,

    /// Forward captured auth headers to the exact same origin: same-origin | never.
    #[arg(long, default_value = "same-origin", global = true)]
    forward_auth: ForwardAuth,
    /// Header names to forward from captured requests.
    #[arg(long = "forward-header", default_values_t = ["cookie".to_string(), "authorization".to_string()], global = true)]
    forward_headers: Vec<String>,
    /// Extra `Name: value` header for every in-scope fetch (repeatable).
    #[arg(long = "header", value_parser = parse_header, global = true)]
    headers: Vec<(String, String)>,
    /// Allow fetching loopback/private/link-local addresses (off by default: SSRF guard).
    #[arg(long, global = true)]
    allow_private_targets: bool,
    /// Download JS from out-of-scope hosts when referenced by in-scope pages.
    #[arg(long, global = true)]
    download_referred_js: bool,

    /// Numeric chunk ids tried when no chunk table is found.
    #[arg(long, default_value_t = 3000, global = true)]
    bruteforce_limit: u32,
    /// Max chunk-discovery recursion depth.
    #[arg(long, default_value_t = 3, global = true)]
    max_depth: u32,
    /// Disable chunk discovery.
    #[arg(long, global = true)]
    no_chunks: bool,
    /// Disable source-map discovery.
    #[arg(long, global = true)]
    no_sourcemaps: bool,
    /// Disable AST analysis.
    #[arg(long, global = true)]
    no_analyze: bool,
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| format!("expected `Name: value`, got `{s}`"))?;
    let k = k.trim();
    if k.is_empty() {
        return Err("empty header name".into());
    }
    Ok((k.to_string(), v.trim().to_string()))
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the ingest endpoint and the TUI (default).
    Serve(ServeArgs),
    /// Fetch and process URLs from a file (or `-` for stdin), then exit.
    IngestUrls {
        /// File with one URL per line, or `-` for stdin.
        file: String,
        /// Print the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Import a HAR file, then exit.
    IngestHar {
        file: PathBuf,
        /// Print the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List saved assets.
    Assets {
        /// Only URLs containing this text.
        #[arg(long)]
        search: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Scripts loaded by an HTML page.
    Loads { page_url: String },
    /// Pages that loaded a script.
    Loaded { script_url: String },
    /// List AST findings.
    Findings {
        /// Only findings for this asset URL.
        #[arg(long)]
        asset: Option<String>,
        /// Category prefix, e.g. `Data/Secrets`.
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the built-in AST rules.
    Rules,
    /// Analyze a local JavaScript file (no network, no database).
    Analyze {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Delete all tracked data for the project from the database.
    Truncate {
        /// Required confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Address to listen on.
    #[arg(long, default_value = "localhost")]
    hostname: String,
    #[arg(long, default_value_t = 3333)]
    port: u16,
    /// Headless mode: logs to stderr, no TUI.
    #[arg(long)]
    no_tui: bool,
    /// Bearer token required on ingest requests. Default: a random token
    /// generated once and stored in <output-dir>/.jxscout-rs/ingest-token.
    #[arg(long, env = "JXSCOUT_INGEST_TOKEN")]
    ingest_token: Option<String>,
    /// Disable ingest authentication (any local process or web page that
    /// reaches the port can submit traffic).
    #[arg(long, conflicts_with = "ingest_token")]
    no_auth: bool,
    /// Allow listening on non-loopback addresses.
    #[arg(long)]
    allow_remote_ingest: bool,
}

impl Default for ServeArgs {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            port: 3333,
            no_tui: false,
            ingest_token: std::env::var("JXSCOUT_INGEST_TOKEN").ok(),
            no_auth: false,
            allow_remote_ingest: false,
        }
    }
}

fn build_config(g: &GlobalArgs) -> anyhow::Result<Config> {
    validate_project_name(&g.project).map_err(anyhow::Error::msg)?;
    let mut scope = Scope::from_patterns(&g.scope);
    if let Some(f) = &g.scope_file {
        scope.merge(
            Scope::from_file(f).with_context(|| format!("reading scope file {}", f.display()))?,
        );
    }
    Ok(Config {
        output_dir: g
            .output_dir
            .clone()
            .unwrap_or_else(Config::default_output_dir),
        project: g.project.clone(),
        scope,
        download_referred_js: g.download_referred_js,
        fetch: FetchConfig {
            concurrency: g.fetch_concurrency,
            max_rps: g.rate_limit_rps,
            max_rpm: g.rate_limit_rpm,
            timeout: Duration::from_secs(g.timeout_secs),
            max_body_bytes: g.max_download_mb * 1024 * 1024,
            retries: g.retries,
            forward_auth: g.forward_auth,
            forward_headers: g
                .forward_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            extra_headers: g.headers.clone(),
            allow_private_targets: g.allow_private_targets,
            ..FetchConfig::default()
        },
        discovery: DiscoveryConfig {
            bruteforce_limit: g.bruteforce_limit,
            max_depth: g.max_depth,
            chunks: !g.no_chunks,
            sourcemaps: !g.no_sourcemaps,
            analyze: !g.no_analyze,
            ..DiscoveryConfig::default()
        },
    })
}

/// Log destinations: always a file; plus stderr, or the TUI's event bus.
fn init_logging(
    cfg: &Config,
    debug: bool,
    to_stderr: bool,
    bus: Option<&EventBus>,
) -> anyhow::Result<PathBuf> {
    let dir = cfg.output_dir.join(".jxscout-rs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("jxscout.log");
    // Simple size cap: start fresh when the log passes 10 MiB.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 10 * 1024 * 1024) {
        let _ = std::fs::remove_file(&path);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let default = if debug {
        "jxscout=debug,jxscout_rs=debug,warn"
    } else {
        "jxscout=info,jxscout_rs=info,warn"
    };
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .with_filter(filter());
    let stderr_layer = to_stderr.then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(false)
            .compact()
            .with_filter(filter())
    });
    let bus_layer = bus.map(|b| LogLayer::new(b.clone()).with_filter(filter()));
    tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .with(bus_layer)
        .init();
    Ok(path)
}

fn print_stats(p: &Pipeline, json: bool) -> anyhow::Result<()> {
    let s = p.stats();
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
    } else {
        println!(
            "received {} · out of scope {} · saved {} · unchanged {} · findings {} · chunks {} · source maps {} · errors {}",
            s.received,
            s.out_of_scope,
            s.saved,
            s.unchanged,
            s.findings,
            s.chunks,
            s.sourcemaps,
            s.errors
        );
        println!("project dir: {}", p.store().root().display());
    }
    Ok(())
}

async fn resolve_listen(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}"))?
        .collect();
    // `localhost` often resolves to `::1` first; prefer IPv4 so clients
    // posting to 127.0.0.1 (the Caido plugin default, curl examples) connect.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .with_context(|| format!("{host} resolved to no address"))
}

async fn serve(cfg: Config, args: ServeArgs, debug: bool) -> anyhow::Result<()> {
    let use_tui = !args.no_tui && std::io::stdout().is_terminal();
    let bus = EventBus::default();
    let log_path = init_logging(&cfg, debug, !use_tui, use_tui.then_some(&bus))?;
    let addr = resolve_listen(&args.hostname, args.port).await?;
    check_bind_addr(&addr, args.allow_remote_ingest).map_err(anyhow::Error::msg)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    let local = listener.local_addr()?;

    let pipeline = Pipeline::new(cfg, bus)?;
    let shutdown = CancellationToken::new();
    let token = if args.no_auth {
        tracing::warn!("ingest authentication disabled (--no-auth)");
        None
    } else {
        Some(match args.ingest_token {
            Some(t) => t,
            None => load_or_create_token(&pipeline.config().output_dir)?,
        })
    };
    let server_config = if args.allow_remote_ingest {
        ServerConfig {
            token: token.clone(),
            allowed_hosts: None,
        }
    } else {
        ServerConfig::loopback(local, &args.hostname, token.clone())
    };
    let server = ServerSource {
        listener,
        config: server_config,
        shutdown: shutdown.clone(),
    };
    let server_task = tokio::spawn(server.run(pipeline.clone()));

    {
        let s = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            s.cancel();
        });
    }

    if use_tui {
        let header = tui::app::HeaderInfo {
            project: pipeline.config().project.clone(),
            project_dir: pipeline.store().root().display().to_string(),
            listen: Some(format!("http://{local}/ingest")),
            token: token.clone(),
        };
        tui::run(pipeline.clone(), header, shutdown.clone()).await?;
        shutdown.cancel();
    } else {
        tracing::info!(
            project_dir = %pipeline.store().root().display(),
            log = %log_path.display(),
            "jxscout-rs ready on http://{local}/ingest (Ctrl-C to stop)"
        );
        if let Some(t) = &token {
            eprintln!("ingest token: {t}  (send `Authorization: Bearer {t}`)");
        }
        shutdown.cancelled().await;
    }
    server_task.await??;
    // Give in-flight work a moment to finish writing.
    let _ = tokio::time::timeout(Duration::from_secs(2), pipeline.wait_idle()).await;
    Ok(())
}

/// Read the persisted ingest token, or create one (mode 0600 on Unix).
fn load_or_create_token(output_dir: &Path) -> anyhow::Result<String> {
    let path = output_dir.join(".jxscout-rs").join("ingest-token");
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = jxscout::ingest::server::generate_token();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    opts.open(&path)
        .and_then(|mut f| f.write_all(token.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(token)
}

fn open_db(cfg: &Config) -> anyhow::Result<Db> {
    let path = jxscout::pipeline::db_path(&cfg.output_dir, &cfg.project);
    if !path.exists() {
        bail!(
            "no database for project `{}` at {} (nothing ingested yet?)",
            cfg.project,
            path.display()
        );
    }
    Ok(Db::open(&path)?)
}

fn analyze_file(file: &Path, json: bool) -> anyhow::Result<()> {
    let src =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let pretty = jxscout::js::beautify(&src).unwrap_or_else(|e| {
        eprintln!("warning: parse error ({e}); analyzing as-is");
        src.clone()
    });
    let findings = rules::analyze_source(&pretty, &Registry::default())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        for f in &findings {
            println!(
                "{}:{}:{}  {}  {}",
                file.display(),
                f.line,
                f.column,
                clean(&f.category),
                clean(&f.value)
            );
        }
        eprintln!("{} finding(s)", findings.len());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = build_config(&cli.global)?;
    let debug = cli.global.debug;

    match cli
        .command
        .unwrap_or_else(|| Command::Serve(ServeArgs::default()))
    {
        Command::Serve(args) => serve(cfg, args, debug).await?,
        Command::IngestUrls { file, json } => {
            init_logging(&cfg, debug, true, None)?;
            let pipeline = Pipeline::new(cfg, EventBus::default())?;
            let report = if file == "-" {
                UrlListSource::new(tokio::io::stdin())
                    .run(pipeline.clone())
                    .await?
            } else {
                let f = tokio::fs::File::open(&file)
                    .await
                    .with_context(|| format!("opening {file}"))?;
                UrlListSource::new(f).run(pipeline.clone()).await?
            };
            tracing::info!(
                submitted = report.submitted,
                rejected = report.rejected,
                "url list read"
            );
            pipeline.wait_idle().await;
            print_stats(&pipeline, json)?;
        }
        Command::IngestHar { file, json } => {
            init_logging(&cfg, debug, true, None)?;
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let source = HarSource::parse(&text).context("parsing HAR")?;
            let pipeline = Pipeline::new(cfg, EventBus::default())?;
            let report = source.run(pipeline.clone()).await?;
            tracing::info!(
                submitted = report.submitted,
                rejected = report.rejected,
                "HAR read"
            );
            pipeline.wait_idle().await;
            print_stats(&pipeline, json)?;
        }
        Command::Assets {
            search,
            limit,
            json,
        } => {
            let rows = open_db(&cfg)?.assets(search.as_deref(), limit, 0)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for r in rows {
                    println!(
                        "{:<6} {}  →  {}",
                        r.kind.as_str(),
                        clean(&r.url),
                        clean(&r.path)
                    );
                }
            }
        }
        Command::Loads { page_url } => {
            for s in open_db(&cfg)?.scripts_of(&page_url)? {
                println!("{}", clean(&s));
            }
        }
        Command::Loaded { script_url } => {
            for p in open_db(&cfg)?.pages_of(&script_url)? {
                println!("{}", clean(&p));
            }
        }
        Command::Findings {
            asset,
            category,
            json,
        } => {
            let rows = open_db(&cfg)?.findings(asset.as_deref(), category.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for f in &rows {
                    println!(
                        "{}:{}:{}  {}  {}",
                        clean(&f.asset_url),
                        f.line,
                        f.column,
                        clean(&f.category),
                        clean(&f.value)
                    );
                }
                eprintln!("{} finding(s)", rows.len());
            }
        }
        Command::Rules => {
            for r in Registry::default().rules() {
                println!("{:<10} {}", r.id(), r.description());
            }
        }
        Command::Analyze { file, json } => analyze_file(&file, json)?,
        Command::Truncate { yes } => {
            if !yes {
                bail!(
                    "this deletes all tracked data for project `{}`; re-run with --yes",
                    cfg.project
                );
            }
            open_db(&cfg)?.truncate()?;
            println!("truncated project `{}`", cfg.project);
        }
    }
    Ok(())
}
