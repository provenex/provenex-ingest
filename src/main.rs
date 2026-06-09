//! Provenex open-source customer-side ingestor.
//!
//! Single binary, multiple modes. Customers install this once (cargo,
//! Docker, or a prebuilt release binary) and then run whichever
//! subcommand matches their integration appetite:
//!
//!   provenex-ingest send <file.otlp.json>
//!     One-shot HTTP POST of a single OTLP/JSON file to the trial API.
//!     Equivalent to a curl command but with HMAC content-hashing,
//!     batching, and retry-on-failure built in.
//!
//!   provenex-ingest batch <dir/>
//!     Process every *.otlp.json file in a directory in parallel,
//!     report a summary. Good for replaying historical telemetry.
//!
//!   provenex-ingest watch <dir/>
//!     Same as batch but stays running and re-scans every N seconds
//!     for new files, posting them as they arrive. Drop new OTLP
//!     captures into the directory and they flow through automatically.
//!
//!   provenex-ingest listen [--bind addr:port]
//!     Run as an OTLP/HTTP receiver. The customer's OTel Collector
//!     posts to this, and we forward to the trial API after applying
//!     HMAC content-hashing if --mode=hash.
//!
//! Every subcommand respects the same config:
//!   --api-key <key>      (or PROVENEX_API_KEY env)
//!   --upstream <url>     (default https://api.provenex.ai)
//!   --mode plain|hash    (default plain; --mode hash requires --salt)
//!   --salt <salt>        (or PROVENEX_HMAC_SALT env — issued at signup)
//!   --concurrent <n>     max parallel uploads (default 4)
//!
//! In hash mode, gen_ai.input.messages / output.messages /
//! tool.call.arguments / tool.call.result / enduser.id are HMAC-SHA-256
//! hashed under the per-tenant salt before any bytes leave the customer
//! environment. Resource URIs, span structure, tool names, and
//! operation types pass through unchanged (they drive Provenex's zone
//! classification + topology reconstruction; they're not content).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

const CONTENT_FIELDS: &[&str] = &[
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.tool.call.arguments",
    "gen_ai.tool.call.result",
    "gen_ai.system_instructions",
];

const IDENTITY_FIELDS: &[&str] = &["enduser.id", "user.id", "gen_ai.user.id"];

#[derive(Debug, Clone, Copy)]
enum Mode {
    Plain,
    Hash,
}

struct Config {
    upstream: String,
    api_key: String,
    salt: String,
    mode: Mode,
    concurrent: usize,
    /// Optional path to write a self-contained HTML report after each
    /// verdict (`--report verdict.html`). One file per send/batch input;
    /// for batch the file name has a `-<source>` suffix appended.
    report: Option<String>,
    /// When true (default for trial keys), POST each verdict to the
    /// Provenex feedback endpoint so the team can see real-world catches
    /// in real time. Turn off with `--no-feedback`.
    feedback: bool,
    /// Feedback endpoint URL. Configurable for self-hosted Provenex
    /// deployments; default is the public signup Worker.
    feedback_url: String,
    /// Build version stamped on HTML reports + feedback envelopes.
    binary_version: &'static str,
}

const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_FEEDBACK_URL: &str = "https://signup.provenex.ai/verdict-feedback";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        print_usage();
        std::process::exit(0);
    }

    let subcommand = raw[0].clone();
    let rest = raw[1..].to_vec();

    match subcommand.as_str() {
        "send" => cmd_send(rest).await,
        "batch" => cmd_batch(rest).await,
        "watch" => cmd_watch(rest).await,
        "listen" | "proxy" => cmd_listen(rest).await,
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("error: unknown subcommand `{other}`\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    println!(
        "provenex-ingest — customer-side OTel-GenAI ingestor for Provenex.

USAGE
  provenex-ingest <subcommand> [options]

SUBCOMMANDS
  send <file.otlp.json>       One-shot upload of a single OTLP file.
  batch <dir/>                Upload every *.otlp.json in a directory in parallel.
  watch <dir/> [--interval N] Same as batch but stays running, re-scanning every N
                              seconds (default 5) for new files and posting them.
                              Already-processed files are tracked so re-runs are
                              idempotent.
  listen [--bind addr:port]   Run as an OTLP/HTTP receiver. Customer's OTel Collector
                              posts to <bind>, this forwards to the upstream API
                              after applying --mode=hash if configured.

COMMON OPTIONS (all subcommands)
  --upstream <url>            default https://api.provenex.ai
  --api-key <key>             your trial Bearer token (required)
  --mode plain|hash           default plain
  --salt <salt>               per-tenant HMAC salt (required for --mode=hash)
  --concurrent <n>            max parallel uploads (default 4)
  --report <path>             write a self-contained HTML report of the verdict
                              alongside the JSON. For batch, the file stem is
                              appended (e.g. `--report verdict.html` produces
                              `verdict-01_echoleak.html`).
  --no-feedback               opt out of sharing verdicts with Provenex (the
                              default for trial keys is opt-IN so the team can
                              see real-world catches; production keys are
                              opt-out by default and must use --feedback to
                              opt in).
  --feedback                  explicit opt-in (overrides --no-feedback /
                              PROVENEX_NO_FEEDBACK env).

ENVIRONMENT VARIABLES
  PROVENEX_API_KEY            same as --api-key
  PROVENEX_UPSTREAM           same as --upstream
  PROVENEX_HMAC_SALT          same as --salt
  PROVENEX_MODE               same as --mode
  PROVENEX_NO_FEEDBACK        same as --no-feedback (any non-empty truthy value)
  PROVENEX_FEEDBACK_URL       feedback endpoint override
                              (default https://signup.provenex.ai/verdict-feedback)

EXAMPLES
  provenex-ingest send my-trace.otlp.json --api-key pvx_trial_xxx
  provenex-ingest batch ./historical-traces/ --api-key pvx_trial_xxx --mode hash --salt sssss
  provenex-ingest watch ./live-captures/ --api-key pvx_trial_xxx --interval 2
  provenex-ingest listen --bind 0.0.0.0:4318 --api-key pvx_trial_xxx --mode hash --salt sssss

DOCS  https://provenex.ai/docs/onboarding"
    );
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

async fn cmd_send(args: Vec<String>) -> anyhow::Result<()> {
    let (cfg, positional) = parse_common(&args)?;
    let file = positional
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("send requires a file argument"))?;
    let bytes = tokio::fs::read(&file)
        .await
        .map_err(|e| anyhow::anyhow!("read {file}: {e}"))?;
    let client = build_http_client()?;
    let result = forward(&client, &cfg, bytes).await?;
    print_summary(&file, &result);
    if let Err(e) = handle_postprocessing(&client, &cfg, &file, &result, None).await {
        eprintln!("  (postprocessing: {e})");
    }
    Ok(())
}

async fn cmd_batch(args: Vec<String>) -> anyhow::Result<()> {
    let (cfg, positional) = parse_common(&args)?;
    let dir = positional
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("batch requires a directory argument"))?;
    let files = scan_otlp_files(Path::new(&dir)).await?;
    if files.is_empty() {
        eprintln!("no *.otlp.json files in {dir}");
        return Ok(());
    }
    println!("posting {} files from {dir} (mode={:?})", files.len(), cfg.mode);
    let client = build_http_client()?;
    process_files(client, Arc::new(cfg), files).await
}

async fn cmd_watch(args: Vec<String>) -> anyhow::Result<()> {
    let (cfg, mut positional) = parse_common(&args)?;
    let dir = positional
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("watch requires a directory argument"))?;
    positional.remove(0);

    // Parse --interval out of remaining positional (kept simple for the CLI).
    let mut interval_secs = 5u64;
    let mut iter = positional.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--interval" {
            interval_secs = iter
                .next()
                .ok_or_else(|| anyhow::anyhow!("--interval requires a value"))?
                .parse()
                .map_err(|e| anyhow::anyhow!("--interval: {e}"))?;
        }
    }

    println!(
        "watching {dir} every {interval_secs}s (mode={:?}); already-processed files are skipped.\nCtrl-C to stop.",
        cfg.mode
    );
    let client = build_http_client()?;
    let cfg = Arc::new(cfg);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    loop {
        let files = scan_otlp_files(Path::new(&dir)).await?;
        let fresh: Vec<PathBuf> = files
            .into_iter()
            .filter(|p| !seen.contains(p))
            .collect();
        if !fresh.is_empty() {
            for f in &fresh {
                seen.insert(f.clone());
            }
            println!("{} new file(s) detected, processing...", fresh.len());
            process_files(client.clone(), cfg.clone(), fresh).await?;
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

async fn cmd_listen(args: Vec<String>) -> anyhow::Result<()> {
    let (cfg, positional) = parse_common(&args)?;
    let mut bind = std::env::var("PROVENEX_INGEST_BIND").unwrap_or_else(|_| "0.0.0.0:4318".into());

    let mut iter = positional.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--bind" {
            bind = iter
                .next()
                .ok_or_else(|| anyhow::anyhow!("--bind requires a value"))?;
        }
    }

    let client = build_http_client()?;
    let state = Arc::new(ListenState {
        client,
        cfg: Arc::new(cfg),
    });
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/traces", post(receive))
        .route("/v1/receipts", post(receive))
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state.clone());

    println!("provenex-ingest listen mode");
    println!("  bind:     {bind}");
    println!("  mode:     {:?}", state.cfg.mode);
    println!("  upstream: {}", state.cfg.upstream);
    println!("  routes:   GET /healthz  POST /v1/traces  POST /v1/receipts");
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct ListenState {
    client: reqwest::Client,
    cfg: Arc<Config>,
}

async fn receive(
    State(state): State<Arc<ListenState>>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, String)> {
    let res = forward(&state.client, &state.cfg, body.to_vec())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("forward: {e}")))?;
    let parsed: Value = serde_json::from_str(&res.body).unwrap_or_else(|_| json!({ "raw": res.body }));
    Ok(Json(parsed))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_common(args: &[String]) -> anyhow::Result<(Config, Vec<String>)> {
    let mut upstream = std::env::var("PROVENEX_UPSTREAM")
        .unwrap_or_else(|_| "https://api.provenex.ai".into());
    let mut api_key = std::env::var("PROVENEX_API_KEY").unwrap_or_default();
    let mut salt = std::env::var("PROVENEX_HMAC_SALT").unwrap_or_default();
    let mut mode_str = std::env::var("PROVENEX_MODE")
        .unwrap_or_else(|_| "plain".into())
        .to_lowercase();
    let mut concurrent: usize = 4;
    let mut report: Option<String> = None;
    let mut no_feedback = std::env::var("PROVENEX_NO_FEEDBACK")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);
    let feedback_url = std::env::var("PROVENEX_FEEDBACK_URL")
        .unwrap_or_else(|_| DEFAULT_FEEDBACK_URL.to_string());

    let mut positional: Vec<String> = Vec::new();
    let mut iter = args.iter().cloned();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--upstream" => {
                upstream = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--upstream requires a value"))?
            }
            "--api-key" => {
                api_key = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--api-key requires a value"))?
            }
            "--salt" => {
                salt = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--salt requires a value"))?
            }
            "--mode" => {
                mode_str = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--mode requires plain|hash"))?
                    .to_lowercase()
            }
            "--concurrent" => {
                concurrent = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--concurrent requires a value"))?
                    .parse()
                    .map_err(|e| anyhow::anyhow!("--concurrent: {e}"))?;
            }
            "--report" => {
                report = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--report requires a path"))?,
                );
            }
            "--no-feedback" => {
                no_feedback = true;
            }
            "--feedback" => {
                // Explicit opt-in (overrides PROVENEX_NO_FEEDBACK env, useful
                // for a non-trial key that wants to share verdicts).
                no_feedback = false;
            }
            other => positional.push(other.to_string()),
        }
    }

    if api_key.is_empty() {
        anyhow::bail!("--api-key (or PROVENEX_API_KEY) is required");
    }
    let mode = match mode_str.as_str() {
        "plain" => Mode::Plain,
        "hash" => {
            if salt.is_empty() {
                anyhow::bail!("--mode=hash requires --salt (or PROVENEX_HMAC_SALT)");
            }
            Mode::Hash
        }
        other => anyhow::bail!("--mode `{other}` invalid (use plain or hash)"),
    };

    // Default-on for trial keys (pvx_trial_ prefix). Production keys must
    // opt in explicitly via --feedback (we don't ship paying customers'
    // verdicts back to us automatically).
    let is_trial_key = api_key.starts_with("pvx_trial_");
    let feedback = is_trial_key && !no_feedback;

    Ok((
        Config {
            upstream,
            api_key,
            salt,
            mode,
            concurrent,
            report,
            feedback,
            feedback_url,
            binary_version: BINARY_VERSION,
        },
        positional,
    ))
}

fn build_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|e| anyhow::anyhow!("http client: {e}"))
}

async fn scan_otlp_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut rd = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| anyhow::anyhow!("read_dir {}: {e}", dir.display()))?;
    while let Some(entry) = rd.next_entry().await.transpose() {
        let entry = entry.map_err(|e| anyhow::anyhow!("read_dir entry: {e}"))?;
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".otlp.json") || name.ends_with(".otlp.proto.json") {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

async fn process_files(
    client: reqwest::Client,
    cfg: Arc<Config>,
    files: Vec<PathBuf>,
) -> anyhow::Result<()> {
    let semaphore = Arc::new(Semaphore::new(cfg.concurrent.max(1)));
    let mut handles = Vec::new();

    for file in files {
        let semaphore = semaphore.clone();
        let client = client.clone();
        let cfg = cfg.clone();
        let file_path = file.clone();
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.expect("semaphore closed");
            let bytes = match tokio::fs::read(&file_path).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  ✗ {}: read error: {e}", file_path.display());
                    return;
                }
            };
            match forward(&client, &cfg, bytes).await {
                Ok(result) => {
                    let label = file_path.display().to_string();
                    print_summary(&label, &result);
                    if let Err(e) = handle_postprocessing(
                        &client,
                        &cfg,
                        &label,
                        &result,
                        file_path.file_stem().and_then(|s| s.to_str()),
                    )
                    .await
                    {
                        eprintln!("  (postprocessing for {label}: {e})");
                    }
                }
                Err(e) => eprintln!("  ✗ {}: {e}", file_path.display()),
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

struct ForwardResult {
    status: u16,
    body: String,
}

async fn forward(client: &reqwest::Client, cfg: &Config, body: Vec<u8>) -> anyhow::Result<ForwardResult> {
    let transformed = match cfg.mode {
        Mode::Plain => body,
        Mode::Hash => hash_otlp_body(&body, &cfg.salt)?,
    };
    let url = format!("{}/v1/receipts", cfg.upstream.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(header::AUTHORIZATION, format!("Bearer {}", cfg.api_key))
        .header(header::CONTENT_TYPE, "application/json")
        .body(transformed)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("send: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok(ForwardResult { status, body })
}

fn print_summary(label: &str, result: &ForwardResult) {
    let parsed: Value = serde_json::from_str(&result.body).unwrap_or_else(|_| json!({}));
    let red = parsed.get("red_verdicts").and_then(|v| v.as_u64()).unwrap_or(0);
    let egress = parsed
        .get("receipts_ingested")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let prefix = if result.status >= 200 && result.status < 300 {
        if red > 0 {
            "🔴"
        } else {
            "✓ "
        }
    } else {
        "✗ "
    };
    println!(
        "  {prefix} {label}  status={} egress={} red={}",
        result.status, egress, red
    );
    if red > 0 {
        if let Some(verdicts) = parsed.get("verdicts").and_then(|v| v.as_array()) {
            for v in verdicts.iter().take(3) {
                let binding = v
                    .get("binding_reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("(no binding)");
                let risk = v.get("risk").and_then(|x| x.as_str()).unwrap_or("?");
                println!("       • {binding} / {risk}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HMAC content-hashing — same shape as the original ingest-proxy
// ---------------------------------------------------------------------------

fn hmac_content(content: &str, salt: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC accepts any key length");
    mac.update(content.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn hash_otlp_body(body: &[u8], salt: &str) -> anyhow::Result<Vec<u8>> {
    let mut payload: Value = serde_json::from_slice(body)
        .map_err(|e| anyhow::anyhow!("parse OTLP JSON: {e}"))?;
    walk(&mut payload, salt);
    Ok(serde_json::to_vec(&payload)?)
}

fn walk(v: &mut Value, salt: &str) {
    match v {
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                walk(item, salt);
            }
        }
        Value::Object(map) => {
            transform_attributes(map, salt);
            for (_, child) in map.iter_mut() {
                walk(child, salt);
            }
        }
        _ => {}
    }
}

fn transform_attributes(obj: &mut Map<String, Value>, salt: &str) {
    let Some(key_val) = obj.get("key") else {
        return;
    };
    let Some(key) = key_val.as_str() else {
        return;
    };
    let redact = CONTENT_FIELDS.contains(&key) || IDENTITY_FIELDS.contains(&key);
    if !redact {
        return;
    }
    let Some(value) = obj.get_mut("value") else {
        return;
    };
    let Some(value_obj) = value.as_object_mut() else {
        return;
    };
    if let Some(s) = value_obj
        .get("stringValue")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        let hashed = hmac_content(&s, salt);
        value_obj.insert(
            "stringValue".into(),
            Value::String(format!("hmac-sha256:{hashed}")),
        );
    }
}

// ---------------------------------------------------------------------------
// Postprocessing: HTML report + verdict-feedback POST.
// ---------------------------------------------------------------------------

/// Called after each successful `forward()`. Writes an HTML report if
/// `--report` is set, and POSTs the verdict to the feedback endpoint if
/// `--feedback` (default-on for trial keys, opt-out via `--no-feedback`).
/// Errors are non-fatal: a failed report write or feedback POST should
/// not break the customer's pipeline.
async fn handle_postprocessing(
    client: &reqwest::Client,
    cfg: &Config,
    source_label: &str,
    result: &ForwardResult,
    file_stem: Option<&str>,
) -> anyhow::Result<()> {
    let verdict_json: Value =
        serde_json::from_str(&result.body).unwrap_or_else(|_| json!({ "raw": &result.body }));

    if let Some(report_path) = cfg.report.as_deref() {
        let path = derive_report_path(report_path, file_stem);
        let html = render_verdict_html(source_label, &verdict_json, cfg.binary_version);
        tokio::fs::write(&path, html)
            .await
            .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
        println!("  report written: {}", path.display());
    }

    if cfg.feedback {
        post_verdict_feedback(client, cfg, source_label, &verdict_json).await?;
    }

    Ok(())
}

/// If `--report verdict.html` is set and we're processing a single file,
/// write to that path verbatim. For batch runs, append the file stem so
/// `--report dir/verdict.html` becomes `dir/verdict-echoleak.html`,
/// `dir/verdict-curxecute.html`, etc.
fn derive_report_path(report_arg: &str, file_stem: Option<&str>) -> PathBuf {
    let p = Path::new(report_arg);
    match file_stem {
        None => p.to_path_buf(),
        Some(stem) => {
            let parent = p.parent().unwrap_or_else(|| Path::new("."));
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("html");
            let base = p.file_stem().and_then(|s| s.to_str()).unwrap_or("verdict");
            parent.join(format!("{base}-{stem}.{ext}"))
        }
    }
}

fn render_verdict_html(source_label: &str, verdict: &Value, version: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let red = verdict
        .get("red_verdicts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let receipts_ingested = verdict
        .get("receipts_ingested")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tenant = verdict
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    let verdicts = verdict
        .get("verdicts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let badge = if red > 0 { "RED" } else { "OK" };
    let badge_class = if red > 0 { "badge-red" } else { "badge-ok" };
    let headline = verdicts
        .first()
        .and_then(|v| v.get("binding_reason"))
        .and_then(|v| v.as_str())
        .unwrap_or(if red == 0 {
            "No red verdicts; closure walked clean."
        } else {
            "Cross-zone composition detected."
        });

    let mut verdict_cards = String::new();
    for (i, vd) in verdicts.iter().enumerate() {
        let binding = vd
            .get("binding_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("(unclassified)");
        let risk = vd.get("risk").and_then(|v| v.as_str()).unwrap_or("?");
        let key = vd
            .get("correlation_key")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let explanation = vd
            .get("explanation")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        verdict_cards.push_str(&format!(
            r#"<div class="card">
  <div class="card-header"><span class="binding">{binding}</span><span class="risk risk-{risk_lc}">{risk}</span><span class="idx">#{idx}</span></div>
  <p class="explanation">{explanation}</p>
  <p class="key">correlation: <code>{key}</code></p>
</div>
"#,
            binding = html_escape(binding),
            risk = html_escape(risk),
            risk_lc = risk.to_ascii_lowercase(),
            idx = i + 1,
            key = html_escape(key),
            explanation = html_escape(explanation),
        ));
    }

    let raw_pretty = serde_json::to_string_pretty(verdict).unwrap_or_else(|_| String::new());
    let raw_escaped = html_escape(&raw_pretty);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Provenex verdict — {headline_esc}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; color: #1f1f1f; line-height: 1.55; background: #fafafa; }}
  h1 {{ font-size: 1.7rem; margin: 0 0 .3rem; }}
  h2 {{ font-size: 1.1rem; margin: 2rem 0 .8rem; padding-bottom: .25rem; border-bottom: 1px solid #ddd; color: #444; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 700; font-size: 0.85rem; letter-spacing: .04em; margin-right: .5rem; }}
  .badge-red {{ background: #d83b3b; color: #fff; }}
  .badge-ok {{ background: #2c9c5e; color: #fff; }}
  .meta {{ color: #666; margin: .25rem 0 1.5rem; font-size: 0.9rem; }}
  .stats {{ display: flex; gap: 1.5rem; padding: 1rem 1.25rem; background: #fff; border: 1px solid #e5e5e5; border-radius: 8px; margin: 1.5rem 0; }}
  .stat {{ flex: 1; }}
  .stat-label {{ font-size: 0.85rem; color: #666; text-transform: uppercase; letter-spacing: .04em; }}
  .stat-value {{ font-size: 1.4rem; font-weight: 700; margin-top: 4px; }}
  .card {{ background: #fff; border: 1px solid #e5e5e5; border-left: 4px solid #d83b3b; border-radius: 6px; padding: 1rem 1.25rem; margin: .75rem 0; }}
  .card-header {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .4rem; }}
  .binding {{ font-weight: 700; font-family: ui-monospace, Menlo, monospace; font-size: 0.95rem; color: #d83b3b; }}
  .risk {{ font-size: 0.75rem; padding: 2px 8px; border-radius: 999px; font-weight: 700; text-transform: uppercase; }}
  .risk-high {{ background: #fee; color: #a00; }}
  .risk-medium {{ background: #fff5d6; color: #9a6800; }}
  .risk-low {{ background: #e6f4ea; color: #2c7a3f; }}
  .risk-unknown {{ background: #eee; color: #555; }}
  .idx {{ margin-left: auto; color: #888; font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; }}
  .explanation {{ margin: .35rem 0; }}
  .key {{ font-size: 0.85rem; color: #666; margin: .2rem 0 0; }}
  code {{ background: #f0f0f0; padding: 1px 5px; border-radius: 3px; font-size: 0.88em; }}
  pre {{ background: #1f1f1f; color: #e6e6e6; padding: 1rem 1.25rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; line-height: 1.45; }}
  details {{ margin: 1rem 0; }}
  details summary {{ cursor: pointer; color: #5560b4; font-weight: 500; padding: .5rem 0; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; color: #777; font-size: 0.9rem; }}
  footer a {{ color: #5560b4; }}
  .source-label {{ font-family: ui-monospace, Menlo, monospace; color: #444; font-size: 0.9rem; }}
</style>
</head>
<body>
<header>
  <span class="badge {badge_class}">{badge}</span>
  <h1>{headline_esc}</h1>
  <p class="meta">Source: <span class="source-label">{source_esc}</span></p>
</header>

<div class="stats">
  <div class="stat"><div class="stat-label">Egress points evaluated</div><div class="stat-value">{receipts_ingested}</div></div>
  <div class="stat"><div class="stat-label">Red verdicts</div><div class="stat-value">{red}</div></div>
  <div class="stat"><div class="stat-label">Tenant</div><div class="stat-value" style="font-family: ui-monospace, Menlo, monospace; font-size: 0.95rem; word-break: break-all;">{tenant_esc}</div></div>
</div>

<h2>Verdicts ({n_verdicts})</h2>
{verdict_cards}

<h2>Raw response</h2>
<details>
  <summary>Show raw verdict JSON</summary>
  <pre>{raw_escaped}</pre>
</details>

<footer>
  <p>Generated by <code>provenex-ingest v{version}</code> on {now}.</p>
  <p>Questions / feedback: <a href="mailto:skulk@provenex.ai">skulk@provenex.ai</a> · <a href="https://provenex.ai">provenex.ai</a></p>
  <p style="margin-top: 1rem; font-size: 0.85rem; color: #888;">
    Each verdict in the response carries an <code>ed25519</code>-signed artifact under the
    <code>trial-2026-06</code> key (retrievable via <code>/v1/verdicts</code>) so the closure
    is verifiable even after this HTML report is forwarded onward.
  </p>
</footer>
</body>
</html>
"#,
        headline_esc = html_escape(headline),
        source_esc = html_escape(source_label),
        tenant_esc = html_escape(tenant),
        n_verdicts = verdicts.len(),
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

async fn post_verdict_feedback(
    client: &reqwest::Client,
    cfg: &Config,
    source_label: &str,
    verdict: &Value,
) -> anyhow::Result<()> {
    // tenant_id is the only correlation identifier we send. The previous
    // `api_key_prefix` field was a stable per-tenant fingerprint that doubled
    // up with tenant_id; the team can join on tenant_id alone for the same
    // operational benefit without putting any of the secret on the wire.
    let envelope = json!({
        "tenant_id": verdict.get("tenant_id").cloned().unwrap_or(Value::Null),
        "source": source_label,
        "binary_version": cfg.binary_version,
        "verdict_response": verdict,
    });
    let resp = client
        .post(&cfg.feedback_url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&envelope)?)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("feedback POST: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("feedback POST returned {}", resp.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_same_content_same_salt_produces_same_hash() {
        let a = hmac_content("hello world", "salt-1");
        let b = hmac_content("hello world", "salt-1");
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_same_content_different_salt_produces_different_hash() {
        let a = hmac_content("hello world", "salt-1");
        let b = hmac_content("hello world", "salt-2");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_otlp_replaces_input_messages_but_keeps_resource_uri() {
        let payload = serde_json::json!({
            "resourceSpans": [{
                "scopeSpans": [{
                    "spans": [{
                        "attributes": [
                            { "key": "gen_ai.input.messages", "value": { "stringValue": "Hello assistant, please help me" } },
                            { "key": "gen_ai.data_source.id", "value": { "stringValue": "outlook://mailbox/inbox/external/promo" } },
                            { "key": "enduser.id",           "value": { "stringValue": "alice@acme.com" } },
                            { "key": "gen_ai.operation.name", "value": { "stringValue": "chat" } }
                        ]
                    }]
                }]
            }]
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let out = hash_otlp_body(&body, "the-salt").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("Hello assistant"));
        assert!(!s.contains("alice@acme.com"));
        assert!(s.contains("hmac-sha256:"));
        assert!(s.contains("outlook://mailbox/inbox/external/promo"));
        assert!(s.contains("gen_ai.operation.name"));
        assert!(s.contains("\"chat\""));
    }
}
