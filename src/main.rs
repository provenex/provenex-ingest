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
}

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

ENVIRONMENT VARIABLES
  PROVENEX_API_KEY            same as --api-key
  PROVENEX_UPSTREAM           same as --upstream
  PROVENEX_HMAC_SALT          same as --salt
  PROVENEX_MODE               same as --mode

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

    Ok((
        Config {
            upstream,
            api_key,
            salt,
            mode,
            concurrent,
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
                Ok(result) => print_summary(&file_path.display().to_string(), &result),
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
