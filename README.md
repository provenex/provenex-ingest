# provenex-ingest

The open-source customer-side ingestor for [Provenex](https://provenex.ai). A single binary, multiple modes — point it at your existing telemetry and it forwards to Provenex's verdict engine, optionally HMAC-hashing prompts and tool I/O locally so content never leaves your environment.

## Install

Three paths:

```bash
# Cargo (Rust toolchain)
cargo install --git https://github.com/provenex/provenex-ingest provenex-ingest

# Docker
docker pull ghcr.io/provenex/provenex-ingest:latest

# One-line shell installer (auto-detects OS+arch, verifies SHA-256)
curl -fsSL https://signup.provenex.ai/install | sh
```

Full install guide + verification: https://signup.provenex.ai/docs/install

## Usage

You'll need a trial API key — sign up free at https://provenex.ai (30-day trial, no credit card).

```bash
provenex-ingest <subcommand> [options]
```

### Subcommands

```bash
# One-shot: post a single OTLP/JSON file
provenex-ingest send my-trace.otlp.json --api-key pvx_trial_xxx

# Batch: post every *.otlp.json in a directory, in parallel
provenex-ingest batch ./historical/ --api-key pvx_trial_xxx --concurrent 8

# Watch: live-tail a directory; new files are sent as they appear
provenex-ingest watch ./live/ --api-key pvx_trial_xxx --interval 2

# Listen: run as an OTLP/HTTP receiver, forward to api.provenex.ai
provenex-ingest listen --bind 0.0.0.0:4318 --api-key pvx_trial_xxx
```

### Privacy-preserving hash mode

Add `--mode hash --salt <your-per-tenant-salt>` to any subcommand. The following OTLP attributes are HMAC-SHA-256 hashed locally **before** any bytes leave your environment:

- `gen_ai.input.messages` — prompts
- `gen_ai.output.messages` — assistant outputs
- `gen_ai.tool.call.arguments` and `.result` — tool I/O
- `gen_ai.system_instructions` — system prompts
- `enduser.id` / `user.id` / `gen_ai.user.id` — end-user identifiers

Resource URIs (`gen_ai.data_source.id`), tool/agent names, operation kinds, and span structure pass through unchanged — those drive Provenex's zone classification + topology reconstruction; they're not content.

Same content + same salt → same hash, so cross-source linking still works on the server side. Cross-tenant correlation is impossible because each tenant's salt is independent.

The HMAC salt is issued at trial signup; it lives in your environment, never on Provenex servers.

### Config (CLI flags + env vars)

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--api-key` | `PROVENEX_API_KEY` | (required) | Your trial Bearer token |
| `--upstream` | `PROVENEX_UPSTREAM` | `https://api.provenex.ai` | Where to forward |
| `--mode` | `PROVENEX_MODE` | `plain` | `plain` or `hash` |
| `--salt` | `PROVENEX_HMAC_SALT` | — | Required when `--mode hash` |
| `--concurrent` | — | 4 | Max parallel uploads (batch/watch) |

## What's in the binary (and what's not)

**Contains:**
- OTLP/JSON parsing
- HMAC-SHA-256 over content fields (when `--mode hash`)
- HTTPS forwarding via `reqwest`
- Directory scanning + polling
- An `axum` HTTP server for `listen` mode

**Does NOT contain:**
- Any Provenex zone classification rules
- The closure walker or archetype catalog (server-side)
- Any policy configuration
- Any customer-specific state (in-memory only; nothing persisted to disk)

The binary is a thin, auditable, content-redacting forwarder. A reverse-engineer reveals nothing proprietary — by design. The catch surface lives entirely on the server.

## Build from source

```bash
git clone https://github.com/provenex/provenex-ingest.git
cd provenex-ingest
cargo build --release
./target/release/provenex-ingest --help
```

Requires Rust 1.86+ (any recent stable). Install via [rustup](https://rustup.rs).

## Releases

Pre-built tarballs for darwin/linux × x86_64/aarch64 are published on the [Releases page](https://github.com/provenex/provenex-ingest/releases). Each artifact ships with a `.sha256` checksum for verification.

The shell installer at https://signup.provenex.ai/install detects your platform, downloads the right artifact, verifies the checksum, and installs to `~/.local/bin` (or `/usr/local/bin` for root). Source is at https://signup.provenex.ai/install — view it in a browser before piping to `sh`.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Security

Disclosures: security@provenex.ai. We acknowledge within 1 business day.

## Related repos

- [provenex/provenex-public](https://github.com/provenex/provenex-public) — sample telemetry bundle + customer-facing docs
- The Provenex verdict engine itself is hosted; the source is not public (it's the trial-product backend).
