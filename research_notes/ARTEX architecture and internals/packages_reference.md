# ARTEX Package-by-Package Reference

## What does each package do?

### Takeaway

ARTEX is an autonomous penetration-testing platform built on the `norma` agent harness. It has a three-agent architecture (MainAgent, Planner, Worker) orchestrated by a central server, with PostgreSQL persistence, an HTTP recording proxy, configurable tool-call interception, LLM failover, and a full web UI served over a JSON HTTP API. The packages divide into agent logic, safety/policy enforcement, traffic capture, data persistence, notification, and configuration layers.

### Cited Findings

Below is a package-by-package breakdown sourced directly from the codebase.

---

## agent/

### Takeaway

The `agent` package contains the three LLM agent roles (MainAgent, Planner, Worker) that drive autonomous penetration testing, plus all their tools, prompt management, session handling, and supporting infrastructure.

### Key Types and Responsibilities

- **`MainAgent`** (`mainagent.go`) -- The human-interface orchestrator. The human chats with it; it observes via read tools and steers by injecting hints (to the planner) or direct high-priority intents (to the frontier). It does NOT run the autonomous intent-generation loop. Key fields: `findingRecorder`, `prov` (LLM provider), `model`, `tx` (transcript store), `window` (context window for compaction), `proxyAddr`/`proxyCACert` (recording proxy), `webSearch`, `steerWork` callback.

- **`Planner`** (`planner.go`) -- The event-driven LLM planner. Each time the asset/exploration graph changes, it reads the exploration route, queries assets, judges whether the task goal is met, and emits 0..N exploration intents into the frontier. It is the sole intent generator. Maintains a per-task TODO scratchpad (`todos`) for multi-step plan persistence across wake-ups.

- **`Worker`** (`worker.go`) -- Claims ONE intent, completes it with real tools (Bash/Kali tooling through the recording proxy), writes FACTS back into the graph, and stops. Does NOT generate new directions. Multiple workers run concurrently as goroutines.

- **`ChatAgent`** (`chat.go`) -- The conversational runner for the chat page (independent conversations, not tied to a task).

- **`Config`** / `FromEnv()` (`provider.go`) -- LLM provider configuration (API key, endpoint, model, format: "anthropic" or "openai").

- **`WebSearchOpts`** (`worker.go`) -- Web-search backend selection (ddgs, brave-free, tavily, deepseek).

- **`FindingRecorder`** (`finding_recorder.go`) -- Interface for recording vulnerability findings from agent output.

- **Tool files**: `tools.go`, `toolcatalog.go`, `toolrag.go`, `filetools.go`, `webfetch.go`, `scan_ingest.go`, `bbot_ingest.go` -- Define and register the tools available to agents (Bash, file operations, web fetch, scan ingestion, etc.).

- **`Compactor`** / `coldgraph.go` -- Cold-node compaction for large exploration graphs.

- **Prompt management**: `prompt.go`, `promptcatalog.go` -- Built-in and DB-stored prompt templates with template variable rendering.

### Dependencies

Imports: `db`, `intercept`, `egress`, and the external `norma` agent harness (`agentcore`, `harness`, `llm`, `permission`, `tool`, `transcript`).

---

## server/

### Takeaway

The `server` package is the central HTTP backend: it exposes the entire ARTEX JSON API for the shadcn/ui frontend, orchestrates the task engine, manages LLM providers and failover pools, coordinates trigger scheduling, archiving, and notification delivery. It is the heaviest package and depends on nearly every other internal package.

### Key Types and Responsibilities

- **`Server`** (`server.go`) -- Main struct; holds the Manager, Engine, JWT auth, LLM provider caches, trigger queues, chat agents, archive workers, side-question state. Created via `New()`.

- **`Manager`** (`manager.go`) -- Lower-level runtime: holds the PostgreSQL DB, Traffic proxy, ExplorationStore references, assets, and the task lifecycle. The Server wraps a Manager.

- **`Task`** (`manager.go`) -- One engagement: description + goal + its own exploration store, guard, target guard, lifecycle state (paused/queued/running/done/failed/timeout). Has per-task LLM profile binding and failover state.

- **`Engine`** (`engine.go`) -- Coordinates the planner/worker loop for active tasks: scheduling, budget management, intent claiming, deadlines.

### HTTP API Endpoints (grouped by domain)

The server registers ~170+ routes on a `net/http` ServeMux. Major groups:

| Group | Routes | Purpose |
|---|---|---|
| **Auth** | `/api/auth/{status,init,login,change-password}` | JWT authentication |
| **Health/Stats** | `/api/health`, `/api/ready`, `/api/stats`, `/api/logs{,/history,/stream}` | Operational status, log streaming |
| **Tasks** | `/api/tasks`, `/api/tasks/{id}`, `/api/tasks/{id}/control`, etc. | CRUD, lifecycle control (start/stop/pause), scope, goals, constraints, credentials, coverage, assets, intents, archiving |
| **Task Archives** | `/api/task-archives{,/{id},/{id}/restore}` | Cold-storage archival and restoration |
| **Task Templates/Categories** | `/api/task-templates`, `/api/task-categories` | Reusable task templates and organizational categories |
| **Exploration** | `/api/exploration/{frontier,findings,intents,graph,nodes,activity,tokens}` | The core pentest findings, intents, graph, activity stream, token usage |
| **Findings** | `/api/exploration/findings/{id}{,/deepen,/retests,/lineage}` | Individual finding management, retesting, deepening |
| **Traffic** | `/api/traffic{,/hosts,/exchange,/stream,/blob,/ingest,/replay,/import/har,/export/har}` | Recorded HTTP traffic browsing, replay, HAR import/export |
| **Traffic Rewrite** | `/api/traffic/rewrite-rules` | CRUD for traffic rewrite rules |
| **Traffic Hooks (Tamper)** | `/api/traffic/hooks` | Programmable traffic modification hooks |
| **Intercept** | `/api/intercept/{rules,pending,history,tool-config,judge}` | Tool-call interception rules, pending approvals, decision history |
| **Target Gate** | `/api/target-gate/exemptions{,/history}` | Target-scope approval gate exemptions |
| **Asset Intercept** | `/api/asset-intercept/rules` | Asset-level interception rules |
| **Assets** | `/api/assets{,/counts}` | Global asset inventory |
| **Companies** | `/api/companies{,/{id},/{id}/scope}` | Company/organization management and scope attribution |
| **LLM** | `/api/llm{,/test,/records,/context/summary,/profiles,/retry-policy,/pool,/models}` | LLM provider config, testing, usage records, profiles, failover pool status |
| **Settings** | `/api/settings{,/noise,/web-search/test}` | App settings including noise profile |
| **Notifications** | `/api/notify/{meta,channels,deliveries}` | IM/email push channel config and delivery history |
| **Chat** | `/api/chat{,/upload,/mentions}`, `/api/conversations` | Conversational chat (task-bound and standalone conversations) |
| **Agents** | `/api/agents{,/{key},/{key}/config,/{key}/prompt,/{key}/triggers,/{key}/visibility}` | Custom agent CRUD, prompt versioning, trigger management |
| **Tools** | `/api/tools{,/custom}` | Tool registry, custom HTTP tools |
| **MCP** | `/api/mcp{,/{id}/tools,/{id}/refresh}` | MCP server registration and tool discovery |
| **Skills** | `/api/skills{,/{name}/files,/{name}/usage}` | Skill filesystem management |
| **Workspace** | `/api/workspace/{list,read,write,mkdir,delete,download,upload}` | Workspace file manager |
| **Reports** | `/api/report` | Report generation |
| **Visibility** | `/api/visibility/{kind}/{id}` | Per-resource visibility toggles |
| **ScopeSentry Sync** | `/api/sync/scopesentry/*` | External ScopeSentry integration |

### Dependencies

Imports: `agent`, `archivestore`, `db`, `egress`, `intercept`, `llmpool`, `llmrec`, `report`, `traffic`, plus `norma/llm`, `norma/tool`, `norma/transcript`.

---

## intercept/

### Takeaway

The `intercept` package implements the user-configurable tool-call interception layer. Rules are loaded from the database, cached in memory, and evaluated in priority order on every PreToolUse event. Three actions: **allow** (permit immediately), **deny** (block with message to model), **ask** (pause and wait for human approval via the API).

### Key Types

- **`Interceptor`** -- Main struct; caches rules from DB, evaluates them against tool calls. Created with `New()` or `NewWithStore()`.
- **`Rule`** (from DB) -- Priority, pattern (regex on tool name + arguments), action (allow/deny/ask), timeout config.
- **`TargetScope`** -- Binds approval for an asset target to one task or conversation; includes `Enabled` func, `WaitBound`, and reference to its `Interceptor`.
- **`Trace`** (`trace.go`) -- Records the evaluation path of a tool call through the rule chain for debugging.
- **Target gate** (`target.go`, `target_gate.go`, `target_dial.go`, `target_redirect.go`) -- Approval gate for new targets; redirects, dial checks, exemptions.
- **`ClosedJudge`** (`closed_judge.go`) -- LLM-based fallback approval: commands that hit no rule go to the model for judgment.
- **Context helpers**: `WithConvID`, `WithTaskContext` -- Inject conversation/task metadata for pending records and activity emission.

### Dependencies

Imports: `config`, `db`.

---

## guard/

### Takeaway

The `guard` package implements the safety boundary layer: an audit log, user-configured intercept-rule evaluation, and Observer/G5 failure attribution. Every tool call passes through the PreToolUse hook before executing. Destructive/exfil gating lives in DB intercept rules (seeded as built-in rules).

### Key Types

- **`Guard`** -- Enforces the side-effect policy via agent-core hooks. Holds an audit ring, failure attribution counters, and an optional `Interceptor`. Created via `New()`, `NewWithInterceptor()`, or `NewTargetOnly()`.
- **`AuditEntry`** -- Records one gated tool call: timestamp, tool, action (allow/block), reason, command.
- **`targetGate`** -- Interface for the target-scope approval gate.

### Dependencies

Imports: `intercept`, `norma/hook`.

---

## egress/

### Takeaway

The `egress` package is the governor for platform-owned HTTP requests to targets (WebFetch, HTTP custom tools, enrich probe). A noise profile sets rate limiting, jitter, concurrency caps, backoff, and caching per host and globally. Four profiles: `off` (strict passthrough), `quiet`, `balanced`, `aggressive`.

### Key Types

- **`Profile`** -- One noise level configuration: RPS, burst, max-per-host, max-global, jitter, cache TTL, retries, backoff, user agent.
- **`Governor`** -- The active rate limiter instance. Created from a Profile; process-wide singleton via `Current()`.
- **`Pace`** (`pace.go`) -- Per-host token-bucket + concurrency slot.

### Dependencies

Imports: `intercept` (for target-scope context).

---

## hardening/

### Takeaway

The `hardening` package provides opt-in intercept rules that pause the agent and ask the operator before it acquires third-party code (downloads, git clone, package installs, piped remote content). NOT seeded automatically -- must be applied manually via `apply-intercept-rules.sh`. Priority 70-72 (below built-in destructive denies at 80/90/100).

### Key Files

- `intercept-rules.sql` -- The SQL rules to insert.
- `apply-intercept-rules.sh` -- Applies the rules (idempotent).
- `rulecheck_test.go` -- Tests the rules against `intercept.Match`.
- `README.md` -- Documentation.

---

## traffic/

### Takeaway

The `traffic` package implements the request-recording subsystem: an embedded go-mitmproxy proxy that writes every target HTTP exchange into a human-browsable file tree with a sidecar SQLite index. Full capture, plaintext (no redaction), target HTTP only. Also handles SOCKS5 proxying, transparent proxying, WebSocket/SSE stream recording, HAR import/export, traffic replay, and rewrite rules.

### Key Types

- **`Traffic`** -- Main struct; holds the MITM proxy, SQLite DB, blob store, file tree root. Created via `New()`.
- **`Exchange`** -- One recorded HTTP request/response pair.
- **`StreamMessage`** -- WebSocket/SSE event within a stream exchange.
- **`RewriteFlow`** (`rewrite_flow.go`) -- Traffic rewrite pipeline.
- **`RewriteHook`** (`rewrite_hooks.go`) -- Programmable traffic modification hooks (JavaScript-based via `hookvm/`).
- **`Evidence`** (`evidence.go`) -- Search traffic for finding evidence.
- **`Replay`** (`replay.go`) -- Replay recorded exchanges.
- **`Archive`** (`archive.go`) -- Archive/restore traffic data.
- **SOCKS5** (`socks5.go`, `socks5_udp.go`) -- SOCKS5 proxy with UDP support.
- **Transparent proxy** (`transparent.go`) -- Linux iptables-based transparent proxying.

### Dependencies

Imports: `db`, `traffic/rewrite`, `norma/permission`, `norma/tool`, go-mitmproxy, modernc.org/sqlite.

---

## llmrec/

### Takeaway

The `llmrec` package implements a recording decorator for `llm.Provider`. It intercepts every Stream call, captures the full request and accumulated response (including raw HTTP wire bodies), and persists them to PostgreSQL for later inspection. Also provides context-key helpers for task ID, worker lane, usage sink, and stop reason sink.

### Key Types

- **`Recorder`** -- Wraps an `llm.Provider`; records every completion call to the DB. Implements `llm.Provider` interface.
- **`Capture`** (`capture.go`) -- Collects untouched wire bodies (request + all HTTP attempts with status codes) of one logical LLM call for debugging. Attached via context.
- **Context helpers**: `WithTaskID`, `WithWorker`, `WithUsageSink`, `WithStopSink` -- Attach metadata to LLM calls for recording and metering.

### Dependencies

Imports: `db`, `norma/llm`, `norma/transcript`.

---

## config/

### Takeaway

The `config` package loads runtime configuration from a JSON file, with environment variables taking precedence. Handles base directory resolution (including `go run` detection), key directory location, and PostgreSQL connection config assembly.

### Key Types

- **`Config`** -- Top-level config file shape: `Database`, `SkillDir`, `TaskUserAgents`.
- **`Database`** -- PostgreSQL connection config (DSN or component fields).
- **`TaskUserAgents`** (`task_user_agents.go`) -- Per-task user-agent configuration for the recording proxy.

### Key Functions

- `BaseDir()` -- Returns the directory anchoring all runtime artifacts.
- `KeyDir()` -- Returns the directory holding jwt.key and secret.key.
- `Path()` -- Returns the config file path (env > CWD > next-to-binary).
- `Load()` -- Loads the config file.
- `DSN()` -- Assembles the PostgreSQL DSN from config + env.

### Dependencies

No internal ARTEX imports; standard library only.

---

## notify/

### Takeaway

The `notify` package implements IM/email push channel adapters for vulnerability findings. It is a **leaf package** (depends only on the standard library). Channel configuration is passed as `map[string]any` and content as a `Message`. Supports DingTalk, Feishu/Lark, WeCom, generic webhook, Telegram, and email (SMTP).

### Key Types

- **`Channel`** (interface) -- Adapter for one notification channel: `Kind()`, `Validate()`, `Send()`, `DefaultRatePerMin()`, `SecretKeys()`, `DestinationKeys()`.
- **`Message`** (`event.go`) -- The content to push (finding data, severity, status changes).
- **`Filter`** (`filter.go`) -- Severity/status filtering for notifications.
- **Channel implementations**: `dingTalkChannel`, `feishuChannel`, `weComChannel`, `webhookChannel`, `telegramChannel`, `emailChannel`.
- **Rendering**: `html.go`, `markdown.go`, `render.go` -- Format messages for each platform.
- **Security**: `mask.go` -- Credential masking on readback; `sign_test.go` -- Signature computation for DingTalk/Feishu.

### Dependencies

Standard library only (leaf package).

---

## mcphttp/

### Takeaway

The `mcphttp` package contains remote MCP (Model Context Protocol) clients that speak Streamable HTTP and legacy SSE transports. It adapts an HTTP/JSON-RPC MCP server to the same `tool.CoreTool` shape (`mcp__server__tool`) without touching the SDK. Custom headers (e.g., Authorization) come from the MCP row's env map.

### Key Types

- **`Client`** -- Connection to one remote MCP server. Created via `New()` (Streamable HTTP) or `NewSSE()` (legacy GET `/sse` + POST `/message`). Handles JSON-RPC over HTTP POST, with server free to answer as `application/json` or SSE.
- **`rpcRequest`/`rpcResponse`** -- JSON-RPC 2.0 message types.
- **`ToolName(server, name)`** -- Generates the `mcp__server__tool` naming scheme for remote tools.

### Dependencies

Imports: `norma/llm`, `norma/permission`, `norma/tool`.

---

## evidence/

### Takeaway

The `evidence` package preserves finding evidence independently of disposable traffic. It copies relevant request/response bodies from the traffic store into a durable, content-addressed blob store (SHA-256 keyed), with PostgreSQL metadata. Includes GC for unreferenced blobs (1-day grace period).

### Key Types

- **`Store`** -- Holds references to `db.DB`, `traffic.Traffic`, and a directory for blob storage. Created via `New()`.
- **`writeBody()`** -- Writes evidence body to content-addressed storage with integrity verification.
- **`verifyFile()`** -- SHA-256 verification of stored evidence.

### Dependencies

Imports: `db`, `traffic`.

---

## db/

### Takeaway

The `db` package is the PostgreSQL data layer for all of ARTEX. It opens the connection, applies the idempotent base schema (`schema.sql`), runs numbered migrations (`migrations/NNNN_slug.sql` with SHA-256 checksums), and seeds built-in agents and the variable catalog. Contains data-access methods for every domain: tasks, explorations, findings, assets, intents, intercept rules, LLM records/usage, notifications, conversations, secrets, settings, triggers, side questions, traffic rewrites, coverage, and more.

### Key Types

- **`DB`** -- The main database handle; wraps `*sql.DB` with all query methods.
- **`ExplorationStore`** -- Per-exploration (per-task) data access: intents, findings, facts, assets, activity stream, nodes, coverage ledger.
- **`Activity`** -- One activity record in the exploration stream.
- Schema types for every domain: `Finding`, `Intent`, `Asset`, `InterceptRule`, `LLMRecord`, `NotificationChannel`, `Conversation`, `Trigger`, `TaskArchive`, `SideQuestionSession`, `SideQuestionRequest`, etc.

### Key Functions

- `Open()` -- Opens PostgreSQL, applies schema + migrations, seeds built-ins.
- `DSN()` -- Resolves the connection string from config + env.
- Domain-specific CRUD and query methods on `*DB` and `*ExplorationStore`.

### Dependencies

Imports: `config`, plus PostgreSQL driver (`pgx/v5`).

---

## llmpool/

### Takeaway

The `llmpool` package implements LLM failover: a `Provider` decorator that walks an ordered chain of LLM profiles and moves to the next when the current one fails (out of credit, revoked key, rate-limited, or down). The whole process shares one chain and one circuit-breaker registry, so when one task discovers a profile is broken, every other task skips it immediately.

### Key Types

- **`Pool`** -- An `llm.Provider` that fails over across an ordered chain of `Member`s. The hard rule: a member may only be abandoned BEFORE it has yielded any event (once text has reached the caller, mid-stream failure is surfaced as-is).
- **`Member`** -- One LLM profile in the chain: ID, name, model, format, priority, rank, window tokens, and the underlying provider.
- **`Registry`** (`health.go`) -- Process-wide circuit-breaker state for every profile. Tracks consecutive failures, trip counts, cooling-off windows. Persists to DB so cooling-off survives restarts.
- **`State`** -- One profile's circuit-breaker state: fails, trips, open-until, last error.
- **Backoff ladder**: 1 min, 5 min, 30 min. `softTripAfter = 3` consecutive transient failures.

### Dependencies

Imports: `norma/llm`.

---

## sidequestion/

### Takeaway

The `sidequestion` package implements independent side questions: while the main agent runs a task, a user can ask a question answered from the agent's current context snapshot. The service uses one LLM completion (no agent loop, no tools), with bounded context preparation and optional context-overflow recovery. Supports streaming, follow-ups, stop, and clear.

### Key Types

- **`SideQuestionService`** -- Wraps an `llm.Provider`; `Answer()` performs one completion (streaming or non-streaming).
- **`Exchange`** -- One side Q&A: question, answer, status, model, usage, context info, timestamps.
- **`Snapshot`** -- The immutable structured context snapshot from the main agent at submission time.
- **`Memory`** -- Persisted conversation memory: rolling history summary, snapshot summary, cursor ordinal.
- **`ContextInfo`** -- Diagnostic info about context building: phase, recent exchanges count, budget, overflow retry status.
- **`contextBuilder`** -- Builds the LLM request from snapshot + recent history + rolling summary, respecting token budgets.

### Key Constants

- `DefaultOutputTokens = 8192`, `MaxRecentExchanges = 20`.
- `instruction` -- System instruction: "independent side question, no tool execution capability".

### Dependencies

Imports: `norma/llm`, `norma/compaction`.

---

## archivestore/

### Takeaway

The `archivestore` package stores immutable cold-task packages in S3-compatible storage. Configured via environment variables (`ARTEX_ARCHIVE_STORAGE=s3`). Supports S3 path-style, server-side encryption (AES256 or aws:kms), and session tokens. Falls back to local storage when unconfigured.

### Key Types

- **`Config`** -- S3 configuration: endpoint, region, bucket, prefix, credentials, path style, encryption settings.
- **`Store`** -- S3 client wrapper: `Put()`, `Get()`, `Delete()` for archive blobs.
- **`FromEnv()`** -- Creates a Store from environment variables; returns nil for local backend.

### Security

- Endpoint must be HTTPS (HTTP only on loopback).
- Encryption cannot be disabled (default AES256).
- KMS key validated as proper ARN.
- Credential and bucket validation.

### Dependencies

Imports: AWS SDK v2 (`aws-sdk-go-v2`).

---

## How do packages depend on each other?

### Takeaway

The dependency graph flows from leaf packages inward toward the `server` package, which sits at the top and imports nearly everything. The `norma` external module provides the agent harness, LLM provider abstraction, tool framework, and transcript persistence.

### Dependency Flow (simplified)

```
config (leaf -- no internal deps)
notify (leaf -- no internal deps)
  |
  v
db (imports: config)
  |
  v
intercept (imports: config, db)
egress (imports: intercept)
guard (imports: intercept)
  |
  v
traffic (imports: db, traffic/rewrite)
evidence (imports: db, traffic)
llmrec (imports: db)
llmpool (no internal deps -- only norma/llm)
mcphttp (no internal deps -- only norma/*)
sidequestion (no internal deps -- only norma/*)
archivestore (no internal deps -- only AWS SDK)
  |
  v
agent (imports: db, intercept, egress, and norma/*)
  |
  v
server (imports: agent, archivestore, db, egress, enrich, guard,
         intercept, llmpool, llmrec, report, traffic)
```

The external `norma` module (`github.com/Autumn-27/norma`) provides:
- `agentcore` -- Agent session and runner
- `harness` -- Agent harness lifecycle
- `llm` -- LLM provider interface (`Provider`, `CompletionRequest`, `StreamEvent`, `Usage`)
- `permission` -- Permission model for tools
- `tool` -- Tool definition and registry (`CoreTool`, `TodoStore`)
- `transcript` -- Conversation persistence
- `hook` -- PreToolUse/PostToolUse hook system
- `compaction` -- Context compaction/token estimation

---

## Gaps

- The `enrich/` and `report/` packages are imported by `server` but were not in the requested list; they likely handle target enrichment (DNS/port probes) and report generation respectively, but were not investigated.
- The `extension/` directory exists but was not in scope.
- Internal structure of `traffic/rewrite/` and `traffic/hookvm/` subdirectories (JavaScript-based traffic modification engine) was not deeply explored.
- The exact schema of `db/schema.sql` and migration files was not read in detail.

---

## Inferences

- ARTEX follows a hub-and-spoke architecture where `server` is the hub, coordinating all subsystems and exposing them via a single HTTP API.
- The `norma` external module is the foundational agent framework; ARTEX adds penetration-testing domain logic, safety rails, traffic recording, and a full web application on top.
- The intercept/guard/hardening packages form a layered safety system: `intercept` defines rules, `guard` enforces them via hooks, and `hardening` provides optional additional rules for third-party code acquisition.
- The LLM subsystem has three layers: `llmrec` (recording), `llmpool` (failover), and per-profile provider caching in `server` -- providing observability, resilience, and multi-model support.
- Side questions are carefully isolated from the main agent loop: they share context read-only via snapshots but cannot execute tools or affect the main task graph.
