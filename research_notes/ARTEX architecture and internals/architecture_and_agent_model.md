# ARTEX Architecture and Agent Execution Model

## How does the two-graph model work (asset graph vs exploration graph)? What tables/structures back them?

### Takeaway

ARTEX separates "what exists" (the asset graph) from "what was tried and what it produced" (the exploration graph) into two independent PostgreSQL-backed graphs linked by anchors. The asset graph is globally shared across tasks; the exploration graph is per-task. Anchors (`exploration_anchors`) tie exploration nodes to concrete assets, enabling asset test coverage tracking.

### Cited Findings

- **Asset graph tables** (`companies`, `company_scope`, `assets`, `task_scope`): The `assets` table stores rows with `type IN ('root_domain','ip','subdomain','app','service','endpoint')`, each with a `company_id` FK to `companies`. Deduplication is enforced by unique indexes per asset type (e.g., `uq_av2_root_domain ON assets(domain) WHERE type = 'root_domain'`, `uq_av2_endpoint ON assets(url, method) WHERE type = 'endpoint'`). Parent-child relationships (domain -> subdomain -> service -> endpoint) are computed by the program, not explicitly stored as edges; agents only submit raw observations via `insert_assets`. — Source: `db/schema.sql` lines 41-114

- **Exploration graph tables** (`explorations`, `exploration_nodes`, `activity`): The `explorations` table is the per-task container. `exploration_nodes` stores all reasoning nodes with `kind IN ('begin','goal','intent','fact','finding','hint','digest')` and states per kind (e.g., intents can be `open/running/paused/done/blocked/exhausted/stopped/deleted`; goals can be `open/met/abandoned`). Nodes have a `payload JSONB` column for kind-specific data. The `activity` table logs per-step execution records for each node. — Source: `db/schema.sql` lines 154-227

- **Anchors linking the two graphs**: `exploration_anchors(node_id, asset_id)` ties intents, facts, and findings to concrete assets, powering the asset test coverage and the coverage graph. This is described in `db/finding_assets.go` and referenced in `docs/ARCHITECTURE.md`. — Source: `docs/ARCHITECTURE.md` line 17; README line 139

- **Findings table** (`findings`): A separate `findings` table (line 1188 of schema.sql) stores standalone vulnerability records with their own ID space, linked to exploration nodes. Findings carry a PoE level, verification status, evidence version, and report evidence version. — Source: `db/schema.sql` line 1188

- **Intent claim lease mechanism**: Running intents use a fencing-token-based claim system (`unclaim_token`, `last_heartbeat_at` columns on `exploration_nodes`). Claims expire after `IntentClaimTTL` without a heartbeat, and a sweep loop returns them to the frontier. — Source: `db/schema.sql` lines 206-210; `server/engine.go` lines 1067-1087

### Inferences

- The asset graph is a flat table with type-based unique indexes rather than an explicit parent-child edge table. Containment hierarchy (domain -> subdomain -> service -> endpoint) is implied by the asset types and computed by the application.
- The exploration graph uses a polymorphic node table where `kind` determines valid states and semantics, connected by implicit lineage (parent_ids in payload) rather than a separate edges table.

### Gaps

- The exact structure of the `exploration_anchors` table was not directly read from schema.sql (only referenced in architecture docs). Its columns are described as `(node_id, asset_id)` but additional columns (like anchor type) may exist.

---

## How does the planner/worker agent loop function?

### Takeaway

The engine is event-driven: graph changes wake the planner (debounced at 800ms), the planner reads the full situation, judges goals, and emits 0..N intents into a frontier queue. N concurrent worker goroutines claim intents from the frontier, execute them with real tools, write facts/assets/findings back, and stop. Write-backs trigger the next planner round, forming a closed loop until `prove_goal` closes the task.

### Cited Findings

- **Engine.Run** starts 1 planner loop + 1 claim-sweep loop + N worker goroutines per task (default N=3, configurable). All run as goroutines under a task-scoped context. The loops always run but idle until an LLM provider is configured. — Source: `server/engine.go` lines 835-869

- **Planner loop** (`plannerLoop`): Waits on either an edge trigger (`t.notify` channel, fired by worker completion/finding) or a heartbeat timer (default 600s = 10 min). On wake, it debounces 800ms to coalesce bursts, checks guards (paused, deleting, terminal, settling, budget), then calls `planner.Plan()`. The planner receives `TriggerEvent` structs describing what changed (worker done, finding reported, goal added, hint added, etc.). — Source: `server/engine.go` lines 921-1061

- **Planner.Plan** runs one LLM planning round. It pre-fetches the full graph overview into the prompt (no need for the model to call `graph_overview` itself), renders triggers (what changed since last round), injects the persistent todolist (surviving across wake-ups), and the goal anchor. The planner uses Norma's `agentcore.Options` with `permission.ModeBypass`. It emits intents via `add_intent` tool calls. Returns whether goals are met. — Source: `agent/planner.go` lines 519-678

- **Persistent todolist**: The planner maintains a per-task `TodoStore` (`actool.TodoStore`) that survives across wake-ups. Each `Plan()` is a fresh LLM session, but the shared store lets it record serial exploit chains once and dispatch step-by-step over rounds. Items are rendered into the prompt as `[Your planning todos (kept across wake-ups)]`. — Source: `agent/planner.go` lines 55-57, 125-163

- **Worker loop** (`workerLoop`): Continuously tries to claim intents from the frontier. Claims use `claimNext` which reads up to 20 open intents and attempts `ClaimIntentToken` on each. Once claimed, `runWorkerStep` -> `runIntent` runs the full intent lifecycle. — Source: `server/engine.go` lines 1121-1171, 1499-1507

- **Worker.Execute**: Claims ONE intent, creates a ToolSet with the exploration store, asset store, finding recorder, enrichment trigger, and coverage support. The worker's system prompt is a detailed pentesting instruction that emphasizes: do only the assigned intent, write back as you discover (record_fact for conclusions, insert_assets for new assets, report_finding for confirmed vulnerabilities), and stop. The intent's target assets are fetched and rendered into the launch prompt. — Source: `agent/worker.go` lines 29, 266-298, 535-650

- **Worker write-back triggers planner**: After `runIntent` completes, `t.NotifyDone(intent.ID)` wakes the planner with the finished intent ID. If the worker reported a finding mid-run, `t.NotifyFinding` wakes the planner immediately without waiting for the worker to finish. — Source: `server/engine.go` line 1417; `agent/worker.go` line 549

- **Quiet mode** (#86): When enabled per task, edge-triggered planning rounds are skipped while work is in flight and the open-goal fingerprint is unchanged since the last completed round. The heartbeat still supervises. — Source: `server/engine.go` lines 896-906, 991

- **Model error retry**: Workers that fail with a model error get up to 2 automatic retries with 3-second backoff, as long as the task is not paused/settling. — Source: `server/engine.go` lines 71-75, 1270-1285

### Inferences

- The planner is the sole intent generator and the worker is a pure executor. Workers never generate new exploration directions; they note observations as facts for the planner to synthesize.
- The debounce (800ms) and heartbeat (default 10 min) balance responsiveness with LLM cost. The debounce coalesces bursts of worker completions into a single planning round.
- The claim-sweep loop (`claimSweepLoop`) recovers stale claims from crashed workers by checking heartbeat freshness.

### Gaps

- The exact mechanism of `graph_overview` data assembly (the `tsx.graphOverviewData()` call) was not traced to its final implementation.

---

## How does Norma orchestrate tool calls? What is its role?

### Takeaway

Norma (`github.com/Autumn-27/norma`, originally `github.com/BaaRai/Norma`) is the LLM agent SDK that ARTEX builds on. It provides the agent-core loop, tool execution, permission system, hook registry, transcript persistence, compaction, and the untrusted-output boundary. ARTEX does not implement the LLM conversation loop itself; it configures Norma's `agentcore.Options` and delegates execution.

### Cited Findings

- **Norma packages used by ARTEX** (from imports in `agent/planner.go` and `agent/worker.go`):
  - `norma/agentcore` — The core agent loop. `agentcore.Options` configures provider, system prompt, tools, permission mode, compaction, settlement, turn/time budgets, web search, and the untrusted-output boundary.
  - `norma/harness` — Hook runner interface (`harness.HookRunner`) with `PreToolUse` and `PostToolUse` hooks. Terminal reasons (`harness.ReasonMaxTurns`, `harness.ReasonTimeout`, `harness.ReasonModelError`, `harness.ReasonCompleted`).
  - `norma/llm` — LLM provider interface (`llm.Provider`), message types (`llm.Message`, `llm.RoleAssistant`).
  - `norma/permission` — Permission modes (`permission.ModeBypass` used by both planner and worker, meaning all tool calls are auto-approved at the SDK level; ARTEX's own guard/intercept layer handles approval).
  - `norma/tool` — Tool definition interface (`actool.CoreTool`), `TodoStore` for persistent planning todos, deferred tools.
  - `norma/transcript` — Raw LLM conversation persistence (`transcript.Store`).
  — Source: `agent/planner.go` lines 13-18; `agent/worker.go` lines 17-22

- **How ARTEX uses Norma**: Both `Planner.Plan` and `Worker.execute` build an `agentcore.Options` struct and call `captureRun(ctx, opts, input, emit)`. The options include: the LLM provider, system prompt segments, tools (domain-specific + SDK defaults like Read/Write/Edit/Bash), hooks (guard/intercept for approval gates), compaction config, settlement (wrap-up behavior when budgets are hit), turn limits, time limits, transcript store, web search config, and the untrusted-output boundary toggle. — Source: `agent/planner.go` lines 592-636; `agent/worker.go` lines 626-649

- **Hook system for tool approval**: ARTEX wraps Norma's hook runner with its own `steerHooks` struct that adds: (1) planner mid-run steering (injecting course corrections before tool calls), (2) intent budget enforcement (blocking non-write-back tools when exhausted), (3) idle-turn rerun injection (nudging the model when it thinks but never acts). The underlying `guard.Guard` implements the interception/approval gate as a `PreToolUse` hook. — Source: `server/engine.go` lines 587-690; `docs/ARCHITECTURE.md` line 37

- **Untrusted-output boundary**: Tool results are framed between nonce-tagged markers so the model treats them as data, not instructions. Controlled by `ARTEX_UNTRUSTED_BOUNDARY` env var (on by default). Implemented through Norma's `UntrustedOutputBoundary` option. — Source: `agent/planner.go` line 629; `docs/ARCHITECTURE.md` line 91

- **Compaction and settlement**: Norma handles context-window management (compaction) and budget-based wrap-up (settlement). When a worker hits its turn cap, Norma's settlement phase injects a wrap-up prompt telling the agent to write back all findings before stopping. — Source: `agent/worker.go` lines 176, 622-625

- **Role in architecture**: The `docs/ARCHITECTURE.md` package map describes agent capabilities as coming from the "norma SDK (agentcore / tool / permission / harness / memory / transcript)". — Source: `docs/ARCHITECTURE.md` line 32; README line 891

### Inferences

- Norma is effectively the "agent runtime" that handles the LLM conversation loop, tool dispatch, context management, and streaming. ARTEX focuses on the domain-specific layer: graph tools, approval gates, evidence linking, and orchestration.
- By using `permission.ModeBypass`, ARTEX opts out of Norma's built-in permission system entirely and replaces it with its own intercept/guard layer that supports argv-prefix matching, human approval, model-based decisions, and audit trails.

### Gaps

- The Norma SDK is a separate repository (`github.com/Autumn-27/norma`); its internal implementation was not read. The exact `captureRun` function and `agentcore` loop mechanics are inferred from usage.

---

## How does the traffic recording proxy work (the -proxy flag, the traffic/ package)?

### Takeaway

The traffic recording proxy is an embedded go-mitmproxy MITM proxy that captures every HTTP exchange agents make to targets, storing them in a SQLite-indexed file tree with full request/response bodies. It generates a CA certificate that agents trust, enabling HTTPS interception. The proxy also supports SOCKS5, transparent TCP, WebSocket/SSE recording, and rewrite rules.

### Cited Findings

- **Architecture**: The `traffic` package implements "an embedded go-mitmproxy proxy whose addon writes every target HTTP exchange into a human-browsable file tree, with a sidecar SQLite index for paged queries. Full capture, plaintext (no redaction), target HTTP only." — Source: `traffic/traffic.go` package doc, lines 1-5

- **SQLite schema**: The `exchanges` table indexes each exchange by `id, ts, host, method, url_template, url, status, content_type, req_len, resp_len, path`. Bodies are stored in `exchange_bodies` with inline storage up to 256KB (`maxInlineBody`), spilling to a content-addressed blob store (`_blobs/sha256`) for larger payloads. Full-text search uses FTS5 with trigram tokenization for substring matching. — Source: `traffic/traffic.go` lines 42-176

- **WebSocket and SSE**: The `stream_messages` table captures WebSocket messages and SSE events per exchange, with direction (c2s/s2c/meta), message kind, payload (up to 1MB), and ordering. Bounded at 10,000 messages or 32MB per stream. — Source: `traffic/traffic.go` lines 79-96

- **Raw TCP/UDP**: SOCKS5 CONNECT relayed TCP streams go in `raw_tcp_streams`; UDP ASSOCIATE datagrams go in `raw_udp_datagrams`. Each is separate from HTTP exchanges. — Source: `traffic/traffic.go` lines 120-161

- **Rewrite rules**: The `exchange_rewrites` table tracks per-exchange rewrite rule application (phase, source kind rule/hook, outcome applied/skipped/error). Rules can modify method, URL, headers, body, or status. — Source: `traffic/traffic.go` lines 97-118; `docs/traffic-rewrite-rules.md`

- **Startup and integration**: `NewManager` opens the traffic store with `traffic.Open(filepath.Join(dir, "traffic"), proxyAddr)`. It optionally starts SOCKS5 and transparent TCP listeners. The proxy runs in a goroutine. The manager's `ProxyAddr()` returns the MITM proxy address when capture is on, or the global egress proxy when capture is off. — Source: `server/manager.go` lines 478-532

- **Agent integration**: Workers route all Bash subprocess HTTP through the proxy via environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, plus CA trust vars `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, etc.). WebFetch goes through the proxy with the CA cert loaded for HTTPS verification. — Source: `agent/worker.go` lines 220-259

- **Noise governor integration**: When a noise profile is set, Bash commands routed through the proxy are paced per-host by the same rate/jitter/backoff rules. The proxy URL carries a pace marker userinfo so the proxy can identify paced connections. — Source: README lines 548-563; `agent/worker.go` lines 234-241

### Inferences

- The proxy is optional (empty `-proxy` flag disables it), but when enabled it becomes the central traffic observation point for all agent activity. Even the browser MCP (Playwright) is wired through it.
- The dual storage strategy (SQLite for indexing + content-addressed blob store for large bodies) balances query performance with storage efficiency for large captures.

### Gaps

- The exact `go-mitmproxy` addon implementation (how the proxy intercepts and records) was not read from the source.

---

## How are findings linked to evidence (HTTP request/response pairs)?

### Takeaway

Findings are linked to captured HTTP traffic through a multi-layered evidence system: `traffic_evidence_snapshots` store immutable copies of exchange metadata and body hashes, `finding_traffic_bindings` link findings to snapshots with roles (baseline/proof/verification/supporting) and ordering. Evidence bodies are stored by content hash in a dedicated `data/evidence/blobs/` directory, independent of the cleanable traffic store.

### Cited Findings

- **Evidence snapshot storage**: When a finding binds traffic, the full body is read under the traffic write lock (including large-body blobs), persisted to `data/evidence/blobs/<first two chars>/<hash>.bin`, and a `traffic_evidence_snapshots` row records the original traffic ID, capture time, URL, method, status, headers, body length, and SHA-256. Multiple findings can share snapshots/bodies. — Source: `docs/vulnerability-traffic-evidence.md` lines 56-58

- **Binding model**: `finding_traffic_bindings` link a finding to its evidence snapshots with `role` (baseline, proof, verification, supporting), `note`, and ordering. The `findings.evidence_version` counter tracks changes. Roles indicate the evidence's purpose: baseline = normal control request, proof = vulnerability proof, verification = additional verification, supporting = auxiliary evidence. — Source: `docs/vulnerability-traffic-evidence.md` lines 12-24

- **Agent-side binding**: The `report_finding` tool accepts optional `traffic_refs` with traffic IDs and roles. The agent is instructed to verify traffic with `traffic_search` / `traffic_get` before binding. The `bind_finding_traffic` tool allows after-the-fact binding without re-registering the finding. — Source: `docs/vulnerability-traffic-evidence.md` lines 12-16

- **EvidenceExchange type**: The `traffic/evidence.go` file defines `EvidenceExchange` with complete captured data: ID, URL, Method, ContentType, Status, request/response headers, body lengths, hashes, and `io.Reader` streams for the full bodies. `ReadEvidence` reads under the traffic write lock so blob deletion cannot race with evidence copy. — Source: `traffic/evidence.go` lines 19-27, 46-61

- **Atomic write**: "Files are persisted and verified first, then a single PostgreSQL transaction writes the exploration node, intent relations, vulnerability, snapshot, and bindings; the planner is notified only after commit. Failures may leave unreferenced files but never partial business records." — Source: `docs/vulnerability-traffic-evidence.md` lines 62-63

- **Export and archiving**: Evidence exports include the finding Markdown plus evidence attachments (manifest.json, request.http, response.http, request.bin, response.bin). Archive v3 collects snapshots by vulnerability binding. Hashes are verified before download. — Source: `docs/vulnerability-traffic-evidence.md` lines 69-83

- **Verification**: "A finding is verified only when a bound proof/response and verbatim evidence quotes support it. Gzip/deflate bodies are decoded before the quote check." Proof strength (PoE level, verification state, bound-evidence count) is shown in reports. — Source: README lines 236-238; `docs/vulnerability-traffic-evidence.md` lines 70-71

### Inferences

- The evidence system is designed for forensic integrity: snapshots are immutable copies stored by content hash, independent of the live traffic store that can be cleaned. This means findings retain their proof even after traffic is purged.
- The two-phase approach (agent auto-binding when enabled, plus manual binding through the UI) provides flexibility for both autonomous and human-guided workflows.

### Gaps

- None significant. The evidence linking model is well-documented.

---

## What is the overall request flow from the frontend through the API to the agent system?

### Takeaway

The frontend (Next.js static export, embedded via `go:embed`) communicates with the Go backend over REST (`/api/*`) with JWT auth and SSE for live streaming. The `Manager` owns all persistence and task handles. Task creation writes to PostgreSQL and starts an `Engine` which runs the planner/worker loops. Human-in-the-loop interaction goes through the main agent. Activity records flow through the `Broadcaster` via SSE to the frontend.

### Cited Findings

- **End-to-end flow** (from docs/ARCHITECTURE.md):
  1. **Task creation**: `server.createTask` -> `Manager.CreateTaskWithOptions` writes the task, scope, seed goals, and creates the exploration graph.
  2. **Loop start**: `Engine.Run` starts planner loop + N worker goroutines under a task-scoped context.
  3. **Decomposition**: The `goals` role writes goals and constraints through `set_goals`/`set_constraints`.
  4. **Planning**: `Planner.Plan` reads the route, queries assets, judges goals, emits intents.
  5. **Execution**: `Worker.Execute` claims an intent, runs tools with guard hooks, writes facts back.
  6. **Tools and traffic**: Shell/HTTP calls go through the recording proxy and egress governor.
  7. **Findings**: `addFinding` records severity, class, confidence, asset references; evidence is linked to captured traffic.
  8. **Completion**: `prove_goal` marks a goal met; the last met goal completes the task.
  — Source: `docs/ARCHITECTURE.md` lines 49-72

- **HTTP layer**: `server.New` creates the HTTP server with ~270 routes, JWT auth, SSE broadcaster, and middleware (secret scrub, trusted proxies, exec privilege, isolation status). The `Broadcaster` publishes activity records to live SSE subscribers per task. — Source: `docs/ARCHITECTURE.md` line 33; `server/engine.go` line 706

- **Manager lifecycle**: `Manager` owns: the PostgreSQL data source (asset graph + exploration graphs + config), the traffic recording proxy, the enrichment engine, and the interception/approval gate. It creates task handles, resolves LLM providers, and manages settings. — Source: `server/manager.go` lines 259-303

- **Activity emission**: Every execution step goes through `Engine.emitActivity` which persists the activity row to PostgreSQL (with retry on write failure) and publishes to the SSE broadcaster in a single code path. — Source: `server/engine.go` lines 710-784

- **Human-in-the-loop**: The `mainagent` handles human chat interaction. It can add goals, add hints, and inject human messages into running worker intents (via `runDetachedIntent`). — Source: `docs/ARCHITECTURE.md` line 33; `server/engine.go` lines 1433-1474

### Inferences

- The architecture is a monolithic Go backend with the frontend embedded as static files. There is no separate frontend server in production; the Go binary serves everything on one port.
- The SSE stream is same-origin by default, sharing port 8787 with the REST API and static files.

### Gaps

- The exact route registration and middleware chain was not read from the server package.

---

## Startup sequence (cmd/artex/main.go)

### Takeaway

The startup sequence is: (1) exec shim check for Bash/MCP drops, (2) seal secrets from `/proc`, (3) parse flags, (4) emit config snapshot, (5) resolve exec privilege and isolation, (6) signal handling, (7) open Manager (connects to PostgreSQL, starts traffic proxy), (8) create HTTP server with all middleware, (9) listen and serve, (10) graceful shutdown on signal.

### Cited Findings

- **Process entry** (`main()`): First calls `server.RunExecShimIfRequested` (for Bash shim or MCP drop command identity), then `server.SealProcessEnv()` to strip secrets from `/proc/<pid>/environ`, then `os.Exit(run())`. — Source: `cmd/artex/main.go` lines 80-86

- **Flags**: `-addr` (default `127.0.0.1:8787`), `-data` (runtime data directory), `-proxy` (default `127.0.0.1:8788`, traffic recording proxy address), `-exec-uid`/`-exec-gid` (agent process identity), `-dev-no-isolation` (development escape). — Source: `cmd/artex/main.go` lines 101-110

- **Config snapshot**: After resolving all settings (config file, env vars, DSN, skill dir, key dir, trusted proxies, noise profile, untrusted boundary), emits a single structured JSON log line so an operator can reproduce the exact configuration. — Source: `cmd/artex/main.go` lines 126-175

- **Exec privilege and isolation**: `ResolveExecPrivilege` determines the uid/gid for agent subprocesses. `PrepareExecPrivilege` sets up permissions. `InstallBashShim` installs the privilege-dropping Bash wrapper. `IsolationSelfTest` verifies the isolation holds. On Linux as root, a failed self-test stops the start (unless `-dev-no-isolation`). — Source: `cmd/artex/main.go` lines 179-203

- **Manager creation**: `server.NewManager(dataDir, proxy)` connects to PostgreSQL, opens the traffic store, starts the MITM proxy, initializes the interceptor, loads settings, initializes the enrichment engine, and syncs the browser MCP proxy config. — Source: `cmd/artex/main.go` line 209; `server/manager.go` lines 412-575

- **HTTP server**: `server.New()` creates the server with options (secret scrub, trusted proxies, exec privilege, isolation status). The HTTP server has `ReadHeaderTimeout: 10s`, `ReadTimeout: 30min`, `IdleTimeout: 2min`, no WriteTimeout (to allow SSE streams). — Source: `cmd/artex/main.go` lines 215-225

- **Graceful shutdown**: On SIGINT/SIGTERM: (1) close the HTTP listener (10s timeout), (2) drain task goroutines (15s timeout), (3) flush LLM health, (4) deferred `mgr.Close()`. — Source: `cmd/artex/main.go` lines 236-258

### Inferences

- The isolation model ensures agent processes (Bash, shell, tools) run as a non-root user even when the server runs as root, preventing agents from reading server keys and config.
- The `SealProcessEnv` call at startup removes secrets from the process environment early, before any listener or child process exists.

### Gaps

- None significant for the startup sequence.

---

## High-level architecture from README

### Takeaway

ARTEX is a self-hosted, LLM-driven autonomous penetration testing platform. It is a single Go binary with the Next.js UI embedded, backed by PostgreSQL. The core architecture is a dual-graph model (asset graph + exploration graph) with an event-driven agent loop (planner decomposes goals into intents, workers execute them). Key features include: recording MITM proxy for evidence capture, human-in-the-loop approval gates (argv-prefix rules, scope/deny gates, approval decisions tracked by source), token/turn budgets, noise governor, untrusted-output boundary, multi-provider LLM failover, MCP/skills/memory, and worker shared traces.

### Cited Findings

- **Self-hosted, model-agnostic**: "One Go binary with the Next.js UI embedded, PostgreSQL, your own Anthropic/OpenAI-compatible endpoint, or a local Ollama." — Source: README line 39

- **LLM multi-agent**: Six agent roles: `goals` (goal decomposition), `planner` (sole intent generator), `worker` (executor, N concurrent), `mainagent` (human-in-the-loop), `retester` (vulnerability retest), `chat` (conversations). — Source: README lines 889-920

- **Supporting subsystems**: Traffic recording proxy (MITM + CA tracing), guard/intercept (tool approval gate), enrich (DNS/HTTP async enrichment), MCP/skills/memory/report extensions. — Source: README lines 918-920

- **Approval gate**: "every tool call can require human approval, with rules by string, regex or argv prefix. An argv rule is a JSON array of 1 to 8 tokens (Bash only); it matches only a single simple command whose parsed prefix equals the pattern exactly." Each approval records who decided: human, rule, model, or system. — Source: README lines 253-258

- **Budgets**: Task-level and intent-level token and turn budgets. Near the wrap-up reserve (larger of 5% and 20,000 tokens, plus 2 turns) the task enters forced wrap-up. — Source: README lines 264-268

- **Noise governor**: Per-host rate limiting with profiles quiet/balanced/aggressive, jitter, backoff on 429/503, in-flight caps, brief GET caching. — Source: README lines 269, 548-563

- **Worker shared traces**: "Workers can search each other's execution traces (search_all_worker_traces, list_worker_traces, get_worker_trace). Observations that never became formal facts are still reusable by the next worker." — Source: README lines 208-211

### Inferences

- ARTEX is designed to be a complete, self-contained penetration testing platform that can operate autonomously with safety controls, not a chat wrapper around individual security tools.
- The multi-provider LLM support with failover and per-intent rotation across providers is a production-oriented feature for reliability and cost management.

### Gaps

- None significant for the high-level overview.
