# ARTEX Extension Points and Integrations

## How are custom tools defined and executed?

### Takeaway

Custom tools are user-defined automation units stored in the database (`tools` table with `system=false`), supporting four kinds -- `command`, `script`, `http`, and `shell` -- each with its own execution model, and are dispatched through a unified `actool.CoreTool` interface that the LLM agent can call like any built-in tool. -- Source: [server/customtool.go](/home/user/ARTEX/server/customtool.go)

### Cited Findings

- Custom tools have four kinds: `command` (renders a template and executes it via the Bash low-level runner), `script` (Python only; writes a temp .py file, passes parameters via stdin JSON and `TOOL_*` environment variables), `http` (native HTTP request with optional proxy and template expansion), and `shell` (bash environment declarations with no executable content, surfaced through the Bash tool description). -- [server/customtool.go, line 66](/home/user/ARTEX/server/customtool.go)

- The CRUD API uses `customToolReq` for create/update:
  ```go
  type customToolReq struct {
      Key         string          `json:"key"`
      Description string          `json:"description"`
      Schema      json.RawMessage `json:"schema"`
      Agents      []string        `json:"agents"`
      Enabled     bool            `json:"enabled"`
      Kind        string          `json:"kind"` // command | script | http
      Exec        json.RawMessage `json:"exec"`
      Deferred    bool            `json:"deferred"`
  }
  ```
  Keys must start with a lowercase letter and contain only lowercase letters/digits/underscores. -- [server/customtool.go, lines 38-47](/home/user/ARTEX/server/customtool.go)

- Execution specs are kind-specific:
  ```go
  type commandExec struct {
      Command   string `json:"command"`
      TimeoutMs int    `json:"timeout_ms"`
  }
  type scriptExec struct {
      Code      string `json:"code"`
      TimeoutMs int    `json:"timeout_ms"`
  }
  type httpExec struct {
      Method            string            `json:"method"`
      URL               string            `json:"url"`
      Headers           map[string]string `json:"headers"`
      Body              string            `json:"body"`
      TimeoutMs         int               `json:"timeout_ms"`
      Proxy             string            `json:"proxy"`
      UseRecordingProxy bool              `json:"use_recording_proxy"`
  }
  ```
  -- [server/customtool.go, lines 251-267](/home/user/ARTEX/server/customtool.go)

- Template expansion uses `{name}` placeholders replaced with parameter values: `renderTemplate(tmpl, params, quote)` with `shellQuote` for commands and `identity` for HTTP URLs/bodies/headers. -- [server/customtool.go, lines 696-702](/home/user/ARTEX/server/customtool.go)

- When no JSON Schema is provided, the tool auto-generates a thin `{args: string}` wrapper schema. HTTP tools require an explicit schema (at least one property) since the `{param}` placeholders in URL/headers/body need named parameters. -- [server/customtool.go, lines 410-440](/home/user/ARTEX/server/customtool.go)

- Each custom tool is wrapped into a `actool.CoreTool` via `actool.Build(actool.Spec{...})` with auto-allowed permissions. The tool's `Run` function dispatches to `runCommandTool`, `runScriptTool`, or `runHTTPTool` based on `kind`. -- [server/customtool.go, lines 378-407](/home/user/ARTEX/server/customtool.go)

- A test endpoint (`pgTestCustomTool`) allows dry-running an exec spec with sample params without persisting the tool. -- [server/customtool.go, lines 159-212](/home/user/ARTEX/server/customtool.go)

- HTTP tools pass through the target gate (`intercept.GateRenderedURL`) and the egress governor (`egress.Current().Transport`), and can optionally route through the recording proxy for traffic capture. -- [server/customtool.go, lines 551-604](/home/user/ARTEX/server/customtool.go)

- Script tools use a configurable Python interpreter (auto-detected as `python3`/`python`, or user-set via the `python_interpreter` setting). Parameters are passed both as JSON on stdin and as `TOOL_<NAME>` environment variables for scalar values. -- [server/customtool.go, lines 467-547](/home/user/ARTEX/server/customtool.go)

- Secret masking: header values, proxy, and body fields in HTTP tool exec specs are masked on API readback using `maskToolExec`, and `unmaskToolExec` restores them on update, refusing to carry stored secrets to a changed destination (URL or kind). -- [server/customtool.go, lines 272-347](/home/user/ARTEX/server/customtool.go)

### Inferences

- To add a new custom tool, one calls the CRUD API with a key, kind, exec spec (command string, Python code, or HTTP method/URL/headers/body), and optionally a JSON Schema for parameters.
- The `shell` kind is for environment hints only and cannot be executed directly -- it surfaces in the Bash tool description.
- The `Deferred` flag likely controls whether the tool is loaded eagerly or lazily by the agent.

### Gaps

- The `Agents` field on custom tools suggests binding to specific agent types, but the exact binding mechanism was not traced in this research.


## How does MCP (Model Context Protocol) integration work?

### Takeaway

ARTEX supports three MCP transports -- stdio, Streamable HTTP, and legacy SSE -- each connecting to external MCP servers, listing their tools, and wrapping them into the same `actool.CoreTool` shape (named `mcp__<server>__<tool>`) so the LLM agent can call them alongside built-in and custom tools. -- Source: [mcphttp/client.go](/home/user/ARTEX/mcphttp/client.go), [server/mcpdiscover.go](/home/user/ARTEX/server/mcpdiscover.go)

### Cited Findings

- The `mcphttp` package implements two transports: **Streamable HTTP** (JSON-RPC over HTTP POST, server replies as `application/json` or `text/event-stream`) via `New()`, and **legacy SSE** (GET `/sse` + POST `/message`) via `NewSSE()`. -- [mcphttp/client.go, lines 1-9, 166-265](/home/user/ARTEX/mcphttp/client.go)

- The `mcpClient` interface abstracts all three transports:
  ```go
  type mcpClient interface {
      Tools(context.Context) ([]actool.CoreTool, error)
      Close() error
  }
  ```
  -- [server/mcpdiscover.go, lines 18-21](/home/user/ARTEX/server/mcpdiscover.go)

- Server connection dispatches by transport:
  ```go
  case "stdio":  mcp.NewStdioClient(ctx, m.Name, command, envMap, args...)
  case "http":   mcphttp.New(ctx, m.Name, m.URL, envMap, m.Insecure, m.TimeoutSeconds)
  case "sse":    mcphttp.NewSSE(ctx, m.Name, m.URL, envMap, m.Insecure)
  ```
  -- [server/mcpdiscover.go, lines 24-52](/home/user/ARTEX/server/mcpdiscover.go)

- MCP servers are stored in the `mcp_servers` database table (via `db.MCPServer`) with fields: `Name`, `Transport` (stdio/http/sse), `Command`, `Args`, `URL`, `Env` (map of environment variables or HTTP headers), `Insecure` (skip TLS verification), `TimeoutSeconds`, `Enabled`. -- [server/mcpdiscover.go](/home/user/ARTEX/server/mcpdiscover.go)

- Tool naming: remote tools are named `mcp__<server>__<tool>` by the `ToolName` function, sharing the same namespace convention as stdio MCP tools. -- [mcphttp/client.go, line 40](/home/user/ARTEX/mcphttp/client.go)

- Protocol version negotiation: the client tries `2025-11-25`, then falls back to `2025-06-18`; legacy SSE uses `2024-11-05`. The server can respond with its negotiated version. -- [mcphttp/client.go, lines 33-35, 334-366](/home/user/ARTEX/mcphttp/client.go)

- Tool discovery is cached to the `mcp_tools_cache` table so the UI can show available tools without a live MCP connection. Auto-discovery runs on startup for enabled MCP servers with empty caches. -- [server/mcpdiscover.go, lines 56-100](/home/user/ARTEX/server/mcpdiscover.go)

- Each remote tool is wrapped with an `actool.Spec` that asks the user for permission (`permission.AskUser("call MCP tool ...")`) and handles output size via `actool.Capture` (truncation at session's MaxOutputChars, spill to disk when configured). Max response size is 8 MiB (`mcpMaxRPCBytes`). -- [mcphttp/client.go, lines 37, 403-449](/home/user/ARTEX/mcphttp/client.go)

- The `Client.Call()` method provides a programmatic bypass of the agent permission layer for backend batch jobs (e.g. asset sync). -- [mcphttp/client.go, lines 456-479](/home/user/ARTEX/mcphttp/client.go)

- Safety: redirect policy refuses redirects that leave the origin of the configured endpoint, session cleanup sends a DELETE with the session id per the Streamable HTTP spec, and an SSE endpoint must stay on the same origin as the configured SSE URL. -- [mcphttp/client.go, lines 108-162, 270-301, 483-515](/home/user/ARTEX/mcphttp/client.go)

### Inferences

- To add a new MCP server, one creates a `db.MCPServer` record with the transport, command/URL, environment map (which serves as HTTP headers for http/sse transports), and optionally enables TLS skip for self-signed certs.
- The env map for HTTP/SSE transports doubles as custom headers, so a bearer token is configured as `{"Authorization": "Bearer ..."}`.

### Gaps

- The stdio transport implementation is in the `norma/mcp` package (external dependency), not in the ARTEX repository itself.


## What notification channels are supported?

### Takeaway

ARTEX supports six notification channels -- DingTalk, Feishu/Lark, WeCom, Generic Webhook, Telegram, and SMTP Email -- all implementing a stateless `Channel` interface with per-channel validation, delivery, rate limiting, secret masking, and destination-aware credential protection; a rich filter system controls which findings reach each channel. -- Source: [notify/channel.go](/home/user/ARTEX/notify/channel.go), [notify/notify.go](/home/user/ARTEX/notify/notify.go)

### Cited Findings

- The `Channel` interface is the extension point for new notification channels:
  ```go
  type Channel interface {
      Kind() string
      Validate(cfg map[string]any) error
      Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
      DefaultRatePerMin() int
      SecretKeys() []string
      DestinationKeys() []string
  }
  ```
  -- [notify/channel.go, lines 14-55](/home/user/ARTEX/notify/channel.go)

- The channel registry is an explicit map literal (not self-registration):
  ```go
  var registry = map[string]Channel{
      KindDingTalk: dingTalkChannel{},
      KindFeishu:   feishuChannel{},
      KindWeCom:    weComChannel{},
      KindWebhook:  webhookChannel{},
      KindTelegram: telegramChannel{},
      KindEmail:    emailChannel{},
  }
  ```
  -- [notify/channel.go, lines 61-68](/home/user/ARTEX/notify/channel.go)

- Channel kind constants: `dingtalk`, `feishu`, `wecom`, `webhook`, `telegram`, `email`. -- [notify/notify.go, lines 22-28](/home/user/ARTEX/notify/notify.go)

- **DingTalk**: HMAC-SHA256 signing, rate-limited to 20 msg/min, renders as ActionCard (with detail link) or Markdown. Secret keys: `webhook`, `secret`. -- [notify/dingtalk.go](/home/user/ARTEX/notify/dingtalk.go)

- **Telegram**: Bot API with HTML parse mode, 20 msg/min rate limit, supports custom `base_url` for self-hosted reverse proxies. Secret keys: `bot_token`. Destination keys: `base_url`. -- [notify/telegram.go](/home/user/ARTEX/notify/telegram.go)

- **Email**: Full SMTP with STARTTLS/implicit TLS, authentication, RFC 5322 messages with base64 encoding, 60 msg/min default. Secret keys: `password`. Destination keys: `host`, `port`, `tls`. Includes SSRF protection via `blockInternalDial`. -- [notify/email.go](/home/user/ARTEX/notify/email.go)

- **Generic Webhook**: Covers Slack/Mattermost/Discord/self-hosted via configurable method (GET/POST/PUT/PATCH), custom headers, and a Go `text/template` body template with `json` and `jsons` helper functions. Default template renders findings as a JSON structure. Secret keys: `url`, `headers`. No default rate limit. -- [notify/webhook.go](/home/user/ARTEX/notify/webhook.go)

- The `Send` method returns `(kept int, error)` where `kept` is the number of items actually delivered (to handle platform message length limits and batched truncation). `PermanentError` marks failures that should not be retried. -- [notify/channel.go, lines 24-34, 97-115](/home/user/ARTEX/notify/channel.go)

- Filter system (`notify/filter.go`): channels can filter by minimum severity, task IDs, asset IDs, vulnerability class include/exclude keywords (case-insensitive substring), and status-change opt-in. Parsing never fails (degrades to no filtering, favoring over-push over missed alerts). -- [notify/filter.go](/home/user/ARTEX/notify/filter.go)

- Event types: `finding_created` and `finding_status_changed`. Events carry immutable `Snapshot` structs with the finding's state at event time, stored in `notification_events.snapshot`. -- [notify/event.go](/home/user/ARTEX/notify/event.go)

- SSRF protection: all HTTP deliveries go through `blockInternalDial` (loopback/link-local addresses blocked by default, overridable with `ARTEX_NOTIFY_ALLOW_LOCAL=1`); cross-host redirects are refused; request target addresses are redacted in error messages to prevent credential leakage. -- [notify/http.go](/home/user/ARTEX/notify/http.go)

- Credential protection: `SecretKeys()` and `DestinationKeys()` together prevent credential forwarding: changing a destination key requires re-entering all secret keys, so stored credentials cannot be silently redirected to an attacker-controlled server. -- [notify/channel.go, lines 39-55](/home/user/ARTEX/notify/channel.go)

### Inferences

- To add a new notification channel: implement the `Channel` interface, register it in the `registry` map literal in `channel.go`, define a new `Kind*` constant. The compile-time visible registry means omissions surface at compile time.
- The webhook channel is intentionally generic enough to cover most platforms without needing dedicated implementations.

### Gaps

- The delivery orchestration (rate limiting, batching, retry with backoff) lives in the server layer, not in the `notify` package itself; the exact dispatcher was not traced.


## How does LLM provider integration work?

### Takeaway

ARTEX supports five LLM provider formats -- Anthropic, OpenAI (Chat Completions), OpenAI Responses, Ollama (local/keyless), and Bedrock Gateway (AWS) -- each configurable via environment variables or saved profiles, with per-provider transport adaptation, quota-aware HTTP transport, and comprehensive retry/rate-limiting configuration. -- Source: [agent/provider.go](/home/user/ARTEX/agent/provider.go), [agent/bedrock_gateway.go](/home/user/ARTEX/agent/bedrock_gateway.go)

### Cited Findings

- The `Config` struct describes one LLM backend:
  ```go
  type Config struct {
      Format         llm.Format
      BaseURL        string
      APIKey         string
      Model          string
      Proxy          string
      RatePerSecond  float64
      RatePerMinute  float64
      ContextWindowK int
      ThinkingType   string   // "" | "disabled" | "enabled"
      ReasoningEffort string  // "" | "low" | "medium" | "high" | "xhigh" | "max"
      Stream          bool
      MaxTokens       int
      MaxTokensField  string  // "" (max_tokens) | "max_completion_tokens"
      SessionHeaderKey string
      UserAgent        string
      CustomHeaders    string
      Retry            RetryConfig
  }
  ```
  -- [agent/provider.go, lines 35-101](/home/user/ARTEX/agent/provider.go)

- Provider format constants:
  - `llm.FormatAnthropic` (default, model: `claude-opus-4-8`)
  - `llm.FormatOpenAI` (model: `gpt-4o`)
  - `llm.FormatOpenAIResponses` (model: `gpt-5`)
  - `FormatOllama` (custom, mapped to OpenAI wire format; model: `llama3.2`, default base URL: `http://127.0.0.1:11434/v1`)
  - `FormatBedrockGateway` (custom, mapped to Anthropic wire format with request/response adaptation)
  -- [agent/provider.go, lines 140-151, 224-298](/home/user/ARTEX/agent/provider.go)

- Environment-based configuration:
  ```
  ARTEX_LLM_PROVIDER   = anthropic|openai|openai-responses|ollama|bedrock-gateway
  ARTEX_LLM_MODEL      = model id
  ARTEX_LLM_BASE_URL   = endpoint
  ARTEX_LLM_PROXY      = proxy URL (http/https/socks5)
  ANTHROPIC_API_KEY / OPENAI_API_KEY = credentials
  ARTEX_LLM_API_KEY    = bearer token (bedrock-gateway)
  ARTEX_LLM_STREAM     = true/false
  ARTEX_LLM_CUSTOM_HEADERS = newline-separated headers (bedrock-gateway)
  ```
  -- [agent/provider.go, lines 223-298](/home/user/ARTEX/agent/provider.go)

- `NewProvider()` builds an `llm.Provider` with a `quotaAwareTransport` that intercepts 429 responses whose body indicates quota exhaustion (not just rate limiting) and rewrites them to 402 so the pool's failover logic can distinguish "try again later" from "this key is dead". -- [agent/provider.go, lines 381-440, 486-543](/home/user/ARTEX/agent/provider.go)

- `ConfigFrom()` builds a Config from UI-provided strings with normalization (stripping endpoint suffixes, Ollama base URL normalization). -- [agent/provider.go, lines 304-350](/home/user/ARTEX/agent/provider.go)

- `TestConnection()` makes a minimal real completion ("ping" -> "OK") to verify the provider/model/endpoint/key work, with detailed wire-level logging of HTTP status and response body for each attempt. -- [agent/provider.go, lines 660-721](/home/user/ARTEX/agent/provider.go)

- **Bedrock Gateway**: `bedrockGatewayTransport` adapts Anthropic Messages API to Bedrock InvokeModel by rewriting request paths (`/model/<model>/invoke[-with-response-stream]`), adding `anthropic_version: "bedrock-2023-05-31"`, converting SSE events from Amazon EventStream format, and validating custom headers (up to 20, 8 KiB max, reserved headers refused). -- [agent/bedrock_gateway.go](/home/user/ARTEX/agent/bedrock_gateway.go)

- Retry configuration is three-layer: SDK connection retries (429/5xx/reset), SDK empty-response retries (OpenAI format), and stream-level safe-window retries (project-added, before any output). Each has attempts + interval controls. -- [agent/provider.go, lines 108-127](/home/user/ARTEX/agent/provider.go)

- Ollama uses a placeholder bearer token (`"ollama"`) to prevent the SDK from falling back to `OPENAI_API_KEY` (which would ship a real cloud key to the local server). -- [agent/provider.go, lines 155-157, 393-402](/home/user/ARTEX/agent/provider.go)

### Inferences

- To add a new LLM provider: add a new `llm.Format` constant, add a case in `FromEnv()` and `ConfigFrom()`, and if the wire format differs from Anthropic or OpenAI, implement a custom `http.RoundTripper` (as done for Bedrock Gateway).
- The `SessionHeaderKey` allows integration with gateways that do session-keyed prompt caching/sticky routing.

### Gaps

- The `llm.Provider` and `llm.Format` interfaces are defined in the external `norma/llm` package, not in the ARTEX repo.


## How does the LLM pool/rotation work?

### Takeaway

The `llmpool` package implements a failover chain of LLM profiles with circuit-breaker health tracking, priority-based ordering with round-robin load spreading within priority groups, context-window-aware filtering, and a process-wide health registry that persists to the database across restarts. -- Source: [llmpool/pool.go](/home/user/ARTEX/llmpool/pool.go), [llmpool/health.go](/home/user/ARTEX/llmpool/health.go)

### Cited Findings

- `Pool` implements `llm.Provider` with failover:
  ```go
  type Pool struct {
      members []*Member
      health  *Registry
      rr      atomic.Uint64 // rotates within equal-priority groups
  }
  ```
  Members are immutable after construction. -- [llmpool/pool.go, lines 49-53](/home/user/ARTEX/llmpool/pool.go)

- Each `Member` carries:
  ```go
  type Member struct {
      ID           int64
      Name         string
      Model        string
      Format       string // "anthropic" | "openai"
      Priority     int
      Active       bool
      Rank         int
      WindowTokens int
      Prov         llm.Provider
  }
  ```
  `Rank` determines ordering; `RankActive` (max int - 1) ensures the active profile always leads. -- [llmpool/pool.go, lines 21-37, 41](/home/user/ARTEX/llmpool/pool.go)

- The `Stream()` method has one hard rule: a member may only be abandoned **before** it has yielded any event. Once text or tool_use has reached the caller, re-sending would duplicate output. Fortunately, failover-eligible failures (402, 401, 429, 5xx) all surface during request establishment. -- [llmpool/pool.go, lines 75-123](/home/user/ARTEX/llmpool/pool.go)

- `shouldFailover()` returns true for: no HTTP status (transport failure), 401, 402, 403, 404, 408, 429, 5xx. Returns false for: context cancellation, 400 (bad request is identical everywhere). -- [llmpool/pool.go, lines 226-249](/home/user/ARTEX/llmpool/pool.go)

- `order()` filters members by: (1) skipping those in a cooling-off window, (2) skipping those whose context window cannot hold the estimated request size, then (3) rotating within equal-rank groups. If everything is filtered out, the head is tried anyway (stalling the engine is worse than one more failed request). Token estimation is ~3.5 chars/token. -- [llmpool/pool.go, lines 168-208](/home/user/ARTEX/llmpool/pool.go)

- `Registry` is the process-wide circuit breaker:
  ```go
  type State struct {
      Fails     int
      Trips     int
      OpenUntil time.Time
      LastError string
      LastAt    time.Time
  }
  ```
  Backoff ladder: 1 min, 5 min, 30 min (last rung repeats). Soft-trip threshold: 3 consecutive transient failures (configurable). Hard failures (401, 402, 403, 404) trip immediately. -- [llmpool/health.go, lines 22-39, 139-161](/home/user/ARTEX/llmpool/health.go)

- The registry supports `persist`/`forget` callbacks to mirror state to the DB, `Restore` for seeding from DB on startup, `Reset` for the UI's "Recover now" action, and `SetPolicy` for operator-configurable soft-trip threshold and cooldown. -- [llmpool/health.go, lines 44-71, 94-105, 204-212](/home/user/ARTEX/llmpool/health.go)

- `RecordCall()` unifies health tracking for both Pool-routed and direct-provider calls, ensuring a profile's state is consistent regardless of which path the request took. -- [llmpool/health.go, lines 170-202](/home/user/ARTEX/llmpool/health.go)

### Inferences

- The pool is rebuilt when the profile list changes (e.g., saving a profile), but the health registry outlives the pool so accumulated knowledge about broken backends persists.
- Multiple profiles at the same priority share load via round-robin rotation.

### Gaps

- The chain construction logic (how profiles are read from `llm_profiles` and ordered) is in the server layer, not in the `llmpool` package.


## How does the browser extension integrate?

### Takeaway

The ARTEX browser extension (Chrome Manifest V3) captures network traffic from a tab using the Chrome Debugger API and pushes request/response pairs in batches to the ARTEX server's `/api/traffic/ingest` endpoint, enabling operator-driven authenticated browsing sessions to become agent-visible evidence. -- Source: [extension/](/home/user/ARTEX/extension/)

### Cited Findings

- The extension is a Manifest V3 Chrome extension with permissions: `debugger`, `storage`, `tabs`, and `<all_urls>` host permissions. -- [extension/manifest.json](/home/user/ARTEX/extension/manifest.json)

- Capture flow: attaches to the active tab via `chrome.debugger.attach`, enables `Network.enable`, captures `requestWillBeSent` / `responseReceived` / `loadingFinished` events, retrieves response bodies via `Network.getResponseBody`, and queues `ExternalExchange` objects. -- [extension/background.js, lines 167-189](/home/user/ARTEX/extension/background.js)

- Batching: flushes at 10 entries (`FLUSH_AT`), max body size 256 KiB (`MAX_BODY`), skips binary MIME types (image/font/audio/video/octet-stream), queue capped at 200 entries on failure. -- [extension/background.js, lines 10-12](/home/user/ARTEX/extension/background.js)

- Configuration: server URL and API token stored in `chrome.storage.local`, set via the popup UI. -- [extension/background.js, lines 36-38](/home/user/ARTEX/extension/background.js)

- Ingest API call: `POST /api/traffic/ingest` with Bearer token, body `{ exchanges: [...] }`. Response contains `{ ingested, failed }` counts. -- [extension/background.js, lines 148-158](/home/user/ARTEX/extension/background.js)

- Each exchange object contains: `method`, `url`, `status`, `requestHeaders`, `requestBody`, `responseHeaders`, `responseBody`. -- [extension/background.js, lines 126-134](/home/user/ARTEX/extension/background.js)

### Inferences

- The extension is designed for manual pentest sessions where the operator browses authenticated surfaces and the captured traffic becomes evidence for the AI agent's analysis.
- The `/api/traffic/ingest` endpoint is the integration point for any external traffic source (not just the browser extension).

### Gaps

- The server-side implementation of `/api/traffic/ingest` was not read in this research.


## What is the traffic rewrite system?

### Takeaway

The `traffic/rewrite` package is a rule-based HTTP request/response transformation engine used by the capture proxy, supporting matchers (method, host, URL regex, headers, body regex, status) and actions (set/replace method, URL path, headers, body, status) in a pipeline model with safety constraints, sensitive-value masking, and binary/streaming detection. -- Source: [traffic/rewrite/rule.go](/home/user/ARTEX/traffic/rewrite/rule.go), [traffic/rewrite/engine.go](/home/user/ARTEX/traffic/rewrite/engine.go)

### Cited Findings

- Rules operate in two phases: `PhaseRequest` and `PhaseResponse`. Within a phase, rules pipeline (each sees the previous rule's output). Within a rule, actions execute in fixed order: method/URL, delete_header, set/replace_header, body, status. -- [traffic/rewrite/rule.go, lines 36-96](/home/user/ARTEX/traffic/rewrite/rule.go)

- The `Rule` model:
  ```go
  type Rule struct {
      ID       int64    `json:"id"`
      Name     string   `json:"name"`
      Enabled  bool     `json:"enabled"`
      Phase    Phase    `json:"phase"`
      Priority int      `json:"priority"`
      Matchers Matchers `json:"matchers"`
      Actions  []Action `json:"actions"`
      Note     string   `json:"note"`
  }
  ```
  -- [traffic/rewrite/rule.go, lines 86-96](/home/user/ARTEX/traffic/rewrite/rule.go)

- Matchers combine with AND: `Methods`, `Host` (exact or `*.suffix` glob), `URLRegex`, `Headers` (name + optional value regex), `BodyRegex`, `Status` (code or class like `4xx`), `RespHeaders`, `RespBodyRegex`. -- [traffic/rewrite/rule.go, lines 55-72](/home/user/ARTEX/traffic/rewrite/rule.go)

- Action types: `set_method`, `set_path_query`, `replace_url`, `delete_header`, `set_header`, `replace_header`, `set_body`, `replace_body`, `set_status`. Replace actions use `regexp.Expand` syntax (`$1`, `${name}`). The `Sensitive` flag on an action keeps its value out of API responses, traces, and rule snapshots. -- [traffic/rewrite/rule.go, lines 42-83](/home/user/ARTEX/traffic/rewrite/rule.go)

- Safety: rules fail open (error leaves the message unchanged), WebSocket upgrades are never rewritten, bodies over 1 MiB are skipped, compressed/binary bodies are skipped, hop-by-hop headers cannot be written, `Host`/`Content-Length`/`Transfer-Encoding`/`Connection`/`Proxy-*` headers are forbidden targets. Max regex size: 1 KiB, max value size: 1 MiB, max expansion: 1 MiB. -- [traffic/rewrite/rule.go, lines 24-30](/home/user/ARTEX/traffic/rewrite/rule.go), [traffic/rewrite/engine.go, lines 86-119, 122-165](/home/user/ARTEX/traffic/rewrite/engine.go)

- `Set.Apply(phase, input)` returns a `Result` with potentially rewritten request/response, change flag, trace lines (with before/after hashes and optional body), and a tainted-fields map (fields touched by sensitive actions get HMAC-masked hashes). -- [traffic/rewrite/engine.go, lines 42-55, 86-119](/home/user/ARTEX/traffic/rewrite/engine.go)

### Inferences

- The rewrite engine is used to modify traffic on the fly through the capture proxy -- for example, injecting authentication headers, modifying request paths, or redacting sensitive response content.
- The sensitive-action feature allows credential injection (e.g., setting an Authorization header) without the credential appearing in traces or logs.

### Gaps

- How rules are created and stored in the database was not traced (likely via a CRUD API similar to custom tools).


## How does the enrichment system work?

### Takeaway

The `enrich` package is an async worker pool that auto-completes the asset graph by resolving domains via DNS (dnsx) and probing web assets via HTTP, writing results (IPs, subdomains, HTTP service info) back into the asset store, with integration to the recording proxy for traffic capture and the intercept/egress systems for scope gating. -- Source: [enrich/enrich.go](/home/user/ARTEX/enrich/enrich.go)

### Cited Findings

- The `Engine` struct owns a DNS resolver (dnsx), an HTTP client routed through the recording proxy, and a worker pool (default 4 workers, queue size 1024). -- [enrich/enrich.go, lines 46-55, 67-92](/home/user/ARTEX/enrich/enrich.go)

- Two job types: `jobDNS` (resolve domain -> upsert IPs and subdomains) and `jobHTTP` (probe URL -> upsert HTTP service info with status code, content length, page title). -- [enrich/enrich.go, lines 33-44](/home/user/ARTEX/enrich/enrich.go)

- DNS resolution uses `dnsx` with question types A, AAAA, CNAME, default resolvers, 3 retries, 4s timeout. Results are written back via `as.UpsertIP`, `as.UpsertSubdomain`. -- [enrich/enrich.go, lines 198-236](/home/user/ARTEX/enrich/enrich.go)

- HTTP probing: GET request with assessment user agent, 12s timeout, body capped at 1 MiB, title extraction via regex. Routes through recording proxy (for traffic capture) and `intercept.PinnedDialer` (for scope gating). The egress governor applies per-request. -- [enrich/enrich.go, lines 97-129, 240-267](/home/user/ARTEX/enrich/enrich.go)

- Cooldown: 5 minutes per (kind, id) pair to prevent repeated enrichment of the same asset. Best-effort: dropped jobs when queue is full. -- [enrich/enrich.go, lines 57-58, 141-151, 182-193](/home/user/ARTEX/enrich/enrich.go)

### Inferences

- Enrichment is triggered by asset discovery elsewhere in the system (new domain found -> enqueue DNS, new site found -> enqueue HTTP probe).
- DNS enrichment is ungated (no scope check), while HTTP probing is gated by Rules of Engagement (the target scope travels on the request context).

### Gaps

- How enrichment is triggered (which callers call `ResolveDomain` and `ProbeSite`) was not traced.


## How do report templates work?

### Takeaway

The `report` package renders Markdown penetration test reports from an `Input` struct containing findings, asset counts, coverage data, and finding quality metadata, with honest proof-strength rendering (PoE level, verification state, bound traffic, rationale/counterevidence, stale-report warnings) and no template customization mechanism. -- Source: [report/report.go](/home/user/ARTEX/report/report.go), [report/quality.go](/home/user/ARTEX/report/quality.go)

### Cited Findings

- Report generation entry point:
  ```go
  type Input struct {
      Title       string
      Goal        string
      GeneratedAt time.Time
      AssetCounts map[string]int
      Findings    []*db.Node
      Coverage    *db.CoverageLedger
      Quality     map[int64]db.FindingQuality
  }
  func Markdown(in Input) string { ... }
  ```
  -- [report/report.go, lines 15-36, 67](/home/user/ARTEX/report/report.go)

- Report structure: title, task goal, generated timestamp, summary (finding count + asset counts), findings sorted by severity (critical first), and optional coverage gaps section. -- [report/report.go, lines 67-134](/home/user/ARTEX/report/report.go)

- Each finding renders: severity tag, name/vulnclass, summary, quality bullets (PoE level, verification state, bound traffic count, verification note), PoC/Evidence block, confidence rationale, counterevidence, stale-report warning, and detailed report body (capped at 8 KiB in task report, uncapped in per-finding export). -- [report/report.go, lines 92-115](/home/user/ARTEX/report/report.go)

- Quality rendering is explicitly honest:
  - Unavailable lookup: "quality lookup failed -- proof strength unavailable"
  - Missing record: "not assessed (no finding record)"
  - Zero bound traffic: "no bound traffic evidence" (always shown)
  - Stale report: "The evidence has changed; the detailed report needs updating."
  -- [report/quality.go, lines 103-166](/home/user/ARTEX/report/quality.go)

- The `Quality` struct tracks three distinct states: `Missing` (no standalone row), `Unavailable` (lookup failed), and present (with PoE, verification, notes, traffic count, report body, evidence version). -- [report/quality.go, lines 22-43](/home/user/ARTEX/report/quality.go)

### Inferences

- Report generation is code-driven (not user-customizable templates). To change the report format, one modifies the Go source.
- The report model is tightly coupled to the findings data model and the coverage ledger.

### Gaps

- Whether report generation is triggered via API or UI was not traced.
- The `report/findings.go` file was not read; it likely contains per-finding export formatting.


## How does the archivestore work for task archival?

### Takeaway

The `archivestore` package stores immutable cold-task packages in S3-compatible storage with mandatory server-side encryption, SHA-256 verified uploads/downloads, chunked reading with retry, and strict endpoint/bucket/prefix validation. -- Source: [archivestore/s3.go](/home/user/ARTEX/archivestore/s3.go)

### Cited Findings

- Configuration:
  ```go
  type Config struct {
      Endpoint, Region, Bucket, Prefix, AccessKey, SecretKey string
      PathStyle                                              bool
      SessionToken, SSE, KMSKeyID                            string
  }
  ```
  Configured via environment variables: `ARTEX_ARCHIVE_STORAGE` (local|s3), `ARTEX_ARCHIVE_S3_*`. -- [archivestore/s3.go, lines 30-34, 46-61](/home/user/ARTEX/archivestore/s3.go)

- Validation: endpoint must be HTTPS (HTTP only on loopback), no userinfo/query/fragment, bucket cannot contain `/\:@?# `, prefix is cleaned and defaults to `artex/tasks`. Encryption is mandatory (AES256 or aws:kms), KMS key must be a full key ARN. -- [archivestore/s3.go, lines 63-139](/home/user/ARTEX/archivestore/s3.go)

- URI format: `s3://<bucket>/<prefix>/task-<taskID>-<archiveID>-<checksum>.tar.zst`. -- [archivestore/s3.go, line 141](/home/user/ARTEX/archivestore/s3.go)

- Upload: multipart (8 MiB parts, 2 concurrency), followed by full read-back verification (chunked at 8 MiB, 5 retries per chunk with exponential backoff). On verification failure, the uploaded object is deleted (version-aware for versioned buckets). -- [archivestore/s3.go, lines 165-226](/home/user/ARTEX/archivestore/s3.go)

- Download: chunked reading with SHA-256 verification, ETag pinning (IfMatch) to ensure consistency, encryption verification. Output file created with mode 0o600. -- [archivestore/s3.go, lines 228-363](/home/user/ARTEX/archivestore/s3.go)

- Safety: no redirects (signed requests cannot be redirected to another origin), explicit credential management (static credentials or default AWS config chain), SDK retries disabled per-chunk (the application owns retry logic). -- [archivestore/s3.go, lines 126-137](/home/user/ARTEX/archivestore/s3.go)

### Inferences

- The archive store is used for cold storage of completed task data (findings, evidence, traffic captures). The local backend is the default; S3 is opt-in.
- The `.tar.zst` format suggests tasks are packaged as compressed tarballs before archival.

### Gaps

- How tasks are packaged before upload (the tarball creation) was not traced.


## What webhook/API integration points exist?

### Takeaway

ARTEX exposes multiple API integration points: the custom tool CRUD API, the MCP server management API, the notification channel CRUD/test API, the traffic ingest endpoint (`/api/traffic/ingest`), the generic webhook notification channel (outbound), and the report generation API, all served as JSON REST endpoints under `/api/`. -- Source: various files

### Cited Findings

- **Custom tool API**: POST create, PUT update (by key), DELETE (by key), POST test (dry-run). -- [server/customtool.go, lines 50-212](/home/user/ARTEX/server/customtool.go)

- **Traffic ingest API**: `POST /api/traffic/ingest` accepts `{ exchanges: [...] }` with Bearer token auth (used by the browser extension and potentially other external traffic sources). -- [extension/background.js, lines 148-158](/home/user/ARTEX/extension/background.js)

- **Outbound webhook channel**: configurable method, URL, headers, and body template for pushing findings/status-changes to any HTTP endpoint (Slack, Discord, Mattermost, custom). -- [notify/webhook.go](/home/user/ARTEX/notify/webhook.go)

- **MCP server management**: CRUD for MCP server configurations, health status tracking (`UpdateMCPHealth`), tool cache (`SaveMCPTools`). -- [server/mcpdiscover.go](/home/user/ARTEX/server/mcpdiscover.go)

### Inferences

- The `/api/traffic/ingest` endpoint is the main inbound integration point for external tools to feed traffic data into ARTEX.
- The webhook channel is the main outbound integration point for pushing notifications to external systems.

### Gaps

- A complete API route listing was not extracted in this research. The server routes are likely defined in a routes file not read here.
- Authentication mechanisms (JWT, API tokens) for the REST API were not traced.


## Feishu and WeCom notification channels

### Takeaway

Feishu (Lark) and WeCom are Chinese enterprise messaging platforms supported as notification channels, each with their own signing, rate limiting, and message formatting. -- Source: [notify/feishu.go](/home/user/ARTEX/notify/feishu.go), [notify/wecom.go](/home/user/ARTEX/notify/wecom.go)

### Cited Findings

- **Feishu**: supports Lark international, rate-limited (documented as 5 msg/min for group bots), HMAC-SHA256 signing, renders as interactive card messages. Secret keys: `webhook`, `secret`. -- Inferred from file listing; file not read in full.

- **WeCom**: group bot webhook, the entire webhook URL is a credential. Secret keys include the webhook URL. -- Inferred from channel.go registry entry.

### Inferences

- Both follow the same `Channel` interface pattern as DingTalk and Telegram.

### Gaps

- The full implementation of Feishu and WeCom was not read in this research.
