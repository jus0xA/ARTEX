# ARTEX Data Model, Skills System, and Configuration

## PostgreSQL Schema: Core Tables and Structure

### Takeaway
ARTEX uses a single PostgreSQL database as its source of truth, organized into ~30+ tables across distinct layers: asset graph, exploration graph, task management, LLM profiles, agent definitions, MCP servers, interception rules, findings with traffic evidence, notifications, and an RSI lesson library. The schema is applied idempotently at every startup (`db/schema.sql`), with numbered migrations in `db/migrations/` for additive changes.

### Cited Findings

**Schema application strategy**: The schema file is idempotent (uses `IF NOT EXISTS`, `OR REPLACE`, `DROP TRIGGER IF EXISTS`), runs at every startup, and backfills old databases with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. Numbered migrations in `db/migrations/` handle additive schema changes (14 migrations as of the current codebase). -- Source: `db/schema.sql` lines 1-3; `README.md` line ~795

**Core tables by section** (from schema.sql section comments):

| Section | Tables | Purpose |
|---------|--------|---------|
| A. Asset layer | `companies`, `assets`, `company_scope` | Shared asset graph |
| B. Exploration | `explorations`, `exploration_nodes`, `exploration_edges`, `exploration_anchors`, `task_constraints`, `activity`, `main_sessions` | Per-task reasoning graph |
| C. LLM profiles | `settings`, `llm_profiles`, `llm_profile_health` | Model configuration and failover |
| D. Task layer | `task_categories`, `tasks`, `task_archives`, `task_templates`, `task_relations`, `task_asset_links`, `task_llm_profiles`, `task_scope` | Task lifecycle |
| E. Agents | `agents`, `agent_prompts`, `agent_prompt_vars` | Agent definitions and versioned prompts |
| F. MCP servers | `mcp_servers`, `mcp_tools_cache` | External tool integration |
| G. Visibility | `agent_visibility`, `agent_skill_visibility`, `skill_usage`, `tool_usage` | Agent-to-resource bindings |
| H. Tool catalog | `tools` | Built-in tool registry |
| I. Sessions | `conversations`, `conversation_activities` | Chat page sessions |
| J. Triggers | `agent_triggers`, `scheduler_state` | Event-driven agent invocation |
| K. Interception | `intercept_rules`, `intercept_pending`, `target_pins`, `target_gate_exemption_log` | Tool call approval gates |
| L. Findings | `findings`, `finding_retests`, `traffic_evidence_snapshots`, `finding_traffic_bindings` | Vulnerability records with evidence |
| M. Misc | `server_logs`, `side_question_sessions/requests`, `asset_intercept_rules`, `task_intercept_rules`, `task_credentials`, `notification_channels/events/deliveries` | Logging, side questions, notifications |
| RSI | `rsi_lessons`, `rsi_lesson_evidence`, `rsi_lesson_usage` | Lesson library from past tasks |
| Coverage | `coverage_ledger`, `coverage_ledger_history` | Agent-reported test coverage |

-- Source: `db/schema.sql` section comments and table definitions

**Migrations** (14 numbered files in `db/migrations/`):
- `0001_llm_records.sql` -- LLM call recording table
- `0002_llm_usage.sql` -- Token usage accounting
- `0003_task_scope_icp_index.sql` -- Index for ICP scope entries
- `0004_llm_usage_ts_index.sql` -- Timestamp index on usage
- `0005_traffic_rewrite_rules.sql` -- Capture proxy rewrite rules (encrypted at rest)
- `0006_activity_outbox.sql` -- Activity outbox pattern
- `0007_finding_report_state.sql` -- Finding report stage tracking
- `0008_traffic_evidence_rewrite_flag.sql` -- Rewrite flag on evidence
- `0009_llm_context.sql` -- Per-call LLM context size telemetry
- `0010_dashboard_usage_indexes.sql` -- Dashboard query indexes
- `0011_traffic_tamper_hooks.sql` -- Go tampering hooks for capture proxy
- `0012_lesson_withdrawn.sql` -- Lesson withdrawal tracking
- `0013_lesson_evidence_history.sql` -- Evidence history with surrogate key
- `0014_bedrock_gateway_profiles.sql` -- Bedrock gateway LLM format

-- Source: `db/migrations/*.sql` file listing

### Inferences
- The schema is designed for zero-downtime upgrades: idempotent baseline + ordered migrations, all applied automatically at startup.
- No manual database step is ever needed for upgrades; the binary is the upgrade.

### Gaps
- None for this question; the schema is fully documented in `db/schema.sql`.

---

## Asset Graph Structure

### Takeaway
The asset graph is a globally shared, company-scoped inventory of infrastructure entities. Assets have six types (`root_domain`, `ip`, `subdomain`, `app`, `service`, `endpoint`) with per-type uniqueness constraints and rich metadata columns. Companies own assets through `company_id`, with scope rules in `company_scope` controlling auto-attribution. Parent-child relationships (domain->subdomain->service->endpoint) are computed by the program; agents only submit raw observations.

### Cited Findings

**`assets` table** (central entity, ~40 columns):
```sql
CREATE TABLE IF NOT EXISTS assets (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL CHECK (type IN (
                        'root_domain','ip','subdomain','app','service','endpoint'
                    )),
    company_id      BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    company_source  TEXT NOT NULL DEFAULT 'explicit'
                    CHECK (company_source IN ('explicit','scope')),
    task_ids        BIGINT[] NOT NULL DEFAULT '{}',
    domain          TEXT,
    root_domain     TEXT,
    ip              TEXT,
    ...
    url             TEXT,
    service_type    TEXT CHECK (service_type IN ('http','other')),
    technologies    TEXT[]  NOT NULL DEFAULT '{}',
    extra           JSONB   NOT NULL DEFAULT '{}',
    ...
);
```
-- Source: `db/schema.sql` lines 41-83

**Per-type uniqueness constraints**:
- `root_domain`: unique on `domain` where type='root_domain'
- `ip`: unique on `ip` where type='ip'
- `subdomain`: unique on `(domain, COALESCE(record_type,''))` where type='subdomain'
- `app`: unique on `bundle_id` or `app_name`
- `service` (http): unique on `url`
- `service` (other): unique on `(domain, ip, port, service_name)`
- `endpoint`: unique on `(url, method)`

-- Source: `db/schema.sql` lines 84-92

**`companies` table**: organizational grouping with `nkey` (normalized key) for dedup.
```sql
CREATE TABLE IF NOT EXISTS companies (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL,
    nkey TEXT NOT NULL UNIQUE, logo TEXT, ...
);
```
-- Source: `db/schema.sql` lines 28-39

**`company_scope` table**: defines how assets are auto-attributed to companies. Five `kind` values: `domain`, `ip`, `cidr`, `icp`, `keyword`. Payload constraint ensures the right columns are populated per kind.
-- Source: `db/schema.sql` lines 116-149

**`task_asset_links` table**: records provenance of each task-asset association (source: `system`, `legacy`, `agent`), with a trigger (`sync_task_asset_links`) that keeps it synchronized with the legacy `assets.task_ids` array.
-- Source: `db/schema.sql` lines 675-719

**`task_scope` table**: defines the coverage denominator for a task (what assets are in scope). Kinds include `company`, `root_domain`, `subdomain`, `ip`, `cidr`, `icp`, `keyword`. Source can be `auto` (system-filled), `agent`, or `manual`.
-- Source: `db/schema.sql` lines 760-791

### Inferences
- The asset graph is designed for deduplication: agents submit raw observations and the system computes containment and uniqueness.
- Company attribution can be `explicit` (operator-set) or `scope` (derived from company_scope rules), allowing automatic asset-to-company mapping.
- The `task_ids` array on assets is a legacy mechanism; `task_asset_links` is the new provenance-tracking replacement.

### Gaps
- None; the asset layer is well-documented in schema.sql.

---

## Exploration Graph Structure

### Takeaway
The exploration graph is a per-task directed acyclic graph of reasoning nodes connected by typed edges. Nodes have kinds (`begin`, `goal`, `intent`, `fact`, `finding`, `hint`, `digest`) with kind-specific state machines. Edges carry relationship types (`spawns`, `derived_from`, `yields`, `proves`, `covers`). Anchors link exploration nodes to assets, forming the bridge between the two graphs. The planner generates intents, workers claim and execute them, and results are written back as facts/findings.

### Cited Findings

**`explorations` table**: top-level container for a task's reasoning.
```sql
CREATE TABLE IF NOT EXISTS explorations (
    id          BIGSERIAL PRIMARY KEY,
    description TEXT,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','achieved','failed')),
    round_no    BIGINT NOT NULL DEFAULT 0,
    ...
);
```
`round_no` is bumped each planner wake-up; used for cold-node debounce.
-- Source: `db/schema.sql` lines 154-169

**`exploration_nodes` table**: the core graph entities.
```sql
CREATE TABLE IF NOT EXISTS exploration_nodes (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}',
    priority       INT  NOT NULL DEFAULT 0,
    state          TEXT NOT NULL DEFAULT 'open',
    origin         TEXT,
    owner          TEXT,
    ...
);
```
-- Source: `db/schema.sql` lines 171-204

**Node kinds and their state machines**:
| Kind | Valid States |
|------|-------------|
| `begin` | `open` |
| `intent` | `open`, `running`, `paused`, `done`, `blocked`, `exhausted`, `stopped`, `deleted` |
| `goal` | `open`, `met`, `abandoned` |
| `fact` | `confirmed`, `dismissed`, `origin` |
| `finding` | `confirmed`, `dismissed` |
| `hint` | `active`, `consumed` |
| `digest` | `active`, `superseded` |

-- Source: `db/schema.sql` lines 185-195 (ck_node_state constraint)

**Intent claiming**: Nodes have `last_heartbeat_at` and `unclaim_token` for lease-based intent claiming. A running intent whose heartbeat is older than `db.IntentClaimTTL` may be taken over.
-- Source: `db/schema.sql` lines 208-210

**`exploration_edges` table**: directed relationships between nodes.
```sql
CREATE TABLE IF NOT EXISTS exploration_edges (
    exploration_id BIGINT NOT NULL,
    src_id         BIGINT NOT NULL,
    dst_id         BIGINT NOT NULL,
    rel            TEXT NOT NULL,
    PRIMARY KEY (exploration_id, src_id, rel, dst_id),
    CONSTRAINT ck_edge_rel CHECK (rel IN ('spawns','derived_from','yields','proves','covers'))
);
```
-- Source: `db/schema.sql` lines 256-282

**Edge semantics** (from README and schema):
- `spawns`: goal -> intent (goal decomposition)
- `derived_from`: fact -> intent (a fact inspires a new direction)
- `yields`: intent -> fact (execution produces observations)
- `proves`: intent -> finding (execution proves a vulnerability)
- `covers`: digest -> member nodes (cold-digest aggregation)

-- Source: `db/schema.sql` line 264; `README.md` lines 142-166

**`exploration_anchors` table**: links nodes to assets.
```sql
CREATE TABLE IF NOT EXISTS exploration_anchors (
    node_id   BIGINT NOT NULL REFERENCES exploration_nodes(id),
    asset_id  BIGINT NOT NULL REFERENCES assets(id),
    PRIMARY KEY (node_id, asset_id)
);
```
This powers asset test coverage and the coverage graph visualization.
-- Source: `db/schema.sql` lines 284-289

**`task_constraints` table**: operator-authored allow/deny rules extracted from the goal/description, injected into planner/worker prompts.
-- Source: `db/schema.sql` lines 295-304

**`activity` table**: append-only log of everything that happens in an exploration (tool calls, LLM responses, errors). Records `worker`, `kind`, `tool`, `tool_use_id`, token counts, and optional `metadata` JSONB. Supports main-agent session segmentation via `main_seg`.
-- Source: `db/schema.sql` lines 306-347

### Inferences
- The exploration graph is a reasoning trace: it captures not just what was found, but WHY each direction was explored and what produced each result.
- The cold-digest mechanism (`content_version`, `cold_since_round`, `covers` edges) compresses stale branches for efficiency in long-running tasks.
- The intent claim/heartbeat system enables concurrent workers to safely claim and execute intents without conflict.

### Gaps
- None for the graph structure itself.

---

## Findings and Evidence

### Takeaway
Findings are stored in the `findings` table with rich metadata (vulnerability class, severity, summary, evidence text, verification status, POE level). Evidence is linked through a two-table binding system: `traffic_evidence_snapshots` stores immutable snapshots of HTTP exchanges, and `finding_traffic_bindings` connects findings to those snapshots with roles and positions. The evidence store (`evidence/store.go`) manages content-addressed blob storage on disk with a 24-hour garbage collection grace period.

### Cited Findings

**`findings` table** (key columns):
```sql
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT REFERENCES tasks(id),
    node_id     BIGINT REFERENCES exploration_nodes(id),
    vulnclass   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    report      TEXT NOT NULL DEFAULT '',
    poe_level            SMALLINT NOT NULL DEFAULT 0,
    verification_status  TEXT NOT NULL DEFAULT 'unverified',
    verification_note    TEXT NOT NULL DEFAULT '',
    counterevidence      TEXT NOT NULL DEFAULT '',
    confidence_rationale TEXT NOT NULL DEFAULT '',
    report_state         TEXT NOT NULL DEFAULT 'none',
    ...
);
```
Status values: `pending`, `in_progress`, `confirmed`, `resolved`, `fixed`, `false_positive`, `ignored`, `duplicate`, `risk_accepted` (validated server-side, no CHECK constraint).
Verification status: `verified`, `unverified`, `blocked`, `not_assessed`, `false_positive`.
Report state (post-triage): `none`, `submitted`, `accepted`, `rejected`, `duplicate`.
-- Source: `db/schema.sql` lines 1188-1267

**`traffic_evidence_snapshots` table**: immutable records of HTTP exchanges.
```sql
CREATE TABLE IF NOT EXISTS traffic_evidence_snapshots (
    id TEXT PRIMARY KEY,
    source_traffic_id TEXT NOT NULL,
    captured_at BIGINT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    req_head TEXT NOT NULL,
    resp_head TEXT NOT NULL,
    req_hash TEXT NOT NULL,  -- SHA-256 of request body blob
    resp_hash TEXT NOT NULL, -- SHA-256 of response body blob
    req_len BIGINT NOT NULL,
    resp_len BIGINT NOT NULL,
    ...
);
```
-- Source: `db/schema.sql` lines 1269-1285

**`finding_traffic_bindings` table**: links findings to snapshots with role and position.
```sql
CREATE TABLE IF NOT EXISTS finding_traffic_bindings (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id),
    snapshot_id TEXT NOT NULL REFERENCES traffic_evidence_snapshots(id),
    role TEXT NOT NULL DEFAULT 'supporting',
    note TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    UNIQUE(finding_id, snapshot_id)
);
```
-- Source: `db/schema.sql` lines 1286-1297

### Inferences
- Findings have a dual-track status system: `status` for human disposition (pending/confirmed/fixed/etc.) and `verification_status` for machine-checked proof strength. These are independent.
- The POE (Proof of Exploitation) level and verification status enable graduated confidence in findings.
- Report state tracks the external reporting lifecycle separately from internal disposition.

### Gaps
- None for the findings model.

---

## Evidence Store

### Takeaway
The evidence store (`evidence/store.go`) is a content-addressed blob store that persists HTTP request/response bodies independently of the disposable traffic capture. Bodies are stored as SHA-256-addressed `.bin` files in a `blobs/` directory tree (sharded by first two hex characters). Writes use atomic staging (temp file -> fsync -> rename), and garbage collection runs hourly with a 24-hour grace period for unreferenced blobs.

### Cited Findings

**Store structure**:
```go
type Store struct {
    DB      *db.DB
    Traffic *traffic.Traffic
    Dir     string   // root directory for blob storage
}
```
-- Source: `evidence/store.go` lines 24-28

**Content-addressed storage**: Bodies are stored at `<Dir>/blobs/<hash[:2]>/<hash>.bin` where hash is a lowercase hex SHA-256.
```go
func hashPath(dir, hash string) (string, error) {
    return filepath.Join(dir, "blobs", hash[:2], hash+".bin"), nil
}
```
-- Source: `evidence/store.go` lines 34-42

**Atomic writes** (`writeBody`): writes to a staging directory (`.staging/`), computes SHA-256 during write, calls `fsync`, then atomically renames to the final content-addressed path. Existing blobs are verified rather than overwritten.
-- Source: `evidence/store.go` lines 63-117

**Key operations**:
- `Record()`: Creates a finding with bound traffic evidence in a single transaction (advisory lock on task).
- `Bind()`: Adds traffic evidence to an existing finding (advisory lock on finding).
- `OpenBody()`: Returns an `os.File` handle for streaming a body blob; called without holding the evidence lock to avoid blocking writes during large downloads.
- `CopySnapshots()`: Makes real file copies (not links) for exports and archives.
- `InstallSnapshots()`: Restores archived evidence bodies back into the store.

-- Source: `evidence/store.go` lines 213-376

**Garbage collection** (`Collect` and `RunGC`):
1. Marks unreferenced snapshots with `unreferenced_at = now()`.
2. Deletes snapshots unreferenced for >24 hours (and not re-bound).
3. Walks `blobs/` and `.staging/` directories, removing files whose hash is not in any snapshot row AND whose mtime is >24 hours old.
4. Runs on an hourly ticker.

-- Source: `evidence/store.go` lines 378-450

### Inferences
- The 24-hour grace period prevents race conditions where a body is written but the SQL transaction hasn't committed yet.
- The `OpenBody` method deliberately operates outside the advisory lock to prevent large downloads from blocking all evidence writes process-wide.
- Bodies survive across tasks and archives; the content-addressed design means identical bodies are stored once.

### Gaps
- None for the evidence store internals.

---

## Skills System

### Takeaway
Skills are filesystem directories under a configurable skill root, each containing a `SKILL.md` file with YAML frontmatter (name, description, optional `mcps` field for MCP server dependencies) and Markdown body containing the skill's prompt/playbook content. Skills are loaded at agent runtime by matching directory names against the `agent_skill_visibility` table. When an agent invokes a skill, its MCP dependencies are unlocked (deferred tool pattern). The system ships 11 built-in skills focused on offensive security workflows.

### Cited Findings

**Skill directory structure**: Each skill is a directory under the skill root containing at minimum `SKILL.md`. Additional files (scripts, references) can be included.
```
skills/
  api-recon/
    SKILL.md
    reference.md
    scripts/
  codeaudit/
    SKILL.md
  rea/
    SKILL.md
  ...
```
-- Source: `skills/*/SKILL.md` file listing

**SKILL.md frontmatter format** (YAML between `---` delimiters):
```yaml
---
name: api-recon
description: Invoke this skill when collecting a website's API endpoints.
---
```
Optional `mcps` field declares MCP server dependencies:
```yaml
---
name: rea
description: "Reverse-engineer binaries..."
mcps: rea
---
```
-- Source: `skills/api-recon/SKILL.md` lines 1-4; `skills/rea/SKILL.md` lines 1-5

**Shipped skills** (11 total):

| Skill | Purpose |
|-------|---------|
| `api-recon` | Frontend API endpoint reconnaissance (static + runtime harvest) |
| `api-security` | API security testing |
| `bbot-recon` | BBOT-based reconnaissance |
| `codeaudit` | White-box source code audit (attacker-first forward analysis) |
| `edr-bypass-re` | EDR/AV telemetry analysis for adversary simulation |
| `patch-diff` | Patch diffing analysis |
| `php2shell` | PHP exploitation |
| `playwright-cli` | Browser automation with Playwright |
| `rea` | Binary reverse engineering via rea MCP server |
| `scopesentry` | ScopeSentry asset sync integration |
| `third-party-code-review` | Third-party code review |

-- Source: `skills/*/SKILL.md` file listing

**Skill loading** (`server/assembly.go` `wireAgentAugment` function):
1. Agent's visible skill names are fetched from `pg.AgentSkillNames(agentID)` (reads `agent_skill_visibility` table).
2. All skills are loaded from the filesystem with `loadSkillsConfined(skillDir)` -- uses `skill.LoadDir` from the norma SDK with symlink confinement (refuses symlinks that escape the skill directory).
3. Skills are matched by directory name (`filepath.Base(s.Dir)`), not by the display name in SKILL.md.
4. MCP servers named in a skill's `mcps:` field become "skill-gated" -- their tools are deferred (not available at session start) and only unlocked when the skill is invoked.

-- Source: `server/assembly.go` lines 31-69; `server/pathconfine.go` lines 222-314

**Skill creation tools** (platform tools for the Auto agent):
- `create_skill`: Creates a new skill directory with `SKILL.md`.
- `update_skill_file`: Writes/overwrites files inside a skill directory.

-- Source: `server/platform_tools.go` lines 84-132

**Skill usage tracking**: The `skill_usage` table records every `Skill()` call with dimensions (skill name, agent key, task/exploration/intent IDs, session ID, args length, and whether the skill was found). Misses (`found=false`) are tracked to inform which skills to add.
-- Source: `db/schema.sql` lines 941-956

### Inferences
- Skills are essentially prompt/playbook injection: when invoked, the SKILL.md content is loaded into the agent's context along with any additional files in the skill directory.
- The skill-gated MCP pattern provides a form of lazy loading: expensive MCP servers are only connected when a skill that needs them is actually invoked.
- Skills are hot-reloadable: the Docker Compose mounts `./skills` from the host, so changes require no image rebuild.

### Gaps
- The exact mechanism by which the Skill() meta-tool presents skill content to the LLM was not fully traced into the norma SDK internals (it's in the external `github.com/Autumn-27/norma/skill` package).

---

## Configuration and Environment Variables

### Takeaway
ARTEX uses a layered configuration system: environment variables take precedence over config file values, which default to sensible values. The config file is `config.json` (located via `ARTEX_CONFIG` env var, or CWD, or next to the binary). The database connection has three tiers of precedence: `ARTEX_PG_DSN` > `ARTEX_PG_*` component vars > config file `database` section. A missing config file yields zero config (defaults), but a malformed one is a hard error.

### Cited Findings

**Config file format** (`config/config.go`):
```go
type Config struct {
    Database       Database       `json:"database"`
    SkillDir       string         `json:"skill_dir"`
    TaskUserAgents TaskUserAgents `json:"task_user_agents,omitempty"`
}
type Database struct {
    DSN      string `json:"dsn"`
    Host     string `json:"host"`
    Port     int    `json:"port"`
    User     string `json:"user"`
    Password string `json:"password"`
    DBName   string `json:"dbname"`
    SSLMode  string `json:"sslmode"`
}
```
-- Source: `config/config.go` lines 20-35

**Config file resolution order**:
1. `ARTEX_CONFIG` env var (explicit override)
2. `./config.json` in CWD
3. `config.json` next to the executable

-- Source: `config/config.go` lines 99-114

**Database DSN precedence**:
1. `ARTEX_PG_DSN` (full connection URL, returned unchanged)
2. `ARTEX_PG_HOST` / `ARTEX_PG_PORT` / `ARTEX_PG_USER` / `ARTEX_PG_PASSWORD` / `ARTEX_PG_DBNAME` / `ARTEX_PG_SSLMODE` (assembled with percent-encoding)
3. Config file `database.dsn` or `database.*` fields
4. No fallback: returns error if none configured.

-- Source: `config/config.go` lines 165-199

**Skill directory precedence**:
1. `ARTEX_SKILL_DIR` env var
2. Config file `skill_dir`
3. `BaseDir()/skills`

-- Source: `config/config.go` lines 146-163

**Key `ARTEX_*` environment variables** (cataloged from source code, non-test files):

| Variable | Purpose | Source |
|----------|---------|--------|
| `ARTEX_CONFIG` | Path to config.json | `config/config.go` |
| `ARTEX_PG_DSN` | Full PostgreSQL connection URL | `config/config.go` |
| `ARTEX_PG_HOST` | PostgreSQL host | `config/config.go` |
| `ARTEX_PG_PORT` | PostgreSQL port (default 5432) | `config/config.go` |
| `ARTEX_PG_USER` | PostgreSQL user | `config/config.go` |
| `ARTEX_PG_PASSWORD` | PostgreSQL password (raw, percent-encoded by ARTEX) | `config/config.go` |
| `ARTEX_PG_DBNAME` | PostgreSQL database name | `config/config.go` |
| `ARTEX_PG_SSLMODE` | TLS mode (disable/require/verify-ca/verify-full) | `config/config.go` |
| `ARTEX_JWT_KEY_DIR` | Directory for jwt.key and secret.key | `config/config.go` |
| `ARTEX_SECRET_KEY` | Encryption key for secrets at rest (32 bytes, base64 or hex) | `db/secrets.go` |
| `ARTEX_SKILL_DIR` | Override skill root directory | `config/config.go` |
| `ARTEX_LLM_PROVIDER` | Default LLM format (anthropic/openai/openai-responses/ollama/bedrock-gateway) | `agent/provider.go` |
| `ARTEX_LLM_MODEL` | Default LLM model name | `agent/provider.go` |
| `ARTEX_LLM_BASE_URL` | Default LLM API base URL | `agent/provider.go` |
| `ARTEX_LLM_PROXY` | HTTP proxy for LLM API calls | `agent/provider.go` |
| `ARTEX_LLM_API_KEY` | Default LLM API key | `agent/provider.go` |
| `ARTEX_LLM_STREAM` | Streaming toggle for default profile | `agent/provider.go` |
| `ARTEX_LLM_CUSTOM_HEADERS` | Custom headers for LLM requests (newline-separated Name: Value) | `agent/provider.go` |
| `ARTEX_LLM_PRIVATE_ENDPOINTS` | Allowed private host:port for model-list fetch | `server/server.go` |
| `ARTEX_TRUSTED_PROXIES` | Comma-separated CIDRs for reverse proxy trust | `cmd/artex/main.go` |
| `ARTEX_UNTRUSTED_BOUNDARY` | Prompt-injection boundary (on by default; 0/false/off/no to disable) | `agent/untrusted_boundary.go` |
| `ARTEX_NOISE_PROFILE` | Target request pacing (off/quiet/balanced/aggressive) | `egress/egress.go` |
| `ARTEX_TARGET_USER_AGENT` | User-Agent for target requests | `egress/egress.go` |
| `ARTEX_UPDATE_CHECK` | Enable GitHub update check (1 to enable) | `server/update_check.go` |
| `ARTEX_RSI_LESSONS` | Enable RSI lesson library | `server/lessons.go` |
| `ARTEX_BTW_MAX_OUTPUT_TOKENS` | Max output tokens for /btw side questions | `server/side_questions.go` |
| `ARTEX_ARCHIVE_STORAGE` | Archive backend: `local` (default) or `s3` | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_ENDPOINT` | S3 endpoint URL | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_REGION` | S3 region | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_BUCKET` | S3 bucket name | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_PREFIX` | S3 key prefix | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_ACCESS_KEY_ID` | S3 access key | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_SECRET_ACCESS_KEY` | S3 secret key | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_SESSION_TOKEN` | S3 session token | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_PATH_STYLE` | S3 path-style access (true/false) | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_SSE` | S3 server-side encryption | `archivestore/s3.go` |
| `ARTEX_ARCHIVE_S3_KMS_KEY_ID` | S3 KMS key ID | `archivestore/s3.go` |

Additionally from `docker-compose.yml`:
| Variable | Purpose |
|----------|---------|
| `ARTEX_BIND_ADDR` | Listen address (default `127.0.0.1`) |
| `ARTEX_TASK_BUDGET_TOKENS` | Per-task token budget (0 = unlimited) |
| `ARTEX_TASK_BUDGET_TURNS` | Per-task turn budget (0 = unlimited) |
| `ARTEX_INTENT_BUDGET_TOKENS` | Per-intent/worker token budget |
| `ARTEX_INTENT_BUDGET_TURNS` | Per-intent/worker turn budget |
| `ARTEX_VERSION` | Build version tag |
| `ANTHROPIC_API_KEY` | Anthropic API key (non-ARTEX prefix) |
| `OPENAI_API_KEY` | OpenAI API key (non-ARTEX prefix) |

-- Source: grep of `os.Getenv("ARTEX_` across non-test .go files; `docker-compose.yml` environment section

### Inferences
- The config system is designed to work well in both Docker (env vars from compose) and bare-metal (config.json) deployments.
- Password handling is robust: `ARTEX_PG_PASSWORD` is taken raw and percent-encoded by the system, so special characters work without manual escaping. The password is scrubbed from the environment at startup.
- There is no built-in fallback for the database connection: missing config is a hard startup failure, preventing silent misconfiguration.

### Gaps
- None for the configuration system.

---

## Docker vs Bare Metal Deployment

### Takeaway
ARTEX supports five installation methods: (1) one-click install script, (2) Docker Compose (checkout build or prebuilt GHCR image), (3) prebuilt binaries from releases, (4) build from source, (5) cross-platform release archives. Docker Compose is the recommended path and bundles PostgreSQL 16 Alpine. The bare-metal path requires an external PostgreSQL instance. The Docker image includes a scanner toolchain (nmap, nuclei, httpx, katana, ffuf, dalfox, sqlmap, etc.) and built-in skills.

### Cited Findings

**Docker Compose deployment** (`docker-compose.yml`):
- Two services: `postgres` (PostgreSQL 16 Alpine with SCRAM-SHA-256 auth) and `artex` (built from checkout).
- Security: `no-new-privileges:true` on the artex container; agent processes run as unprivileged executor.
- Volumes: `pgdata` (named volume for PostgreSQL data), `./data:/app/data` (traffic, transcripts, task files), `./keys:/app/keys` (JWT and secret keys), `./skills:/app/skills` (hot-reloadable skills).
- Ports: `8787` (web UI + API, bound to `127.0.0.1` by default via `ARTEX_BIND_ADDR`), `8788` (recording MITM proxy, localhost only).
- Health check on PostgreSQL with 5s interval, 10 retries.

-- Source: `docker-compose.yml` full file

**Prebuilt GHCR image**: Published to `ghcr.io/baarai/artex` on `v*` tags, multi-arch (linux/amd64, linux/arm64). Includes scanner toolchain and built-in `/app/skills`.
-- Source: `README.md` lines 353-397

**Bare-metal deployment**: Single Go binary with embedded Next.js UI (`go:embed`). Only external dependency is PostgreSQL. Build command: `CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex`.
-- Source: `README.md` lines 456-464

**Data directory**: `data/` stores traffic blobs, LLM transcripts, task working files, and local task archives. This directory stays on local disk even with an external PostgreSQL; heavy workloads can fill it.
-- Source: `README.md` lines 649-656

**Upgrade mechanism**: Zero-downtime: replace binary/container, restart. Schema migrations are applied automatically at startup.
-- Source: `README.md` lines 789-797

### Inferences
- The architecture is designed for minimal operational complexity: PostgreSQL is the only external dependency, and all state lives in the database or the `data/` directory.
- The skill mount (`./skills:/app/skills`) overriding the image's built-in skills enables development/customization without image rebuilds.
- The `no-new-privileges` security option and unprivileged executor design show defense-in-depth for the agent execution environment.

### Gaps
- The Dockerfile itself was not read (only the compose file), so the exact scanner toolchain included in the image is known only from README descriptions.

---

## Schema Evolution via Migrations

### Takeaway
Schema evolution uses a two-tier approach: (1) the idempotent `db/schema.sql` baseline runs at every startup using `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` patterns, and (2) numbered migrations in `db/migrations/` (currently 14 files, `0001` through `0014`) handle additive changes that cannot be expressed idempotently. Each migration runs in its own transaction, in order. The baseline includes inline migration logic (DO blocks that check constraints and recreate them).

### Cited Findings

**Migration examples**:
- `0001_llm_records.sql`: Creates `llm_records` table for per-call LLM request/response logging.
- `0002_llm_usage.sql`: Creates `llm_usage` table for token accounting (input/output/cache_read/cache_write per task/worker/model).
- `0005_traffic_rewrite_rules.sql`: Creates `traffic_rewrite_rules` for capture proxy rewrite configuration (encrypted at rest).
- `0009_llm_context.sql`: Creates `llm_context` for opt-in context size telemetry (byte sizes only, never content).
- `0011_traffic_tamper_hooks.sql`: Creates `traffic_tamper_hooks` and `traffic_tamper_hook_versions` for Go-based capture proxy tampering.
- `0013_lesson_evidence_history.sql`: Migrates `rsi_lesson_evidence` from composite PK to surrogate ID with partial unique index for withdrawal history.
- `0014_bedrock_gateway_profiles.sql`: Adds Bedrock gateway as an LLM profile format.

-- Source: `db/migrations/0001_llm_records.sql`, `0002_llm_usage.sql`, `0005_traffic_rewrite_rules.sql`, `0009_llm_context.sql`, `0011_traffic_tamper_hooks.sql`, `0013_lesson_evidence_history.sql`

**Inline constraint migrations in schema.sql**: The baseline includes `DO` blocks that check whether constraints are outdated (e.g., missing new enum values) and recreate them. Example: the `ck_node_kind` constraint is recreated if it doesn't include `'digest'`; `ck_edge_rel` is recreated if it doesn't include `'covers'`.
-- Source: `db/schema.sql` lines 212-282

### Inferences
- The dual-tier approach (idempotent baseline + numbered migrations) handles both "add a column" (baseline) and "transform existing data" (migration) gracefully.
- The `DO` blocks for constraint recreation show that the system must handle databases created at any historical version, not just the latest.

### Gaps
- The migration runner itself was not read (likely in `db/db.go`), so the exact ordering and transaction semantics are inferred from the README description.
