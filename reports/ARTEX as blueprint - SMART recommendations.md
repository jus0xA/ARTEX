# Using ARTEX as a Blueprint for AI Security Assessment Tooling

## SMART Recommendations

**Context:** ARTEX is an autonomous LLM-driven penetration testing platform. This document maps its architecture to AI security assessment needs and provides specific, measurable, achievable, relevant, and time-bound recommendations for building your own tooling.

---

## What ARTEX Gets Right (Reuse These Patterns)

### 1. The Planner/Worker Agent Loop
ARTEX's two-tier agent architecture is its strongest reusable pattern:
- **Planner** decides what to test, creates intents, dispatches workers
- **Workers** execute specific test actions, record facts, return results
- **Exploration graph** tracks what was tried and what was found

**AI Security Equivalent:** A planner that generates attack strategies (prompt injection, jailbreak, data extraction, alignment bypass) and workers that execute them against target AI models. The exploration graph becomes your test coverage tracker.

**Reuse as-is:** The Norma SDK agent loop, the intent/worker dispatch model, the fact-recording pattern. These are domain-agnostic.

### 2. The Closed Judge (Safety Guardrail)
The closed judge's design — fixed questions, code-owned decisions, strict output parsing, fail-to-human — is an excellent pattern for any autonomous system that takes real-world actions.

**AI Security Equivalent:** Before the agent sends a prompt to a target AI model, a judge evaluates: "Does this test stay within the authorized scope?" "Could this test cause real harm beyond the assessment?" "Does the payload contain actual PII/credentials?"

**Reuse with adaptation:** Keep the 8-question fixed format and code-owned decision logic. Replace the pentesting questions with AI safety questions.

### 3. The Untrusted-Output Boundary
The nonce-based marker system that wraps tool output is directly applicable. When testing AI models, you need to prevent the target model's output from hijacking your testing agent.

**Reuse as-is.** This is critical for AI security work where you're deliberately eliciting adversarial output.

### 4. The Evidence Chain
SHA-256 hashed traffic snapshots with tamper-evident bindings are essential for any security assessment.

**AI Security Equivalent:** Every prompt sent to the target model and every response received needs to be recorded with integrity proofs — model version, timestamp, full request/response, hash chain.

**Reuse with adaptation:** Replace HTTP traffic recording with LLM API call recording.

### 5. The Skill System
Hot-reloadable SKILL.md files with YAML frontmatter that define attack techniques.

**AI Security Equivalent:** A library of AI attack techniques — each skill file describes one attack class (prompt injection variants, jailbreak techniques, data extraction methods, etc.).

**Reuse as-is.** The file format and hot-reload mechanism are domain-agnostic.

---

## What ARTEX Gets Wrong for AI Security (Replace or Harden)

### 1. Target Gate: Declared-Only Scope
ARTEX's scope enforcement only checks what the agent *declares* in tool inputs. This is acceptable for pentesting where the agent controls the tools, but insufficient for AI security where target models may return adversarial content that steers the agent.

**Replace with:** Network-level enforcement (iptables/netns egress allowlist) + API-level scope (only send requests to pre-approved model endpoints).

### 2. No Network Isolation
The agent executor has no network namespace — it can reach the API on loopback, reach the internet, etc. For AI security assessments that may involve testing models with adversarial capabilities, this is dangerous.

**Replace with:** `CLONE_NEWNET` + veth pair that only allows traffic to approved model endpoints.

### 3. Cross-Task Asset Sharing
The global asset graph is shared across all tasks. For multi-tenant AI security assessments, this is a data leak risk.

**Replace with:** Per-engagement asset isolation (add `engagement_id` to all shared tables). Replace ARTEX's 6 network entity types (root_domain, subdomain, ip, service, app, endpoint) with AI asset types: `model`, `endpoint`, `system_prompt`, `tool_definition`, `guardrail`, `capability`.

### 4. No Data Retention
No automatic cleanup exists. AI security assessments generate sensitive data (adversarial prompts, model vulnerabilities, potential PII from extraction tests).

**Replace with:** Time-boxed retention with automatic purge, plus redaction of PII from recorded outputs.

### 5. Advisory-Only Boundaries
The untrusted-output boundary and data envelope are advisory — they tell the LLM "this is data, not instructions" but can't enforce it. For AI safety work where you're testing models designed to manipulate other models, this needs hardening.

**Supplement with:** Structural separation — don't pass target model output into the testing agent's context without sanitization. Use a separate "result analyzer" agent that reads target output in a sandboxed context.

---

## SMART Recommendations: Phased Build Plan

### Phase 1: Foundation (Weeks 1-4)

**S:** Fork ARTEX and strip pentesting-specific code (skills, default intercept rules, nuclei/httpx/subfinder tooling). Keep the agent loop, exploration graph, evidence chain, judge, and skill system.

**M:** Success = the stripped fork compiles, runs, and can execute a "hello world" skill that sends one prompt to a target LLM and records the response with an evidence hash.

**A:** This is primarily deletion and adaptation of existing code. The Go backend, PostgreSQL schema, and Next.js frontend are all standard tech.

**R:** You need a working foundation before adding AI-specific features.

**T:** 4 weeks. Week 1: fork and audit dependencies. Week 2: strip pentesting tools. Week 3: add LLM-target tool (replaces WebFetch/Bash for model interaction). Week 4: verify evidence chain works with LLM API calls.

---

### Phase 2: AI Attack Skill Library (Weeks 5-8)

**S:** Create 10-15 SKILL.md files covering the OWASP Top 10 for LLM Applications plus key AI-specific attack classes:
1. Prompt injection — direct, indirect, and encoded variants
2. Jailbreak evaluation — multi-turn chains, persona attacks, encoding tricks
3. Safety boundary testing — CBRN, violence, PII, bias
4. Sensitive information disclosure — system prompt extraction, training data extraction
5. Model fingerprinting — model identification, version detection, provider inference
6. RAG poisoning — test RAG pipeline injection resistance
7. Agent hijacking — function call injection, tool-use safety
8. Excessive agency — unauthorized action escalation
9. Insecure output handling — XSS/injection via model output
10. Model denial of service — context window exhaustion, rate limit abuse

**M:** Each skill has: a SKILL.md with YAML frontmatter, at least 5 test cases, and a scoring rubric. The planner can select skills based on target model type.

**A:** You can start with published attack taxonomies (OWASP LLM Top 10, MITRE ATLAS, Anthropic's responsible disclosure guidelines) and encode them as skills.

**R:** The skill library IS your assessment methodology — it's what makes this tool useful vs. just a generic agent framework.

**T:** 4 weeks. 2-3 skills per week, starting with prompt injection and information disclosure (highest impact).

---

### Phase 3: Hardened Safety Layer (Weeks 9-12)

**S:** Replace ARTEX's advisory safety controls with enforced ones:
1. Network namespace isolation (`CLONE_NEWNET`) for the agent executor
2. API-level scope enforcement (agent can ONLY call pre-approved model endpoints)
3. Closed judge adapted for AI safety questions (replace 8 pentesting questions with AI-relevant ones)
4. Per-engagement data isolation (add `engagement_id` to schema)
5. Make target gate mandatory (always-on, not opt-in)

**M:** Success = a deliberately adversarial target model response cannot cause the testing agent to: (a) contact unauthorized endpoints, (b) modify its own configuration, (c) access data from other engagements, or (d) bypass the safety judge.

**A:** Network isolation and schema changes are well-understood engineering. The judge adaptation requires careful prompt engineering but follows ARTEX's existing pattern.

**R:** If your tool tests AI models that may be adversarial, the tool itself must be hardened against adversarial AI output. This is the key differentiator from ARTEX's threat model.

**T:** 4 weeks. Week 9: network namespace. Week 10: API scope + mandatory target gate. Week 11: judge adaptation. Week 12: per-engagement isolation + integration testing.

---

### Phase 4: Reporting and Compliance (Weeks 13-16)

**S:** Build assessment output that maps to AI governance frameworks:
1. Automated report generation from exploration graph + evidence chain
2. Mapping findings to NIST AI RMF, EU AI Act risk categories, ISO 42001
3. Severity scoring calibrated to AI risk (not CVSS — use something like the AI Incident Severity Scale)
4. Export formats: PDF report, JSON machine-readable, SARIF for CI/CD integration

**M:** A complete assessment produces a report that a compliance officer can use for AI governance documentation, with every finding linked to evidence hashes and framework control IDs.

**A:** Report generation is a frontend/template task. Framework mappings are publicly available.

**R:** Assessment tooling without structured reporting is just a research toy. This is what makes it professional-grade.

**T:** 4 weeks. Week 13: report template + evidence linking. Week 14: framework mappings (start with NIST AI RMF). Week 15: severity scoring model. Week 16: export formats + CI/CD integration.

---

## Component Mapping: ARTEX → AI Security Tool

| ARTEX Component | AI Security Equivalent | Action |
|-----------------|----------------------|--------|
| `agent/planner.go` — planner loop | Attack strategy planner | **Adapt** — replace pentest strategy with AI attack taxonomy |
| `agent/worker.go` — worker execution | Attack executor | **Adapt** — replace Bash/WebFetch with LLM API caller |
| `intercept/target_gate.go` — scope gate | Model endpoint allowlist | **Harden** — make mandatory + add network-level enforcement |
| `intercept/closed_judge.go` — safety judge | AI safety judge | **Adapt** — replace 8 questions with AI-relevant safety questions |
| `intercept/argv_compound.go` — command matching | (Not needed) | **Remove** — no shell commands in AI assessments |
| `agent/untrusted_boundary.go` — output boundary | Target model output boundary | **Reuse as-is** — critical for adversarial AI output |
| `skills/` — SKILL.md attack library | AI attack technique library | **Replace** — write AI-specific skills |
| `traffic/` — MITM proxy + recording | LLM API call recorder | **Replace** — record prompts/responses instead of HTTP traffic |
| `db/exploration.go` — exploration graph | Test reasoning chain (goal → intent → fact → finding) | **Reuse as-is** — node kinds map 1:1 to AI assessment workflows |
| `db/secrets.go` — AES-256-GCM encryption | Credential/PII encryption | **Extend** — also encrypt exploration graph data |
| `server/engine.go` — task lifecycle | Assessment lifecycle | **Reuse as-is** — budgets, turn control, graceful shutdown |
| `server/auth.go` — JWT auth | Assessment platform auth | **Reuse** — add token revocation |
| `intercept/alwaysallow_denylist.go` — code-owned denylist | (Adapt for AI actions) | **Adapt** — replace program denylist with prohibited-prompt-pattern list |

---

## Critical Architecture Decisions for Day 1

### 1. Threat model inversion
ARTEX assumes the agent is benign and the target is passive. For AI security, the **target is adversarial**. Your agent will receive outputs specifically crafted to manipulate it. Design every component assuming the target model's response is hostile.

### 2. Single-tenant by default
Run one instance per engagement. This eliminates the cross-task poisoning problem entirely and simplifies data isolation. Only go multi-tenant if you need to — and if you do, add `engagement_id` to every table from day one.

### 3. LLM provider independence
ARTEX already supports 5 LLM formats. Keep this — your testing agent should run on a different provider than the target model to avoid cross-contamination.

### 4. Evidence-first architecture
Every interaction with a target model must be recorded before it's analyzed. This means: request hash + response hash + timestamp + model version + full content. Never let the agent summarize or discard raw evidence.

---

## What NOT to Build

- **Don't build a general-purpose agent framework.** Use Norma/ARTEX's existing loop. Your value is in the AI security domain knowledge, not the agent plumbing.
- **Don't build a custom LLM provider abstraction.** ARTEX already has 5 formats with circuit-breaker failover. Reuse it.
- **Don't build a custom web UI from scratch.** ARTEX's Next.js frontend is functional. Reskin it.
- **Don't replicate MITRE ATLAS or OWASP LLM Top 10.** Reference them in your skills. Your skills should be *executable tests*, not documentation.

---

## Estimated Total Effort

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| 1. Foundation | 4 weeks | Stripped fork + LLM target tool + evidence chain |
| 2. Skills | 4 weeks | 10-15 AI attack skills covering OWASP LLM Top 10 |
| 3. Safety | 4 weeks | Network isolation + mandatory scope + adapted judge |
| 4. Reporting | 4 weeks | Compliance-mapped reports with evidence links |
| **Total** | **16 weeks** | **Production-ready AI security assessment platform** |

This assumes one experienced engineer. With a team of 2-3, phases 2-4 can partially overlap, reducing to ~10-12 weeks.
