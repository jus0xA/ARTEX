# Using ARTEX as a Blueprint for AI Security Assessment Tooling

## SMART Recommendations

**Context:** ARTEX is an autonomous LLM-driven penetration testing platform. This document maps its architecture to AI security assessment needs and provides specific, measurable, achievable, relevant, and time-bound recommendations for building your own tooling.

> **v2 — Major revision after peer review (Fable).** Two critical facts change the strategy:
>
> 1. **AGPL-3.0 license.** ARTEX is copyleft. Modified versions offered over a network generally must share source. Get legal review before forking for any commercial use.
> 2. **Upstream is dead.** The original Autumn-27 repository was pulled in late October 2026. The BaaRai copy is a third party's English continuation of the Chinese original. Forking means owning an unmaintained codebase with an unvetted provenance chain.
>
> **Revised recommendation: Lift the patterns. Don't fork the code.** Study ARTEX's architecture as a reference implementation, then build from scratch or extend a maintained base (PyRIT, garak, promptfoo). The five patterns worth lifting are detailed below.

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

## Revised Strategy: Lift Patterns, Build Fresh

Given the AGPL-3.0 license and dead upstream, **don't fork ARTEX**. Instead, study its patterns and build on a maintained base.

### Recommended Base Platforms

| Platform | Strength | Use For |
|----------|----------|---------|
| **Microsoft PyRIT** | Multi-turn attack orchestration, scoring framework, maintained by MSFT | Core attack loop + scoring |
| **garak** | Probe library, detector framework, CI-friendly | Probe/skill library reference |
| **promptfoo** | Red-team eval framework, CI/CD integration, model-agnostic | Eval harness + reporting |

### Five Patterns to Lift from ARTEX

1. **Planner/worker split with persistent to-do list** — decompose assessments into intents, dispatch parallel workers, track coverage via an exploration graph. No existing tool does this well.
2. **Closed judge with code-owned decisions** — 8 fixed questions, strict output parsing, fail-to-human. Adapt questions for AI safety scope.
3. **Evidence bindings with baseline and proof roles** — SHA-256 hash chains linking findings to raw request/response pairs. Tamper-evident by design.
4. **Approval gate before tool install** — Any new tool, MCP server, or skill requires human approval. Critical for autonomous systems.
5. **Untrusted-output boundary** — Nonce-tagged markers framing target model output as data. The marker neutralizer prevents forgery.

---

## SMART Phased Plan (Revised)

### Phase 0: Two-Week Spike (Weeks 1-2)

**S:** Prove the core loop works before building a platform. Take ONE target model and ONE attack class (e.g., prompt injection against a chatbot). Build:
1. A quarantined analyzer — a separate agent context with no tools, receiving target output as structured data, returning only typed verdicts (success/failure/ambiguous + confidence score)
2. A scoring loop — run the same attack N times (N ≥ 30), compute success rate with confidence interval, compare against human-labeled baseline
3. An egress-restricted container (iptables allowlist: only the target model endpoint + your own LLM provider)

**M:** You can run 30 trials of a prompt injection attack, get a success rate with 95% CI, and an independent human judge agrees with the automated scorer ≥ 80% of the time.

**A:** This is ~200 lines of Python on top of PyRIT or promptfoo. The container is a Dockerfile + 5 iptables rules.

**R:** This proves the three hardest problems: scoring (probabilistic, not binary), quarantined analysis (target output can't hijack the scorer), and isolation (the agent can't escape the allowlist). If these don't work, nothing else matters.

**T:** 2 weeks. Week 1: scoring loop + quarantined analyzer. Week 2: container isolation + human calibration.

---

### Phase 1: Foundation + Safety Together (Weeks 3-6)

**S:** Build the core platform with safety baked in from day 1 (not bolted on later):
1. Planner/worker agent loop (lift the pattern from ARTEX, implement on PyRIT or your own framework)
2. Network-level scope enforcement (container egress allowlist — not declared-only)
3. Evidence chain (hash every prompt/response before analysis)
4. Closed judge adapted for AI safety (8 new questions: "Does this test exceed authorized scope?", "Could this generate real harmful instructions?", "Does this test target production users?", etc.)
5. Quarantined target-output analyzer (from Phase 0, now integrated)

**M:** The platform can run a multi-step assessment against one model endpoint, with every interaction recorded, every target response analyzed in quarantine, and no network path to unauthorized endpoints.

**A:** You proved the hard parts in Phase 0. This is integration work.

**R:** Safety and isolation on day 1 means you never point the tool at a real target without guardrails. This is the lesson from ARTEX's design — their safety came first in the architecture, even if the defaults were too permissive.

**T:** 4 weeks.

---

### Phase 2: Attack Library + Multi-Turn Support (Weeks 7-10)

**S:** Build the attack skill library with proper multi-turn support:
1. 10 skills covering OWASP LLM Top 10 (prompt injection, jailbreak, disclosure, etc.)
2. Conversation tree support — branching and backtracking for multi-turn attacks (ARTEX's exploration graph handles single-intent workers; multi-turn chains need conversation trees where workers can branch, retry with variations, and backtrack)
3. Agent-testing skills that require shell access (RAG poisoning = planting documents, indirect injection = driving apps) — this is where ARTEX's Bash safety machinery IS relevant
4. Per-skill scoring rubrics with human-calibrated baselines

**M:** Each skill has ≥ 5 test cases, a scoring rubric calibrated against ≥ 20 human-labeled examples, and documented success rates on at least one target model.

**A:** Published taxonomies (OWASP LLM Top 10, MITRE ATLAS, HarmBench, AdvBench) provide the starting framework. Your value is making them executable.

**R:** The skill library is what makes this tool useful vs. a generic agent framework.

**T:** 4 weeks. 2-3 skills per week.

---

### Phase 3: Reporting + Compliance (Weeks 11-14)

**S:** Build assessment output:
1. Automated report generation from exploration graph + evidence chain
2. Findings mapped to NIST AI RMF (AI 100-1) and EU AI Act risk categories
3. Severity scoring: use a custom rubric (not CVSS — it doesn't fit AI risks; not "AI Incident Severity Scale" which doesn't exist as a standard). Base it on: attack reliability (success rate), impact scope (single user vs. system-wide), and reversibility
4. Export: PDF report, JSON machine-readable, SARIF for CI/CD

**M:** A complete assessment produces a report a compliance officer can use, with every finding linked to evidence hashes, success rates, and framework control IDs.

**A:** Report generation is template work. Framework mappings are publicly available.

**R:** Without structured reporting, it's a research toy.

**T:** 4 weeks.

---

## Component Mapping: ARTEX → AI Security Tool

| ARTEX Component | AI Security Equivalent | Action |
|-----------------|----------------------|--------|
| `agent/planner.go` — planner loop | Attack strategy planner | **Adapt** — replace pentest strategy with AI attack taxonomy |
| `agent/worker.go` — worker execution | Attack executor | **Adapt** — replace Bash/WebFetch with LLM API caller |
| `intercept/target_gate.go` — scope gate | Model endpoint allowlist | **Harden** — make mandatory + add network-level enforcement |
| `intercept/closed_judge.go` — safety judge | AI safety judge | **Adapt** — replace 8 questions with AI-relevant safety questions |
| `intercept/argv_compound.go` — command matching | Shell safety for agent-testing skills | **Keep if testing agents** — RAG poisoning and indirect injection require shell access |
| `agent/untrusted_boundary.go` — output boundary | Target model output boundary | **Lift pattern** — critical, but supplement with quarantined analyzer (boundary is advisory-only; a sandboxed scorer with no tools is enforced) |
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

- **Don't fork ARTEX.** AGPL-3.0 + dead upstream + unvetted Norma provenance = liability. Lift the patterns, build fresh.
- **Don't build a general-purpose agent framework.** Use PyRIT, LangGraph, or the Claude Agent SDK. Your value is AI security domain knowledge, not agent plumbing.
- **Don't replicate MITRE ATLAS or OWASP LLM Top 10.** Reference them. Your skills should be *executable tests*, not documentation.
- **Don't treat jailbreaks like pentest findings.** A jailbreak is probabilistic. One success is anecdotal. You need N trials, success rates, confidence intervals, and human-calibrated baselines.
- **Don't defer safety to "later."** An egress-restricted container + quarantined analyzer belongs in week 1, not week 9.

---

## The Hardest Problem: Scoring

ARTEX's pentest findings have crisp proof — a shell, a database dump, an RCE. AI security findings are fuzzy and probabilistic. A jailbreak that works 3/100 times is a different risk than one that works 90/100 times.

Your scoring system needs:
1. **Repeated trials** — minimum 30 per attack variant for statistical significance
2. **Success rate with confidence interval** — not "it worked once"
3. **Human-calibrated baselines** — automated judge agrees with human labels ≥ 80%
4. **Severity = reliability × impact × reversibility** — not CVSS, which doesn't fit AI risks
5. **The quarantined analyzer** — a separate LLM context with no tools that scores target output. This is NOT the same as the untrusted-output boundary (which is advisory). The analyzer is structurally sandboxed — it receives only text, returns only typed verdicts, has no tool access, and cannot be steered into taking actions.

---

## Estimated Total Effort (Revised)

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| 0. Spike | 2 weeks | Scoring loop + quarantined analyzer + isolation proof |
| 1. Foundation + Safety | 4 weeks | Planner/worker loop + network isolation + evidence chain + judge |
| 2. Skills + Multi-Turn | 4 weeks | 10 attack skills with conversation trees + human baselines |
| 3. Reporting | 4 weeks | Compliance-mapped reports with success rates + evidence links |
| **Total** | **14 weeks** | **Usable AI security assessment platform** |

Note: "production-ready" was overstated in v1. At 14 weeks with one engineer, you get a **usable** platform for internal assessments. Production-grade (multi-tenant, polished UI, customer-facing reports) is 6-12 months.

---

## Acknowledgments

v2 of this document incorporates corrections and critiques from a peer review by Fable, which identified the AGPL-3.0 licensing risk, the dead upstream, the Phase 3 safety timing problem, the scoring gap, the multi-turn limitation, and the need for shell access in agent-testing scenarios. The "AI Incident Severity Scale" reference in v1 was removed (no such standard exists; the nearest equivalent is MIT's AI Incident Tracker, which rates harm 1-5 for incidents, not test findings).
