# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build          # Build to bin/joern_audit (injects version via ldflags)
make test           # go test -v ./...
make lint           # golangci-lint run ./...
go test -v -run TestTokenBucket ./internal/llm/   # Run a single test
go build ./...      # Quick compile check without producing binary
```

## Running the Tool

```bash
# Full audit pipeline (requires joern-parse in PATH)
joern_audit scan /path/to/java-project --lang java --mode standard

# Scan modes: quick, standard, deep, joern-only
# joern-only skips LLM verification entirely

# Standalone fuzz re-run on existing report
joern_audit fuzz --report .joern_audit/reports/audit_report.json \
  --target http://localhost:8080 --source /path/to/source

# List discovered endpoints without fuzzing
joern_audit fuzz --list-endpoints --source /path/to/java-project
```

## Architecture

### Six-Phase Pipeline

The core pipeline is orchestrated by `internal/orchestrator/engine.go`:

```
Phase 0: Init → create dirs, evidence store, coverage matrix
Phase 1: CPG Build + Scan → joern-parse → index → rule scan + XML mapper scan
Phase 2: LLM Verification → Prosecutor-Defender-Judge tribunal per candidate
Phase 2.5: Deep Verify → re-verify NEEDS_DEEPER candidates with expanded context
Phase 3: Fuzz Verify → (optional) live target testing with sqlmap/HTTP payloads
Phase 4: Attack Chain → (not yet implemented)
Phase 5: Report → JSON + Markdown-ZH + SARIF output
```

### Three-Layer Truth Verification

This is the core design principle. Each layer is independent and progressively more definitive:

1. **Joern CPG** (deterministic) — taint flow analysis via CPGQL queries. Rules in `rules/java/*.yaml`.
2. **LLM Agents** (semantic) — Prosecutor (red team) argues exploitation, Defender (blue team) argues safety, Judge arbitrates. Prompts in `prompts/`. Verdicts: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `NEEDS_DEEPER`, `EXPLOITABLE_WITH_CONDITION`.
3. **Fuzz/PoC** (runtime) — actual HTTP requests against a live target. Only runs on TP/CONDITIONAL verdicts.

### Key Package Relationships

```
cmd/joern_audit → orchestrator → cpg (Joern CLI wrapper)
                                → scanner (rule loading + CPGQL matching)
                                → llm (multi-provider: Claude, OpenAI, Ollama, DeepSeek)
                                → verifier/tribunal (three-role LLM verification)
                                → fuzzer/manager (CWE-based strategy dispatch)
                                → evidence (in-memory record store)
                                → report (JSON, Markdown-ZH, SARIF generators)
```

### Fuzzer Strategy System

`internal/fuzzer/` uses a Strategy interface dispatched by CWE:
- **SQLi** (CWE-89) → sqlmap with auto-detection in PATH/pip locations
- **XXE** (CWE-611) → custom XML entity injection payloads
- **HTTP Generic** (CWE-78/94/918/79/22) → payload sets with response indicator matching
- **Deser** (CWE-502) → ysoserial gadget chains + optional marshalsec JNDI

The `EndpointRegistry` pre-scans Java Spring controllers (`@RequestMapping`, `@GetMapping`, etc.) to resolve real HTTP paths from source code. It also traces MyBatis XML mapper methods back to controller endpoints.

### Context On-Demand System

`internal/cpg/context.go` provides three levels of source context for LLM verification:
- **Level 0**: Alert location only
- **Level 1**: Full function body containing the vulnerable line
- **Level 2**: Call chain (callers + callees)

When a Judge returns `NEEDS_DEEPER`, the orchestrator re-runs verification at Level 2.

### LLM Provider Abstraction

`internal/llm/provider.go` defines the Provider interface (`Chat`, `ChatJSON`). All LLM calls go through token-bucket rate limiting (`ratelimit.go`) with exponential backoff retry. JSON responses from LLMs are auto-sanitized, extracted from markdown fences, and repaired (`utils.go`).

## Configuration

YAML config loaded from (in order): `--config` flag, `joern_audit.yaml`, `.joern_audit.yaml`, `~/.config/joern_audit/config.yaml`. CLI flags override config values.

Key config sections: `joern` (binary paths, timeout), `llm` (provider, model, api_key, rate limits, concurrency), `scan` (mode, rules_dir, excludes), `fuzzer` (target_url, tool paths), `report` (output_dir, formats).

## Language Notes

- All user-facing output (CLI messages, report text) is in **Chinese**
- Code comments and identifiers are in English
- The project currently supports **Java** rules only; the rule/prompt system is designed for multi-language extension

## External Dependencies

Runtime: `joern-parse` (Joern >= 4.0), optionally `sqlmap`, `ysoserial`, `marshalsec` for fuzz phase.
Go: Only 3 direct deps — cobra (CLI), yaml.v3 (config), go-sqlite3 (unused persistence placeholder).

## Joern/CPG Reference

Reference material from LoRexxar's "深入浅出Joern" series for writing and improving CPGQL rules.

### CPG Fundamentals

CPG (Code Property Graph) = AST + CFG + PDG fused into a single graph. Compared to any single intermediate structure, CPG leverages the graph's capacity to hold multi-dimensional code relationships. Joern separates CPG generation (frontend) from query analysis (backend) — the CPG is built first, and edges/relationships are resolved lazily during queries, which keeps parse time fast.

### CPGQL Core Patterns

Source-sink taint analysis (the primary pattern used by our rules in `internal/scanner/`):

```scala
// Define source: Spring controller parameters with @*Mapping annotations
def source = cpg.method.where(_.annotation.name(".*Mapping")).parameter

// Define sink: dangerous function calls
def sink = cpg.call.name("exec")

// Check reachability (boolean) or get full flow paths
sink.reachableBy(source)
sink.reachableByFlows(source).p
```

Common query building blocks:

```scala
// Find all methods, get details
cpg.method.map(n => List(n.lineNumber, n.name, n.code)).l

// Find callers of a specific method
cpg.method.name("getRequestBody").caller.map(n => List(n.filename, n.lineNumber, n.fullName)).l

// Find all web entry points (Spring)
cpg.method.where(_.annotation.name(".*Mapping")).map(n => (n.name, n.annotation.code.l)).l

// Forward search: from @Mapping methods down to a target call
cpg.method.where(_.annotation.name(".*Mapping")).repeat(_.callee)(_.until(_.name("getRequestBody"))).l

// Backward search: from target call up to @Mapping annotation
cpg.method.name("getRequestBody").repeat(_.caller)(_.until(_.annotation.name(".*Mapping"))).l

// Filter calls by method signature
cpg.method("getConnection").callIn.filter(_.methodFullName.contains("java.lang.String,java.lang.String,java.lang.String")).l

// Search for field access on specific class fields
cpg.call("<operator>.fieldAccess").filter(_.code.equals("com.example.TokenUtils.tokenMap")).l

// Find identifier usage with call-site filtering
cpg.identifier("username").map(n => n._callViaAstIn.filter(_.code.contains("put")).dedup.l).l
```

### Real-World Query Examples

XXE detection (SAXReader without secure configuration):
```scala
def source = cpg.method("getParameter").callIn
def sink = cpg.call.filter(_.methodFullName.contains("java.io.StringReader.<init>"))
sink.reachableByFlows(source).p
```

JDBC injection detection:
```scala
def sink = cpg.method("getConnection").callIn.filter(_.methodFullName.contains("java.lang.String,java.lang.String,java.lang.String"))
def source = cpg.method("testDBConnect").where(_.annotation.name(".*Mapping")).parameter
sink.reachableByFlows(source).p
```

### Joern Limitations to Be Aware Of

These limitations directly affect how we design rules in `internal/scanner/`:

1. **Object state tracking is weak** — Joern cannot easily track attribute changes on instances after initialization. For example, SAXReader's XXE fix depends on calling `setFeature()` after construction, not on parameter filtering. Detecting this requires regex workarounds, not native CPGQL.
2. **Inter-procedural data flow** — `reachableBy` confirms call-graph connectivity, but doesn't prove actual data propagation. A connected path means a call relationship exists, but whether user input actually flows through requires deeper analysis (which our LLM verification layer addresses).
3. **Non-code-level information is ignored** — Joern's CPG only represents code structure. Configuration files, deployment settings, and runtime behavior are invisible. This is by design but means certain vulnerability classes (e.g., H2 JDBC RCE via connection URL parameters) require supplementary analysis.
4. **Large project performance** — For very large projects, CPG generation should use `joern-parse` separately with increased heap (`-J-Xmx8092m`) rather than inline `importCode`.
5. **Familiarity requirement** — Effective Joern scanning requires understanding the target codebase's patterns. Generic rules catch common patterns, but targeted auditing (like tracing authentication token flows) needs domain-specific queries.

### Reference Links

- [LoRexxar: 深入浅出Joern（一）Joern与CPG是什么](https://lorexxar.cn/2023/08/21/joern-and-cpg/)
- [LoRexxar: Joern In RealWorld (3) 致远OA SSRF2RCE](https://lorexxar.cn/2023/11/21/joernrw3/)
- [Joern CPG Schema Spec](https://cpg.joern.io/)
- [Joern CPGQL Reference Card](https://docs.joern.io/cpgql/reference-card/)
- [Joern Community Queries](https://queries.joern.io/)
