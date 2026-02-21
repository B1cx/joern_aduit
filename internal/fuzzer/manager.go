package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/evidence"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

// Manager orchestrates fuzz verification across all registered strategies.
type Manager struct {
	cfg        *config.FuzzerConfig
	strategies []Strategy
	sourceRoot string
	registry   *EndpointRegistry
}

// NewManager creates a Manager and registers all built-in strategies.
func NewManager(cfg *config.FuzzerConfig) *Manager {
	return &Manager{
		cfg:        cfg,
		strategies: NewStrategies(cfg),
	}
}

// SetSourceRoot sets the source code root and triggers a project scan
// to build the endpoint registry.
func (m *Manager) SetSourceRoot(root string) {
	m.sourceRoot = root
	if root != "" {
		m.registry = ScanProject(root)
	}
}

// RunAll runs fuzz verification on all eligible records.
// Returns counts of confirmed, failed, and errored attempts.
func (m *Manager) RunAll(ctx context.Context, records []*evidence.Record) (confirmed, failed, errored int) {
	if !m.preflightCheck(m.cfg.TargetURL) {
		fmt.Printf("  ⚠️  目标不可达: %s，跳过 Fuzz 验证\n", m.cfg.TargetURL)
		return 0, 0, 0
	}
	fmt.Printf("  ✓ 目标可达: %s\n", m.cfg.TargetURL)

	eligible := 0
	for _, rec := range records {
		if !m.isEligible(rec) {
			continue
		}
		eligible++

		strategy := m.findStrategy(rec.CWE)
		if strategy == nil {
			fmt.Printf("  ⚠️  [%s] CWE %s 无匹配策略，跳过\n", rec.CandidateID, rec.CWE)
			continue
		}

		fmt.Printf("  🎯 [%s] %s:%d → 策略: %s\n",
			rec.CandidateID, rec.FilePath, rec.LineNumber, strategy.Name())

		pocReq := m.buildPoCRequest(rec)

		poc, err := strategy.GeneratePoC(ctx, pocReq)
		if err != nil {
			fmt.Printf("    ❌ PoC 生成失败: %v\n", err)
			m.setFuzzResult(rec, strategy.Name(), FuzzError, "", fmt.Sprintf("PoC generation failed: %v", err))
			errored++
			continue
		}

		m.injectAuth(poc)

		result, err := strategy.Execute(ctx, poc)
		if err != nil {
			fmt.Printf("    ❌ Fuzz 执行失败: %v\n", err)
			m.setFuzzResult(rec, strategy.Name(), FuzzError, "", fmt.Sprintf("Fuzz execution failed: %v", err))
			errored++
			continue
		}

		rec.FuzzVerify = &evidence.FuzzVerification{
			Tool:     result.Tool,
			PoC:      result.PoC,
			Result:   string(result.Status),
			Evidence: result.ResponseDiff,
		}

		switch result.Status {
		case FuzzConfirmed:
			fmt.Printf("    ✅ CONFIRMED — %s\n", truncate(result.PoC, 100))
			confirmed++
		case FuzzPartial:
			fmt.Printf("    ⚠️  PARTIAL — %s\n", truncate(result.ResponseDiff, 100))
			failed++
		case FuzzFailed:
			fmt.Printf("    ❌ FAILED — %s\n", truncate(result.ResponseDiff, 100))
			failed++
		default:
			fmt.Printf("    ❓ %s — %s\n", result.Status, result.Error)
			errored++
		}
	}

	if eligible == 0 {
		fmt.Printf("  ℹ️  无符合条件的候选（需 TRUE_POSITIVE 或 EXPLOITABLE_WITH_CONDITION）\n")
	}

	return confirmed, failed, errored
}

// --- Internal helpers ---

func (m *Manager) isEligible(rec *evidence.Record) bool {
	if rec.LLMVerify == nil || rec.LLMVerify.Judge == nil {
		return false
	}
	v := rec.LLMVerify.Judge.Verdict
	return v == verifier.VerdictTruePositive || v == verifier.VerdictConditional
}

func (m *Manager) findStrategy(cwe string) Strategy {
	for _, s := range m.strategies {
		if s.CanHandle(cwe) {
			return s
		}
	}
	return nil
}

func (m *Manager) buildPoCRequest(rec *evidence.Record) PoCRequest {
	req := PoCRequest{
		CWE:        rec.CWE,
		TargetURL:  m.cfg.TargetURL,
		SourceRoot: m.sourceRoot,
		Registry:   m.registry,
	}

	if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
		req.AttackVector = rec.LLMVerify.Judge.AttackVector
	}

	if rec.CPGEvidence != nil {
		for _, node := range rec.CPGEvidence.TaintFlow {
			req.Evidence = append(req.Evidence, EvidenceRef{
				File: node.File,
				Line: node.Line,
				Code: node.Expr,
				Role: node.NodeType,
			})
		}
	}

	return req
}

func (m *Manager) setFuzzResult(rec *evidence.Record, tool string, status FuzzStatus, poc, ev string) {
	rec.FuzzVerify = &evidence.FuzzVerification{
		Tool:     tool,
		Result:   string(status),
		PoC:      poc,
		Evidence: ev,
	}
}

func (m *Manager) preflightCheck(targetURL string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	if m.cfg.Cookie != "" {
		req.Header.Set("Cookie", m.cfg.Cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode < 500
}

func (m *Manager) injectAuth(poc *PoCTemplate) {
	if m.cfg.Cookie == "" && len(m.cfg.Headers) == 0 {
		return
	}
	if poc.Headers == nil {
		poc.Headers = make(map[string]string)
	}
	if m.cfg.Cookie != "" {
		poc.Headers["Cookie"] = m.cfg.Cookie
		if poc.Command != "" && poc.Type == "sqlmap" {
			poc.Args = append(poc.Args, "--cookie", m.cfg.Cookie)
		}
	}
	for k, v := range m.cfg.Headers {
		poc.Headers[k] = v
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
