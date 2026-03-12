package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/db"
	"github.com/joern-audit/joern_audit/internal/output"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

// Engine is the top-level orchestrator that drives the full audit pipeline.
type Engine struct {
	cfg *config.Config
}

func NewEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Run executes the full audit pipeline on the target.
func (e *Engine) Run(ctx context.Context, target string) error {
	log := output.NewConsoleLogger()

	session := &Session{
		ID:        fmt.Sprintf("audit_%s", time.Now().Format("20060102_150405")),
		Target:    target,
		Languages: e.cfg.Scan.Languages,
		Mode:      e.cfg.Scan.Mode,
		Phase:     PhaseInit,
		Round:     1,
		StartedAt: time.Now(),
		Status:    "running",
	}

	log.Summary("\n🛡️  DeepAudit 安全审计系统")
	log.Summary("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Summary("会话ID: %s", session.ID)
	log.Summary("目标: %s", target)
	log.Summary("模式: %s", session.Mode)
	log.Summary("语言: %v", session.Languages)
	log.Summary("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	state := &PipelineState{
		Session: session,
		Config:  e.cfg,
		Logger:  log,
	}

	phases := []PhaseRunner{
		&InitPhase{},
		&CPGPhase{},
		NewVerifyPhase(),
		&ExplorePhase{},
		&FuzzPhase{},
		&ChainPhase{},
		&ReportPhase{},
	}

	for _, phase := range phases {
		log.PhaseStart(phase.Name())
		if err := phase.Execute(ctx, state); err != nil {
			return fmt.Errorf("%s: %w", phase.Name(), err)
		}
		log.PhaseEnd(phase.Name())
	}

	e.printCoverageSummary(state, log)

	session.Status = "completed"
	session.UpdatedAt = now()

	if state.Database != nil {
		if database, ok := state.Database.(*db.DB); ok {
			SaveSession(database, session)
			database.Close()
		}
	}

	duration := time.Since(session.StartedAt)
	log.Summary("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Summary("✅ 审计完成！耗时: %s", duration.Round(time.Second))
	log.Summary("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	return nil
}

func (e *Engine) printCoverageSummary(state *PipelineState, log output.AuditLogger) {
	if state.Coverage == nil {
		return
	}
	log.Summary("📊 覆盖率矩阵: %d/10 维度已覆盖", state.Coverage.CoveredCount())
	for _, dim := range state.Coverage.All() {
		statusIcon := map[CoverageStatus]string{
			Covered: "✅", Shallow: "🔶", Uncovered: "⬜",
		}
		icon := statusIcon[dim.Status]
		findingStr := ""
		if dim.FindingCount > 0 {
			findingStr = fmt.Sprintf(" (%d findings)", dim.FindingCount)
		}
		log.Summary("  %s %s: %s — %s%s", icon, dim.ID, dim.Name, dim.Status, findingStr)
	}
}

// buildAttackSurface constructs an AttackSurface from CPG index data and coverage gaps.
// Reuses the existing CPG engine instead of creating a new one.
func buildAttackSurface(ctx context.Context, cpgEngine *cpg.Engine, indexStore cpg.IndexStore, coverage *CoverageMatrix, target, language string, joernCfg *config.JoernConfig) verifier.AttackSurface {
	surface := verifier.AttackSurface{
		TechStack:  language,
		Dimensions: make(map[string]string),
	}

	for _, dim := range coverage.Gaps() {
		priority := "medium"
		switch dim.ID {
		case DimInjection, DimAuth, DimAuthz:
			priority = "high"
		}
		surface.Dimensions[string(dim.ID)+": "+dim.Name] = priority
	}

	entryQuery := `cpg.method.where(_.annotation.name(".*Mapping")).map(n => Map("name" -> n.name, "file" -> n.filename, "line" -> n.lineNumber.toString)).l`
	results, err := cpgEngine.Query(ctx, entryQuery)
	if err == nil {
		for _, r := range results {
			name, _ := r.Data["name"].(string)
			file, _ := r.Data["file"].(string)
			line, _ := r.Data["line"].(int)
			if name != "" && file != "" {
				surface.EntryPoints = append(surface.EntryPoints, verifier.EntryPoint{
					Method:  "GET",
					Path:    "/" + name,
					Handler: name,
					File:    file,
					Line:    line,
				})
			}
		}
	}

	surface.HighRiskAreas = []string{
		"Authentication and session management",
		"Input validation at API boundaries",
		"File upload/download handling",
		"Database query construction",
		"External service communication",
	}

	return surface
}

func now() time.Time { return time.Now() }
