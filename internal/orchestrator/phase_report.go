package orchestrator

import (
	"context"
	"fmt"

	"github.com/joern-audit/joern_audit/internal/report"
)

type ReportPhase struct{}

func (p *ReportPhase) Name() string { return "Phase 5: 生成报告" }

func (p *ReportPhase) Execute(ctx context.Context, state *PipelineState) error {
	log := state.Logger
	cfg := state.Config

	records, err := state.Store.List(state.Session.ID)
	if err != nil {
		return fmt.Errorf("list evidence: %w", err)
	}

	reportData := report.BuildReportData(
		state.Session.ID,
		state.Session.Target,
		state.Session.Mode,
		state.Session.Languages,
		records,
	)

	reportData.Coverage = report.CoverageMatrix{
		Dimensions: make([]report.DimensionCoverage, 0),
	}
	for _, dim := range state.Coverage.All() {
		reportData.Coverage.Dimensions = append(reportData.Coverage.Dimensions, report.DimensionCoverage{
			ID:           string(dim.ID),
			Name:         dim.Name,
			Status:       string(dim.Status),
			JoernRules:   dim.JoernRules,
			LLMExplored:  dim.LLMExplored,
			FindingCount: dim.FindingCount,
		})
	}

	reportMgr := report.NewManager(cfg.Report.OutputDir)
	reportPaths, err := reportMgr.Generate(ctx, reportData, cfg.Report.Formats)
	if err != nil {
		return fmt.Errorf("generate reports: %w", err)
	}

	log.Progress("✓ 报告生成成功:")
	for format, path := range reportPaths {
		log.Progress("  [%s] %s", format, path)
	}

	return nil
}
