package orchestrator

import (
	"context"
	"fmt"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/shared"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

type ExplorePhase struct{}

func (p *ExplorePhase) Name() string { return "Phase 2.8: Explorer Agent" }

func (p *ExplorePhase) Execute(ctx context.Context, state *PipelineState) error {
	if state.Config.Scan.Mode == "joern-only" {
		return nil
	}

	log := state.Logger
	cfg := state.Config

	maxRounds := cfg.Scan.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 2
	}

	for round := 1; round <= maxRounds; round++ {
		if !state.Coverage.ShouldContinue(round, maxRounds+1) {
			log.Progress("📊 覆盖率已满足终止条件，跳过第 %d 轮探索", round)
			break
		}

		if len(state.Coverage.Gaps()) == 0 {
			break
		}

		log.Progress("🔭 Explorer Agent Round %d/%d — 探索规则未覆盖的安全维度", round, maxRounds)
		state.Session.Round = round

		language := "java"
		if len(state.Session.Languages) > 0 {
			language = state.Session.Languages[0]
		}

		surface := buildAttackSurface(ctx, state.CPGEngine, state.IndexStore, state.Coverage, state.Session.Target, language, &cfg.Joern)

		if len(surface.EntryPoints) == 0 && len(surface.Dimensions) == 0 {
			log.Warning("无入口点或覆盖率缺口，跳过探索")
			break
		}

		explorerProvider, provErr := llm.NewProvider(&cfg.LLM)
		if provErr != nil {
			log.Warning("Explorer LLM 初始化失败: %v", provErr)
			break
		}

		contextMgr := cpg.NewContextManager(state.CPGEngine, state.IndexStore, state.Session.Target, cfg.LLM.TokenBudget.PerCandidate)
		prompts := shared.NewPromptLoader(cfg.Scan.PromptsDir)
		explorer := verifier.NewExplorer(explorerProvider, contextMgr, verifier.DefaultAgentContract(), prompts)

		log.Progress("⏳ 探索 %d 个未覆盖维度，%d 个入口点",
			len(surface.Dimensions), len(surface.EntryPoints))

		findings, exploreErr := explorer.Explore(ctx, surface)
		if exploreErr != nil {
			log.Warning("Explorer 执行失败: %v", exploreErr)
			break
		}

		if len(findings) == 0 {
			log.Progress("✓ Explorer 未发现额外漏洞，终止多轮探索")
			break
		}

		log.Progress("✓ Explorer 发现 %d 个候选漏洞", len(findings))

		tribunal := verifier.NewTribunal(explorerProvider, contextMgr, prompts)
		tribunal.SetParallelAgents(cfg.LLM.ParallelAgents)

		for i, finding := range findings {
			log.Progress("[Explorer %d/%d] %s (%s:%d)",
				i+1, len(findings), finding.Description, finding.FilePath, finding.LineNumber)

			explorerCandidate := domain.Candidate{
				RuleID:     "EXPLORER-" + finding.Dimension,
				Severity:   "medium",
				FilePath:   finding.FilePath,
				LineNumber: finding.LineNumber,
				Message:    finding.Description,
			}

			tribunalResult, verifyErr := tribunal.VerifyFull(ctx, &explorerCandidate)
			if verifyErr != nil {
				log.Warning("Tribunal 验证失败: %v", verifyErr)
				continue
			}

			judgeResult := tribunalResult.Judge
			candidateID := fmt.Sprintf("EXPLORER_R%d_%s_%d", round, finding.Dimension, finding.LineNumber)

			rec := &domain.Record{
				CandidateID:     candidateID,
				RuleID:          explorerCandidate.RuleID,
				FilePath:        finding.FilePath,
				LineNumber:      finding.LineNumber,
				InitialSeverity: "medium",
				FinalSeverity:   judgeResult.Severity,
				CWE:             judgeResult.CWE,
				LLMVerify: &domain.LLMVerification{
					Prosecutor: tribunalResult.Prosecutor,
					Defender:   tribunalResult.Defender,
					Judge:      judgeResult,
				},
			}

			if err := state.Store.Save(rec); err != nil {
				log.Warning("保存证据失败: %v", err)
			}

			if judgeResult.Verdict == domain.VerdictTruePositive || judgeResult.Verdict == domain.VerdictConditional {
				state.Coverage.AddFinding(explorerCandidate.RuleID)
			}

			log.Verdict(candidateID, judgeResult.Verdict, judgeResult.Confidence, judgeResult.Severity)

			dim := ResolveDimension("EXPLORER-" + finding.Dimension)
			if dim != "" {
				state.Coverage.MarkLLMExplored(dim)
			}
		}
	}

	return nil
}
