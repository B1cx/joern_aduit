package orchestrator

import (
	"context"

	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/shared"
)

type ChainPhase struct{}

func (p *ChainPhase) Name() string { return "Phase 4: 攻击链分析" }

func (p *ChainPhase) Execute(ctx context.Context, state *PipelineState) error {
	if state.Config.Scan.Mode != "deep" {
		return nil
	}

	log := state.Logger

	chainRecords, chainListErr := state.Store.List(state.Session.ID)
	if chainListErr != nil {
		log.Warning("加载证据失败: %v", chainListErr)
		return nil
	}

	confirmedCount := 0
	for _, rec := range chainRecords {
		if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
			v := rec.LLMVerify.Judge.Verdict
			if v == domain.VerdictTruePositive || v == domain.VerdictConditional {
				confirmedCount++
			}
		}
	}

	if confirmedCount < 2 {
		log.Warning("确认漏洞不足 2 个（当前 %d），跳过攻击链分析", confirmedCount)
		return nil
	}

	chainProvider, provErr := llm.NewProvider(&state.Config.LLM)
	if provErr != nil {
		log.Warning("LLM 初始化失败: %v", provErr)
		return nil
	}

	prompts := shared.NewPromptLoader(state.Config.Scan.PromptsDir)
	analyzer := NewChainAnalyzer(chainProvider, prompts)

	log.Progress("⏳ 分析 %d 个确认漏洞的攻击链关系", confirmedCount)

	chainResult, chainErr := analyzer.Analyze(ctx, chainRecords)
	if chainErr != nil {
		log.Warning("攻击链分析失败: %v", chainErr)
		return nil
	}

	log.Progress("✓ 发现 %d 条攻击链", len(chainResult.Chains))
	for _, chain := range chainResult.Chains {
		log.Progress("  [%s] %s (严重性: %s, 可能性: %s)",
			chain.ID, chain.Name, chain.Severity, chain.Likelihood)
		for _, step := range chain.Steps {
			log.Progress("    %d. %s → %s", step.Order, step.Action, step.Outcome)
		}
	}
	if chainResult.Summary != "" {
		log.Progress("📋 总结: %s", chainResult.Summary)
	}

	return nil
}
