package orchestrator

import (
	"context"
	"fmt"
	"sync"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/knowledge"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/shared"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

type VerifyPhase struct {
	cweDB *knowledge.CWEDatabase
}

func NewVerifyPhase() *VerifyPhase {
	return &VerifyPhase{cweDB: knowledge.NewCWEDatabase()}
}

func (p *VerifyPhase) Name() string { return "Phase 2: LLM 三角色验证" }

func (p *VerifyPhase) Execute(ctx context.Context, state *PipelineState) error {
	if len(state.Candidates) == 0 {
		state.Logger.Summary("🎉 未发现候选漏洞，跳过 LLM 验证阶段")
		return nil
	}
	if state.Config.Scan.Mode == "joern-only" {
		state.Logger.Summary("⚠️  仅 Joern 模式，跳过 LLM 验证")
		p.saveJoernOnlyResults(state)
		return nil
	}

	log := state.Logger
	cfg := state.Config

	llmProvider, err := llm.NewProvider(&cfg.LLM)
	if err != nil {
		return fmt.Errorf("create LLM provider: %w", err)
	}

	contextMgr := cpg.NewContextManager(state.CPGEngine, state.IndexStore, state.Session.Target, cfg.LLM.TokenBudget.PerCandidate)
	prompts := shared.NewPromptLoader(cfg.Scan.PromptsDir)
	tribunal := verifier.NewTribunal(llmProvider, contextMgr, prompts)
	tribunal.SetParallelAgents(cfg.LLM.ParallelAgents)

	log.Progress("⏳ 验证 %d 个候选漏洞", len(state.Candidates))

	verifiedCount, failedCandidates := p.verifyAll(ctx, state, tribunal)

	retrySuccess, unverified := p.retryFailed(ctx, state, tribunal, failedCandidates)

	log.Progress("✓ LLM 验证完成: 成功 %d / 重试成功 %d / 未验证 %d",
		verifiedCount, retrySuccess, unverified)

	p.deepVerify(ctx, state, tribunal)

	return nil
}

type failedCandidate struct {
	index     int
	candidate domain.Candidate
	err       error
}

func (p *VerifyPhase) verifyAll(ctx context.Context, state *PipelineState, tribunal *verifier.Tribunal) (int, []failedCandidate) {
	log := state.Logger
	maxConcurrent := state.Config.LLM.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failedCandidates []failedCandidate
	verifiedCount := 0

	for i, c := range state.Candidates {
		wg.Add(1)
		go func(index int, candidate domain.Candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)

			mu.Lock()
			log.Progress("[%d/%d] 验证候选: %s (%s:%d)",
				index+1, len(state.Candidates), candidateID, candidate.FilePath, candidate.LineNumber)
			mu.Unlock()

			tribunalResult, err := tribunal.VerifyFull(ctx, &candidate)
			if err != nil {
				mu.Lock()
				log.Error("验证失败（将重试）: %v", err)
				failedCandidates = append(failedCandidates, failedCandidate{index, candidate, err})
				mu.Unlock()
				return
			}

			judgeResult := tribunalResult.Judge
			rec := &domain.Record{
				CandidateID:     candidateID,
				RuleID:          candidate.RuleID,
				FilePath:        candidate.FilePath,
				LineNumber:      candidate.LineNumber,
				InitialSeverity: candidate.Severity,
				FinalSeverity:   judgeResult.Severity,
				CWE:             judgeResult.CWE,
				CPGEvidence:     candidate.CPGEvidence,
				LLMVerify: &domain.LLMVerification{
					Prosecutor: tribunalResult.Prosecutor,
					Defender:   tribunalResult.Defender,
					Judge:      judgeResult,
				},
			}

			mu.Lock()
			if err := state.Store.Save(rec); err != nil {
				log.Warning("保存证据失败: %v", err)
			}
			verifiedCount++

			if judgeResult.Verdict == domain.VerdictTruePositive || judgeResult.Verdict == domain.VerdictConditional {
				state.Coverage.AddFinding(candidate.RuleID)
			}
			mu.Unlock()

			mu.Lock()
			log.Verdict(candidateID, judgeResult.Verdict, judgeResult.Confidence, judgeResult.Severity)
			mu.Unlock()
		}(i, c)
	}

	wg.Wait()
	return verifiedCount, failedCandidates
}

func (p *VerifyPhase) retryFailed(ctx context.Context, state *PipelineState, tribunal *verifier.Tribunal, failed []failedCandidate) (int, int) {
	if len(failed) == 0 {
		return 0, 0
	}

	log := state.Logger
	log.Progress("🔄 重试 %d 个失败候选（串行执行）", len(failed))

	retrySuccess, unverified := 0, 0
	for _, fc := range failed {
		candidateID := fmt.Sprintf("%s_%d", fc.candidate.RuleID, fc.candidate.LineNumber)
		log.Progress("[重试] %s (%s:%d) 原始错误: %v",
			candidateID, fc.candidate.FilePath, fc.candidate.LineNumber, fc.err)

		retryCandidate := fc.candidate
		judgeResult, err := tribunal.Verify(ctx, &retryCandidate)
		if err != nil {
			log.Error("重试仍失败: %v → 保存为 UNVERIFIED", err)
			rec := &domain.Record{
				CandidateID:     candidateID,
				RuleID:          fc.candidate.RuleID,
				FilePath:        fc.candidate.FilePath,
				LineNumber:      fc.candidate.LineNumber,
				InitialSeverity: fc.candidate.Severity,
				FinalSeverity:   fc.candidate.Severity,
				CWE:             p.cweDB.ResolveCWE(fc.candidate.RuleID),
				CPGEvidence:     fc.candidate.CPGEvidence,
				LLMVerify: &domain.LLMVerification{
					Judge: &domain.JudgeResult{
						Verdict:    domain.Verdict("UNVERIFIED"),
						Severity:   fc.candidate.Severity,
						Confidence: 0,
						Reasoning:  fmt.Sprintf("LLM verification failed after retry: %v", err),
					},
				},
			}
			state.Store.Save(rec)
			unverified++
			continue
		}

		log.Progress("✅ 重试成功: %s (置信度: %.2f)", judgeResult.Verdict, judgeResult.Confidence)
		rec := &domain.Record{
			CandidateID:     candidateID,
			RuleID:          fc.candidate.RuleID,
			FilePath:        fc.candidate.FilePath,
			LineNumber:      fc.candidate.LineNumber,
			InitialSeverity: fc.candidate.Severity,
			FinalSeverity:   judgeResult.Severity,
			CWE:             judgeResult.CWE,
			CPGEvidence:     fc.candidate.CPGEvidence,
			LLMVerify: &domain.LLMVerification{
				Judge: judgeResult,
			},
		}
		state.Store.Save(rec)
		retrySuccess++
	}

	return retrySuccess, unverified
}

func (p *VerifyPhase) deepVerify(ctx context.Context, state *PipelineState, tribunal *verifier.Tribunal) {
	log := state.Logger
	records, listErr := state.Store.List(state.Session.ID)
	if listErr != nil {
		return
	}

	var needsDeeperRecords []*domain.Record
	var needsDeeperCandidates []domain.Candidate
	for _, rec := range records {
		if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil &&
			rec.LLMVerify.Judge.Verdict == domain.VerdictNeedsDeeper {
			needsDeeperRecords = append(needsDeeperRecords, rec)
			needsDeeperCandidates = append(needsDeeperCandidates, domain.Candidate{
				RuleID:      rec.RuleID,
				FilePath:    rec.FilePath,
				LineNumber:  rec.LineNumber,
				Severity:    rec.InitialSeverity,
				CPGEvidence: rec.CPGEvidence,
			})
		}
	}

	if len(needsDeeperRecords) == 0 {
		return
	}

	log.Progress("🔬 NEEDS_DEEPER 深度验证（%d 个候选）", len(needsDeeperRecords))

	for i, deepCandidate := range needsDeeperCandidates {
		candidateID := needsDeeperRecords[i].CandidateID
		log.Progress("[深度 %d/%d] %s (%s:%d) — 提升上下文到 CallChain",
			i+1, len(needsDeeperCandidates), candidateID,
			deepCandidate.FilePath, deepCandidate.LineNumber)

		judgeResult, err := tribunal.VerifyDeep(ctx, &deepCandidate, cpg.ContextLevelCallChain)
		if err != nil {
			log.Error("深度验证失败: %v（保留原始 NEEDS_DEEPER 裁决）", err)
			continue
		}

		updatedRec := needsDeeperRecords[i]
		updatedRec.FinalSeverity = judgeResult.Severity
		updatedRec.CWE = judgeResult.CWE
		updatedRec.LLMVerify = &domain.LLMVerification{
			Judge:         judgeResult,
			ContextRounds: 2,
		}
		state.Store.Save(updatedRec)

		log.Verdict(candidateID, judgeResult.Verdict, judgeResult.Confidence, judgeResult.Severity)
	}

	log.Progress("✓ NEEDS_DEEPER 深度验证完成")
}

func (p *VerifyPhase) saveJoernOnlyResults(state *PipelineState) {
	for _, c := range state.Candidates {
		rec := &domain.Record{
			CandidateID:     fmt.Sprintf("%s_%d", c.RuleID, c.LineNumber),
			RuleID:          c.RuleID,
			FilePath:        c.FilePath,
			LineNumber:      c.LineNumber,
			InitialSeverity: c.Severity,
			FinalSeverity:   c.Severity,
			CWE:             p.cweDB.ResolveCWE(c.RuleID),
			CPGEvidence:     c.CPGEvidence,
		}
		state.Store.Save(rec)
	}
}
