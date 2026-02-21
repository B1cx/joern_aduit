package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/db"
	"github.com/joern-audit/joern_audit/internal/evidence"
	"github.com/joern-audit/joern_audit/internal/fuzzer"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/report"
	"github.com/joern-audit/joern_audit/internal/scanner"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

// Phase represents a stage in the audit pipeline.
type Phase int

const (
	PhaseInit          Phase = 0
	PhaseCPGBuild      Phase = 1
	PhaseLLMVerify     Phase = 2
	PhaseFuzzVerify    Phase = 3
	PhaseAttackChain   Phase = 4
	PhaseReport        Phase = 5
)

func (p Phase) String() string {
	names := map[Phase]string{
		PhaseInit: "init", PhaseCPGBuild: "cpg_build", PhaseLLMVerify: "llm_verify",
		PhaseFuzzVerify: "fuzz_verify", PhaseAttackChain: "attack_chain", PhaseReport: "report",
	}
	return names[p]
}

// Session tracks the state of an audit session.
type Session struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Languages   []string  `json:"languages"`
	Mode        string    `json:"mode"`
	Phase       Phase     `json:"phase"`
	Round       int       `json:"round"`
	StartedAt   time.Time `json:"started_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Status      string    `json:"status"` // running, completed, failed
}

// Engine is the top-level orchestrator that drives the full audit pipeline.
type Engine struct {
	cfg *config.Config
}

func NewEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Run executes the full audit pipeline on the target.
func (e *Engine) Run(ctx context.Context, target string) error {
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

	fmt.Printf("\n🛡️  DeepAudit 安全审计系统\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("会话ID: %s\n", session.ID)
	fmt.Printf("目标: %s\n", target)
	fmt.Printf("模式: %s\n", session.Mode)
	fmt.Printf("语言: %v\n", session.Languages)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Phase 0: Init
	session.Phase = PhaseInit
	fmt.Printf("📌 [Phase 0] 初始化\n")

	// Create output directories
	dirs := []string{
		e.cfg.Joern.CPGDir,
		e.cfg.Report.OutputDir,
		".joern_audit/conversations",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	fmt.Printf("  ✓ 创建输出目录\n")

	// Initialize evidence store (SQLite-backed)
	dbPath := filepath.Join(e.cfg.Report.OutputDir, session.ID+".db")
	database, err := db.Open(dbPath)
	if err != nil {
		fmt.Printf("  ⚠️  SQLite 初始化失败，回退到内存存储: %v\n", err)
		database = nil
	}
	if database != nil {
		defer database.Close()
	}

	var store evidence.Store
	if database != nil {
		store = evidence.NewSQLiteStore(database, session.ID)
		fmt.Printf("  ✓ 初始化证据存储 (SQLite: %s)\n", dbPath)

		// Persist session to SQLite
		session.UpdatedAt = time.Now()
		if err := SaveSession(database, session); err != nil {
			fmt.Printf("  ⚠️  保存会话失败: %v\n", err)
		}
	} else {
		store = evidence.NewMemoryStore()
		fmt.Printf("  ✓ 初始化证据存储 (内存模式)\n")
	}

	// Initialize coverage matrix
	coverage := NewCoverageMatrix()
	fmt.Printf("  ✓ 初始化覆盖率矩阵\n\n")

	// Phase 1: CPG Build + Scan
	session.Phase = PhaseCPGBuild
	fmt.Printf("🔍 [Phase 1] CPG 构建与扫描\n")

	// Create CPG Engine
	cpgEngine := cpg.NewEngine(&e.cfg.Joern)

	// Parse target (use first language)
	language := "java" // default
	if len(session.Languages) > 0 {
		language = session.Languages[0]
	}
	fmt.Printf("  ⏳ 解析源代码到 CPG: %s (语言: %s)\n", target, language)
	if err := cpgEngine.Parse(ctx, target, language); err != nil {
		return fmt.Errorf("parse CPG: %w", err)
	}
	cpgPath := filepath.Join(e.cfg.Joern.CPGDir, "cpg.bin")
	fmt.Printf("  ✓ CPG 生成成功: %s\n", cpgPath)

	// Create index store
	indexStore := cpg.NewMemoryIndexStore()

	// Build index
	fmt.Printf("  ⏳ 构建 CPG 索引\n")
	if err := cpgEngine.BuildIndex(ctx, indexStore); err != nil {
		return fmt.Errorf("build index: %w", err)
	}
	fmt.Printf("  ✓ CPG 索引构建完成\n")

	// Create scanner and load rules
	fmt.Printf("  ⏳ 加载扫描规则\n")
	scanEngine := scanner.NewEngine(&e.cfg.Scan, cpgEngine)
	if err := scanEngine.LoadRules(session.Languages); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	fmt.Printf("  ✓ 加载了 %d 条规则\n", len(scanEngine.Rules()))

	// Scan for candidates (Joern CPG rules)
	fmt.Printf("  ⏳ 执行规则扫描\n")
	candidates, err := scanEngine.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	fmt.Printf("  ✓ Joern 规则发现 %d 个候选漏洞\n", len(candidates))

	// Update coverage matrix: mark all scanned rule categories as shallow
	for _, rule := range scanEngine.Rules() {
		coverage.MarkRuleScanned(rule.ID)
	}

	// XML Mapper scan (independent of Joern CPG, Java only)
	for _, lang := range session.Languages {
		if strings.ToLower(lang) == "java" {
			fmt.Printf("  ⏳ 扫描 MyBatis XML Mapper\n")
			xmlCandidates, xmlErr := scanner.ScanXML(target)
			if xmlErr != nil {
				fmt.Printf("  ⚠️  XML 扫描失败: %v\n", xmlErr)
			} else {
				fmt.Printf("  ✓ XML Mapper 发现 %d 个候选漏洞\n", len(xmlCandidates))
				candidates = append(candidates, xmlCandidates...)
			}
			break
		}
	}
	fmt.Printf("  ✓ 合计 %d 个候选漏洞\n", len(candidates))

	// Incremental scan: filter candidates by git diff
	if e.cfg.Scan.DiffRef != "" {
		fmt.Printf("  ⏳ 增量扫描: 过滤 git diff %s 变更文件\n", e.cfg.Scan.DiffRef)
		diffFilter, diffErr := NewDiffFilter(target, e.cfg.Scan.DiffRef)
		if diffErr != nil {
			fmt.Printf("  ⚠️  git diff 失败（跳过过滤）: %v\n", diffErr)
		} else {
			beforeCount := len(candidates)
			var filtered []cpg.Candidate
			for _, c := range candidates {
				if diffFilter.Contains(c.FilePath) {
					filtered = append(filtered, c)
				}
			}
			candidates = filtered
			fmt.Printf("  ✓ 增量过滤: %d → %d 个候选（变更文件 %d 个）\n",
				beforeCount, len(candidates), diffFilter.Count())
		}
	}
	fmt.Printf("\n")

	// Phase 2: LLM Verification
	if len(candidates) > 0 && e.cfg.Scan.Mode != "joern-only" {
		session.Phase = PhaseLLMVerify
		fmt.Printf("🤖 [Phase 2] LLM 三角色验证\n")

		// Create LLM provider
		llmProvider, err := llm.NewProvider(&e.cfg.LLM)
		if err != nil {
			return fmt.Errorf("create LLM provider: %w", err)
		}

		// Create context manager
		contextMgr := cpg.NewContextManager(cpgEngine, indexStore, target, e.cfg.LLM.TokenBudget.PerCandidate)

		// Create tribunal
		tribunal := verifier.NewTribunal(llmProvider, contextMgr)
		tribunal.SetParallelAgents(e.cfg.LLM.ParallelAgents)

		// Verify each candidate
		fmt.Printf("  ⏳ 验证 %d 个候选漏洞\n", len(candidates))

		// Determine concurrency level
		maxConcurrent := e.cfg.LLM.MaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 1 // Default to sequential
		}

		// failedCandidate tracks a candidate that failed LLM verification due to errors
		type failedCandidate struct {
			index     int
			candidate cpg.Candidate
			err       error
		}

		// Use semaphore pattern for concurrency control
		sem := make(chan struct{}, maxConcurrent)
		var wg sync.WaitGroup
		var mu sync.Mutex // Protect shared resources (store, output, failedCandidates)
		var failedCandidates []failedCandidate
		verifiedCount := 0

	for i, c := range candidates {
		wg.Add(1)
		go func(index int, candidate cpg.Candidate) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)

			// Thread-safe progress output
			mu.Lock()
			fmt.Printf("\n  [%d/%d] 验证候选: %s (%s:%d)\n",
				index+1, len(candidates), candidateID, candidate.FilePath, candidate.LineNumber)
			mu.Unlock()

			// Run tribunal verification (full: Prosecutor + Defender + Judge)
			tribunalResult, err := tribunal.VerifyFull(ctx, &candidate)
			if err != nil {
				mu.Lock()
				fmt.Printf("  ❌ 验证失败（将重试）: %v\n", err)
				failedCandidates = append(failedCandidates, failedCandidate{
					index:     index,
					candidate: candidate,
					err:       err,
				})
				mu.Unlock()
				return
			}

			judgeResult := tribunalResult.Judge

			// Create evidence record with full P/D/J results
			rec := &evidence.Record{
				CandidateID:     candidateID,
				RuleID:          candidate.RuleID,
				FilePath:        candidate.FilePath,
				LineNumber:      candidate.LineNumber,
				InitialSeverity: candidate.Severity,
				FinalSeverity:   judgeResult.Severity,
				CWE:             judgeResult.CWE,
				CPGEvidence:     candidate.CPGEvidence,
				LLMVerify: &evidence.LLMVerification{
					Prosecutor: tribunalResult.Prosecutor,
					Defender:   tribunalResult.Defender,
					Judge:      judgeResult,
				},
			}

			// Save to store (thread-safe)
			mu.Lock()
			if err := store.Save(rec); err != nil {
				fmt.Printf("  ⚠️  保存证据失败: %v\n", err)
			}
			verifiedCount++

			// Update coverage matrix for confirmed findings
			if judgeResult.Verdict == verifier.VerdictTruePositive ||
				judgeResult.Verdict == verifier.VerdictConditional {
				coverage.AddFinding(candidate.RuleID)
			}
			mu.Unlock()

			// Print verdict (thread-safe)
			verdictEmoji := map[string]string{
				"TRUE_POSITIVE":               "✅",
				"FALSE_POSITIVE":              "❌",
				"NEEDS_DEEPER":                "🔬",
				"EXPLOITABLE_WITH_CONDITION":  "",
			}
			emoji := verdictEmoji[string(judgeResult.Verdict)]

			mu.Lock()
			fmt.Printf("  %s 裁决: %s (置信度: %.2f, 严重性: %s)\n",
				emoji, judgeResult.Verdict, judgeResult.Confidence, judgeResult.Severity)
			mu.Unlock()
		}(i, c)
	}

		// Wait for all goroutines to complete
		wg.Wait()

		// Phase 2 Retry: retry failed candidates (serial, max 1 retry)
		retrySuccessCount := 0
		unverifiedCount := 0
		if len(failedCandidates) > 0 {
			fmt.Printf("\n  🔄 重试 %d 个失败候选（串行执行）\n", len(failedCandidates))

			for _, fc := range failedCandidates {
				candidateID := fmt.Sprintf("%s_%d", fc.candidate.RuleID, fc.candidate.LineNumber)
				fmt.Printf("\n  [重试] %s (%s:%d) 原始错误: %v\n",
					candidateID, fc.candidate.FilePath, fc.candidate.LineNumber, fc.err)

				retryCandidate := fc.candidate
				judgeResult, err := tribunal.Verify(ctx, &retryCandidate)
				if err != nil {
					// Still failed — save as UNVERIFIED
					fmt.Printf("  ❌ 重试仍失败: %v → 保存为 UNVERIFIED\n", err)
					rec := &evidence.Record{
						CandidateID:     candidateID,
						RuleID:          fc.candidate.RuleID,
						FilePath:        fc.candidate.FilePath,
						LineNumber:      fc.candidate.LineNumber,
						InitialSeverity: fc.candidate.Severity,
						FinalSeverity:   fc.candidate.Severity,
						CWE:             extractCWE(fc.candidate.RuleID),
						CPGEvidence:     fc.candidate.CPGEvidence,
						LLMVerify: &evidence.LLMVerification{
							Judge: &verifier.JudgeResult{
								Verdict:    verifier.Verdict("UNVERIFIED"),
								Severity:   fc.candidate.Severity,
								Confidence: 0,
								Reasoning:  fmt.Sprintf("LLM verification failed after retry: %v", err),
							},
							TotalTokens: 0,
						},
					}
					if saveErr := store.Save(rec); saveErr != nil {
						fmt.Printf("  ⚠️  保存证据失败: %v\n", saveErr)
					}
					unverifiedCount++
					continue
				}

				// Retry succeeded
				fmt.Printf("  ✅ 重试成功: %s (置信度: %.2f)\n", judgeResult.Verdict, judgeResult.Confidence)
				rec := &evidence.Record{
					CandidateID:     candidateID,
					RuleID:          fc.candidate.RuleID,
					FilePath:        fc.candidate.FilePath,
					LineNumber:      fc.candidate.LineNumber,
					InitialSeverity: fc.candidate.Severity,
					FinalSeverity:   judgeResult.Severity,
					CWE:             judgeResult.CWE,
					CPGEvidence:     fc.candidate.CPGEvidence,
					LLMVerify: &evidence.LLMVerification{
						Judge:       judgeResult,
						TotalTokens: 0,
					},
				}
				if saveErr := store.Save(rec); saveErr != nil {
					fmt.Printf("  ⚠️  保存证据失败: %v\n", saveErr)
				}
				retrySuccessCount++
			}
		}

		fmt.Printf("\n  ✓ LLM 验证完成: 成功 %d / 重试成功 %d / 未验证 %d\n\n",
			verifiedCount, retrySuccessCount, unverifiedCount)

		// Phase 2.5: NEEDS_DEEPER deep verification
		records, listErr := store.List(session.ID)
		if listErr == nil {
			var needsDeeperRecords []*evidence.Record
			var needsDeeperCandidates []cpg.Candidate
			for _, rec := range records {
				if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil &&
					rec.LLMVerify.Judge.Verdict == verifier.VerdictNeedsDeeper {
					needsDeeperRecords = append(needsDeeperRecords, rec)
					// Reconstruct candidate from record
					needsDeeperCandidates = append(needsDeeperCandidates, cpg.Candidate{
						RuleID:      rec.RuleID,
						FilePath:    rec.FilePath,
						LineNumber:  rec.LineNumber,
						Severity:    rec.InitialSeverity,
						CPGEvidence: rec.CPGEvidence,
					})
				}
			}

			if len(needsDeeperRecords) > 0 {
				fmt.Printf("🔬 [Phase 2.5] NEEDS_DEEPER 深度验证（%d 个候选）\n", len(needsDeeperRecords))

				for i, deepCandidate := range needsDeeperCandidates {
					candidateID := needsDeeperRecords[i].CandidateID
					fmt.Printf("\n  [深度 %d/%d] %s (%s:%d) — 提升上下文到 CallChain\n",
						i+1, len(needsDeeperCandidates), candidateID,
						deepCandidate.FilePath, deepCandidate.LineNumber)

					// Re-verify with expanded context level (CallChain)
					judgeResult, err := tribunal.VerifyDeep(ctx, &deepCandidate, cpg.ContextLevelCallChain)
					if err != nil {
						fmt.Printf("  ❌ 深度验证失败: %v（保留原始 NEEDS_DEEPER 裁决）\n", err)
						continue
					}

					// Update the record in store
					updatedRec := needsDeeperRecords[i]
					updatedRec.FinalSeverity = judgeResult.Severity
					updatedRec.CWE = judgeResult.CWE
					updatedRec.LLMVerify = &evidence.LLMVerification{
						Judge:         judgeResult,
						ContextRounds: 2, // Round 1 was initial, Round 2 is deep
						TotalTokens:   0,
					}
					if saveErr := store.Save(updatedRec); saveErr != nil {
						fmt.Printf("  ⚠️  更新证据失败: %v\n", saveErr)
					}

					verdictEmoji := map[string]string{
						"TRUE_POSITIVE":              "✅",
						"FALSE_POSITIVE":             "❌",
						"NEEDS_DEEPER":               "🔬",
						"EXPLOITABLE_WITH_CONDITION": "",
					}
					emoji := verdictEmoji[string(judgeResult.Verdict)]
					fmt.Printf("  %s 深度裁决: %s (置信度: %.2f, 严重性: %s)\n",
						emoji, judgeResult.Verdict, judgeResult.Confidence, judgeResult.Severity)
				}
				fmt.Printf("\n  ✓ NEEDS_DEEPER 深度验证完成\n\n")
			}
		}
	} else {
		// Handle joern-only mode or no candidates
		if len(candidates) == 0 {
			fmt.Printf("🎉 未发现候选漏洞，跳过 LLM 验证阶段\n\n")
		} else if e.cfg.Scan.Mode == "joern-only" {
			fmt.Printf("⚠️  仅 Joern 模式，跳过 LLM 验证\n\n")
			// Save candidates as-is without LLM verification
			for _, c := range candidates {
				rec := &evidence.Record{
					CandidateID:     fmt.Sprintf("%s_%d", c.RuleID, c.LineNumber),
					RuleID:          c.RuleID,
					FilePath:        c.FilePath,
					LineNumber:      c.LineNumber,
					InitialSeverity: c.Severity,
					FinalSeverity:   c.Severity,
					CWE:             extractCWE(c.RuleID),
					CPGEvidence:     c.CPGEvidence,
				}
				store.Save(rec)
			}
		}
	}

	// Print coverage matrix summary
	fmt.Printf("📊 覆盖率矩阵: %d/10 维度已覆盖\n", coverage.CoveredCount())
	for _, dim := range coverage.All() {
		statusIcon := map[CoverageStatus]string{
			Covered: "✅", Shallow: "🔶", Uncovered: "⬜",
		}
		icon := statusIcon[dim.Status]
		findingStr := ""
		if dim.FindingCount > 0 {
			findingStr = fmt.Sprintf(" (%d findings)", dim.FindingCount)
		}
		fmt.Printf("  %s %s: %s — %s%s\n", icon, dim.ID, dim.Name, dim.Status, findingStr)
	}
	fmt.Printf("\n")

	// Phase 2.8: Multi-round Explorer Agent (LLM free exploration for uncovered dimensions)
	maxRounds := e.cfg.Scan.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 2 // default
	}

	for round := 1; round <= maxRounds && e.cfg.Scan.Mode != "joern-only"; round++ {
		if !coverage.ShouldContinue(round, maxRounds+1) {
			fmt.Printf("📊 覆盖率已满足终止条件，跳过第 %d 轮探索\n\n", round)
			break
		}

		if len(coverage.Gaps()) == 0 {
			break
		}

		fmt.Printf("🔭 [Phase 2.8 Round %d/%d] Explorer Agent — 探索规则未覆盖的安全维度\n", round, maxRounds)
		session.Round = round

		// Build attack surface from CPG index
		surface := e.buildAttackSurface(ctx, indexStore, coverage, target, language)

		if len(surface.EntryPoints) == 0 && len(surface.Dimensions) == 0 {
			fmt.Printf("  ⚠️  无入口点或覆盖率缺口，跳过探索\n\n")
			break
		}

		// Create LLM provider
		explorerProvider, provErr := llm.NewProvider(&e.cfg.LLM)
		if provErr != nil {
			fmt.Printf("  ⚠️  Explorer LLM 初始化失败: %v\n\n", provErr)
			break
		}

		contextMgr := cpg.NewContextManager(cpgEngine, indexStore, target, e.cfg.LLM.TokenBudget.PerCandidate)
		explorer := verifier.NewExplorer(explorerProvider, contextMgr, verifier.DefaultAgentContract())
		explorer.SetPromptsDir(e.cfg.Scan.RulesDir + "/../prompts")

		fmt.Printf("  ⏳ 探索 %d 个未覆盖维度，%d 个入口点\n",
			len(surface.Dimensions), len(surface.EntryPoints))

		findings, exploreErr := explorer.Explore(ctx, surface)
		if exploreErr != nil {
			fmt.Printf("  ⚠️  Explorer 执行失败: %v\n\n", exploreErr)
			break
		}

		if len(findings) == 0 {
			fmt.Printf("  ✓ Explorer 未发现额外漏洞，终止多轮探索\n\n")
			break
		}

		fmt.Printf("  ✓ Explorer 发现 %d 个候选漏洞\n", len(findings))

		// Convert findings to candidates and run through Tribunal
		tribunal := verifier.NewTribunal(explorerProvider, contextMgr)
		tribunal.SetParallelAgents(e.cfg.LLM.ParallelAgents)

		for i, finding := range findings {
			fmt.Printf("  [Explorer %d/%d] %s (%s:%d)\n",
				i+1, len(findings), finding.Description, finding.FilePath, finding.LineNumber)

			explorerCandidate := cpg.Candidate{
				RuleID:     "EXPLORER-" + finding.Dimension,
				Severity:   "medium",
				FilePath:   finding.FilePath,
				LineNumber: finding.LineNumber,
				Message:    finding.Description,
			}

			tribunalResult, verifyErr := tribunal.VerifyFull(ctx, &explorerCandidate)
			if verifyErr != nil {
				fmt.Printf("    ⚠️  Tribunal 验证失败: %v\n", verifyErr)
				continue
			}

			judgeResult := tribunalResult.Judge
			candidateID := fmt.Sprintf("EXPLORER_R%d_%s_%d", round, finding.Dimension, finding.LineNumber)

			rec := &evidence.Record{
				CandidateID:     candidateID,
				RuleID:          explorerCandidate.RuleID,
				FilePath:        finding.FilePath,
				LineNumber:      finding.LineNumber,
				InitialSeverity: "medium",
				FinalSeverity:   judgeResult.Severity,
				CWE:             judgeResult.CWE,
				LLMVerify: &evidence.LLMVerification{
					Prosecutor: tribunalResult.Prosecutor,
					Defender:   tribunalResult.Defender,
					Judge:      judgeResult,
				},
			}

			if err := store.Save(rec); err != nil {
				fmt.Printf("    ⚠️  保存证据失败: %v\n", err)
			}

			if judgeResult.Verdict == verifier.VerdictTruePositive ||
				judgeResult.Verdict == verifier.VerdictConditional {
				coverage.AddFinding(explorerCandidate.RuleID)
			}

			verdictEmoji := map[string]string{
				"TRUE_POSITIVE": "✅", "FALSE_POSITIVE": "❌",
				"NEEDS_DEEPER": "🔬", "EXPLOITABLE_WITH_CONDITION": "",
			}
			emoji := verdictEmoji[string(judgeResult.Verdict)]
			fmt.Printf("    %s 裁决: %s (置信度: %.2f)\n",
				emoji, judgeResult.Verdict, judgeResult.Confidence)

			// Mark dimension as LLM explored
			dim := ResolveDimension("EXPLORER-" + finding.Dimension)
			if dim != "" {
				coverage.MarkLLMExplored(dim)
			}
		}
		fmt.Printf("\n")
	}

	// Phase 3: Fuzz Verification
	if e.cfg.Fuzzer.Enabled {
		session.Phase = PhaseFuzzVerify
		fmt.Printf("🎯 [Phase 3] Fuzz 验证\n")
		fmt.Printf("  目标: %s\n", e.cfg.Fuzzer.TargetURL)

		fuzzRecords, _ := store.List(session.ID)
		fuzzMgr := fuzzer.NewManager(&e.cfg.Fuzzer)
		fuzzMgr.SetSourceRoot(target) // Pass source root for endpoint path extraction
		confirmed, fuzzFailed, fuzzErrored := fuzzMgr.RunAll(ctx, fuzzRecords)

		// Update store with fuzz results
		for _, rec := range fuzzRecords {
			if rec.FuzzVerify != nil {
				store.Save(rec)
			}
		}

		fmt.Printf("  ✓ Fuzz 完成: 确认 %d / 失败 %d / 错误 %d\n\n",
			confirmed, fuzzFailed, fuzzErrored)
	}

	// Phase 4: Attack Chain Analysis
	if e.cfg.Scan.Mode == "deep" {
		session.Phase = PhaseAttackChain
		fmt.Printf("🔗 [Phase 4] 攻击链分析\n")

		chainRecords, chainListErr := store.List(session.ID)
		if chainListErr != nil {
			fmt.Printf("  ⚠️  加载证据失败: %v\n", chainListErr)
		} else {
			// Count confirmed findings
			confirmedCount := 0
			for _, rec := range chainRecords {
				if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
					v := rec.LLMVerify.Judge.Verdict
					if v == verifier.VerdictTruePositive || v == verifier.VerdictConditional {
						confirmedCount++
					}
				}
			}

			if confirmedCount < 2 {
				fmt.Printf("  ⚠️  确认漏洞不足 2 个（当前 %d），跳过攻击链分析\n\n", confirmedCount)
			} else {
				chainProvider, provErr := llm.NewProvider(&e.cfg.LLM)
				if provErr != nil {
					fmt.Printf("  ⚠️  LLM 初始化失败: %v\n\n", provErr)
				} else {
					analyzer := NewChainAnalyzer(chainProvider, "prompts")

					fmt.Printf("  ⏳ 分析 %d 个确认漏洞的攻击链关系\n", confirmedCount)

					chainResult, chainErr := analyzer.Analyze(ctx, chainRecords)
					if chainErr != nil {
						fmt.Printf("  ⚠️  攻击链分析失败: %v\n\n", chainErr)
					} else {
						fmt.Printf("  ✓ 发现 %d 条攻击链\n", len(chainResult.Chains))
						for _, chain := range chainResult.Chains {
							fmt.Printf("    [%s] %s (严重性: %s, 可能性: %s)\n",
								chain.ID, chain.Name, chain.Severity, chain.Likelihood)
							for _, step := range chain.Steps {
								fmt.Printf("      %d. %s → %s\n", step.Order, step.Action, step.Outcome)
							}
						}
						if chainResult.Summary != "" {
							fmt.Printf("  📋 总结: %s\n", chainResult.Summary)
						}
						fmt.Printf("\n")
					}
				}
			}
		}
	}

	// Phase 5: Report
	session.Phase = PhaseReport
	fmt.Printf("📄 [Phase 5] 生成报告\n")

	// Get all evidence records
	records, err := store.List(session.ID)
	if err != nil {
		return fmt.Errorf("list evidence: %w", err)
	}

	// Build report data
	reportData := report.BuildReportData(
		session.ID,
		target,
		session.Mode,
		session.Languages,
		records,
	)

	// Add coverage matrix
	reportData.Coverage = report.CoverageMatrix{
		Dimensions: make([]report.DimensionCoverage, 0),
	}
	for _, dim := range coverage.All() {
		reportData.Coverage.Dimensions = append(reportData.Coverage.Dimensions, report.DimensionCoverage{
			ID:           string(dim.ID),
			Name:         dim.Name,
			Status:       string(dim.Status),
			JoernRules:   dim.JoernRules,
			LLMExplored:  dim.LLMExplored,
			FindingCount: dim.FindingCount,
		})
	}

	// Generate reports
	reportMgr := report.NewManager(e.cfg.Report.OutputDir)
	reportPaths, err := reportMgr.Generate(ctx, reportData, e.cfg.Report.Formats)
	if err != nil {
		return fmt.Errorf("generate reports: %w", err)
	}

	fmt.Printf("  ✓ 报告生成成功:\n")
	for format, path := range reportPaths {
		fmt.Printf("    [%s] %s\n", format, path)
	}

	session.Status = "completed"
	session.UpdatedAt = time.Now()

	// Persist final session state
	if database != nil {
		SaveSession(database, session)
	}

	duration := time.Since(session.StartedAt)
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("✅ 审计完成！耗时: %s\n", duration.Round(time.Second))
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	return nil
}

// extractCategory extracts vulnerability category from rule ID.
// Example: "JAVA-SQLI-001" -> "SQLI"
func extractCategory(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) >= 2 {
		return strings.ToUpper(parts[1])
	}
	return "UNKNOWN"
}

// extractCWE extracts CWE ID from rule ID or uses default mapping.
// Example: "JAVA-SQLI-001" -> "CWE-89"
func extractCWE(ruleID string) string {
	category := extractCategory(ruleID)
	cweMapping := map[string]string{
		"SQLI":     "CWE-89",
		"CMDI":     "CWE-78",
		"RCE":      "CWE-94",
		"SSTI":     "CWE-94",
		"XSS":      "CWE-79",
		"SSRF":     "CWE-918",
		"LFI":      "CWE-22",
		"FILE":     "CWE-22",
		"DESER":    "CWE-502",
		"XXE":      "CWE-611",
		"AUTH":     "CWE-287",
		"AUTHZ":    "CWE-285",
		"CRYPTO":   "CWE-327",
	}
	if cwe, ok := cweMapping[category]; ok {
		return cwe
	}
	return "CWE-UNKNOWN"
}

// buildAttackSurface constructs an AttackSurface from CPG index data and coverage gaps.
func (e *Engine) buildAttackSurface(ctx context.Context, indexStore cpg.IndexStore, coverage *CoverageMatrix, target, language string) verifier.AttackSurface {
	surface := verifier.AttackSurface{
		TechStack:   language,
		Dimensions:  make(map[string]string),
	}

	// Identify uncovered dimensions as exploration targets
	for _, dim := range coverage.Gaps() {
		priority := "medium"
		switch dim.ID {
		case DimInjection, DimAuth, DimAuthz:
			priority = "high"
		}
		surface.Dimensions[string(dim.ID)+": "+dim.Name] = priority
	}

	// Extract entry points from CPG index (public methods with annotations)
	// Use Joern to query for Spring controller entry points
	cpgEngine := cpg.NewEngine(&e.cfg.Joern)
	entryQuery := `cpg.method.where(_.annotation.name(".*Mapping")).map(n => Map("name" -> n.name, "file" -> n.filename, "line" -> n.lineNumber.toString)).l`
	results, err := cpgEngine.Query(ctx, entryQuery)
	if err == nil {
		for _, r := range results {
			name, _ := r.Data["name"].(string)
			file, _ := r.Data["file"].(string)
			line, _ := r.Data["line"].(int)
			if name != "" && file != "" {
				surface.EntryPoints = append(surface.EntryPoints, verifier.EntryPoint{
					Method:  "GET", // default; actual method would need annotation parsing
					Path:    "/" + name,
					Handler: name,
					File:    file,
					Line:    line,
				})
			}
		}
	}

	// Identify high-risk areas from common patterns
	surface.HighRiskAreas = []string{
		"Authentication and session management",
		"Input validation at API boundaries",
		"File upload/download handling",
		"Database query construction",
		"External service communication",
	}

	return surface
}
