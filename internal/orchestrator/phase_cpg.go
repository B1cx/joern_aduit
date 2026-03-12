package orchestrator

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/scanner"
)

type CPGPhase struct{}

func (p *CPGPhase) Name() string { return "Phase 1: CPG 构建与扫描" }

func (p *CPGPhase) Execute(ctx context.Context, state *PipelineState) error {
	log := state.Logger
	cfg := state.Config
	session := state.Session

	cpgEngine := cpg.NewEngine(&cfg.Joern)
	state.CPGEngine = cpgEngine

	language := "java"
	if len(session.Languages) > 0 {
		language = session.Languages[0]
	}

	log.Progress("⏳ 解析源代码到 CPG: %s (语言: %s)", session.Target, language)
	if err := cpgEngine.Parse(ctx, session.Target, language); err != nil {
		return fmt.Errorf("parse CPG: %w", err)
	}
	cpgPath := filepath.Join(cfg.Joern.CPGDir, "cpg.bin")
	log.Progress("✓ CPG 生成成功: %s", cpgPath)

	indexStore := cpg.NewMemoryIndexStore()
	state.IndexStore = indexStore

	log.Progress("⏳ 构建 CPG 索引")
	if err := cpgEngine.BuildIndex(ctx, indexStore); err != nil {
		return fmt.Errorf("build index: %w", err)
	}
	log.Progress("✓ CPG 索引构建完成")

	log.Progress("⏳ 加载扫描规则")
	scanEngine := scanner.NewEngine(&cfg.Scan, cpgEngine)
	if err := scanEngine.LoadRules(session.Languages); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	log.Progress("✓ 加载了 %d 条规则", len(scanEngine.Rules()))

	log.Progress("⏳ 执行规则扫描")
	candidates, err := scanEngine.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	log.Progress("✓ Joern 规则发现 %d 个候选漏洞", len(candidates))

	for _, rule := range scanEngine.Rules() {
		state.Coverage.MarkRuleScanned(rule.ID)
	}

	for _, lang := range session.Languages {
		if strings.ToLower(lang) == "java" {
			log.Progress("⏳ 扫描 MyBatis XML Mapper")
			xmlCandidates, xmlErr := scanner.ScanXML(session.Target)
			if xmlErr != nil {
				log.Warning("XML 扫描失败: %v", xmlErr)
			} else {
				log.Progress("✓ XML Mapper 发现 %d 个候选漏洞", len(xmlCandidates))
				candidates = append(candidates, xmlCandidates...)
			}
			break
		}
	}
	log.Progress("✓ 合计 %d 个候选漏洞", len(candidates))

	if cfg.Scan.DiffRef != "" {
		log.Progress("⏳ 增量扫描: 过滤 git diff %s 变更文件", cfg.Scan.DiffRef)
		diffFilter, diffErr := NewDiffFilter(session.Target, cfg.Scan.DiffRef)
		if diffErr != nil {
			log.Warning("git diff 失败（跳过过滤）: %v", diffErr)
		} else {
			beforeCount := len(candidates)
			var filtered []domain.Candidate
			for _, c := range candidates {
				if diffFilter.Contains(c.FilePath) {
					filtered = append(filtered, c)
				}
			}
			candidates = filtered
			log.Progress("✓ 增量过滤: %d → %d 个候选（变更文件 %d 个）",
				beforeCount, len(candidates), diffFilter.Count())
		}
	}

	state.Candidates = candidates
	return nil
}
