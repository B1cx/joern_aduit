package scanner

import (
	"context"
	"fmt"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
)

// Engine orchestrates rule-based scanning using Joern.
type Engine struct {
	cfg   *config.ScanConfig
	cpg   *cpg.Engine
	rules []*Rule
}

func NewEngine(cfg *config.ScanConfig, cpgEngine *cpg.Engine) *Engine {
	return &Engine{cfg: cfg, cpg: cpgEngine}
}

// LoadRules loads YAML rules for the specified languages.
func (e *Engine) LoadRules(languages []string) error {
	for _, lang := range languages {
		rules, err := LoadRulesForLanguage(e.cfg.RulesDir, lang)
		if err != nil {
			return err
		}
		e.rules = append(e.rules, rules...)
	}
	return nil
}

// Scan executes all loaded rules against the CPG and returns candidates.
func (e *Engine) Scan(ctx context.Context) ([]domain.Candidate, error) {
	var candidates []domain.Candidate

	for _, rule := range e.rules {
		if len(rule.Sources) > 0 && len(rule.Sinks) > 0 {
			flowCandidates, err := e.scanWithTaintFlow(ctx, rule)
			if err != nil {
				continue
			}
			candidates = append(candidates, flowCandidates...)
		} else {
			queryCandidates, err := e.scanWithQuery(ctx, rule)
			if err != nil {
				continue
			}
			candidates = append(candidates, queryCandidates...)
		}
	}

	return candidates, nil
}

func (e *Engine) scanWithTaintFlow(ctx context.Context, rule *Rule) ([]domain.Candidate, error) {
	var candidates []domain.Candidate

	for _, sink := range rule.Sinks {
		for _, source := range rule.Sources {
			flows, err := e.cpg.Flow(ctx, source.Pattern, sink.Pattern)
			if err != nil {
				continue
			}

			for _, flow := range flows {
				if len(flow.Nodes) == 0 {
					continue
				}

				sinkNode := flow.Nodes[len(flow.Nodes)-1]
				c := domain.Candidate{
					RuleID:   rule.ID,
					Severity: rule.Severity,
					FilePath: sinkNode.File,
					LineNumber: sinkNode.Line,
					Message:  rule.Name,
					CPGEvidence: &domain.CPGEvidence{
						TaintFlow:  flow.Nodes,
						JoernQuery: fmt.Sprintf("Flow: %s -> %s", source.Pattern, sink.Pattern),
					},
					Status:          domain.StatusPending,
					Confidence:      0.7,
					GuidedQuestions: rule.GuidedQuestions,
					Sanitizers:      extractSanitizerPatterns(rule),
				}

				candidates = append(candidates, c)
			}
		}
	}

	return candidates, nil
}

func (e *Engine) scanWithQuery(ctx context.Context, rule *Rule) ([]domain.Candidate, error) {
	results, err := e.cpg.Query(ctx, rule.Query)
	if err != nil {
		return nil, err
	}

	var candidates []domain.Candidate
	for _, r := range results {
		filePath, _ := r.Data["file"].(string)
		lineNumber, _ := r.Data["line"].(int)
		code, _ := r.Data["code"].(string)
		methodName, _ := r.Data["method_name"].(string)

		if filePath == "" || filePath == "unknown" || lineNumber <= 0 {
			continue
		}

		c := domain.Candidate{
			RuleID:   rule.ID,
			Severity: rule.Severity,
			FilePath: filePath,
			LineNumber: lineNumber,
			Message:  rule.Name,
			CPGEvidence: &domain.CPGEvidence{
				JoernQuery: rule.Query,
				CallChain:  []string{methodName},
			},
			Status:          domain.StatusPending,
			Confidence:      0.5,
			GuidedQuestions: rule.GuidedQuestions,
			Sanitizers:      extractSanitizerPatterns(rule),
		}

		if code != "" {
			c.Message = rule.Name + " at: " + code
		}

		candidates = append(candidates, c)
	}

	return candidates, nil
}

// Rules returns all loaded rules.
func (e *Engine) Rules() []*Rule {
	return e.rules
}

func extractSanitizerPatterns(rule *Rule) []string {
	if len(rule.Sanitizers) == 0 {
		return nil
	}
	patterns := make([]string, len(rule.Sanitizers))
	for i, s := range rule.Sanitizers {
		patterns[i] = s.Pattern
	}
	return patterns
}
