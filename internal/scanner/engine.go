package scanner

import (
	"context"
	"fmt"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
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
// Uses taint flow analysis for rules with sources/sinks, query matching for others.
func (e *Engine) Scan(ctx context.Context) ([]cpg.Candidate, error) {
	var candidates []cpg.Candidate

	for _, rule := range e.rules {
		// If rule has sources and sinks, use taint flow analysis
		if len(rule.Sources) > 0 && len(rule.Sinks) > 0 {
			flowCandidates, err := e.scanWithTaintFlow(ctx, rule)
			if err != nil {
				// log warning, continue with other rules
				continue
			}
			candidates = append(candidates, flowCandidates...)
		} else {
			// Fallback to query-based matching
			queryCandidates, err := e.scanWithQuery(ctx, rule)
			if err != nil {
				// log warning, continue with other rules
				continue
			}
			candidates = append(candidates, queryCandidates...)
		}
	}

	return candidates, nil
}

// scanWithTaintFlow uses Joern's reachableByFlows for taint analysis
func (e *Engine) scanWithTaintFlow(ctx context.Context, rule *Rule) ([]cpg.Candidate, error) {
	var candidates []cpg.Candidate

	// Build source and sink patterns from rule
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

				// Create candidate at the sink location
				sinkNode := flow.Nodes[len(flow.Nodes)-1]
				c := cpg.Candidate{
					RuleID:     rule.ID,
					Severity:   rule.Severity,
					FilePath:   sinkNode.File,
					LineNumber: sinkNode.Line,
					Message:    rule.Name,
					CPGEvidence: &cpg.CPGEvidence{
						TaintFlow:  flow.Nodes,
						JoernQuery: fmt.Sprintf("Flow: %s -> %s", source.Pattern, sink.Pattern),
					},
					Status:     cpg.StatusPending,
					Confidence: 0.7, // Higher confidence for taint flow matches
				}

				candidates = append(candidates, c)
			}
		}
	}

	return candidates, nil
}

// scanWithQuery uses CPGQL pattern matching
func (e *Engine) scanWithQuery(ctx context.Context, rule *Rule) ([]cpg.Candidate, error) {
	results, err := e.cpg.Query(ctx, rule.Query)
	if err != nil {
		return nil, err
	}

	var candidates []cpg.Candidate
	for _, r := range results {
		// Extract structured data from query result
		filePath, _ := r.Data["file"].(string)
		lineNumber, _ := r.Data["line"].(int)
		code, _ := r.Data["code"].(string)
		methodName, _ := r.Data["method_name"].(string)

		// Skip if we couldn't extract location
		if filePath == "" || filePath == "unknown" || lineNumber <= 0 {
			continue
		}

		c := cpg.Candidate{
			RuleID:     rule.ID,
			Severity:   rule.Severity,
			FilePath:   filePath,
			LineNumber: lineNumber,
			Message:    rule.Name,
			CPGEvidence: &cpg.CPGEvidence{
				JoernQuery: rule.Query,
				CallChain:  []string{methodName},
			},
			Status:     cpg.StatusPending,
			Confidence: 0.5, // Lower confidence for pattern matches
		}

		// Store the code snippet as additional context
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
