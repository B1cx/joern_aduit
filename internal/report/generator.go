package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// MarkdownGenerator produces Markdown reports.
type MarkdownGenerator struct{}

func (g *MarkdownGenerator) Format() string { return "markdown" }

func (g *MarkdownGenerator) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Security Audit Report\n\n"))
	b.WriteString(fmt.Sprintf("**Session**: %s\n", data.SessionID))
	b.WriteString(fmt.Sprintf("**Target**: %s\n", data.Target))
	b.WriteString(fmt.Sprintf("**Mode**: %s\n", data.ScanMode))
	b.WriteString(fmt.Sprintf("**Languages**: %s\n", strings.Join(data.Languages, ", ")))
	b.WriteString(fmt.Sprintf("**Tech Stack**: %s\n\n", data.TechStack))

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Total Candidates | %d |\n", data.Summary.TotalCandidates))
	b.WriteString(fmt.Sprintf("| True Positives | %d |\n", data.Summary.TruePositives))
	b.WriteString(fmt.Sprintf("| False Positives | %d |\n", data.Summary.FalsePositives))
	b.WriteString(fmt.Sprintf("| Fuzz Confirmed | %d |\n", data.Summary.FuzzConfirmed))
	b.WriteString(fmt.Sprintf("| Critical | %d |\n", data.Summary.Critical))
	b.WriteString(fmt.Sprintf("| High | %d |\n", data.Summary.High))
	b.WriteString(fmt.Sprintf("| Medium | %d |\n", data.Summary.Medium))
	b.WriteString(fmt.Sprintf("| Low | %d |\n", data.Summary.Low))

	b.WriteString("\n## Coverage Matrix\n\n")
	b.WriteString("| Dimension | Status | Joern | LLM | Findings |\n")
	b.WriteString("|-----------|--------|-------|-----|----------|\n")
	for _, d := range data.Coverage.Dimensions {
		status := map[string]string{"covered": "✅", "shallow": "⚠️", "uncovered": "❌"}[d.Status]
		b.WriteString(fmt.Sprintf("| %s %s | %s | %v | %v | %d |\n",
			d.ID, d.Name, status, d.JoernRules, d.LLMExplored, d.FindingCount))
	}

	b.WriteString("\n## Findings\n\n")
	for i, f := range data.Findings {
		b.WriteString(fmt.Sprintf("### %d. [%s] %s — %s\n\n", i+1, f.FinalSeverity, f.CWE, f.CandidateID))
		if f.LLMVerify != nil && f.LLMVerify.Judge != nil {
			j := f.LLMVerify.Judge
			b.WriteString(fmt.Sprintf("**Verdict**: %s (confidence: %.2f)\n\n", j.Verdict, j.Confidence))
			b.WriteString(fmt.Sprintf("**Reasoning**: %s\n\n", j.Reasoning))
			if j.AttackVector != "" {
				b.WriteString(fmt.Sprintf("**Attack Vector**: `%s`\n\n", j.AttackVector))
			}
			if len(j.EvidenceChain) > 0 {
				b.WriteString("**Evidence Chain**:\n\n```\n")
				for _, e := range j.EvidenceChain {
					b.WriteString(fmt.Sprintf("Step %d [%s]: %s:%d\n  %s\n", e.Step, e.Role, e.File, e.Line, e.Code))
				}
				b.WriteString("```\n\n")
			}
		}
		b.WriteString("---\n\n")
	}

	if len(data.AttackChains) > 0 {
		b.WriteString("## Attack Chains\n\n")
		for i, chain := range data.AttackChains {
			b.WriteString(fmt.Sprintf("### Chain %d: %s (CVSS %.1f)\n\n", i+1, chain.Name, chain.CVSS))
			for j, step := range chain.Steps {
				b.WriteString(fmt.Sprintf("%d. %s\n", j+1, step))
			}
			b.WriteString("\n")
		}
	}

	return []byte(b.String()), nil
}

// JSONGenerator produces JSON reports.
type JSONGenerator struct{}

func (g *JSONGenerator) Format() string { return "json" }

func (g *JSONGenerator) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}
