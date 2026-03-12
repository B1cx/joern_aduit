package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/shared"
)

// ChainStep is one step in an attack chain.
type ChainStep struct {
	Order        int    `json:"order"`
	FindingID    string `json:"finding_id"`
	Action       string `json:"action"`
	Precondition string `json:"precondition"`
	Outcome      string `json:"outcome"`
}

// AttackChain describes an end-to-end attack path combining multiple vulnerabilities.
type AttackChain struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Severity   string      `json:"severity"`
	Steps      []ChainStep `json:"steps"`
	Impact     string      `json:"impact"`
	Likelihood string      `json:"likelihood"`
	Reasoning  string      `json:"reasoning"`
}

// AttackChainResponse is the structured LLM output for attack chain analysis.
type AttackChainResponse struct {
	Chains    []AttackChain `json:"chains"`
	Unchained []string      `json:"unchained"`
	Summary   string        `json:"summary"`
}

// ChainAnalyzer performs attack chain correlation on confirmed findings.
type ChainAnalyzer struct {
	provider llm.Provider
	prompts  *shared.PromptLoader
}

func NewChainAnalyzer(provider llm.Provider, prompts *shared.PromptLoader) *ChainAnalyzer {
	return &ChainAnalyzer{
		provider: provider,
		prompts:  prompts,
	}
}

// Analyze takes confirmed findings and produces attack chains.
func (ca *ChainAnalyzer) Analyze(ctx context.Context, records []*domain.Record) (*AttackChainResponse, error) {
	var confirmed []*domain.Record
	for _, rec := range records {
		if rec.LLMVerify == nil || rec.LLMVerify.Judge == nil {
			continue
		}
		v := rec.LLMVerify.Judge.Verdict
		if v == domain.VerdictTruePositive || v == domain.VerdictConditional {
			confirmed = append(confirmed, rec)
		}
	}

	if len(confirmed) < 2 {
		return &AttackChainResponse{
			Summary: "Insufficient confirmed findings for attack chain analysis.",
		}, nil
	}

	promptTemplate, err := ca.prompts.Load("attack_chain.md")
	if err != nil {
		return nil, fmt.Errorf("load attack_chain prompt: %w", err)
	}

	userMessage := ca.buildMessage(confirmed)

	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   6000,
		Temperature: 0.2,
		JSONMode:    true,
	}

	var response AttackChainResponse
	callErr := ca.provider.ChatJSON(ctx, req, &response)
	if callErr != nil {
		return nil, fmt.Errorf("attack chain LLM call: %w", callErr)
	}

	return &response, nil
}

func (ca *ChainAnalyzer) buildMessage(records []*domain.Record) string {
	var sb strings.Builder

	sb.WriteString("# Confirmed Vulnerabilities for Chain Analysis\n\n")
	sb.WriteString(fmt.Sprintf("Total confirmed findings: %d\n\n", len(records)))

	for i, rec := range records {
		sb.WriteString(fmt.Sprintf("## Finding %d: %s\n\n", i+1, rec.CandidateID))
		sb.WriteString(fmt.Sprintf("- **Rule**: %s\n", rec.RuleID))
		sb.WriteString(fmt.Sprintf("- **CWE**: %s\n", rec.CWE))
		sb.WriteString(fmt.Sprintf("- **Severity**: %s\n", rec.FinalSeverity))
		sb.WriteString(fmt.Sprintf("- **Location**: %s:%d\n", rec.FilePath, rec.LineNumber))

		if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
			sb.WriteString(fmt.Sprintf("- **Verdict**: %s\n", rec.LLMVerify.Judge.Verdict))
			sb.WriteString(fmt.Sprintf("- **Confidence**: %.2f\n", rec.LLMVerify.Judge.Confidence))
			if rec.LLMVerify.Judge.AttackVector != "" {
				sb.WriteString(fmt.Sprintf("- **Attack Vector**: %s\n", rec.LLMVerify.Judge.AttackVector))
			}
			if rec.LLMVerify.Judge.Reasoning != "" {
				sb.WriteString(fmt.Sprintf("- **Reasoning**: %s\n", rec.LLMVerify.Judge.Reasoning))
			}
		}

		if rec.FuzzVerify != nil && rec.FuzzVerify.Result == "CONFIRMED" {
			sb.WriteString("- **Fuzz Status**: CONFIRMED\n")
		}

		sb.WriteString("\n")
	}

	sb.WriteString("**Your task**: Analyze the relationships between these confirmed vulnerabilities and identify attack chains. Return your analysis in the JSON format specified.\n")

	return sb.String()
}
