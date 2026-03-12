package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/llm"
	"github.com/joern-audit/joern_audit/internal/shared"
)

// Tribunal orchestrates the Prosecutor-Defender-Judge verification flow.
type Tribunal struct {
	provider       llm.Provider
	contextMgr     *cpg.ContextManager
	prompts        *shared.PromptLoader
	maxRounds      int
	logger         *ConversationLogger
	parallelAgents bool
}

func NewTribunal(provider llm.Provider, contextMgr *cpg.ContextManager, prompts *shared.PromptLoader) *Tribunal {
	return &Tribunal{
		provider:       provider,
		contextMgr:     contextMgr,
		prompts:        prompts,
		maxRounds:      3,
		parallelAgents: false,
	}
}

func (t *Tribunal) SetParallelAgents(enabled bool) {
	t.parallelAgents = enabled
}

func (t *Tribunal) SetLogger(logger *ConversationLogger) {
	t.logger = logger
}

// Verify runs the Prosecutor-Defender-Judge cycle and returns the Judge result.
func (t *Tribunal) Verify(ctx context.Context, candidate *domain.Candidate) (*domain.JudgeResult, error) {
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     cpg.ContextLevelFunctionBody,
	})
	if err != nil {
		return nil, fmt.Errorf("extract context: %w", err)
	}

	prosResult, defResult, err := t.runProsecutorAndDefender(ctx, candidate, codeCtx)
	if err != nil {
		return nil, err
	}

	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed: %w", err)
	}

	return judgeResult, nil
}

// VerifyFull runs the full cycle and returns all three results.
func (t *Tribunal) VerifyFull(ctx context.Context, candidate *domain.Candidate) (*domain.TribunalResult, error) {
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     cpg.ContextLevelFunctionBody,
	})
	if err != nil {
		return nil, fmt.Errorf("extract context: %w", err)
	}

	prosResult, defResult, err := t.runProsecutorAndDefender(ctx, candidate, codeCtx)
	if err != nil {
		return nil, err
	}

	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed: %w", err)
	}

	return &domain.TribunalResult{
		Prosecutor: prosResult,
		Defender:   defResult,
		Judge:      judgeResult,
	}, nil
}

// VerifyDeep runs the cycle with an expanded context level for NEEDS_DEEPER candidates.
func (t *Tribunal) VerifyDeep(ctx context.Context, candidate *domain.Candidate, level cpg.ContextLevel) (*domain.JudgeResult, error) {
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     level,
	})
	if err != nil {
		return nil, fmt.Errorf("extract deep context (level %d): %w", level, err)
	}

	prosResult, defResult, err := t.runProsecutorAndDefender(ctx, candidate, codeCtx)
	if err != nil {
		return nil, err
	}

	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed (deep): %w", err)
	}

	return judgeResult, nil
}

func (t *Tribunal) runProsecutorAndDefender(ctx context.Context, candidate *domain.Candidate, codeCtx *cpg.ContextResult) (*domain.ProsecutorResult, *domain.DefenderResult, error) {
	var (
		prosResult *domain.ProsecutorResult
		defResult  *domain.DefenderResult
		prosErr    error
		defErr     error
	)

	if t.parallelAgents {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx) }()
		go func() { defer wg.Done(); defResult, defErr = t.runDefender(ctx, candidate, codeCtx) }()
		wg.Wait()
	} else {
		prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx)
		if prosErr == nil {
			defResult, defErr = t.runDefender(ctx, candidate, codeCtx)
		}
	}

	if prosErr != nil {
		return nil, nil, fmt.Errorf("prosecutor failed: %w", prosErr)
	}
	if defErr != nil {
		return nil, nil, fmt.Errorf("defender failed: %w", defErr)
	}
	return prosResult, defResult, nil
}

func (t *Tribunal) runProsecutor(ctx context.Context, candidate *domain.Candidate, codeCtx *cpg.ContextResult) (*domain.ProsecutorResult, error) {
	promptTemplate, err := t.prompts.Load("prosecutor.md")
	if err != nil {
		return nil, err
	}

	userMessage := t.buildProsecutorMessage(candidate, codeCtx)

	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result domain.ProsecutorResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	if t.logger != nil {
		location := fmt.Sprintf("%s:%d", candidate.FilePath, candidate.LineNumber)
		candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)
		inputTokens, outputTokens := 0, 0
		if callErr == nil {
			inputTokens = len(promptTemplate+userMessage) / 4
			outputTokens = len(fmt.Sprintf("%v", result)) / 4
		}
		t.logger.Log("prosecutor", candidateID, candidate.RuleID, location, req, result, inputTokens, outputTokens, callErr)
	}

	if callErr != nil {
		return nil, fmt.Errorf("prosecutor LLM call: %w", callErr)
	}
	return &result, nil
}

func (t *Tribunal) runDefender(ctx context.Context, candidate *domain.Candidate, codeCtx *cpg.ContextResult) (*domain.DefenderResult, error) {
	promptTemplate, err := t.prompts.Load("defender.md")
	if err != nil {
		return nil, err
	}

	userMessage := t.buildDefenderMessage(candidate, codeCtx)

	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result domain.DefenderResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	if t.logger != nil {
		location := fmt.Sprintf("%s:%d", candidate.FilePath, candidate.LineNumber)
		candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)
		inputTokens, outputTokens := 0, 0
		if callErr == nil {
			inputTokens = len(promptTemplate+userMessage) / 4
			outputTokens = len(fmt.Sprintf("%v", result)) / 4
		}
		t.logger.Log("defender", candidateID, candidate.RuleID, location, req, result, inputTokens, outputTokens, callErr)
	}

	if callErr != nil {
		return nil, fmt.Errorf("defender LLM call: %w", callErr)
	}
	return &result, nil
}

func (t *Tribunal) runJudge(ctx context.Context, candidate *domain.Candidate, codeCtx *cpg.ContextResult, pros *domain.ProsecutorResult, def *domain.DefenderResult) (*domain.JudgeResult, error) {
	promptTemplate, err := t.prompts.Load("judge.md")
	if err != nil {
		return nil, err
	}

	userMessage := t.buildJudgeMessage(candidate, codeCtx, pros, def)

	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result domain.JudgeResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	if t.logger != nil {
		location := fmt.Sprintf("%s:%d", candidate.FilePath, candidate.LineNumber)
		candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)
		inputTokens, outputTokens := 0, 0
		if callErr == nil {
			inputTokens = len(promptTemplate+userMessage) / 4
			outputTokens = len(fmt.Sprintf("%v", result)) / 4
		}
		t.logger.Log("judge", candidateID, candidate.RuleID, location, req, result, inputTokens, outputTokens, callErr)
	}

	if callErr != nil {
		return nil, fmt.Errorf("judge LLM call: %w", callErr)
	}
	return &result, nil
}

func (t *Tribunal) buildProsecutorMessage(candidate *domain.Candidate, codeCtx *cpg.ContextResult) string {
	var sb strings.Builder

	sb.WriteString("# Candidate Alert\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Severity**: %s\n", candidate.Severity))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n", candidate.FilePath, candidate.LineNumber))
	sb.WriteString(fmt.Sprintf("**Message**: %s\n\n", candidate.Message))

	if candidate.CPGEvidence != nil && len(candidate.CPGEvidence.TaintFlow) > 0 {
		sb.WriteString("## Taint Flow Path\n\n")
		for i, node := range candidate.CPGEvidence.TaintFlow {
			sb.WriteString(fmt.Sprintf("%d. `%s:%d` - %s\n", i+1, node.File, node.Line, node.Expr))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Code Context\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	if len(candidate.GuidedQuestions) > 0 {
		sb.WriteString("## Investigative Questions\n\n")
		sb.WriteString("Use these questions to guide and focus your analysis:\n\n")
		for i, q := range candidate.GuidedQuestions {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, q))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**Your task**: Analyze whether this is a genuine exploitable vulnerability. Provide your verdict in JSON format as specified.\n")

	return sb.String()
}

func (t *Tribunal) buildDefenderMessage(candidate *domain.Candidate, codeCtx *cpg.ContextResult) string {
	var sb strings.Builder

	sb.WriteString("# Alleged Vulnerability\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Severity**: %s\n", candidate.Severity))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n", candidate.FilePath, candidate.LineNumber))
	sb.WriteString(fmt.Sprintf("**Message**: %s\n\n", candidate.Message))

	if candidate.CPGEvidence != nil && len(candidate.CPGEvidence.TaintFlow) > 0 {
		sb.WriteString("## Alleged Taint Flow\n\n")
		for i, node := range candidate.CPGEvidence.TaintFlow {
			sb.WriteString(fmt.Sprintf("%d. `%s:%d` - %s\n", i+1, node.File, node.Line, node.Expr))
		}
		sb.WriteString("\n")
	}

	if len(candidate.Sanitizers) > 0 {
		sb.WriteString("## Known Sanitizer Patterns\n\n")
		sb.WriteString("The following patterns are known mitigations for this vulnerability type. Check if any are present:\n\n")
		for i, s := range candidate.Sanitizers {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, s))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Code Context\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	if len(candidate.GuidedQuestions) > 0 {
		sb.WriteString("## Investigative Questions\n\n")
		sb.WriteString("Consider these questions when searching for defenses:\n\n")
		for i, q := range candidate.GuidedQuestions {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, q))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**Your task**: Search for defenses or constraints that make this vulnerability safe or unexploitable. Provide your verdict in JSON format as specified.\n")

	return sb.String()
}

func (t *Tribunal) buildJudgeMessage(candidate *domain.Candidate, codeCtx *cpg.ContextResult, pros *domain.ProsecutorResult, def *domain.DefenderResult) string {
	var sb strings.Builder

	sb.WriteString("# Case for Judgment\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n\n", candidate.FilePath, candidate.LineNumber))

	sb.WriteString("## Prosecutor's Argument (Red Team)\n\n")
	prosJSON, _ := json.MarshalIndent(pros, "", "  ")
	sb.WriteString("```json\n")
	sb.WriteString(string(prosJSON))
	sb.WriteString("\n```\n\n")

	sb.WriteString("## Defender's Argument (Blue Team)\n\n")
	defJSON, _ := json.MarshalIndent(def, "", "  ")
	sb.WriteString("```json\n")
	sb.WriteString(string(defJSON))
	sb.WriteString("\n```\n\n")

	sb.WriteString("## Code Context (for reference)\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	if len(candidate.GuidedQuestions) > 0 {
		sb.WriteString("## Key Questions to Consider\n\n")
		sb.WriteString("Evaluate both arguments against these rule-specific questions:\n\n")
		for i, q := range candidate.GuidedQuestions {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, q))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**Your task**: Based on both arguments above, make a final verdict. Provide your ruling in JSON format as specified.\n")

	return sb.String()
}
