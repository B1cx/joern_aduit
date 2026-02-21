package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/llm"
)

// Verdict is the final determination for a candidate vulnerability.
type Verdict string

const (
	VerdictTruePositive  Verdict = "TRUE_POSITIVE"
	VerdictFalsePositive Verdict = "FALSE_POSITIVE"
	VerdictNeedsDeeper   Verdict = "NEEDS_DEEPER"
	VerdictConditional   Verdict = "EXPLOITABLE_WITH_CONDITION"
)

// EvidenceStep is a single step in the verified evidence chain.
type EvidenceStep struct {
	Step int    `json:"step"`
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code"`
	Role string `json:"role"` // SOURCE, PROPAGATION, SINK, SANITIZER
}

// ProsecutorResult is the output of the Prosecutor (red team) agent.
type ProsecutorResult struct {
	Verdict       string         `json:"verdict"` // VULNERABLE, INSUFFICIENT_EVIDENCE
	AttackPath    string         `json:"attack_path"`
	Evidence      []EvidenceStep `json:"evidence"`
	Preconditions []string       `json:"preconditions"`
	Impact        string         `json:"impact"`
	Confidence    float64        `json:"confidence"`
	NeedMore      []string       `json:"need_more"`
}

// DefenderResult is the output of the Defender (blue team) agent.
type DefenderResult struct {
	Verdict          string         `json:"verdict"` // SAFE, NO_DEFENSE_FOUND, PARTIAL_DEFENSE
	Defenses         []Defense      `json:"defenses"`
	Constraints      []string       `json:"constraints"`
	BypassAssessment string         `json:"bypass_assessment"`
	Confidence       float64        `json:"confidence"`
	NeedMore         []string       `json:"need_more"`
}

// Defense is a security mitigation found by the Defender.
type Defense struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	Code          string `json:"code"`
	Type          string `json:"type"`          // parameterized, filter, validation, framework
	Effectiveness string `json:"effectiveness"` // complete, bypassable, partial
}

// JudgeResult is the final verdict from the Judge agent.
type JudgeResult struct {
	Verdict       Verdict        `json:"verdict"`
	Severity      string         `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence    float64        `json:"confidence"`
	Reasoning     string         `json:"reasoning"`
	EvidenceChain []EvidenceStep `json:"evidence_chain"`
	Conditions    []string       `json:"conditions"`
	AttackVector  string         `json:"attack_vector"`
	CWE           string         `json:"cwe"`
	CVSSBase      float64        `json:"cvss_base"`
}

// TribunalResult bundles the full three-role verification output.
type TribunalResult struct {
	Prosecutor *ProsecutorResult `json:"prosecutor,omitempty"`
	Defender   *DefenderResult   `json:"defender,omitempty"`
	Judge      *JudgeResult      `json:"judge"`
}

// Tribunal orchestrates the Prosecutor-Defender-Judge verification flow.
type Tribunal struct {
	provider       llm.Provider
	contextMgr     *cpg.ContextManager
	promptsDir     string
	maxRounds      int  // Max context expansion rounds
	logger         *ConversationLogger
	parallelAgents bool // Enable parallel Prosecutor+Defender execution
}

func NewTribunal(provider llm.Provider, contextMgr *cpg.ContextManager) *Tribunal {
	return &Tribunal{
		provider:       provider,
		contextMgr:     contextMgr,
		promptsDir:     "prompts",
		maxRounds:      3,
		parallelAgents: false, // Default to serial execution to avoid rate limits
	}
}

// SetParallelAgents enables or disables parallel agent execution
func (t *Tribunal) SetParallelAgents(enabled bool) {
	t.parallelAgents = enabled
}

// SetPromptsDir sets custom prompts directory (for testing).
func (t *Tribunal) SetPromptsDir(dir string) {
	t.promptsDir = dir
}

// SetLogger sets the conversation logger for recording LLM interactions.
func (t *Tribunal) SetLogger(logger *ConversationLogger) {
	t.logger = logger
}

// Verify runs the full Prosecutor-Defender-Judge cycle on a candidate.
func (t *Tribunal) Verify(ctx context.Context, candidate *cpg.Candidate) (*JudgeResult, error) {
	// Phase 1: Extract initial context (Level 0+1: Alert + Function Body)
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     cpg.ContextLevelFunctionBody,
	})
	if err != nil {
		return nil, fmt.Errorf("extract context: %w", err)
	}

	// Phase 2: Execute Prosecutor and Defender (parallel or serial based on config)
	var (
		prosResult *ProsecutorResult
		defResult  *DefenderResult
		prosErr    error
		defErr     error
	)

	if t.parallelAgents {
		// Parallel execution (faster but may hit rate limits)
		var wg sync.WaitGroup
		wg.Add(2)

		// Prosecutor (Red Team) - tries to prove vulnerability
		go func() {
			defer wg.Done()
			prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx)
		}()

		// Defender (Blue Team) - tries to prove safety
		go func() {
			defer wg.Done()
			defResult, defErr = t.runDefender(ctx, candidate, codeCtx)
		}()

		wg.Wait()
	} else {
		// Serial execution (slower but avoids rate limits)
		prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx)
		if prosErr == nil {
			defResult, defErr = t.runDefender(ctx, candidate, codeCtx)
		}
	}

	// Check for errors
	if prosErr != nil {
		return nil, fmt.Errorf("prosecutor failed: %w", prosErr)
	}
	if defErr != nil {
		return nil, fmt.Errorf("defender failed: %w", defErr)
	}

	// Phase 3: Judge evaluates both arguments
	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed: %w", err)
	}

	return judgeResult, nil
}

// VerifyFull runs the full Prosecutor-Defender-Judge cycle and returns all three results.
func (t *Tribunal) VerifyFull(ctx context.Context, candidate *cpg.Candidate) (*TribunalResult, error) {
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     cpg.ContextLevelFunctionBody,
	})
	if err != nil {
		return nil, fmt.Errorf("extract context: %w", err)
	}

	var (
		prosResult *ProsecutorResult
		defResult  *DefenderResult
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
		return nil, fmt.Errorf("prosecutor failed: %w", prosErr)
	}
	if defErr != nil {
		return nil, fmt.Errorf("defender failed: %w", defErr)
	}

	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed: %w", err)
	}

	return &TribunalResult{
		Prosecutor: prosResult,
		Defender:   defResult,
		Judge:      judgeResult,
	}, nil
}

// VerifyDeep runs the Prosecutor-Defender-Judge cycle with an expanded context level.
// Used for NEEDS_DEEPER candidates that require more context to make a definitive judgment.
func (t *Tribunal) VerifyDeep(ctx context.Context, candidate *cpg.Candidate, level cpg.ContextLevel) (*JudgeResult, error) {
	// Extract context at the specified deeper level
	codeCtx, err := t.contextMgr.Extract(ctx, cpg.ContextRequest{
		Candidate: candidate,
		Level:     level,
	})
	if err != nil {
		return nil, fmt.Errorf("extract deep context (level %d): %w", level, err)
	}

	// Execute Prosecutor and Defender with expanded context
	var (
		prosResult *ProsecutorResult
		defResult  *DefenderResult
		prosErr    error
		defErr     error
	)

	if t.parallelAgents {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx)
		}()
		go func() {
			defer wg.Done()
			defResult, defErr = t.runDefender(ctx, candidate, codeCtx)
		}()
		wg.Wait()
	} else {
		prosResult, prosErr = t.runProsecutor(ctx, candidate, codeCtx)
		if prosErr == nil {
			defResult, defErr = t.runDefender(ctx, candidate, codeCtx)
		}
	}

	if prosErr != nil {
		return nil, fmt.Errorf("prosecutor failed (deep): %w", prosErr)
	}
	if defErr != nil {
		return nil, fmt.Errorf("defender failed (deep): %w", defErr)
	}

	// Judge evaluates with expanded context
	judgeResult, err := t.runJudge(ctx, candidate, codeCtx, prosResult, defResult)
	if err != nil {
		return nil, fmt.Errorf("judge failed (deep): %w", err)
	}

	return judgeResult, nil
}

// runProsecutor executes the Prosecutor (Red Team) agent.
func (t *Tribunal) runProsecutor(ctx context.Context, candidate *cpg.Candidate, codeCtx *cpg.ContextResult) (*ProsecutorResult, error) {
	// Load prosecutor prompt template
	promptTemplate, err := t.loadPrompt("prosecutor.md")
	if err != nil {
		return nil, err
	}

	// Build user message with candidate info and code context
	userMessage := t.buildProsecutorMessage(candidate, codeCtx)

	// Call LLM
	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result ProsecutorResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	// Log conversation (always, even if error occurred)
	if t.logger != nil {
		location := fmt.Sprintf("%s:%d", candidate.FilePath, candidate.LineNumber)
		candidateID := fmt.Sprintf("%s_%d", candidate.RuleID, candidate.LineNumber)

		// Get token counts (approximate if error)
		inputTokens, outputTokens := 0, 0
		if callErr == nil {
			// Estimate tokens (will be enhanced when we add proper token tracking)
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

// runDefender executes the Defender (Blue Team) agent.
func (t *Tribunal) runDefender(ctx context.Context, candidate *cpg.Candidate, codeCtx *cpg.ContextResult) (*DefenderResult, error) {
	// Load defender prompt template
	promptTemplate, err := t.loadPrompt("defender.md")
	if err != nil {
		return nil, err
	}

	// Build user message
	userMessage := t.buildDefenderMessage(candidate, codeCtx)

	// Call LLM
	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result DefenderResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	// Log conversation
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

// runJudge executes the Judge agent with both Prosecutor and Defender results.
func (t *Tribunal) runJudge(ctx context.Context, candidate *cpg.Candidate, codeCtx *cpg.ContextResult, pros *ProsecutorResult, def *DefenderResult) (*JudgeResult, error) {
	// Load judge prompt template
	promptTemplate, err := t.loadPrompt("judge.md")
	if err != nil {
		return nil, err
	}

	// Build user message with both arguments
	userMessage := t.buildJudgeMessage(candidate, codeCtx, pros, def)

	// Call LLM
	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	var result JudgeResult
	callErr := t.provider.ChatJSON(ctx, req, &result)

	// Log conversation
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

// loadPrompt reads a prompt template from the prompts directory.
func (t *Tribunal) loadPrompt(filename string) (string, error) {
	path := filepath.Join(t.promptsDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read prompt %s: %w", filename, err)
	}
	return string(data), nil
}

// buildProsecutorMessage constructs the user message for Prosecutor agent.
func (t *Tribunal) buildProsecutorMessage(candidate *cpg.Candidate, codeCtx *cpg.ContextResult) string {
	var sb strings.Builder

	sb.WriteString("# Candidate Alert\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Severity**: %s\n", candidate.Severity))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n", candidate.FilePath, candidate.LineNumber))
	sb.WriteString(fmt.Sprintf("**Message**: %s\n\n", candidate.Message))

	// Add taint flow if available
	if candidate.CPGEvidence != nil && len(candidate.CPGEvidence.TaintFlow) > 0 {
		sb.WriteString("## Taint Flow Path\n\n")
		for i, node := range candidate.CPGEvidence.TaintFlow {
			sb.WriteString(fmt.Sprintf("%d. `%s:%d` - %s\n", i+1, node.File, node.Line, node.Expr))
		}
		sb.WriteString("\n")
	}

	// Add code context
	sb.WriteString("## Code Context\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	// Add guided questions from rule
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

// buildDefenderMessage constructs the user message for Defender agent.
func (t *Tribunal) buildDefenderMessage(candidate *cpg.Candidate, codeCtx *cpg.ContextResult) string {
	var sb strings.Builder

	sb.WriteString("# Alleged Vulnerability\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Severity**: %s\n", candidate.Severity))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n", candidate.FilePath, candidate.LineNumber))
	sb.WriteString(fmt.Sprintf("**Message**: %s\n\n", candidate.Message))

	// Add taint flow if available
	if candidate.CPGEvidence != nil && len(candidate.CPGEvidence.TaintFlow) > 0 {
		sb.WriteString("## Alleged Taint Flow\n\n")
		for i, node := range candidate.CPGEvidence.TaintFlow {
			sb.WriteString(fmt.Sprintf("%d. `%s:%d` - %s\n", i+1, node.File, node.Line, node.Expr))
		}
		sb.WriteString("\n")
	}

	// Add known sanitizer patterns from rule
	if len(candidate.Sanitizers) > 0 {
		sb.WriteString("## Known Sanitizer Patterns\n\n")
		sb.WriteString("The following patterns are known mitigations for this vulnerability type. Check if any are present:\n\n")
		for i, s := range candidate.Sanitizers {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, s))
		}
		sb.WriteString("\n")
	}

	// Add code context
	sb.WriteString("## Code Context\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	// Add guided questions from rule
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

// buildJudgeMessage constructs the user message for Judge agent.
func (t *Tribunal) buildJudgeMessage(candidate *cpg.Candidate, codeCtx *cpg.ContextResult, pros *ProsecutorResult, def *DefenderResult) string {
	var sb strings.Builder

	sb.WriteString("# Case for Judgment\n\n")
	sb.WriteString(fmt.Sprintf("**Rule ID**: %s\n", candidate.RuleID))
	sb.WriteString(fmt.Sprintf("**Location**: %s:%d\n\n", candidate.FilePath, candidate.LineNumber))

	// Prosecutor's argument
	sb.WriteString("## Prosecutor's Argument (Red Team)\n\n")
	prosJSON, _ := json.MarshalIndent(pros, "", "  ")
	sb.WriteString("```json\n")
	sb.WriteString(string(prosJSON))
	sb.WriteString("\n```\n\n")

	// Defender's argument
	sb.WriteString("## Defender's Argument (Blue Team)\n\n")
	defJSON, _ := json.MarshalIndent(def, "", "  ")
	sb.WriteString("```json\n")
	sb.WriteString(string(defJSON))
	sb.WriteString("\n```\n\n")

	// Code context (for reference)
	sb.WriteString("## Code Context (for reference)\n\n")
	for _, slice := range codeCtx.Slices {
		sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", slice.Role, slice.FilePath, slice.StartLine, slice.EndLine))
		sb.WriteString("```\n")
		sb.WriteString(slice.Code)
		sb.WriteString("\n```\n\n")
	}

	// Add guided questions for the Judge to consider
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
