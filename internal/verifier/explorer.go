package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/llm"
)

// ExplorerFinding is a potential vulnerability discovered by free exploration.
type ExplorerFinding struct {
	Description    string         `json:"description"`
	FilePath       string         `json:"file_path"`
	LineNumber     int            `json:"line_number"`
	Code           string         `json:"code"`
	Dimension      string         `json:"dimension"` // D1-D10
	Confidence     float64        `json:"confidence"`
	Evidence       []EvidenceStep `json:"evidence"`
	NeedsTribunal  bool           `json:"needs_tribunal"`
}

// ExplorerResponse is the structured JSON output from the Explorer LLM call.
type ExplorerResponse struct {
	Findings           []ExplorerFinding `json:"findings"`
	ExploredDirections []string          `json:"explored_directions"`
	SuggestedNext      []string          `json:"suggested_next"`
}

// Explorer performs free-form vulnerability exploration within controlled bounds.
type Explorer struct {
	provider   llm.Provider
	contextMgr *cpg.ContextManager
	contract   AgentContract
	promptsDir string
	logger     *ConversationLogger
}

func NewExplorer(provider llm.Provider, contextMgr *cpg.ContextManager, contract AgentContract) *Explorer {
	return &Explorer{
		provider:   provider,
		contextMgr: contextMgr,
		contract:   contract,
		promptsDir: "prompts",
	}
}

// SetLogger sets the conversation logger for recording LLM interactions.
func (e *Explorer) SetLogger(logger *ConversationLogger) {
	e.logger = logger
}

// SetPromptsDir sets custom prompts directory.
func (e *Explorer) SetPromptsDir(dir string) {
	e.promptsDir = dir
}

// Explore performs free-form security exploration guided by the attack surface map.
// It returns findings that should be further verified by the Tribunal.
func (e *Explorer) Explore(ctx context.Context, attackSurface AttackSurface) ([]ExplorerFinding, error) {
	// Load explorer system prompt
	promptTemplate, err := e.loadPrompt("explorer.md")
	if err != nil {
		return nil, fmt.Errorf("load explorer prompt: %w", err)
	}

	// Build user message with attack surface + code context
	userMessage := e.buildExplorerMessage(&attackSurface)

	// Call LLM
	req := llm.ChatRequest{
		SystemPrompt: promptTemplate,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		MaxTokens:   6000,
		Temperature: 0.3, // slightly higher than tribunal for creative exploration
		JSONMode:    true,
	}

	var response ExplorerResponse
	callErr := e.provider.ChatJSON(ctx, req, &response)

	// Log conversation
	if e.logger != nil {
		inputTokens, outputTokens := 0, 0
		if callErr == nil {
			inputTokens = len(promptTemplate+userMessage) / 4
			outputTokens = len(fmt.Sprintf("%v", response)) / 4
		}
		e.logger.Log("explorer", "explorer_session", "", "", req, response, inputTokens, outputTokens, callErr)
	}

	if callErr != nil {
		return nil, fmt.Errorf("explorer LLM call: %w", callErr)
	}

	// Cap confidence at 0.7 per contract
	for i := range response.Findings {
		if response.Findings[i].Confidence > 0.7 {
			response.Findings[i].Confidence = 0.7
		}
		response.Findings[i].NeedsTribunal = true
	}

	return response.Findings, nil
}

// buildExplorerMessage constructs the user message for the Explorer agent.
func (e *Explorer) buildExplorerMessage(surface *AttackSurface) string {
	var sb strings.Builder

	sb.WriteString("# Attack Surface Summary\n\n")
	sb.WriteString(fmt.Sprintf("**Tech Stack**: %s\n\n", surface.TechStack))

	// Entry points
	if len(surface.EntryPoints) > 0 {
		sb.WriteString("## Entry Points\n\n")
		for i, ep := range surface.EntryPoints {
			if i >= 20 { // limit to 20 entries
				sb.WriteString(fmt.Sprintf("... and %d more entry points\n", len(surface.EntryPoints)-20))
				break
			}
			authStr := "public"
			if ep.AuthReq {
				authStr = "auth-required"
			}
			sb.WriteString(fmt.Sprintf("- `%s %s` → %s (%s:%d) [%s]\n",
				ep.Method, ep.Path, ep.Handler, ep.File, ep.Line, authStr))
		}
		sb.WriteString("\n")
	}

	// High-risk areas
	if len(surface.HighRiskAreas) > 0 {
		sb.WriteString("## High-Risk Areas\n\n")
		for _, area := range surface.HighRiskAreas {
			sb.WriteString(fmt.Sprintf("- %s\n", area))
		}
		sb.WriteString("\n")
	}

	// Data sources
	if len(surface.DataSources) > 0 {
		sb.WriteString("## Data Sources\n\n")
		for _, ds := range surface.DataSources {
			sb.WriteString(fmt.Sprintf("- %s\n", ds))
		}
		sb.WriteString("\n")
	}

	// Auth mechanism
	if surface.AuthMechanism != "" {
		sb.WriteString(fmt.Sprintf("## Authentication: %s\n\n", surface.AuthMechanism))
	}

	// Coverage gaps — focus exploration here
	if len(surface.Dimensions) > 0 {
		sb.WriteString("## Coverage Gaps (Focus Your Exploration Here)\n\n")
		sb.WriteString("The following security dimensions have NOT been covered by automated rules.\n")
		sb.WriteString("Your primary goal is to explore these gaps:\n\n")
		for dimID, priority := range surface.Dimensions {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", dimID, priority))
		}
		sb.WriteString("\n")
	}

	// Code context (entry point function bodies)
	if len(surface.CodeContext) > 0 {
		sb.WriteString("## Code Context\n\n")
		for _, cc := range surface.CodeContext {
			sb.WriteString(fmt.Sprintf("### %s (%s:%d-%d)\n\n", cc.Role, cc.FilePath, cc.StartLine, cc.EndLine))
			sb.WriteString("```\n")
			sb.WriteString(cc.Code)
			sb.WriteString("\n```\n\n")
		}
	}

	// Contract constraints
	sb.WriteString("## Constraints\n\n")
	sb.WriteString(fmt.Sprintf("- Maximum %d exploration directions\n", 3))
	sb.WriteString("- Maximum confidence per finding: 0.7\n")
	sb.WriteString("- Every finding MUST cite file:line evidence\n\n")

	sb.WriteString("**Your task**: Explore the codebase for vulnerabilities that automated rules may have missed, focusing on the coverage gaps listed above. Return findings in the JSON format specified in your system prompt.\n")

	return sb.String()
}

func (e *Explorer) loadPrompt(filename string) (string, error) {
	path := filepath.Join(e.promptsDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read prompt %s: %w", filename, err)
	}
	return string(data), nil
}

// AttackSurface summarizes the target project's security-relevant structure.
type AttackSurface struct {
	TechStack     string            `json:"tech_stack"`
	EntryPoints   []EntryPoint      `json:"entry_points"`
	HighRiskAreas []string          `json:"high_risk_areas"`
	DataSources   []string          `json:"data_sources"`
	AuthMechanism string            `json:"auth_mechanism"`
	Dimensions    map[string]string `json:"dimensions"`   // D1-D10 → priority
	CodeContext   []cpg.CodeSlice   `json:"code_context"` // code snippets for exploration
}

// EntryPoint is an API endpoint or user-facing interface.
type EntryPoint struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	AuthReq bool   `json:"auth_required"`
}

// MarshalFindings serializes findings to JSON.
func MarshalFindings(findings []ExplorerFinding) (string, error) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
