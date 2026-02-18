package cpg

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ContextLevel defines the granularity of code context extraction.
type ContextLevel int

const (
	ContextLevelAlertLine    ContextLevel = 0 // just the alert line
	ContextLevelFunctionBody ContextLevel = 1 // full function body
	ContextLevelCallChain    ContextLevel = 2 // caller/callee functions
	ContextLevelDataFlow     ContextLevel = 3 // taint propagation path nodes
	ContextLevelDefinition   ContextLevel = 4 // variable/type definition sites
	ContextLevelGlobal       ContextLevel = 5 // config files, security framework
)

// CodeSlice is a piece of source code with location metadata.
type CodeSlice struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Code      string `json:"code"`
	Role      string `json:"role"` // source, propagation, sink, caller, callee, definition
}

// ContextRequest specifies what context is needed for a candidate.
type ContextRequest struct {
	Candidate *Candidate
	Level     ContextLevel
	Needs     []string // specific symbols/functions to resolve (for Level 2+)
}

// ContextResult is the assembled code context for LLM consumption.
type ContextResult struct {
	Slices     []CodeSlice  `json:"slices"`
	TokenCount int          `json:"token_count"`
	Level      ContextLevel `json:"level"`
}

// ContextManager extracts code context on demand from CPG + source files.
type ContextManager struct {
	engine    *Engine
	store     IndexStore
	sourceDir string
	budget    int // max tokens per candidate
}

func NewContextManager(engine *Engine, store IndexStore, sourceDir string, budget int) *ContextManager {
	return &ContextManager{
		engine:    engine,
		store:     store,
		sourceDir: sourceDir,
		budget:    budget,
	}
}

// Extract returns code context for a candidate at the requested level.
func (cm *ContextManager) Extract(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	switch req.Level {
	case ContextLevelAlertLine:
		return cm.extractAlertLine(ctx, req)
	case ContextLevelFunctionBody:
		return cm.extractFunctionBody(ctx, req)
	case ContextLevelCallChain:
		return cm.extractCallChain(ctx, req)
	case ContextLevelDataFlow:
		return cm.extractDataFlow(ctx, req)
	case ContextLevelDefinition:
		return cm.extractDefinitions(ctx, req)
	case ContextLevelGlobal:
		return cm.extractGlobal(ctx, req)
	default:
		return nil, fmt.Errorf("unknown context level: %d", req.Level)
	}
}

func (cm *ContextManager) extractAlertLine(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Read alert line ± 5 lines
	const contextLines = 5
	filePath := filepath.Join(cm.sourceDir, req.Candidate.FilePath)

	code, err := cm.readLines(filePath, req.Candidate.LineNumber-contextLines, req.Candidate.LineNumber+contextLines)
	if err != nil {
		return nil, fmt.Errorf("read alert line: %w", err)
	}

	slice := CodeSlice{
		FilePath:  req.Candidate.FilePath,
		StartLine: req.Candidate.LineNumber - contextLines,
		EndLine:   req.Candidate.LineNumber + contextLines,
		Code:      code,
		Role:      "alert",
	}

	return &ContextResult{
		Slices:     []CodeSlice{slice},
		TokenCount: len(code) / 4, // rough estimate
		Level:      ContextLevelAlertLine,
	}, nil
}

func (cm *ContextManager) extractFunctionBody(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Lookup function in index by file:line
	fn, err := cm.store.GetFunctionByLocation(req.Candidate.FilePath, req.Candidate.LineNumber)
	if err != nil {
		return nil, fmt.Errorf("lookup function: %w", err)
	}
	if fn == nil {
		// Fallback to alert line if function not found
		return cm.extractAlertLine(ctx, req)
	}

	// Read function body from source
	filePath := filepath.Join(cm.sourceDir, fn.FilePath)
	code, err := cm.readLines(filePath, fn.StartLine, fn.EndLine)
	if err != nil {
		return nil, fmt.Errorf("read function body: %w", err)
	}

	slice := CodeSlice{
		FilePath:  fn.FilePath,
		StartLine: fn.StartLine,
		EndLine:   fn.EndLine,
		Code:      code,
		Role:      "function",
	}

	return &ContextResult{
		Slices:     []CodeSlice{slice},
		TokenCount: len(code) / 4,
		Level:      ContextLevelFunctionBody,
	}, nil
}

func (cm *ContextManager) extractCallChain(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Start with function body
	result, err := cm.extractFunctionBody(ctx, req)
	if err != nil {
		return nil, err
	}

	// Get the function containing the alert
	fn, err := cm.store.GetFunctionByLocation(req.Candidate.FilePath, req.Candidate.LineNumber)
	if err != nil || fn == nil {
		return result, nil // return what we have
	}

	// Get callers (max 3 levels deep)
	callers, err := cm.store.GetCallers(fn.ID)
	if err == nil && len(callers) > 0 {
		for i, edge := range callers {
			if i >= 3 {
				break // limit to 3 callers
			}
			caller, err := cm.store.GetFunction(edge.CallerID)
			if err != nil || caller == nil {
				continue
			}

			filePath := filepath.Join(cm.sourceDir, caller.FilePath)
			code, err := cm.readLines(filePath, caller.StartLine, caller.EndLine)
			if err != nil {
				continue
			}

			slice := CodeSlice{
				FilePath:  caller.FilePath,
				StartLine: caller.StartLine,
				EndLine:   caller.EndLine,
				Code:      code,
				Role:      "caller",
			}
			result.Slices = append(result.Slices, slice)
			result.TokenCount += len(code) / 4
		}
	}

	// Get callees (functions called from alert function)
	callees, err := cm.store.GetCallees(fn.ID)
	if err == nil && len(callees) > 0 {
		for i, edge := range callees {
			if i >= 3 {
				break // limit to 3 callees
			}
			callee, err := cm.store.GetFunction(edge.CalleeID)
			if err != nil || callee == nil {
				continue
			}

			filePath := filepath.Join(cm.sourceDir, callee.FilePath)
			code, err := cm.readLines(filePath, callee.StartLine, callee.EndLine)
			if err != nil {
				continue
			}

			slice := CodeSlice{
				FilePath:  callee.FilePath,
				StartLine: callee.StartLine,
				EndLine:   callee.EndLine,
				Code:      code,
				Role:      "callee",
			}
			result.Slices = append(result.Slices, slice)
			result.TokenCount += len(code) / 4
		}
	}

	result.Level = ContextLevelCallChain
	return result, nil
}

func (cm *ContextManager) extractDataFlow(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Get taint flow paths for this alert location
	flows, err := cm.store.GetTaintFlowsForSink(req.Candidate.FilePath, req.Candidate.LineNumber)
	if err != nil {
		return nil, fmt.Errorf("get taint flows: %w", err)
	}

	var slices []CodeSlice
	tokenCount := 0

	for _, flow := range flows {
		// Extract code at each node in the taint path
		for _, node := range flow.Nodes {
			// Read ±3 lines around each taint node
			filePath := filepath.Join(cm.sourceDir, node.File)
			code, err := cm.readLines(filePath, node.Line-3, node.Line+3)
			if err != nil {
				continue
			}

			slice := CodeSlice{
				FilePath:  node.File,
				StartLine: node.Line - 3,
				EndLine:   node.Line + 3,
				Code:      code,
				Role:      strings.ToLower(node.NodeType),
			}
			slices = append(slices, slice)
			tokenCount += len(code) / 4
		}
	}

	if len(slices) == 0 {
		// Fallback to function body if no dataflow found
		return cm.extractFunctionBody(ctx, req)
	}

	return &ContextResult{
		Slices:     slices,
		TokenCount: tokenCount,
		Level:      ContextLevelDataFlow,
	}, nil
}

func (cm *ContextManager) extractDefinitions(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Start with dataflow context
	result, err := cm.extractDataFlow(ctx, req)
	if err != nil {
		return nil, err
	}

	// For each symbol in Needs list, try to find its definition using CPG query
	for _, symbol := range req.Needs {
		// Query CPG for symbol definition
		// This is a simplified version - in practice, you'd need more sophisticated symbol resolution
		query := fmt.Sprintf(`cpg.identifier.name("%s").l`, symbol)
		results, err := cm.engine.Query(ctx, query)
		if err != nil || len(results) == 0 {
			continue
		}

		// TODO: Parse query results and extract definition location
		// For now, skip this as it requires parsing identifier nodes
	}

	result.Level = ContextLevelDefinition
	return result, nil
}

func (cm *ContextManager) extractGlobal(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	// Start with previous level
	result, err := cm.extractDefinitions(ctx, req)
	if err != nil {
		return nil, err
	}

	// Look for common config files
	configFiles := []string{
		"application.yml",
		"application.yaml",
		"application.properties",
		"pom.xml",
		"build.gradle",
		"package.json",
		"composer.json",
	}

	for _, configFile := range configFiles {
		configPath := filepath.Join(cm.sourceDir, configFile)
		if _, err := os.Stat(configPath); err == nil {
			// Config file exists, read it (limit to first 100 lines)
			code, err := cm.readLines(configPath, 1, 100)
			if err != nil {
				continue
			}

			slice := CodeSlice{
				FilePath:  configFile,
				StartLine: 1,
				EndLine:   100,
				Code:      code,
				Role:      "config",
			}
			result.Slices = append(result.Slices, slice)
			result.TokenCount += len(code) / 4
		}
	}

	result.Level = ContextLevelGlobal
	return result, nil
}

// readLines reads lines from startLine to endLine (inclusive) from a file.
// Line numbers are 1-indexed. Returns empty string if file doesn't exist.
func (cm *ContextManager) readLines(filePath string, startLine, endLine int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	if startLine < 1 {
		startLine = 1
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	lineNum := 1

	for scanner.Scan() {
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, scanner.Text())
		}
		if lineNum > endLine {
			break
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan file: %w", err)
	}

	return strings.Join(lines, "\n"), nil
}
