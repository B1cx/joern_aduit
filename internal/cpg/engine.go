package cpg

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/domain"
)

// Engine manages Joern CPG lifecycle: parse, index, query, slice.
type Engine struct {
	cfg    *config.JoernConfig
	cpgBin string // path to generated .bin file
}

func NewEngine(cfg *config.JoernConfig) *Engine {
	return &Engine{cfg: cfg}
}

// Parse runs joern-parse on the target directory to generate a CPG binary.
func (e *Engine) Parse(ctx context.Context, targetDir, language string) error {
	// Create CPG output directory
	if err := os.MkdirAll(e.cfg.CPGDir, 0755); err != nil {
		return fmt.Errorf("create CPG dir: %w", err)
	}

	// Generate CPG binary path
	timestamp := time.Now().Format("20060102_150405")
	e.cpgBin = filepath.Join(e.cfg.CPGDir, fmt.Sprintf("cpg_%s.bin", timestamp))

	// Map common language names to Joern's expected format
	// For Java, use 'javasrc' for source-level analysis (doesn't need compilation)
	joernLang := language
	if language == "java" {
		joernLang = "javasrc"
	} else if language == "python" {
		joernLang = "pythonsrc"
	} else if language == "javascript" {
		joernLang = "jssrc"
	} else if language == "csharp" {
		joernLang = "csharpsrc"
	} else if language == "ruby" {
		joernLang = "rubysrc"
	}

	// Build joern-parse command
	args := []string{
		"--language", joernLang,
		"-o", e.cpgBin,
		targetDir,
	}

	cmd := exec.CommandContext(ctx, e.cfg.ParsePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("joern-parse failed: %w", err)
	}

	// Verify CPG file was created
	if _, err := os.Stat(e.cpgBin); err != nil {
		return fmt.Errorf("CPG file not created: %w", err)
	}

	return nil
}

// BuildIndex extracts function/call/dataflow metadata from CPG into the index store.
func (e *Engine) BuildIndex(ctx context.Context, store IndexStore) error {
	if e.cpgBin == "" {
		return fmt.Errorf("CPG not parsed yet, call Parse() first")
	}

	// Create a temporary Scala script to extract index data
	scriptPath := filepath.Join(os.TempDir(), "joern_index_"+time.Now().Format("20060102150405")+".sc")
	defer os.Remove(scriptPath)

	script := `
import io.shiftleft.semanticcpg.language._

@main def exec() = {
  println("===FUNCTIONS_START===")
  cpg.method.l.foreach { m =>
    val annotations = m.annotation.l.map(_.fullName).mkString(",")
    val params = m.parameter.l.size
    val complexity = 0
    val isPublic = m.modifier.l.exists(_.modifierType == "PUBLIC")
    val lineStart = m.lineNumber.getOrElse(-1)
    val lineEnd = m.lineNumberEnd.getOrElse(-1)
    println(s"${m.name}|${m.fullName}|${m.signature}|${m.filename}|${lineStart}|${lineEnd}|${isPublic}|${annotations}|${complexity}|${params}")
  }
  println("===FUNCTIONS_END===")

  println("===CALLS_START===")
  cpg.call.l.foreach { c =>
    val fname = c.file.name.headOption.getOrElse("unknown")
    val callerMethod = c.method.fullName
    println(s"${c.name}|${c.methodFullName}|${callerMethod}|${fname}|${c.lineNumber.getOrElse(-1)}")
  }
  println("===CALLS_END===")
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return fmt.Errorf("write index script: %w", err)
	}

	// Run the script
	output, err := e.runScript(ctx, scriptPath)
	if err != nil {
		return fmt.Errorf("run index script: %w", err)
	}

	// Parse output and populate store
	return e.parseIndexOutput(output, store)
}

// Query executes a CPGQL query against the loaded CPG and returns structured results.
// Extracts file, line, code, and method name from call/method nodes.
func (e *Engine) Query(ctx context.Context, cpgql string) ([]QueryResult, error) {
	if e.cpgBin == "" {
		return nil, fmt.Errorf("CPG not parsed yet")
	}

	// Create temporary script
	scriptPath := filepath.Join(os.TempDir(), "joern_query_"+time.Now().Format("20060102150405")+".sc")
	defer os.Remove(scriptPath)

	// Enhanced script to extract structured data from call nodes
	script := fmt.Sprintf(`
@main def exec() = {
  val result = %s
  println("===QUERY_RESULT===")
  result.foreach { node =>
    // Extract file, line, code from call/method nodes
    val file = node.file.name.headOption.getOrElse("unknown")
    val line = node.lineNumber.getOrElse(-1)
    val code = node.code.take(200).replace("\n", " ").replace("|", "\\|")
    val methodName = node.method.fullName
    println(s"${file}|${line}|${code}|${methodName}")
  }
  println("===QUERY_END===")
}
`, cpgql)

	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("write query script: %w", err)
	}

	output, err := e.runScript(ctx, scriptPath)
	if err != nil {
		return nil, fmt.Errorf("run query: %w", err)
	}

	// Parse structured output
	var results []QueryResult
	inResult := false
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "===QUERY_RESULT===") {
			inResult = true
			continue
		}
		if strings.Contains(line, "===QUERY_END===") {
			break
		}
		if inResult && strings.TrimSpace(line) != "" {
			// Parse: file|line|code|methodName
			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				lineNum, _ := strconv.Atoi(parts[1])
				results = append(results, QueryResult{
					Data: map[string]interface{}{
						"file":        parts[0],
						"line":        lineNum,
						"code":        parts[2],
						"method_name": parts[3],
						"raw":         line,
					},
				})
			}
		}
	}

	return results, nil
}

// Scan runs joern-scan with rule files and returns candidate alerts.
func (e *Engine) Scan(ctx context.Context, rulesDir string) ([]domain.Candidate, error) {
	// For now, we'll implement custom rule scanning using Query()
	// joern-scan's built-in queries may not match our needs
	return nil, fmt.Errorf("Scan not yet implemented - use custom CPGQL queries via Query()")
}

// Slice extracts a program slice (forward or backward) from a given point.
func (e *Engine) Slice(ctx context.Context, req SliceRequest) (*SliceResult, error) {
	// joern-slice is complex and may not be needed for MVP
	// We can get similar info from taint flow analysis
	return nil, fmt.Errorf("Slice not yet implemented - use Flow() for data flow analysis")
}

// Flow traces taint flow between source and sink using Joern's reachableByFlows.
func (e *Engine) Flow(ctx context.Context, source, sink string) ([]TaintPath, error) {
	if e.cpgBin == "" {
		return nil, fmt.Errorf("CPG not parsed yet")
	}

	scriptPath := filepath.Join(os.TempDir(), "joern_flow_"+time.Now().Format("20060102150405")+".sc")
	defer os.Remove(scriptPath)

	// Convert single quotes to double quotes for Scala compatibility
	// YAML patterns use single quotes, but Scala requires double quotes for strings
	sourcePattern := strings.ReplaceAll(source, "'", "\"")
	sinkPattern := strings.ReplaceAll(sink, "'", "\"")

	// Build taint analysis script
	script := fmt.Sprintf(`
import io.shiftleft.semanticcpg.language._

@main def exec() = {
  val sources = %s
  val sinks = %s

  println("===FLOWS_START===")
  sinks.reachableByFlows(sources).l.foreach { flow =>
    println("FLOW_BEGIN")
    flow.elements.foreach { elem =>
      val line = elem.lineNumber.getOrElse(-1)
      val file = elem.file.name.headOption.getOrElse("unknown")
      val code = elem.code.take(100).replace("\n", " ").replace("|", "\\|")
      println(s"${file}|${line}|${code}")
    }
    println("FLOW_END")
  }
  println("===FLOWS_END===")
}
`, sourcePattern, sinkPattern)

	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("write flow script: %w", err)
	}

	output, err := e.runScript(ctx, scriptPath)
	if err != nil {
		return nil, fmt.Errorf("run flow script: %w", err)
	}

	return e.parseFlowOutput(output), nil
}

// runScript executes a Joern Scala script and returns stdout
func (e *Engine) runScript(ctx context.Context, scriptPath string) (string, error) {
	args := []string{
		"--script", scriptPath,
		e.cpgBin,
		"--nocolors",
	}

	cmd := exec.CommandContext(ctx, e.cfg.BinaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("joern script failed: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// parseIndexOutput parses function and call index from script output
func (e *Engine) parseIndexOutput(output string, store IndexStore) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	inFunctions := false
	inCalls := false

	var functions []Function
	var callEdges []CallEdge
	funcIDMap := make(map[string]int64) // fullName -> id
	nextID := int64(1)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "===FUNCTIONS_START===") {
			inFunctions = true
			inCalls = false
			continue
		}
		if strings.Contains(line, "===FUNCTIONS_END===") {
			inFunctions = false
			continue
		}
		if strings.Contains(line, "===CALLS_START===") {
			inCalls = true
			continue
		}
		if strings.Contains(line, "===CALLS_END===") {
			inCalls = false
			continue
		}

		if inFunctions && line != "" {
			// Format: name|fullName|signature|filename|startLine|endLine|isPublic|annotations|complexity|params
			parts := strings.Split(line, "|")
			if len(parts) >= 9 {
				startLine, _ := strconv.Atoi(parts[4])
				endLine, _ := strconv.Atoi(parts[5])
				isPublic := parts[6] == "true"
				complexity, _ := strconv.Atoi(parts[8])

				// Filter out external methods (those without valid line numbers)
				if startLine > 0 {
					fn := Function{
						ID:         nextID,
						Name:       parts[0],
						FullName:   parts[1],
						Signature:  parts[2],
						FilePath:   parts[3],
						StartLine:  startLine,
						EndLine:    endLine,
						IsPublic:   isPublic,
						Annotation: parts[7],
						Complexity: complexity,
					}
					functions = append(functions, fn)
					funcIDMap[fn.FullName] = nextID
					nextID++
				}
			}
		}

		if inCalls && line != "" {
			// Format: callName|calleeFullName|callerFullName|file|line
			parts := strings.Split(line, "|")
			if len(parts) >= 5 {
				callSiteLine, _ := strconv.Atoi(parts[4])
				callerID := funcIDMap[parts[2]]
				calleeID := funcIDMap[parts[1]]

				if callerID > 0 { // Only record if caller is in our index
					callEdges = append(callEdges, CallEdge{
						CallerID:     callerID,
						CalleeID:     calleeID,
						CallSiteLine: callSiteLine,
						CallSiteFile: parts[3],
					})
				}
			}
		}
	}

	// Save to store
	if err := store.SaveFunctions(functions); err != nil {
		return fmt.Errorf("save functions: %w", err)
	}
	if err := store.SaveCallEdges(callEdges); err != nil {
		return fmt.Errorf("save call edges: %w", err)
	}

	return nil
}

// parseFlowOutput parses taint flow paths from script output
func (e *Engine) parseFlowOutput(output string) []TaintPath {
	var paths []TaintPath
	var currentPath []domain.TaintFlowNode

	scanner := bufio.NewScanner(strings.NewReader(output))
	inFlow := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "FLOW_BEGIN" {
			inFlow = true
			currentPath = []domain.TaintFlowNode{}
			continue
		}
		if line == "FLOW_END" {
			if len(currentPath) > 0 {
				paths = append(paths, TaintPath{
					Nodes: currentPath,
				})
			}
			inFlow = false
			continue
		}

		if inFlow && line != "" {
			// Format: file|line|code
			parts := strings.SplitN(line, "|", 3)
			if len(parts) >= 3 {
				lineNum, _ := strconv.Atoi(parts[1])
				node := domain.TaintFlowNode{
					File: parts[0],
					Line: lineNum,
					Expr: parts[2],
				}
				if len(currentPath) == 0 {
					node.NodeType = "SOURCE"
				} else {
					node.NodeType = "PROPAGATION"
				}
				currentPath = append(currentPath, node)
			}
		}
	}

	for i := range paths {
		if len(paths[i].Nodes) > 0 {
			paths[i].Nodes[len(paths[i].Nodes)-1].NodeType = "SINK"
		}
	}

	return paths
}

// GetCPGPath returns the path to the generated CPG binary
func (e *Engine) GetCPGPath() string {
	return e.cpgBin
}

// SetCPGPath sets the CPG binary path (for loading existing CPG)
func (e *Engine) SetCPGPath(path string) {
	e.cpgBin = path
}
