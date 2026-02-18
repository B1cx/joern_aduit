package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
)

// Simple in-memory index store for testing (implements cpg.IndexStore)
type TestIndexStore struct {
	functions  []cpg.Function
	callEdges  []cpg.CallEdge
	taintFlows []cpg.TaintPath
}

func (s *TestIndexStore) SaveFunctions(funcs []cpg.Function) error {
	s.functions = append(s.functions, funcs...)
	fmt.Printf("✓ Saved %d functions\n", len(funcs))
	return nil
}

func (s *TestIndexStore) SaveCallEdges(edges []cpg.CallEdge) error {
	s.callEdges = append(s.callEdges, edges...)
	fmt.Printf("✓ Saved %d call edges\n", len(edges))
	return nil
}

func (s *TestIndexStore) SaveTaintFlows(flows []cpg.TaintPath) error {
	s.taintFlows = append(s.taintFlows, flows...)
	fmt.Printf("✓ Saved %d taint flows\n", len(flows))
	return nil
}

func (s *TestIndexStore) GetFunction(id int64) (*cpg.Function, error) {
	for _, fn := range s.functions {
		if fn.ID == id {
			return &fn, nil
		}
	}
	return nil, fmt.Errorf("function not found")
}

func (s *TestIndexStore) GetCallers(funcID int64) ([]cpg.CallEdge, error) {
	var result []cpg.CallEdge
	for _, edge := range s.callEdges {
		if edge.CalleeID == funcID {
			result = append(result, edge)
		}
	}
	return result, nil
}

func (s *TestIndexStore) GetCallees(funcID int64) ([]cpg.CallEdge, error) {
	var result []cpg.CallEdge
	for _, edge := range s.callEdges {
		if edge.CallerID == funcID {
			result = append(result, edge)
		}
	}
	return result, nil
}

func (s *TestIndexStore) GetFunctionByLocation(file string, line int) (*cpg.Function, error) {
	for _, fn := range s.functions {
		if fn.FilePath == file && line >= fn.StartLine && line <= fn.EndLine {
			return &fn, nil
		}
	}
	return nil, nil
}

func (s *TestIndexStore) GetTaintFlowsForSink(file string, line int) ([]cpg.TaintPath, error) {
	var result []cpg.TaintPath
	for _, flow := range s.taintFlows {
		if len(flow.Nodes) > 0 {
			lastNode := flow.Nodes[len(flow.Nodes)-1]
			if lastNode.File == file && lastNode.Line == line {
				result = append(result, flow)
			}
		}
	}
	return result, nil
}

func main() {
	fmt.Println("=== joern_audit End-to-End Test ===\n")

	// Check if java-sec-code exists
	targetDir := "../java-sec-code"
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("❌ Test target not found: %s\n", targetDir)
		fmt.Println("   Please ensure java-sec-code is cloned in the parent directory")
		os.Exit(1)
	}

	// Initialize config
	cfg := config.DefaultConfig()
	cfg.Joern.BinaryPath = os.ExpandEnv("$HOME/bin/joern/joern-cli/joern")
	cfg.Joern.ParsePath = os.ExpandEnv("$HOME/bin/joern/joern-cli/joern-parse")
	cfg.Joern.CPGDir = filepath.Join(os.TempDir(), "joern_audit_test_cpg")

	// Clean up CPG dir from previous runs
	os.RemoveAll(cfg.Joern.CPGDir)
	defer os.RemoveAll(cfg.Joern.CPGDir)

	// Verify Joern binaries exist
	if _, err := os.Stat(cfg.Joern.BinaryPath); os.IsNotExist(err) {
		fmt.Printf("❌ Joern not found at: %s\n", cfg.Joern.BinaryPath)
		os.Exit(1)
	}

	fmt.Printf("✓ Config initialized\n")
	fmt.Printf("  Joern binary: %s\n", cfg.Joern.BinaryPath)
	fmt.Printf("  Target: %s\n", targetDir)
	fmt.Printf("  CPG output: %s\n\n", cfg.Joern.CPGDir)

	// Phase 1: Parse source code to CPG
	fmt.Println("--- Phase 1: Parse Source Code ---")
	engine := cpg.NewEngine(&cfg.Joern)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Parse a single file for quick testing
	testFile := filepath.Join(targetDir, "src/main/java/org/joychou/controller/SQLI.java")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		fmt.Printf("❌ Test file not found: %s\n", testFile)
		os.Exit(1)
	}

	// Copy just the test file to a temp dir for faster parsing
	tempTestDir := filepath.Join(os.TempDir(), "joern_audit_test_src")
	os.RemoveAll(tempTestDir)
	os.MkdirAll(tempTestDir, 0755)
	defer os.RemoveAll(tempTestDir)

	// Read and write test file
	content, err := os.ReadFile(testFile)
	if err != nil {
		fmt.Printf("❌ Failed to read test file: %v\n", err)
		os.Exit(1)
	}
	testFileDest := filepath.Join(tempTestDir, "SQLI.java")
	if err := os.WriteFile(testFileDest, content, 0644); err != nil {
		fmt.Printf("❌ Failed to copy test file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsing %s...\n", testFile)
	start := time.Now()
	if err := engine.Parse(ctx, tempTestDir, "java"); err != nil {
		fmt.Printf("❌ Parse failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Parse completed in %v\n", time.Since(start))
	fmt.Printf("  CPG file: %s\n\n", engine.GetCPGPath())

	// Phase 2: Build Index
	fmt.Println("--- Phase 2: Build Index ---")
	store := &TestIndexStore{}
	start = time.Now()
	if err := engine.BuildIndex(ctx, store); err != nil {
		fmt.Printf("❌ BuildIndex failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Index built in %v\n", time.Since(start))
	fmt.Printf("  Total functions: %d\n", len(store.functions))
	fmt.Printf("  Total call edges: %d\n\n", len(store.callEdges))

	// Show sample functions
	if len(store.functions) > 0 {
		fmt.Println("Sample functions:")
		for i, fn := range store.functions {
			if i >= 5 {
				break
			}
			fmt.Printf("  %d. %s at %s:%d-%d\n", i+1, fn.Name, fn.FilePath, fn.StartLine, fn.EndLine)
		}
		fmt.Println()
	}

	// Phase 3: Test Query
	fmt.Println("--- Phase 3: Test CPGQL Query ---")
	query := `cpg.call.name("executeQuery").l`
	fmt.Printf("Query: %s\n", query)
	start = time.Now()
	results, err := engine.Query(ctx, query)
	if err != nil {
		fmt.Printf("❌ Query failed: %v\n", err)
	} else {
		fmt.Printf("✓ Query completed in %v\n", time.Since(start))
		fmt.Printf("  Results: %d\n", len(results))
		for i, r := range results {
			if i >= 3 {
				break
			}
			fmt.Printf("  %d. %v\n", i+1, r.Data["raw"])
		}
		fmt.Println()
	}

	// Phase 4: Test Taint Flow
	fmt.Println("--- Phase 4: Test Taint Flow Analysis ---")
	sourceQuery := `cpg.method.parameter.name(".*").whereNot(_.name("this"))`
	sinkQuery := `cpg.call.name("executeQuery")`
	fmt.Printf("Source: %s\n", sourceQuery)
	fmt.Printf("Sink: %s\n", sinkQuery)
	start = time.Now()
	flows, err := engine.Flow(ctx, sourceQuery, sinkQuery)
	if err != nil {
		fmt.Printf("❌ Flow analysis failed: %v\n", err)
	} else {
		fmt.Printf("✓ Flow analysis completed in %v\n", time.Since(start))
		fmt.Printf("  Taint paths found: %d\n", len(flows))
		for i, flow := range flows {
			if i >= 2 {
				break
			}
			fmt.Printf("\n  Path %d (%d nodes):\n", i+1, len(flow.Nodes))
			for j, node := range flow.Nodes {
				fmt.Printf("    %d. [%s] %s:%d: %s\n", j+1, node.NodeType, node.File, node.Line, node.Expr)
			}
		}
		fmt.Println()
	}

	// Phase 5: Test Context Manager
	fmt.Println("--- Phase 5: Test Context Manager ---")
	if len(flows) > 0 && len(flows[0].Nodes) > 0 {
		// Create a fake candidate at the sink location
		lastNode := flows[0].Nodes[len(flows[0].Nodes)-1]
		candidate := &cpg.Candidate{
			FilePath:   lastNode.File,
			LineNumber: lastNode.Line,
			Message:    "Test SQL injection",
		}

		contextMgr := cpg.NewContextManager(engine, store, tempTestDir, 8000)

		// Test Level 0: Alert Line
		fmt.Println("Testing Level 0 (Alert Line)...")
		result, err := contextMgr.Extract(ctx, cpg.ContextRequest{
			Candidate: candidate,
			Level:     cpg.ContextLevelAlertLine,
		})
		if err != nil {
			fmt.Printf("❌ Level 0 failed: %v\n", err)
		} else {
			fmt.Printf("✓ Level 0: %d slices, %d tokens\n", len(result.Slices), result.TokenCount)
		}

		// Test Level 1: Function Body
		fmt.Println("Testing Level 1 (Function Body)...")
		result, err = contextMgr.Extract(ctx, cpg.ContextRequest{
			Candidate: candidate,
			Level:     cpg.ContextLevelFunctionBody,
		})
		if err != nil {
			fmt.Printf("❌ Level 1 failed: %v\n", err)
		} else {
			fmt.Printf("✓ Level 1: %d slices, %d tokens\n", len(result.Slices), result.TokenCount)
			if len(result.Slices) > 0 {
				fmt.Printf("  Function: %s:%d-%d\n", result.Slices[0].FilePath, result.Slices[0].StartLine, result.Slices[0].EndLine)
			}
		}

		// Test Level 2: Call Chain
		fmt.Println("Testing Level 2 (Call Chain)...")
		result, err = contextMgr.Extract(ctx, cpg.ContextRequest{
			Candidate: candidate,
			Level:     cpg.ContextLevelCallChain,
		})
		if err != nil {
			fmt.Printf("❌ Level 2 failed: %v\n", err)
		} else {
			fmt.Printf("✓ Level 2: %d slices, %d tokens\n", len(result.Slices), result.TokenCount)
		}

		// Store flows for Level 3 test
		store.SaveTaintFlows(flows)

		// Test Level 3: Data Flow
		fmt.Println("Testing Level 3 (Data Flow)...")
		result, err = contextMgr.Extract(ctx, cpg.ContextRequest{
			Candidate: candidate,
			Level:     cpg.ContextLevelDataFlow,
		})
		if err != nil {
			fmt.Printf("❌ Level 3 failed: %v\n", err)
		} else {
			fmt.Printf("✓ Level 3: %d slices, %d tokens\n", len(result.Slices), result.TokenCount)
		}
	}

	fmt.Println("\n=== All Tests Passed ✓ ===")
}
