package fuzzer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/joern-audit/joern_audit/internal/config"
)

// SQLiStrategy uses sqlmap to verify SQL injection vulnerabilities.
type SQLiStrategy struct {
	cfg *config.FuzzerConfig
}

func NewSQLiStrategy(cfg *config.FuzzerConfig) *SQLiStrategy {
	return &SQLiStrategy{cfg: cfg}
}

func (s *SQLiStrategy) Name() string { return "sqli" }

func (s *SQLiStrategy) CanHandle(cwe string) bool {
	return cwe == "CWE-89"
}

func (s *SQLiStrategy) GeneratePoC(ctx context.Context, req PoCRequest) (*PoCTemplate, error) {
	parsed := ParseAttackVector(req.AttackVector)
	RefineWithRegistry(parsed, req.Evidence, req.Registry, req.SourceRoot)

	targetURL := BuildTargetURL(req.TargetURL, parsed)

	// If no query params, sqlmap needs at least one parameter to test
	if len(parsed.QueryParams) == 0 && parsed.Body == "" {
		return nil, fmt.Errorf("no injectable parameters found in attack vector: %s", req.AttackVector)
	}

	// Build sqlmap command
	sqlmapBin := s.cfg.SqlmapPath
	if sqlmapBin == "" {
		sqlmapBin = findSqlmap()
	}
	if sqlmapBin == "" {
		return nil, fmt.Errorf("sqlmap not found; install via 'pip3 install sqlmap' or set fuzzer.sqlmap_path in config")
	}

	args := []string{
		"-u", targetURL,
		"--batch",
		"--level=2",
		"--risk=1",
		"--flush-session",
		"--timeout=15",
		"--retries=1",
		"--output-dir=/tmp/sqlmap-output",
	}

	// Specify injection parameter if known
	if parsed.ParamName != "" {
		args = append(args, "-p", parsed.ParamName)
	}

	// Handle POST body
	if parsed.Method == "POST" && parsed.Body != "" {
		args = append(args, "--data", parsed.Body)
	}

	return &PoCTemplate{
		Type:    "sqlmap",
		Command: sqlmapBin,
		Args:    args,
		URL:     targetURL,
		Payload: fmt.Sprintf("%s -u %q --batch -p %s", sqlmapBin, targetURL, parsed.ParamName),
	}, nil
}

func (s *SQLiStrategy) Execute(ctx context.Context, poc *PoCTemplate) (*FuzzResult, error) {
	result, err := RunProcess(ctx, poc.Command, poc.Args, s.cfg.Timeout)
	if err != nil {
		return &FuzzResult{
			Status: FuzzError,
			Tool:   "sqlmap",
			Error:  fmt.Sprintf("failed to run sqlmap: %v", err),
		}, nil
	}

	if result.TimedOut {
		return &FuzzResult{
			Status: FuzzError,
			Tool:   "sqlmap",
			Error:  "sqlmap timed out",
		}, nil
	}

	output := result.Stdout + result.Stderr

	return parseSqlmapOutput(output, poc.Payload), nil
}

// parseSqlmapOutput analyzes sqlmap output to determine the fuzz result.
func parseSqlmapOutput(output string, pocCmd string) *FuzzResult {
	r := &FuzzResult{
		Tool: "sqlmap",
		PoC:  pocCmd,
	}

	lower := strings.ToLower(output)

	// Check for confirmed injection
	if strings.Contains(lower, "sqlmap identified the following injection point") ||
		strings.Contains(lower, "is vulnerable") {
		r.Status = FuzzConfirmed

		// Extract payload lines as evidence
		lines := strings.Split(output, "\n")
		var payloadLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "Payload:") || strings.HasPrefix(trimmed, "Type:") ||
				strings.HasPrefix(trimmed, "Title:") {
				payloadLines = append(payloadLines, trimmed)
			}
		}
		if len(payloadLines) > 0 {
			r.ResponseDiff = strings.Join(payloadLines, "\n")
		} else {
			r.ResponseDiff = "sqlmap confirmed SQL injection"
		}
		return r
	}

	// Check for partial/possible injection
	if strings.Contains(lower, "might be injectable") ||
		strings.Contains(lower, "heuristic") {
		r.Status = FuzzPartial
		r.ResponseDiff = "sqlmap detected possible injection (heuristic match)"
		return r
	}

	// Not injectable
	if strings.Contains(lower, "do not appear to be injectable") ||
		strings.Contains(lower, "all tested parameters do not appear") {
		r.Status = FuzzFailed
		r.ResponseDiff = "sqlmap: parameters do not appear to be injectable"
		return r
	}

	// Default: if sqlmap exited without clear conclusion
	r.Status = FuzzFailed
	r.ResponseDiff = "sqlmap: no injection detected"
	if len(output) > 200 {
		r.ResponseDiff += "\n(last 200 chars): " + output[len(output)-200:]
	}

	return r
}

// findSqlmap searches for sqlmap in PATH and common installation directories.
func findSqlmap() string {
	// Try PATH first
	if p, err := exec.LookPath("sqlmap"); err == nil {
		return p
	}

	// Common pip install locations
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "Library", "Python", "3.9", "bin", "sqlmap"),
		filepath.Join(home, "Library", "Python", "3.10", "bin", "sqlmap"),
		filepath.Join(home, "Library", "Python", "3.11", "bin", "sqlmap"),
		filepath.Join(home, "Library", "Python", "3.12", "bin", "sqlmap"),
		filepath.Join(home, "Library", "Python", "3.13", "bin", "sqlmap"),
		filepath.Join(home, ".local", "bin", "sqlmap"),
		"/usr/local/bin/sqlmap",
		"/opt/homebrew/bin/sqlmap",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return ""
}
