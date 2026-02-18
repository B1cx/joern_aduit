package report

import (
	"context"

	"github.com/joern-audit/joern_audit/internal/evidence"
)

// Generator produces reports in various formats from evidence records.
type Generator interface {
	Format() string
	Generate(ctx context.Context, data *ReportData) ([]byte, error)
}

// ReportData contains all data needed to generate a report.
type ReportData struct {
	SessionID     string              `json:"session_id"`
	Target        string              `json:"target"`
	ScanMode      string              `json:"scan_mode"`
	Languages     []string            `json:"languages"`
	TechStack     string              `json:"tech_stack"`
	Summary       Summary             `json:"summary"`
	Findings      []*evidence.Record  `json:"findings"`
	Coverage      CoverageMatrix      `json:"coverage"`
	AttackChains  []AttackChain       `json:"attack_chains,omitempty"`
}

// Summary is a high-level overview of audit results.
type Summary struct {
	TotalCandidates  int `json:"total_candidates"`
	TruePositives    int `json:"true_positives"`
	FalsePositives   int `json:"false_positives"`
	NeedDeeper       int `json:"need_deeper"`
	FuzzConfirmed    int `json:"fuzz_confirmed"`
	Critical         int `json:"critical"`
	High             int `json:"high"`
	Medium           int `json:"medium"`
	Low              int `json:"low"`
	Info             int `json:"info"`
}

// CoverageMatrix tracks the 10-dimension coverage status.
type CoverageMatrix struct {
	Dimensions []DimensionCoverage `json:"dimensions"`
}

// DimensionCoverage tracks a single security dimension.
type DimensionCoverage struct {
	ID          string `json:"id"`    // D1-D10
	Name        string `json:"name"`
	Status      string `json:"status"` // covered, shallow, uncovered
	JoernRules  bool   `json:"joern_rules"`
	LLMExplored bool   `json:"llm_explored"`
	FindingCount int   `json:"finding_count"`
}

// AttackChain represents a multi-vulnerability exploitation path.
type AttackChain struct {
	Name        string   `json:"name"`
	Steps       []string `json:"steps"`
	CVSS        float64  `json:"cvss"`
	FindingIDs  []string `json:"finding_ids"`
}
