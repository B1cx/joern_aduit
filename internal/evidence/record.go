package evidence

import (
	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/verifier"
)

// Record is the complete audit trail for a single finding.
type Record struct {
	// Basic Info
	CandidateID   string `json:"candidate_id"`
	RuleID        string `json:"rule_id"`
	FilePath      string `json:"file_path"`
	LineNumber    int    `json:"line_number"`
	InitialSeverity string `json:"initial_severity"`
	FinalSeverity string `json:"final_severity"`
	CWE           string `json:"cwe"`

	// CPG Evidence
	CPGEvidence   *cpg.CPGEvidence `json:"cpg_evidence,omitempty"`

	// LLM Verification
	LLMVerify     *LLMVerification `json:"llm_verify,omitempty"`

	// Fuzz Verification (optional)
	FuzzVerify    *FuzzVerification `json:"fuzz_verify,omitempty"`
}

// LLMVerification contains the Tribunal verification results.
type LLMVerification struct {
	Prosecutor *verifier.ProsecutorResult `json:"prosecutor,omitempty"`
	Defender   *verifier.DefenderResult   `json:"defender,omitempty"`
	Judge      *verifier.JudgeResult      `json:"judge"`
	ContextRounds int                     `json:"context_rounds"`
	TotalTokens   int                     `json:"total_tokens"`
}

// FuzzVerification contains the fuzzing test results.
type FuzzVerification struct {
	Tool     string `json:"tool"`
	PoC      string `json:"poc"`
	Result   string `json:"result"` // CONFIRMED, FAILED, PARTIAL
	Evidence string `json:"evidence,omitempty"`
}
