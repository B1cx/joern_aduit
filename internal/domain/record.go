package domain

// Record is the complete audit trail for a single finding.
type Record struct {
	CandidateID     string `json:"candidate_id"`
	RuleID          string `json:"rule_id"`
	FilePath        string `json:"file_path"`
	LineNumber      int    `json:"line_number"`
	InitialSeverity string `json:"initial_severity"`
	FinalSeverity   string `json:"final_severity"`
	CWE             string `json:"cwe"`

	CPGEvidence *CPGEvidence      `json:"cpg_evidence,omitempty"`
	LLMVerify   *LLMVerification  `json:"llm_verify,omitempty"`
	FuzzVerify  *FuzzVerification `json:"fuzz_verify,omitempty"`
}

// LLMVerification contains the Tribunal verification results.
type LLMVerification struct {
	Prosecutor    *ProsecutorResult `json:"prosecutor,omitempty"`
	Defender      *DefenderResult   `json:"defender,omitempty"`
	Judge         *JudgeResult      `json:"judge"`
	ContextRounds int               `json:"context_rounds"`
	TotalTokens   int               `json:"total_tokens"`
}

// FuzzVerification contains the fuzzing test results.
type FuzzVerification struct {
	Tool     string `json:"tool"`
	PoC      string `json:"poc"`
	Result   string `json:"result"` // CONFIRMED, FAILED, PARTIAL
	Evidence string `json:"evidence,omitempty"`
}
