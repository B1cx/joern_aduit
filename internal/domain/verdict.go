package domain

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
	Verdict          string    `json:"verdict"` // SAFE, NO_DEFENSE_FOUND, PARTIAL_DEFENSE
	Defenses         []Defense `json:"defenses"`
	Constraints      []string  `json:"constraints"`
	BypassAssessment string    `json:"bypass_assessment"`
	Confidence       float64   `json:"confidence"`
	NeedMore         []string  `json:"need_more"`
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
