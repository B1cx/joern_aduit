package domain

// TaintFlowNode is a single step in a taint propagation path.
type TaintFlowNode struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Expr      string `json:"expr"`
	Transform string `json:"transform,omitempty"`
	NodeType  string `json:"node_type"` // SOURCE, PROPAGATION, SINK
}

// CPGEvidence contains Joern CPG-derived evidence for a candidate.
type CPGEvidence struct {
	TaintFlow  []TaintFlowNode `json:"taint_flow,omitempty"`
	CallChain  []string        `json:"call_chain,omitempty"`
	JoernQuery string          `json:"joern_query,omitempty"`
}

// CandidateStatus represents the lifecycle status of a candidate.
type CandidateStatus string

const (
	StatusPending     CandidateStatus = "pending"
	StatusLLMTP       CandidateStatus = "llm_tp"
	StatusLLMFP       CandidateStatus = "llm_fp"
	StatusLLMNeedDeep CandidateStatus = "llm_needs_deeper"
	StatusFuzzConfirm CandidateStatus = "fuzz_confirmed"
	StatusFuzzFailed  CandidateStatus = "fuzz_failed"
	StatusUnverified  CandidateStatus = "unverified"
)

// Candidate is a potential vulnerability alert from Joern scanning.
type Candidate struct {
	ID              int64           `json:"id"`
	RuleID          string          `json:"rule_id"`
	Severity        string          `json:"severity"`
	FilePath        string          `json:"file_path"`
	LineNumber      int             `json:"line_number"`
	Message         string          `json:"message"`
	CPGEvidence     *CPGEvidence    `json:"cpg_evidence,omitempty"`
	Status          CandidateStatus `json:"status"`
	Confidence      float64         `json:"confidence"`
	GuidedQuestions []string        `json:"guided_questions,omitempty"`
	Sanitizers      []string        `json:"sanitizers,omitempty"`
}
