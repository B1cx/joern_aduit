package cpg

// Function represents a function/method extracted from CPG.
type Function struct {
	ID         int64  `json:"id" db:"id"`
	Name       string `json:"name" db:"name"`
	FullName   string `json:"full_name" db:"full_name"`
	Signature  string `json:"signature" db:"signature"`
	FilePath   string `json:"file_path" db:"file_path"`
	StartLine  int    `json:"start_line" db:"start_line"`
	EndLine    int    `json:"end_line" db:"end_line"`
	IsPublic   bool   `json:"is_public" db:"is_public"`
	Annotation string `json:"annotation" db:"annotation"`
	Complexity int    `json:"complexity" db:"complexity"`
}

// CallEdge represents a caller→callee relationship.
type CallEdge struct {
	CallerID     int64  `json:"caller_id" db:"caller_id"`
	CalleeID     int64  `json:"callee_id" db:"callee_id"`
	CallSiteLine int    `json:"call_site_line" db:"call_site_line"`
	CallSiteFile string `json:"call_site_file" db:"call_site_file"`
}

// TaintFlowNode is a single step in a taint propagation path.
type TaintFlowNode struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Expr      string `json:"expr"`
	Transform string `json:"transform,omitempty"`
	NodeType  string `json:"node_type"` // SOURCE, PROPAGATION, SINK
}

// TaintPath is a complete source-to-sink taint propagation path.
type TaintPath struct {
	ID       int64           `json:"id"`
	SourceID int64           `json:"source_func_id"`
	SinkID   int64           `json:"sink_func_id"`
	RuleID   string          `json:"rule_id"`
	Nodes    []TaintFlowNode `json:"nodes"`
}

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

type CPGEvidence struct {
	TaintFlow []TaintFlowNode `json:"taint_flow,omitempty"`
	CallChain []string        `json:"call_chain,omitempty"`
	JoernQuery string         `json:"joern_query,omitempty"`
}

type CandidateStatus string

const (
	StatusPending      CandidateStatus = "pending"
	StatusLLMTP        CandidateStatus = "llm_tp"
	StatusLLMFP        CandidateStatus = "llm_fp"
	StatusLLMNeedDeep  CandidateStatus = "llm_needs_deeper"
	StatusFuzzConfirm  CandidateStatus = "fuzz_confirmed"
	StatusFuzzFailed   CandidateStatus = "fuzz_failed"
	StatusUnverified   CandidateStatus = "unverified"
)

// QueryResult is a generic result from a CPGQL query.
type QueryResult struct {
	Data map[string]interface{} `json:"data"`
}

// SliceRequest specifies parameters for program slicing.
type SliceRequest struct {
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	Direction string `json:"direction"` // forward, backward
	Depth     int    `json:"depth"`
}

// SliceResult contains the extracted program slice.
type SliceResult struct {
	Nodes []SliceNode `json:"nodes"`
}

type SliceNode struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code"`
}

// IndexStore is the interface for persisting CPG index data.
type IndexStore interface {
	SaveFunctions(funcs []Function) error
	SaveCallEdges(edges []CallEdge) error
	SaveTaintFlows(flows []TaintPath) error
	GetFunction(id int64) (*Function, error)
	GetCallers(funcID int64) ([]CallEdge, error)
	GetCallees(funcID int64) ([]CallEdge, error)
	GetFunctionByLocation(file string, line int) (*Function, error)
	GetTaintFlowsForSink(file string, line int) ([]TaintPath, error)
}
