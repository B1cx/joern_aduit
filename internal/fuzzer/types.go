package fuzzer

import (
	"context"

	"github.com/joern-audit/joern_audit/internal/config"
)

// --- Strategy interface ---

// Strategy defines how to fuzz-verify a specific vulnerability type.
type Strategy interface {
	// Name returns the strategy identifier (e.g. "sqli", "xss").
	Name() string

	// CanHandle checks if this strategy applies to the given CWE.
	CanHandle(cwe string) bool

	// GeneratePoC creates a PoC template from the evidence chain.
	GeneratePoC(ctx context.Context, req PoCRequest) (*PoCTemplate, error)

	// Execute runs the fuzz verification and returns the result.
	Execute(ctx context.Context, poc *PoCTemplate) (*FuzzResult, error)
}

// --- Request / Response types ---

// PoCRequest contains everything needed to generate a PoC.
type PoCRequest struct {
	CWE          string            `json:"cwe"`
	AttackVector string            `json:"attack_vector"`
	Evidence     []EvidenceRef     `json:"evidence"`
	TargetURL    string            `json:"target_url,omitempty"`
	SourceRoot   string            `json:"source_root,omitempty"`
	Registry     *EndpointRegistry `json:"-"`
}

// EvidenceRef is a reference to a code location from the CPG evidence chain.
type EvidenceRef struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code"`
	Role string `json:"role"`
}

// PoCTemplate is a generated proof-of-concept ready for execution.
type PoCTemplate struct {
	Type    string            `json:"type"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Payload string            `json:"payload,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	URL     string            `json:"url,omitempty"`
	Method  string            `json:"method,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// --- Fuzz result ---

// FuzzResult is the outcome of a fuzz verification attempt.
type FuzzResult struct {
	Status       FuzzStatus `json:"status"`
	Tool         string     `json:"tool"`
	PoC          string     `json:"poc"`
	ResponseDiff string     `json:"response_diff,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// FuzzStatus represents the verification outcome.
type FuzzStatus string

const (
	FuzzConfirmed FuzzStatus = "CONFIRMED"
	FuzzFailed    FuzzStatus = "FAILED"
	FuzzPartial   FuzzStatus = "PARTIAL"
	FuzzError     FuzzStatus = "ERROR"
)

// --- Parsed attack vector ---

// ParsedAttackVector is a structured representation of an HTTP attack vector
// parsed from the judge's free-text AttackVector field.
type ParsedAttackVector struct {
	Method      string
	Path        string
	QueryParams map[string]string
	Headers     map[string]string
	Body        string
	ParamName   string // primary injection parameter
}

// --- Strategy constructors (delegated to individual files) ---

// NewStrategies returns all built-in fuzz strategies in priority order.
func NewStrategies(cfg *config.FuzzerConfig) []Strategy {
	return []Strategy{
		NewSQLiStrategy(cfg),
		NewXXEStrategy(cfg),
		NewHTTPGenericStrategy(cfg),
		NewDeserStrategy(cfg),
	}
}
