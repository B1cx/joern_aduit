package fuzzer

import "context"

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

// PoCRequest contains everything needed to generate a PoC.
type PoCRequest struct {
	CWE          string         `json:"cwe"`
	AttackVector string         `json:"attack_vector"`
	Evidence     []EvidenceRef  `json:"evidence"`
	TargetURL    string         `json:"target_url,omitempty"`
}

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
	Payload string            `json:"payload,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	URL     string            `json:"url,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// FuzzResult is the outcome of a fuzz verification attempt.
type FuzzResult struct {
	Status       FuzzStatus `json:"status"`
	Tool         string     `json:"tool"`
	PoC          string     `json:"poc"`
	ResponseDiff string    `json:"response_diff,omitempty"`
	Error        string     `json:"error,omitempty"`
}

type FuzzStatus string

const (
	FuzzConfirmed FuzzStatus = "CONFIRMED"
	FuzzFailed    FuzzStatus = "FAILED"
	FuzzPartial   FuzzStatus = "PARTIAL"
)
