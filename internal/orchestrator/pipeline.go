package orchestrator

import (
	"context"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/evidence"
	"github.com/joern-audit/joern_audit/internal/output"
)

// Phase represents a stage in the audit pipeline.
type Phase int

const (
	PhaseInit        Phase = 0
	PhaseCPGBuild    Phase = 1
	PhaseLLMVerify   Phase = 2
	PhaseFuzzVerify  Phase = 3
	PhaseAttackChain Phase = 4
	PhaseReport      Phase = 5
)

func (p Phase) String() string {
	names := map[Phase]string{
		PhaseInit: "init", PhaseCPGBuild: "cpg_build", PhaseLLMVerify: "llm_verify",
		PhaseFuzzVerify: "fuzz_verify", PhaseAttackChain: "attack_chain", PhaseReport: "report",
	}
	return names[p]
}

// Session tracks the state of an audit session.
type Session struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Languages []string  `json:"languages"`
	Mode      string    `json:"mode"`
	Phase     Phase     `json:"phase"`
	Round     int       `json:"round"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Status    string    `json:"status"`
}

// PipelineState holds all shared state passed between phases.
type PipelineState struct {
	Session    *Session
	Config     *config.Config
	Store      evidence.Store
	Coverage   *CoverageMatrix
	Candidates []domain.Candidate
	CPGEngine  *cpg.Engine
	IndexStore cpg.IndexStore
	Database   interface{ Close() error } // *db.DB or nil
	Logger     output.AuditLogger
}

// PhaseRunner is the interface for a single pipeline phase.
type PhaseRunner interface {
	Name() string
	Execute(ctx context.Context, state *PipelineState) error
}
