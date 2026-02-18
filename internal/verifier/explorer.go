package verifier

import (
	"context"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/llm"
)

// ExplorerFinding is a potential vulnerability discovered by free exploration.
type ExplorerFinding struct {
	Description string            `json:"description"`
	FilePath    string            `json:"file_path"`
	LineNumber  int               `json:"line_number"`
	Code        string            `json:"code"`
	Dimension   string            `json:"dimension"` // D1-D10
	Confidence  float64           `json:"confidence"`
	Evidence    []EvidenceStep    `json:"evidence"`
}

// Explorer performs free-form vulnerability exploration within controlled bounds.
type Explorer struct {
	provider   llm.Provider
	contextMgr *cpg.ContextManager
	contract   AgentContract
}

func NewExplorer(provider llm.Provider, contextMgr *cpg.ContextManager, contract AgentContract) *Explorer {
	return &Explorer{
		provider:   provider,
		contextMgr: contextMgr,
		contract:   contract,
	}
}

// Explore performs free-form security exploration guided by the attack surface map.
// It returns findings that should be further verified by the Tribunal.
func (e *Explorer) Explore(ctx context.Context, attackSurface AttackSurface) ([]ExplorerFinding, error) {
	// TODO: build explorer prompt with attack surface info + contract constraints
	// TODO: iteratively explore, respecting turn limits and turn-reserve
	return nil, nil
}

// AttackSurface summarizes the target project's security-relevant structure.
type AttackSurface struct {
	TechStack    string            `json:"tech_stack"`
	EntryPoints  []EntryPoint      `json:"entry_points"`
	HighRiskAreas []string         `json:"high_risk_areas"`
	DataSources  []string          `json:"data_sources"`
	AuthMechanism string           `json:"auth_mechanism"`
	Dimensions   map[string]string `json:"dimensions"` // D1-D10 → priority
}

// EntryPoint is an API endpoint or user-facing interface.
type EntryPoint struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Handler  string `json:"handler"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	AuthReq  bool   `json:"auth_required"`
}
