package orchestrator

import "strings"

// CoverageStatus represents the coverage state of a security dimension.
type CoverageStatus string

const (
	Covered   CoverageStatus = "covered"   // deep analysis done
	Shallow   CoverageStatus = "shallow"   // only grep/surface scan
	Uncovered CoverageStatus = "uncovered" // not touched
)

// DimensionID identifies one of the 10 security dimensions.
type DimensionID string

const (
	DimInjection      DimensionID = "D1"
	DimAuth           DimensionID = "D2"
	DimAuthz          DimensionID = "D3"
	DimDeserialization DimensionID = "D4"
	DimFileOps        DimensionID = "D5"
	DimSSRF           DimensionID = "D6"
	DimCrypto         DimensionID = "D7"
	DimConfig         DimensionID = "D8"
	DimBusinessLogic  DimensionID = "D9"
	DimSupplyChain    DimensionID = "D10"
)

// Dimension describes a security dimension with its coverage state.
type Dimension struct {
	ID           DimensionID    `json:"id"`
	Name         string         `json:"name"`
	Status       CoverageStatus `json:"status"`
	JoernRules   bool           `json:"joern_rules"`
	LLMExplored  bool           `json:"llm_explored"`
	FindingCount int            `json:"finding_count"`
}

// CoverageMatrix manages the 10-dimension audit coverage.
type CoverageMatrix struct {
	dims map[DimensionID]*Dimension
}

func NewCoverageMatrix() *CoverageMatrix {
	m := &CoverageMatrix{dims: make(map[DimensionID]*Dimension)}
	defaults := []struct {
		id   DimensionID
		name string
	}{
		{DimInjection, "Injection (SQL/Cmd/LDAP/XPath)"},
		{DimAuth, "Authentication (JWT/Session/OAuth)"},
		{DimAuthz, "Authorization (RBAC/ABAC/IDOR)"},
		{DimDeserialization, "Deserialization"},
		{DimFileOps, "File Operations (Upload/Download/LFI)"},
		{DimSSRF, "SSRF (HTTP/JDBC/Protocol)"},
		{DimCrypto, "Cryptography (Keys/Algorithms)"},
		{DimConfig, "Configuration (Debug/CORS/Headers)"},
		{DimBusinessLogic, "Business Logic (Race/Flow Bypass)"},
		{DimSupplyChain, "Supply Chain (Dependencies/CVE)"},
	}
	for _, d := range defaults {
		m.dims[d.id] = &Dimension{ID: d.id, Name: d.name, Status: Uncovered}
	}
	return m
}

// categoryToDimension maps rule category keywords to security dimensions.
var categoryToDimension = map[string]DimensionID{
	"SQLI":   DimInjection,
	"CMDI":   DimInjection,
	"RCE":    DimInjection,
	"SSTI":   DimInjection,
	"XSS":    DimInjection,
	"XXE":    DimInjection,
	"XPATH":  DimInjection,
	"LDAP":   DimInjection,
	"EL":     DimInjection,
	"AUTH":   DimAuth,
	"AUTHZ":  DimAuthz,
	"IDOR":   DimAuthz,
	"DESER":  DimDeserialization,
	"LFI":    DimFileOps,
	"FILE":   DimFileOps,
	"UPLOAD": DimFileOps,
	"SSRF":   DimSSRF,
	"CRYPTO": DimCrypto,
	"CONFIG": DimConfig,
	"CORS":   DimConfig,
	"DEBUG":  DimConfig,
}

// ResolveDimension maps a rule ID (e.g., "JAVA-SQLI-001") to a DimensionID.
func ResolveDimension(ruleID string) DimensionID {
	parts := strings.Split(ruleID, "-")
	if len(parts) >= 2 {
		category := strings.ToUpper(parts[1])
		if dim, ok := categoryToDimension[category]; ok {
			return dim
		}
	}
	return ""
}

// MarkRuleScanned marks that a Joern rule targeting this dimension was executed.
// Transitions: uncovered → shallow.
func (m *CoverageMatrix) MarkRuleScanned(ruleID string) {
	dim := ResolveDimension(ruleID)
	if dim == "" {
		return
	}
	d := m.dims[dim]
	if d == nil {
		return
	}
	d.JoernRules = true
	if d.Status == Uncovered {
		d.Status = Shallow
	}
}

// AddFinding records a verified finding for a dimension and promotes to covered.
func (m *CoverageMatrix) AddFinding(ruleID string) {
	dim := ResolveDimension(ruleID)
	if dim == "" {
		return
	}
	d := m.dims[dim]
	if d == nil {
		return
	}
	d.FindingCount++
	d.Status = Covered
}

// MarkLLMExplored marks that a dimension was explored by the LLM Explorer agent.
func (m *CoverageMatrix) MarkLLMExplored(dim DimensionID) {
	d := m.dims[dim]
	if d == nil {
		return
	}
	d.LLMExplored = true
	if d.Status == Uncovered {
		d.Status = Shallow
	}
}

// Get returns the dimension by ID.
func (m *CoverageMatrix) Get(id DimensionID) *Dimension {
	return m.dims[id]
}

// Update sets coverage status for a dimension.
func (m *CoverageMatrix) Update(id DimensionID, status CoverageStatus) {
	if d, ok := m.dims[id]; ok {
		d.Status = status
	}
}

// CoveredCount returns how many dimensions are fully covered.
func (m *CoverageMatrix) CoveredCount() int {
	count := 0
	for _, d := range m.dims {
		if d.Status == Covered {
			count++
		}
	}
	return count
}

// Gaps returns dimensions that are uncovered or only shallowly covered.
func (m *CoverageMatrix) Gaps() []*Dimension {
	var gaps []*Dimension
	for _, d := range m.dims {
		if d.Status != Covered {
			gaps = append(gaps, d)
		}
	}
	return gaps
}

// ShouldContinue evaluates the three-question termination rule.
func (m *CoverageMatrix) ShouldContinue(round, maxRounds int) bool {
	if round >= maxRounds {
		return false
	}
	// Q1: Any High/Critical dimensions uncovered?
	critical := []DimensionID{DimInjection, DimAuth, DimAuthz}
	for _, id := range critical {
		if m.dims[id].Status == Uncovered {
			return true
		}
	}
	// Q2: Coverage below threshold?
	if m.CoveredCount() < 8 {
		return true
	}
	return false
}

// All returns all dimensions.
func (m *CoverageMatrix) All() []*Dimension {
	order := []DimensionID{
		DimInjection, DimAuth, DimAuthz, DimDeserialization, DimFileOps,
		DimSSRF, DimCrypto, DimConfig, DimBusinessLogic, DimSupplyChain,
	}
	result := make([]*Dimension, 0, len(order))
	for _, id := range order {
		result = append(result, m.dims[id])
	}
	return result
}
