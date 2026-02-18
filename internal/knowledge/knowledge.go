package knowledge

// CWEEntry is a Common Weakness Enumeration entry.
type CWEEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
}

// PatternDB holds language-specific vulnerability patterns.
type PatternDB struct {
	Patterns map[string][]VulnPattern `json:"patterns"` // language → patterns
}

// VulnPattern is a known vulnerability pattern for a language.
type VulnPattern struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Language    string   `json:"language"`
	CWE         string   `json:"cwe"`
	Dimension   string   `json:"dimension"` // D1-D10
	SinkPattern string   `json:"sink_pattern"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

// KnowledgeBase provides CWE and pattern lookup.
type KnowledgeBase struct {
	cweDB    map[string]*CWEEntry
	patterns *PatternDB
}

func NewKnowledgeBase() *KnowledgeBase {
	return &KnowledgeBase{
		cweDB:    make(map[string]*CWEEntry),
		patterns: &PatternDB{Patterns: make(map[string][]VulnPattern)},
	}
}

// GetCWE returns CWE entry by ID.
func (kb *KnowledgeBase) GetCWE(id string) *CWEEntry {
	return kb.cweDB[id]
}

// GetPatterns returns vulnerability patterns for a language.
func (kb *KnowledgeBase) GetPatterns(language string) []VulnPattern {
	return kb.patterns.Patterns[language]
}

// LoadCWE loads CWE database from a JSON file.
func (kb *KnowledgeBase) LoadCWE(path string) error {
	// TODO: read JSON, populate cweDB
	return nil
}

// LoadPatterns loads vulnerability patterns from YAML files.
func (kb *KnowledgeBase) LoadPatterns(dir string) error {
	// TODO: read YAML files, populate patterns
	return nil
}
