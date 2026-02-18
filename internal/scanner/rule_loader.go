package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule defines a vulnerability detection rule backed by a CPGQL query.
type Rule struct {
	ID              string           `yaml:"id"`
	Name            string           `yaml:"name"`
	Language        string           `yaml:"language"`
	Severity        string           `yaml:"severity"` // critical, high, medium, low, info
	CWE             string           `yaml:"cwe"`
	Category        string           `yaml:"category"` // injection, auth, crypto, ...
	Query           string           `yaml:"query"`     // CPGQL query
	Sources         []SourceSink     `yaml:"sources"`
	Sinks           []SourceSink     `yaml:"sinks"`
	Sanitizers      []Sanitizer      `yaml:"sanitizers"`
	GuidedQuestions []string         `yaml:"guided_questions"`
}

// SourceSink describes a taint source or sink pattern.
type SourceSink struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
}

// Sanitizer describes a defense/mitigation pattern that LLM should check for.
type Sanitizer struct {
	Pattern string `yaml:"pattern"`
}

// LoadRulesForLanguage loads all YAML rule files from rules/<language>/ directory.
func LoadRulesForLanguage(rulesDir, language string) ([]*Rule, error) {
	dir := filepath.Join(rulesDir, language)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", dir, err)
	}
	var rules []*Rule
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", entry.Name(), err)
		}
		var rule Rule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", entry.Name(), err)
		}
		rule.Language = language
		rules = append(rules, &rule)
	}
	return rules, nil
}
