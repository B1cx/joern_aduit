package report

import (
	"context"
	"encoding/json"
)

// SARIFGenerator produces SARIF 2.1.0 format reports.
// SARIF is the standard format for static analysis tools, supported by GitHub, VS Code, etc.
type SARIFGenerator struct{}

func (g *SARIFGenerator) Format() string { return "sarif" }

func (g *SARIFGenerator) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	sarif := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "DeepAudit",
						InformationURI: "https://github.com/yourusername/joern_audit",
						Version:        "0.1.0",
						SemanticVersion: "0.1.0",
					},
				},
				Results: []SARIFResult{},
			},
		},
	}

	// Convert findings to SARIF results
	for _, finding := range data.Findings {
		result := SARIFResult{
			RuleID:  finding.RuleID,
			Level:   severityToSARIFLevel(finding.FinalSeverity),
			Message: SARIFMessage{},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: finding.FilePath,
						},
						Region: SARIFRegion{
							StartLine: finding.LineNumber,
						},
					},
				},
			},
		}

		// Build message text
		messageText := finding.CWE
		if finding.LLMVerify != nil && finding.LLMVerify.Judge != nil {
			messageText = finding.LLMVerify.Judge.Reasoning
			if finding.LLMVerify.Judge.AttackVector != "" {
				result.Message.Markdown = "**Attack Vector**: `" + finding.LLMVerify.Judge.AttackVector + "`\n\n" + finding.LLMVerify.Judge.Reasoning
			}
		}
		result.Message.Text = messageText

		// Add code flow if available
		if finding.LLMVerify != nil && finding.LLMVerify.Judge != nil && len(finding.LLMVerify.Judge.EvidenceChain) > 0 {
			codeFlow := SARIFCodeFlow{
				ThreadFlows: []SARIFThreadFlow{
					{
						Locations: []SARIFThreadFlowLocation{},
					},
				},
			}

			for _, evidence := range finding.LLMVerify.Judge.EvidenceChain {
				codeFlow.ThreadFlows[0].Locations = append(codeFlow.ThreadFlows[0].Locations, SARIFThreadFlowLocation{
					Location: SARIFLocation{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: evidence.File,
							},
							Region: SARIFRegion{
								StartLine: evidence.Line,
								Snippet: SARIFSnippet{
									Text: evidence.Code,
								},
							},
						},
					},
				})
			}

			result.CodeFlows = []SARIFCodeFlow{codeFlow}
		}

		sarif.Runs[0].Results = append(sarif.Runs[0].Results, result)
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// severityToSARIFLevel converts our severity levels to SARIF levels.
func severityToSARIFLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	case "INFO":
		return "none"
	default:
		return "warning"
	}
}

// SARIF 2.1.0 structures
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string `json:"name"`
	InformationURI  string `json:"informationUri"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
	CodeFlows []SARIFCodeFlow  `json:"codeFlows,omitempty"`
}

type SARIFMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int          `json:"startLine"`
	Snippet   SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
}
