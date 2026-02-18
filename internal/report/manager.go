package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joern-audit/joern_audit/internal/evidence"
)

// Manager handles report generation in multiple formats.
type Manager struct {
	generators map[string]Generator
	outputDir  string
}

// NewManager creates a new report manager with all available generators.
func NewManager(outputDir string) *Manager {
	return &Manager{
		generators: map[string]Generator{
			"markdown":    &MarkdownGenerator{},
			"markdown-zh": &ChineseMarkdownGenerator{},
			"json":        &JSONGenerator{},
			"sarif":       &SARIFGenerator{},
		},
		outputDir: outputDir,
	}
}

// Generate creates reports in the specified formats.
func (m *Manager) Generate(ctx context.Context, data *ReportData, formats []string) (map[string]string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(m.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	results := make(map[string]string)

	for _, format := range formats {
		generator, ok := m.generators[format]
		if !ok {
			return nil, fmt.Errorf("unknown format: %s", format)
		}

		// Generate report
		content, err := generator.Generate(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("generate %s report: %w", format, err)
		}

		// Determine file extension
		ext := format
		if format == "markdown" || format == "markdown-zh" {
			ext = "md"
		}

		// Create filename with timestamp
		filename := fmt.Sprintf("audit_report_%s.%s",
			time.Now().Format("20060102_150405"), ext)
		filepath := filepath.Join(m.outputDir, filename)

		// Write to file
		if err := os.WriteFile(filepath, content, 0644); err != nil {
			return nil, fmt.Errorf("write %s report: %w", format, err)
		}

		results[format] = filepath
	}

	return results, nil
}

// BuildReportData constructs ReportData from evidence records.
func BuildReportData(sessionID, target, scanMode string, languages []string, records []*evidence.Record) *ReportData {
	data := &ReportData{
		SessionID: sessionID,
		Target:    target,
		ScanMode:  scanMode,
		Languages: languages,
		Findings:  records,
		Summary:   Summary{},
		Coverage:  CoverageMatrix{Dimensions: []DimensionCoverage{}},
	}

	// Calculate summary statistics
	data.Summary.TotalCandidates = len(records)
	for _, rec := range records {
		if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
			switch rec.LLMVerify.Judge.Verdict {
			case "TRUE_POSITIVE":
				data.Summary.TruePositives++
			case "FALSE_POSITIVE":
				data.Summary.FalsePositives++
			case "NEEDS_DEEPER":
				data.Summary.NeedDeeper++
			}

			// Count by severity
			switch rec.FinalSeverity {
			case "CRITICAL":
				data.Summary.Critical++
			case "HIGH":
				data.Summary.High++
			case "MEDIUM":
				data.Summary.Medium++
			case "LOW":
				data.Summary.Low++
			case "INFO":
				data.Summary.Info++
			}
		}

		// Count fuzz confirmed
		if rec.FuzzVerify != nil && rec.FuzzVerify.Result == "CONFIRMED" {
			data.Summary.FuzzConfirmed++
		}
	}

	return data
}
