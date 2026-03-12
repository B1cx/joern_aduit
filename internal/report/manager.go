package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joern-audit/joern_audit/internal/domain"
)

// Manager handles report generation in multiple formats.
type Manager struct {
	generators map[string]Generator
	outputDir  string
}

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
	if err := os.MkdirAll(m.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	results := make(map[string]string)

	for _, format := range formats {
		generator, ok := m.generators[format]
		if !ok {
			return nil, fmt.Errorf("unknown format: %s", format)
		}

		content, err := generator.Generate(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("generate %s report: %w", format, err)
		}

		ext := format
		if format == "markdown" || format == "markdown-zh" {
			ext = "md"
		}

		filename := fmt.Sprintf("audit_report_%s.%s",
			time.Now().Format("20060102_150405"), ext)
		fpath := filepath.Join(m.outputDir, filename)

		if err := os.WriteFile(fpath, content, 0644); err != nil {
			return nil, fmt.Errorf("write %s report: %w", format, err)
		}

		results[format] = fpath
	}

	return results, nil
}

// BuildReportData constructs ReportData from evidence records.
func BuildReportData(sessionID, target, scanMode string, languages []string, records []*domain.Record) *ReportData {
	data := &ReportData{
		SessionID: sessionID,
		Target:    target,
		ScanMode:  scanMode,
		Languages: languages,
		Findings:  records,
		Summary:   Summary{},
		Coverage:  CoverageMatrix{Dimensions: []DimensionCoverage{}},
	}

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

		if rec.FuzzVerify != nil && rec.FuzzVerify.Result == "CONFIRMED" {
			data.Summary.FuzzConfirmed++
		}
	}

	return data
}
