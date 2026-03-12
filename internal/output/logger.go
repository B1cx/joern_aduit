package output

import (
	"fmt"

	"github.com/joern-audit/joern_audit/internal/domain"
	"github.com/joern-audit/joern_audit/internal/shared"
)

// AuditLogger defines the interface for pipeline output.
type AuditLogger interface {
	PhaseStart(name string)
	PhaseEnd(name string)
	Progress(format string, args ...any)
	Verdict(candidateID string, verdict domain.Verdict, confidence float64, severity string)
	Warning(format string, args ...any)
	Error(format string, args ...any)
	Summary(format string, args ...any)
}

// ConsoleLogger is the default logger that prints to stdout.
type ConsoleLogger struct{}

func NewConsoleLogger() *ConsoleLogger { return &ConsoleLogger{} }

func (l *ConsoleLogger) PhaseStart(name string) {
	fmt.Printf("\n📌 [%s] 开始\n", name)
}

func (l *ConsoleLogger) PhaseEnd(name string) {
	fmt.Printf("  ✓ [%s] 完成\n\n", name)
}

func (l *ConsoleLogger) Progress(format string, args ...any) {
	fmt.Printf("  "+format+"\n", args...)
}

func (l *ConsoleLogger) Verdict(candidateID string, verdict domain.Verdict, confidence float64, severity string) {
	emoji := shared.VerdictEmoji(verdict)
	fmt.Printf("  %s 裁决: %s (置信度: %.2f, 严重性: %s)\n", emoji, verdict, confidence, severity)
}

func (l *ConsoleLogger) Warning(format string, args ...any) {
	fmt.Printf("  ⚠️  "+format+"\n", args...)
}

func (l *ConsoleLogger) Error(format string, args ...any) {
	fmt.Printf("  ❌ "+format+"\n", args...)
}

func (l *ConsoleLogger) Summary(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}
