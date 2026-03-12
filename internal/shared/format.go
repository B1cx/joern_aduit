package shared

import "github.com/joern-audit/joern_audit/internal/domain"

var verdictEmoji = map[domain.Verdict]string{
	domain.VerdictTruePositive:  "✅",
	domain.VerdictFalsePositive: "❌",
	domain.VerdictNeedsDeeper:   "🔬",
	domain.VerdictConditional:   "⚠️",
}

// VerdictEmoji returns the emoji icon for a verdict.
func VerdictEmoji(v domain.Verdict) string {
	if e, ok := verdictEmoji[v]; ok {
		return e
	}
	return "❓"
}

// Truncate shortens a string to maxLen, appending "..." if truncated.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
