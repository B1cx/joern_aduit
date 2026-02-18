package llm

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// truncate returns a truncated string with ellipsis if needed
// It ensures truncation happens at valid UTF-8 character boundaries
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Ensure we don't cut in the middle of a multi-byte UTF-8 character
	// Walk backwards from maxLen to find the last complete rune
	truncPos := maxLen
	for truncPos > 0 {
		r, size := utf8.DecodeRuneInString(s[truncPos:])
		if r != utf8.RuneError || size != 1 {
			// Found a valid rune boundary
			break
		}
		truncPos--
	}

	if truncPos == 0 {
		truncPos = maxLen // Fallback if something goes wrong
	}

	return s[:truncPos] + "..."
}

// extractJSON extracts the first complete JSON object or array from a string
// This handles cases where LLM outputs extra text before/after the JSON
func extractJSON(s string) string {
	s = strings.TrimSpace(s)

	// Find the start of JSON (either { or [)
	start := -1
	for i, r := range s {
		if r == '{' || r == '[' {
			start = i
			break
		}
	}

	if start == -1 {
		return s // No JSON found, return as-is
	}

	// Find the matching closing bracket
	openChar := rune(s[start])
	closeChar := '}'
	if openChar == '[' {
		closeChar = ']'
	}

	depth := 0
	inString := false
	escape := false

	for i := start; i < len(s); i++ {
		r := rune(s[i])

		if escape {
			escape = false
			continue
		}

		if r == '\\' {
			escape = true
			continue
		}

		if r == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if r == openChar {
			depth++
		} else if r == closeChar {
			depth--
			if depth == 0 {
				// Found the complete JSON object
				return s[start : i+1]
			}
		}
	}

	// If we didn't find a complete JSON, return from start to end
	return s[start:]
}

// sanitizeJSON cleans a JSON string to remove characters that might cause parsing errors
func sanitizeJSON(s string) string {
	// 0. First extract the actual JSON object, removing any text before/after
	s = extractJSON(s)

	// 1. Replace Unicode replacement character (U+FFFD: �) which often indicates encoding issues
	s = strings.ReplaceAll(s, "\uFFFD", "")
	s = strings.ReplaceAll(s, "�", "")

	// 2. Remove other problematic Unicode characters that might appear in LLM responses
	// Remove zero-width characters
	s = strings.ReplaceAll(s, "\u200B", "") // Zero-width space
	s = strings.ReplaceAll(s, "\u200C", "") // Zero-width non-joiner
	s = strings.ReplaceAll(s, "\u200D", "") // Zero-width joiner
	s = strings.ReplaceAll(s, "\uFEFF", "") // Zero-width no-break space (BOM)

	// 3. Replace control characters (except newline, tab, carriage return which are valid in JSON)
	var cleaned strings.Builder
	for i, w := 0, 0; i < len(s); i += w {
		r, width := utf8.DecodeRuneInString(s[i:])
		w = width

		// Keep valid JSON whitespace and all printable characters
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) || r == ' ' {
			cleaned.WriteRune(r)
		}
		// Skip control characters and other problematic runes
	}
	s = cleaned.String()

	// 4. Fix common encoding issues in Chinese text that might break JSON
	// Replace any remaining invalid UTF-8 sequences
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}

	// 5. Clean up multiple consecutive spaces (but preserve single spaces)
	re := regexp.MustCompile(` {2,}`)
	s = re.ReplaceAllString(s, " ")

	return s
}
