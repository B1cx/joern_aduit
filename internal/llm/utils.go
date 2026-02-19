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

	// 1. Repair unescaped double quotes inside JSON string values.
	//    LLM often uses ASCII " for Chinese quotation in text like:
	//      "attack_path": "这是一个"漏洞"的分析"
	//    The inner quotes break JSON parsing.
	s = repairJSON(s)

	// 2. Replace Unicode replacement character (U+FFFD: <20>) which often indicates encoding issues
	s = strings.ReplaceAll(s, "\uFFFD", "")
	s = strings.ReplaceAll(s, "<28>", "")

	// 3. Remove zero-width characters
	s = strings.ReplaceAll(s, "\u200B", "") // Zero-width space
	s = strings.ReplaceAll(s, "\u200C", "") // Zero-width non-joiner
	s = strings.ReplaceAll(s, "\u200D", "") // Zero-width joiner
	s = strings.ReplaceAll(s, "\uFEFF", "") // Zero-width no-break space (BOM)

	// 4. Replace control characters (except newline, tab, carriage return which are valid in JSON)
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

	// 5. Fix remaining invalid UTF-8 sequences
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}

	// 6. Clean up multiple consecutive spaces (but preserve single spaces)
	re := regexp.MustCompile(` {2,}`)
	s = re.ReplaceAllString(s, " ")

	return s
}

// repairJSON fixes unescaped double quotes inside JSON string values.
//
// Problem: LLM outputs like  {"reasoning": "这是一个"漏洞"的分析"}
// The inner " around 漏洞 breaks JSON parsing because the parser
// thinks the string ended at 个".
//
// Solution: walk through the JSON byte-by-byte, tracking whether we're
// inside a string. When we hit a " inside a string, look ahead to see
// if what follows is JSON structure (,  }  ]  :) — if so it's a real
// closing quote; otherwise it's an embedded quote that needs escaping.
//
// This is safe for UTF-8: the byte 0x22 (") never appears as a
// continuation byte in multi-byte UTF-8 sequences.
func repairJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 64)

	inString := false
	i := 0

	for i < len(s) {
		ch := s[i]

		// Inside a string: handle escape sequences verbatim
		if inString && ch == '\\' {
			b.WriteByte(ch)
			i++
			if i < len(s) {
				b.WriteByte(s[i])
				i++
			}
			continue
		}

		if ch == '"' {
			if !inString {
				// Opening a new string
				inString = true
				b.WriteByte(ch)
				i++
				continue
			}

			// Inside a string and hit a quote.
			// Decide: is this the real closing quote, or an embedded one?
			// Look at the first non-whitespace character after this quote.
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}

			isClosing := false
			if j >= len(s) {
				isClosing = true // end of input → must be closing
			} else {
				next := s[j]
				// After a closing quote we expect JSON structure: , } ] :
				if next == ',' || next == '}' || next == ']' || next == ':' {
					isClosing = true
				}
			}

			if isClosing {
				inString = false
				b.WriteByte(ch)
			} else {
				// Embedded quote → escape it
				b.WriteString("\\\"")
			}
			i++
			continue
		}

		b.WriteByte(ch)
		i++
	}

	return b.String()
}
