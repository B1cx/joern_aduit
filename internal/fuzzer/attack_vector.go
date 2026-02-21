package fuzzer

import (
	"net/url"
	"regexp"
	"strings"
)

// ParseAttackVector parses a free-text attack vector description into a structured form.
// Examples of input:
//
//	"POST /api/users?name=payload"
//	"GET /search?q=' OR 1=1--"
//	"GET/POST /api/xxx?username=..."
func ParseAttackVector(raw string) *ParsedAttackVector {
	parsed := &ParsedAttackVector{
		Method:      "GET",
		QueryParams: make(map[string]string),
		Headers:     make(map[string]string),
	}

	if raw == "" {
		return parsed
	}

	raw = strings.TrimSpace(raw)
	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		return parsed
	}

	idx := 0

	// Check if first token is an HTTP method (or compound like "GET/POST")
	upper := strings.ToUpper(tokens[0])
	if strings.Contains(upper, "/") {
		// Handle compound methods like "GET/POST" — take the first one
		first := strings.Split(upper, "/")[0]
		if isHTTPMethod(first) {
			parsed.Method = first
			idx = 1
		}
	} else if isHTTPMethod(upper) {
		parsed.Method = upper
		idx = 1
	}

	// Next token should be the URL/path
	if idx < len(tokens) {
		rawURL := tokens[idx]
		idx++

		if !strings.HasPrefix(rawURL, "/") && !strings.HasPrefix(rawURL, "http") {
			rawURL = "/" + rawURL
		}

		if u, err := url.Parse(rawURL); err == nil {
			parsed.Path = u.Path
			for key, vals := range u.Query() {
				if len(vals) > 0 {
					parsed.QueryParams[key] = vals[0]
				}
			}
		} else {
			parsed.Path = rawURL
		}
	}

	// Process remaining tokens for headers and body hints
	remaining := strings.Join(tokens[idx:], " ")
	if remaining == "" {
		parsed.ParamName = detectInjectionParam(parsed.QueryParams)
		return parsed
	}

	for _, part := range strings.Split(remaining, "\n") {
		part = strings.TrimSpace(part)
		if colonIdx := strings.Index(part, ":"); colonIdx > 0 && colonIdx < len(part)-1 {
			key := strings.TrimSpace(part[:colonIdx])
			val := strings.TrimSpace(part[colonIdx+1:])
			if !strings.Contains(key, " ") && !strings.Contains(key, "=") {
				parsed.Headers[key] = val
				continue
			}
		}
		if parsed.Body == "" {
			parsed.Body = part
		} else {
			parsed.Body += "\n" + part
		}
	}

	parsed.ParamName = detectInjectionParam(parsed.QueryParams)
	return parsed
}

// BuildTargetURL constructs a full URL from a base URL and parsed attack vector.
func BuildTargetURL(baseURL string, parsed *ParsedAttackVector) string {
	base := strings.TrimRight(baseURL, "/")
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	u, err := url.Parse(base + path)
	if err != nil {
		return base + path
	}

	q := u.Query()
	for key, val := range parsed.QueryParams {
		q.Set(key, val)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// RefineWithRegistry resolves the correct endpoint path using the pre-scanned
// endpoint registry. This is the primary path resolution method.
//
// Resolution order:
//  1. EndpointRegistry match (direct file match or MyBatis mapper tracing)
//  2. Evidence-based extraction (regex on code snippets)
//  3. Param name extraction from evidence
func RefineWithRegistry(parsed *ParsedAttackVector, evidence []EvidenceRef, registry *EndpointRegistry, sourceRoot string) {
	// Try registry-based resolution first
	if registry != nil {
		if ep := registry.ResolveForEvidence(evidence, sourceRoot); ep != nil {
			parsed.Path = ep.FullPath
			if ep.Method != "ANY" {
				parsed.Method = ep.Method
			}
			if parsed.ParamName == "" && len(ep.Params) > 0 {
				parsed.ParamName = ep.Params[0]
			}
			for _, p := range ep.Params {
				if _, exists := parsed.QueryParams[p]; !exists {
					parsed.QueryParams[p] = "test"
				}
			}
			return
		}
	}

	// Fallback: extract from evidence code snippets
	if parsed.Path == "" || isPlaceholderPath(parsed.Path) {
		if realPath := extractEndpointFromEvidence(evidence); realPath != "" {
			if u, err := url.Parse(realPath); err == nil {
				parsed.Path = u.Path
				for key, vals := range u.Query() {
					if _, exists := parsed.QueryParams[key]; !exists && len(vals) > 0 {
						parsed.QueryParams[key] = vals[0]
					}
				}
			} else {
				parsed.Path = realPath
			}
		}
	}

	// Extract param name from evidence if still missing
	if parsed.ParamName == "" {
		parsed.ParamName = extractParamFromEvidence(evidence)
	}
}

// --- Internal helpers ---

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

var injectionMarkers = []string{
	"payload", "'", "\"", "$", "*", "{{", "${", ";", "`", "<", "../", "FUZZ",
}

// detectInjectionParam finds the query parameter most likely to be an injection point.
func detectInjectionParam(params map[string]string) string {
	for key, val := range params {
		for _, marker := range injectionMarkers {
			if strings.Contains(val, marker) {
				return key
			}
		}
	}
	for key := range params {
		return key
	}
	return ""
}

// placeholderPaths are generic paths the Judge may use when it doesn't know the real endpoint.
var placeholderPaths = []string{
	"/vulnerable-endpoint", "/endpoint", "/any_path", "/api/xxx",
	"/target", "/vuln", "/path", "/protected/api/endpoint",
}

func isPlaceholderPath(path string) bool {
	lower := strings.ToLower(path)
	for _, p := range placeholderPaths {
		if lower == p {
			return true
		}
	}
	return false
}

// extractEndpointFromEvidence tries to extract real endpoint paths from evidence code.
func extractEndpointFromEvidence(evidence []EvidenceRef) string {
	pathRe := regexp.MustCompile(`["'](/[a-zA-Z0-9_/.-]+(?:\?[^"'\s]*)?)["']`)

	// First pass: look for Spring mapping annotations
	for _, e := range evidence {
		if m := methodMappingRe.FindStringSubmatch(e.Code); len(m) > 1 {
			return m[1]
		}
	}

	// Second pass: look for URL-like paths in code strings
	for _, e := range evidence {
		for _, m := range pathRe.FindAllStringSubmatch(e.Code, -1) {
			path := m[1]
			if strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/etc/") ||
				strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/tmp/") {
				continue
			}
			return path
		}
	}

	return ""
}
