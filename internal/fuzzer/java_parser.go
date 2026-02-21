package fuzzer

import (
	"regexp"
	"strings"
)

// Shared regular expressions for parsing Java source files.
var (
	// classMappingRe matches class-level @RequestMapping annotations.
	// Note: @RestController(value=...) sets the BEAN NAME, not the URL path.
	classMappingRe = regexp.MustCompile(
		`@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`,
	)

	// methodMappingRe matches method-level mapping annotations.
	methodMappingRe = regexp.MustCompile(
		`@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`,
	)

	// mappingAnnotationRe captures both the annotation type and path value.
	mappingAnnotationRe = regexp.MustCompile(
		`@(Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']`,
	)

	// controllerAnnotationRe detects Spring controller classes.
	controllerAnnotationRe = regexp.MustCompile(`@(?:Controller|RestController)`)

	// classDeclRe extracts the class name from a declaration.
	classDeclRe = regexp.MustCompile(`(?:public\s+)?class\s+(\w+)`)

	// requestParamAnnotRe extracts parameter names from @RequestParam.
	requestParamAnnotRe = regexp.MustCompile(
		`@RequestParam\s*\(\s*(?:(?:value|name)\s*=\s*)?["']([^"']+)["']`,
	)

	// javaMethodDeclRe matches Java method declarations.
	javaMethodDeclRe = regexp.MustCompile(
		`(?:public|private|protected)\s+\S+\s+(\w+)\s*\(`,
	)

	// xmlSelectIDRe matches MyBatis XML mapper statement IDs.
	xmlSelectIDRe = regexp.MustCompile(
		`<(?:select|insert|update|delete)\s+id\s*=\s*["'](\w+)["']`,
	)

	// getParameterRe matches request.getParameter("name") calls.
	getParameterRe = regexp.MustCompile(`getParameter\s*\(\s*["']([^"']+)["']`)
)

// extractClassPrefix extracts the class-level @RequestMapping path prefix
// from Java source lines. Returns empty string if not found.
func extractClassPrefix(lines []string) string {
	classLineIdx := findClassDeclaration(lines)
	if classLineIdx < 0 {
		return ""
	}

	startIdx := classLineIdx - 10
	if startIdx < 0 {
		startIdx = 0
	}

	for i := startIdx; i <= classLineIdx; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if m := classMappingRe.FindStringSubmatch(trimmed); len(m) > 1 {
			prefix := m[1]
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}
			return prefix
		}
	}
	return ""
}

// findClassDeclaration returns the line index of the class declaration, or -1.
func findClassDeclaration(lines []string) int {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "class ") &&
			(strings.Contains(trimmed, "{") ||
				strings.Contains(trimmed, "extends") ||
				strings.Contains(trimmed, "implements")) {
			return i
		}
	}
	return -1
}

// buildFullPath combines a class-level prefix with a method-level path.
func buildFullPath(classPrefix, methodPath string) string {
	if !strings.HasPrefix(methodPath, "/") {
		methodPath = "/" + methodPath
	}
	if classPrefix == "" {
		return methodPath
	}
	return strings.TrimRight(classPrefix, "/") + methodPath
}

// annotationToHTTPMethod converts a Spring annotation type to an HTTP method.
func annotationToHTTPMethod(annotationType string) string {
	switch annotationType {
	case "Get":
		return "GET"
	case "Post":
		return "POST"
	case "Put":
		return "PUT"
	case "Delete":
		return "DELETE"
	case "Patch":
		return "PATCH"
	default:
		return "ANY"
	}
}

// isControllerFile checks if Java source content contains controller annotations.
func isControllerFile(content string) bool {
	return controllerAnnotationRe.MatchString(content)
}

// isXMLMapperEvidence checks if the evidence chain originates from MyBatis XML mappers.
func isXMLMapperEvidence(evidence []EvidenceRef) bool {
	for _, e := range evidence {
		if !strings.HasSuffix(e.File, ".xml") {
			continue
		}
		if strings.Contains(e.File, "mapper") ||
			strings.Contains(e.Code, "${") ||
			strings.Contains(e.Code, "<select") {
			return true
		}
	}
	return false
}

// extractMapperMethodFromEvidence extracts the MyBatis mapper method name
// from XML evidence (e.g., <select id="findByUserNameVuln02">).
func extractMapperMethodFromEvidence(evidence []EvidenceRef) string {
	for _, e := range evidence {
		if !strings.HasSuffix(e.File, ".xml") {
			continue
		}
		if m := xmlSelectIDRe.FindStringSubmatch(e.Code); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// extractParamFromEvidence extracts the injectable parameter name from evidence code.
// It checks @RequestParam annotations and request.getParameter() calls.
func extractParamFromEvidence(evidence []EvidenceRef) string {
	// Priority pass: check SOURCE-role evidence first
	for _, e := range evidence {
		if e.Role == "SOURCE" || e.Role == "source" {
			if p := findParamInCode(e.Code); p != "" {
				return p
			}
		}
	}
	// Fallback: check all evidence entries
	for _, e := range evidence {
		if p := findParamInCode(e.Code); p != "" {
			return p
		}
	}
	return ""
}

func findParamInCode(code string) string {
	if m := requestParamAnnotRe.FindStringSubmatch(code); len(m) > 1 {
		return m[1]
	}
	if m := getParameterRe.FindStringSubmatch(code); len(m) > 1 {
		return m[1]
	}
	return ""
}
