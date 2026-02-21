package fuzzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EndpointInfo represents a discovered HTTP endpoint from source code.
type EndpointInfo struct {
	Method     string   // HTTP method (GET/POST/PUT/DELETE/PATCH/ANY)
	FullPath   string   // Full path including class prefix (e.g. "/sqli/jdbc/vuln")
	Params     []string // Parameter names from @RequestParam
	File       string   // Source file path (relative to source root)
	ClassName  string   // Java class name
	MethodName string   // Java method name
}

// EndpointRegistry holds all discovered endpoints from a project.
type EndpointRegistry struct {
	endpoints    []*EndpointInfo
	byFile       map[string][]*EndpointInfo
	byMethodName map[string][]*EndpointInfo
}

// NewEndpointRegistry creates an empty registry.
func NewEndpointRegistry() *EndpointRegistry {
	return &EndpointRegistry{
		byFile:       make(map[string][]*EndpointInfo),
		byMethodName: make(map[string][]*EndpointInfo),
	}
}

// ScanProject walks the source root and discovers all Spring controller endpoints.
func ScanProject(sourceRoot string) *EndpointRegistry {
	reg := NewEndpointRegistry()
	if sourceRoot == "" {
		return reg
	}

	filepath.Walk(sourceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		if strings.Contains(path, "/test/") || strings.Contains(path, "/tests/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if !isControllerFile(content) {
			return nil
		}

		relPath, _ := filepath.Rel(sourceRoot, path)
		for _, ep := range parseControllerFile(content, relPath) {
			reg.add(ep)
		}
		return nil
	})

	fmt.Printf("  📋 端点注册表: 扫描到 %d 个 HTTP 端点\n", len(reg.endpoints))
	return reg
}

func (r *EndpointRegistry) add(ep *EndpointInfo) {
	r.endpoints = append(r.endpoints, ep)
	r.byFile[ep.File] = append(r.byFile[ep.File], ep)
	if ep.MethodName != "" {
		r.byMethodName[ep.MethodName] = append(r.byMethodName[ep.MethodName], ep)
	}
}

// AllEndpoints returns all discovered endpoints.
func (r *EndpointRegistry) AllEndpoints() []*EndpointInfo {
	return r.endpoints
}

// FindByFile returns endpoints defined in the given source file.
func (r *EndpointRegistry) FindByFile(filePath string) []*EndpointInfo {
	if eps, ok := r.byFile[filePath]; ok {
		return eps
	}
	// Suffix match: evidence may have full paths, registry has relative paths
	for f, eps := range r.byFile {
		if strings.HasSuffix(filePath, f) || strings.HasSuffix(f, filePath) {
			return eps
		}
	}
	return nil
}

// ResolveForEvidence finds the best endpoint match for the given evidence chain.
//
// Resolution strategies:
//  1. Direct file match — evidence file is a controller
//  2. MyBatis mapper method → controller tracing
//  3. Class name match from evidence file names
func (r *EndpointRegistry) ResolveForEvidence(evidence []EvidenceRef, sourceRoot string) *EndpointInfo {
	// Strategy 1: Direct file match
	for _, e := range evidence {
		eps := r.FindByFile(e.File)
		if len(eps) == 0 {
			continue
		}
		// Prefer endpoint whose method name appears in the evidence code
		for _, ep := range eps {
			if ep.MethodName != "" && strings.Contains(e.Code, ep.MethodName) {
				return ep
			}
		}
		return eps[0]
	}

	// Strategy 2: MyBatis mapper method → controller tracing
	if mapperMethod := extractMapperMethodFromEvidence(evidence); mapperMethod != "" && sourceRoot != "" {
		if ep := r.findControllerForMapper(mapperMethod, sourceRoot); ep != nil {
			return ep
		}
	}

	// Strategy 3: Match evidence file's class name to controller file names
	for _, e := range evidence {
		if !strings.HasSuffix(e.File, ".java") {
			continue
		}
		className := strings.TrimSuffix(filepath.Base(e.File), ".java")
		for _, ep := range r.endpoints {
			if strings.Contains(ep.File, className) {
				return ep
			}
		}
	}

	return nil
}

// findControllerForMapper searches controller files for calls to the given mapper method
// and returns the specific endpoint method containing that call.
func (r *EndpointRegistry) findControllerForMapper(mapperMethod string, sourceRoot string) *EndpointInfo {
	callPattern := mapperMethod + "("

	// Deduplicate files to avoid reading the same file multiple times
	seen := make(map[string]bool)
	for _, ep := range r.endpoints {
		if seen[ep.File] {
			continue
		}
		seen[ep.File] = true

		fullPath := filepath.Join(sourceRoot, ep.File)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, callPattern) {
			continue
		}

		// Narrow down to the specific endpoint method
		return r.narrowToMethod(content, ep.File, mapperMethod)
	}
	return nil
}

// narrowToMethod finds which endpoint method in a file contains the given call.
func (r *EndpointRegistry) narrowToMethod(content, file, callName string) *EndpointInfo {
	eps := r.byFile[file]
	if len(eps) <= 1 {
		if len(eps) == 1 {
			return eps[0]
		}
		return nil
	}

	lines := strings.Split(content, "\n")
	callLineIdx := -1
	for i, line := range lines {
		if strings.Contains(line, callName+"(") {
			callLineIdx = i
			break
		}
	}
	if callLineIdx < 0 {
		return eps[0]
	}

	// Walk backward to find the enclosing mapping annotation
	for i := callLineIdx; i >= 0; i-- {
		if m := methodMappingRe.FindStringSubmatch(strings.TrimSpace(lines[i])); len(m) > 1 {
			path := m[1]
			for _, ep := range eps {
				if strings.HasSuffix(ep.FullPath, path) {
					return ep
				}
			}
		}
	}
	return eps[0]
}

// --- Controller file parsing ---

// parseControllerFile extracts all endpoint definitions from a Java controller.
func parseControllerFile(content string, relPath string) []*EndpointInfo {
	lines := strings.Split(content, "\n")
	var endpoints []*EndpointInfo

	className := ""
	if m := classDeclRe.FindStringSubmatch(content); len(m) > 1 {
		className = m[1]
	}

	classPrefix := extractClassPrefix(lines)

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		matches := mappingAnnotationRe.FindStringSubmatch(trimmed)
		if matches == nil {
			continue
		}

		httpMethod := annotationToHTTPMethod(matches[1])
		fullPath := buildFullPath(classPrefix, matches[2])

		// Scan forward for method declaration and @RequestParam
		var params []string
		var methodName string
		for j := i; j < len(lines) && j < i+10; j++ {
			line := strings.TrimSpace(lines[j])
			for _, pm := range requestParamAnnotRe.FindAllStringSubmatch(line, -1) {
				if len(pm) > 1 {
					params = append(params, pm[1])
				}
			}
			if mm := javaMethodDeclRe.FindStringSubmatch(line); len(mm) > 1 && methodName == "" {
				methodName = mm[1]
			}
		}

		endpoints = append(endpoints, &EndpointInfo{
			Method:     httpMethod,
			FullPath:   fullPath,
			Params:     params,
			File:       relPath,
			ClassName:  className,
			MethodName: methodName,
		})
	}

	return endpoints
}
