package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joern-audit/joern_audit/internal/config"
)

// ClaudeProvider implements Provider for the Anthropic Claude API.
type ClaudeProvider struct {
	cfg         *config.LLMConfig
	client      *http.Client
	rateLimiter *RateLimiter
	retryConfig RetryConfig
}

func NewClaudeProvider(cfg *config.LLMConfig) *ClaudeProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	cfgCopy := *cfg
	cfgCopy.BaseURL = baseURL

	// Create HTTP transport with TLS and proxy support
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certificates
		},
	}

	// Configure proxy from environment variables
	if proxyURL := getProxyURL(); proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
		fmt.Printf("  🌐 使用代理: %s\n", proxyURL.String())
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second, // 2 minutes timeout
	}

	// Create rate limiter with configurable RPM (default: 50 for Claude)
	rpm := cfg.RateLimitRPM
	if rpm <= 0 {
		rpm = 50 // Conservative default for Claude API
	}
	rateLimiter := NewRateLimiter(rpm, time.Minute)

	// Create retry config with configurable max retries
	retryConfig := DefaultRetryConfig()
	if cfg.MaxRetries > 0 {
		retryConfig.MaxRetries = cfg.MaxRetries
	}

	return &ClaudeProvider{
		cfg:         &cfgCopy,
		client:      client,
		rateLimiter: rateLimiter,
		retryConfig: retryConfig,
	}
}

// getProxyURL reads proxy configuration from environment variables
func getProxyURL() *url.URL {
	// Try different proxy environment variables in order
	proxyVars := []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"}

	for _, envVar := range proxyVars {
		if proxyStr := os.Getenv(envVar); proxyStr != "" {
			proxyURL, err := url.Parse(proxyStr)
			if err == nil {
				return proxyURL
			}
		}
	}

	return nil
}

func (p *ClaudeProvider) Name() string { return "claude" }

func (p *ClaudeProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	var response *ChatResponse

	// Use rate limiter and retry with backoff
	err := RetryWithBackoff(ctx, p.retryConfig, func() error {
		// Wait for rate limiter
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return err
		}

		// Perform the actual API call
		resp, err := p.doChat(ctx, req)
		if err != nil {
			return err
		}
		response = resp
		return nil
	})

	return response, err
}

// doChat performs the actual HTTP request to Claude API
func (p *ClaudeProvider) doChat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	msgs := make([]map[string]string, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body := map[string]interface{}{
		"model":      p.cfg.Model,
		"max_tokens": req.MaxTokens,
		"messages":   msgs,
	}
	if req.SystemPrompt != "" {
		body["system"] = req.SystemPrompt
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.cfg.BaseURL+"/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}

	return &ChatResponse{
		Content:      result.Content[0].Text,
		InputTokens:  result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens,
		Model:        p.cfg.Model,
	}, nil
}

func (p *ClaudeProvider) ChatJSON(ctx context.Context, req ChatRequest, target interface{}) error {
	req.SystemPrompt += "\n\nYou MUST respond with valid JSON only. No markdown, no explanation, no code blocks."
	resp, err := p.Chat(ctx, req)
	if err != nil {
		return err
	}

	// Extract JSON from response (handle markdown code blocks)
	content := resp.Content

	// Remove markdown code blocks if present
	if strings.Contains(content, "```json") {
		// Extract content between ```json and ```
		start := strings.Index(content, "```json")
		if start >= 0 {
			content = content[start+7:]
			end := strings.Index(content, "```")
			if end >= 0 {
				content = content[:end]
			}
		}
	} else if strings.Contains(content, "```") {
		// Extract content between ``` and ```
		start := strings.Index(content, "```")
		if start >= 0 {
			content = content[start+3:]
			end := strings.Index(content, "```")
			if end >= 0 {
				content = content[:end]
			}
		}
	}

	content = strings.TrimSpace(content)

	// Validate content is JSON-like before attempting to parse
	if len(content) == 0 {
		return fmt.Errorf("empty response from LLM")
	}

	// Check for HTML error pages
	if strings.HasPrefix(content, "<") || strings.HasPrefix(content, "<!DOCTYPE") {
		return fmt.Errorf("received HTML instead of JSON (likely an error page). Response preview: %s",
			truncate(content, 200))
	}

	// Check if content looks like JSON
	if !strings.HasPrefix(content, "{") && !strings.HasPrefix(content, "[") {
		return fmt.Errorf("response is not valid JSON (does not start with { or [). Response preview: %s",
			truncate(content, 200))
	}

	// Sanitize JSON to remove problematic Unicode characters before parsing
	content = sanitizeJSON(content)

	// Try to parse JSON
	if err := json.Unmarshal([]byte(content), target); err != nil {
		return fmt.Errorf("parse response: %w. Response preview: %s", err, truncate(content, 200))
	}

	return nil
}
