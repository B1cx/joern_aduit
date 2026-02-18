package llm

import (
	"bytes"
	"context"
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

// OpenAIProvider implements Provider for OpenAI-compatible APIs.
// Works with OpenAI, DeepSeek, vLLM, and other compatible endpoints.
type OpenAIProvider struct {
	cfg         *config.LLMConfig
	client      *http.Client
	rateLimiter *RateLimiter
	retryConfig RetryConfig
}

func NewOpenAIProvider(cfg *config.LLMConfig) *OpenAIProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	cfgCopy := *cfg
	cfgCopy.BaseURL = baseURL

	// Create HTTP transport with proxy support
	transport := &http.Transport{}

	// Configure proxy from environment variables
	if proxyURL := getOpenAIProxyURL(); proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
		fmt.Printf("  🌐 使用代理: %s\n", proxyURL.String())
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second, // 2 minutes timeout
	}

	// Create rate limiter with configurable RPM (default: 60 for OpenAI)
	rpm := cfg.RateLimitRPM
	if rpm <= 0 {
		rpm = 60 // Conservative default for OpenAI API
	}
	rateLimiter := NewRateLimiter(rpm, time.Minute)

	// Create retry config with configurable max retries
	retryConfig := DefaultRetryConfig()
	if cfg.MaxRetries > 0 {
		retryConfig.MaxRetries = cfg.MaxRetries
	}

	return &OpenAIProvider{
		cfg:         &cfgCopy,
		client:      client,
		rateLimiter: rateLimiter,
		retryConfig: retryConfig,
	}
}

// getOpenAIProxyURL reads proxy configuration from environment variables
func getOpenAIProxyURL() *url.URL {
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

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
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

// doChat performs the actual HTTP request to OpenAI API
func (p *OpenAIProvider) doChat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	msgs := make([]map[string]string, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": req.SystemPrompt})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body := map[string]interface{}{
		"model":       p.cfg.Model,
		"messages":    msgs,
		"max_tokens":  req.MaxTokens,
		"temperature": req.Temperature,
	}
	if req.JSONMode {
		body["response_format"] = map[string]string{"type": "json_object"}
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.cfg.BaseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)

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
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &ChatResponse{
		Content:      result.Choices[0].Message.Content,
		InputTokens:  result.Usage.PromptTokens,
		OutputTokens: result.Usage.CompletionTokens,
		Model:        p.cfg.Model,
	}, nil
}

func (p *OpenAIProvider) ChatJSON(ctx context.Context, req ChatRequest, target interface{}) error {
	req.JSONMode = true
	resp, err := p.Chat(ctx, req)
	if err != nil {
		return err
	}

	content := strings.TrimSpace(resp.Content)

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
