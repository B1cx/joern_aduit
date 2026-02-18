package llm

import "context"

// Provider is the interface for LLM API backends.
type Provider interface {
	// Name returns the provider identifier (e.g. "claude", "openai").
	Name() string

	// Chat sends a prompt and returns the LLM response.
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)

	// ChatJSON sends a prompt expecting a JSON response, with retries on parse failure.
	ChatJSON(ctx context.Context, req ChatRequest, target interface{}) error
}

// ChatRequest is a single LLM API call request.
type ChatRequest struct {
	SystemPrompt string        `json:"system_prompt"`
	Messages     []Message     `json:"messages"`
	MaxTokens    int           `json:"max_tokens"`
	Temperature  float64       `json:"temperature"`
	JSONMode     bool          `json:"json_mode"`
}

// Message is a single message in a conversation.
type Message struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

// ChatResponse is the LLM API response.
type ChatResponse struct {
	Content      string `json:"content"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	Model        string `json:"model"`
}

// TokenCounter estimates token count for a given text.
type TokenCounter interface {
	Count(text string) int
}

// SimpleTokenCounter uses a rough char/4 estimation.
type SimpleTokenCounter struct{}

func (s *SimpleTokenCounter) Count(text string) int {
	return len([]rune(text)) / 4
}
