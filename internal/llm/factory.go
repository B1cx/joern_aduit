package llm

import (
	"fmt"

	"github.com/joern-audit/joern_audit/internal/config"
)

// NewProvider creates an LLM Provider based on the config.
func NewProvider(cfg *config.LLMConfig) (Provider, error) {
	switch cfg.Provider {
	case "openai", "deepseek", "ollama":
		return NewOpenAIProvider(cfg), nil
	case "claude":
		return NewClaudeProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
}
