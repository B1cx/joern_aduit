package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

type Config struct {
	Joern   JoernConfig   `yaml:"joern"`
	LLM     LLMConfig     `yaml:"llm"`
	Scan    ScanConfig    `yaml:"scan"`
	DB      DBConfig      `yaml:"db"`
	Report  ReportConfig  `yaml:"report"`
	Fuzzer  FuzzerConfig  `yaml:"fuzzer"`
	Logging LoggingConfig `yaml:"logging"`
}

type JoernConfig struct {
	BinaryPath string `yaml:"binary_path"`
	ParsePath  string `yaml:"parse_path"`
	ScanPath   string `yaml:"scan_path"`
	ExportPath string `yaml:"export_path"`
	SlicePath  string `yaml:"slice_path"`
	FlowPath   string `yaml:"flow_path"`
	ServerMode bool   `yaml:"server_mode"`
	ServerHost string `yaml:"server_host"`
	ServerPort int    `yaml:"server_port"`
	CPGDir     string `yaml:"cpg_dir"`
	Timeout    int    `yaml:"timeout"` // seconds
}

type LLMConfig struct {
	Provider         string            `yaml:"provider"`    // claude, openai, ollama, deepseek
	Model            string            `yaml:"model"`
	APIKey           string            `yaml:"api_key"`
	BaseURL          string            `yaml:"base_url"`
	MaxTokens        int               `yaml:"max_tokens"`
	Temperature      float64           `yaml:"temperature"`
	TokenBudget      TokenBudgetConfig `yaml:"token_budget"`
	ParallelAgents   bool              `yaml:"parallel_agents"`    // Enable parallel Prosecutor+Defender within single candidate
	RateLimitRPM     int               `yaml:"rate_limit_rpm"`     // Requests per minute (0 = use default)
	MaxRetries       int               `yaml:"max_retries"`        // Max retry attempts (0 = use default)
	MaxConcurrent    int               `yaml:"max_concurrent"`     // Max concurrent candidate verifications (0 = sequential, default=3)
}

type TokenBudgetConfig struct {
	PerCandidate   int `yaml:"per_candidate"`
	PerExplorer    int `yaml:"per_explorer"`
	MaxContextRounds int `yaml:"max_context_rounds"`
}

type ScanConfig struct {
	Mode       string   `yaml:"mode"`       // quick, standard, deep, joern-only
	Languages  []string `yaml:"languages"`
	RulesDir   string   `yaml:"rules_dir"`
	PromptsDir string   `yaml:"prompts_dir"`
	MaxRounds  int      `yaml:"max_rounds"`
	Excludes   []string `yaml:"excludes"`
	DiffRef    string   `yaml:"diff_ref"`   // git ref for incremental scan (e.g. HEAD~1, main)
}

type DBConfig struct {
	Path string `yaml:"path"`
}

type ReportConfig struct {
	OutputDir string   `yaml:"output_dir"`
	Formats   []string `yaml:"formats"` // markdown, json, sarif, html
}

type FuzzerConfig struct {
	Enabled        bool              `yaml:"enabled"`
	Sandbox        string            `yaml:"sandbox"` // docker, none
	Timeout        int               `yaml:"timeout"` // per-tool timeout in seconds
	TargetURL      string            `yaml:"target_url"`
	Cookie         string            `yaml:"cookie"`          // auth cookie string for authenticated testing
	Headers        map[string]string `yaml:"headers"`         // extra HTTP headers
	SqlmapPath     string            `yaml:"sqlmap_path"`
	YsoserialPath  string            `yaml:"ysoserial_path"`
	MarshalsecPath string            `yaml:"marshalsec_path"`
	CallbackAddr   string            `yaml:"callback_addr"`   // OOB callback address, empty = skip OOB checks
}

type LoggingConfig struct {
	Level  string `yaml:"level"` // debug, info, warn, error
	File   string `yaml:"file"`
	Pretty bool   `yaml:"pretty"`
}

func DefaultConfig() *Config {
	return &Config{
		Joern: JoernConfig{
			BinaryPath: "joern",
			ParsePath:  "joern-parse",
			ScanPath:   "joern-scan",
			ExportPath: "joern-export",
			SlicePath:  "joern-slice",
			FlowPath:   "joern-flow",
			ServerMode: false,
			ServerHost: "127.0.0.1",
			ServerPort: 8080,
			CPGDir:     ".joern_audit/cpg",
			Timeout:    600,
		},
		LLM: LLMConfig{
			Provider:    "openai",
			Model:       "gpt-4o",
			MaxTokens:   4096,
			Temperature: 0.1,
			TokenBudget: TokenBudgetConfig{
				PerCandidate:     8000,
				PerExplorer:      12000,
				MaxContextRounds: 3,
			},
			ParallelAgents: false, // Disable parallel agents by default to avoid rate limits
			RateLimitRPM:   0,     // 0 = use provider default (50 for Claude, 60 for OpenAI)
			MaxRetries:     3,     // Retry up to 3 times on rate limit errors
		},
		Scan: ScanConfig{
			Mode:       "standard",
			RulesDir:   "rules",
			PromptsDir: "prompts",
			MaxRounds:  2,
			Excludes: []string{
				"node_modules", ".git", "build", "dist",
				"target", "vendor", "test", "tests",
				"__pycache__", ".idea", ".vscode",
			},
		},
		DB: DBConfig{
			Path: ".joern_audit/audit.db",
		},
		Report: ReportConfig{
			OutputDir: ".joern_audit/reports",
			Formats:   []string{"markdown", "json"},
		},
		Fuzzer: FuzzerConfig{
			Enabled: false,
			Sandbox: "docker",
			Timeout: 300,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Pretty: true,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		home, _ := os.UserHomeDir()
		candidates := []string{
			"joern_audit.yaml",
			".joern_audit.yaml",
			filepath.Join(home, ".config", "joern_audit", "config.yaml"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}
