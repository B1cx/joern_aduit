package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joern-audit/joern_audit/internal/llm"
)

// ConversationLogger records all LLM interactions for debugging and audit.
type ConversationLogger struct {
	outputDir   string
	sessionID   string
	conversationCount int
}

// ConversationRecord is a single LLM API call record.
type ConversationRecord struct {
	Timestamp    time.Time       `json:"timestamp"`
	Agent        string          `json:"agent"` // prosecutor, defender, judge
	CandidateID  string          `json:"candidate_id"`
	RuleID       string          `json:"rule_id"`
	Location     string          `json:"location"`
	Request      llm.ChatRequest `json:"request"`
	Response     interface{}     `json:"response"`
	InputTokens  int             `json:"input_tokens"`
	OutputTokens int             `json:"output_tokens"`
	Error        string          `json:"error,omitempty"`
}

// NewConversationLogger creates a logger for LLM conversations.
func NewConversationLogger(outputDir, sessionID string) *ConversationLogger {
	return &ConversationLogger{
		outputDir: outputDir,
		sessionID: sessionID,
	}
}

// Log records a single conversation to both JSON and Markdown files.
func (cl *ConversationLogger) Log(agent string, candidateID, ruleID, location string, req llm.ChatRequest, resp interface{}, inputTokens, outputTokens int, err error) error {
	cl.conversationCount++

	record := ConversationRecord{
		Timestamp:    time.Now(),
		Agent:        agent,
		CandidateID:  candidateID,
		RuleID:       ruleID,
		Location:     location,
		Request:      req,
		Response:     resp,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}

	if err != nil {
		record.Error = err.Error()
	}

	// Ensure output directory exists
	convDir := filepath.Join(cl.outputDir, "conversations")
	if err := os.MkdirAll(convDir, 0755); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}

	// Save JSON format (machine-readable)
	jsonPath := filepath.Join(convDir, fmt.Sprintf("%03d_%s_%s.json", cl.conversationCount, agent, candidateID))
	if err := cl.saveJSON(jsonPath, record); err != nil {
		return err
	}

	// Save Markdown format (human-readable)
	mdPath := filepath.Join(convDir, fmt.Sprintf("%03d_%s_%s.md", cl.conversationCount, agent, candidateID))
	if err := cl.saveMarkdown(mdPath, record); err != nil {
		return err
	}

	return nil
}

// saveJSON saves the conversation record as JSON.
func (cl *ConversationLogger) saveJSON(path string, record ConversationRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// saveMarkdown saves the conversation in human-readable Markdown format.
func (cl *ConversationLogger) saveMarkdown(path string, record ConversationRecord) error {
	var md string

	md += fmt.Sprintf("# LLM对话记录 - %s\n\n", record.Agent)
	md += fmt.Sprintf("- **时间**: %s\n", record.Timestamp.Format("2006-01-02 15:04:05"))
	md += fmt.Sprintf("- **角色**: %s\n", agentNameChinese(record.Agent))
	md += fmt.Sprintf("- **候选ID**: %s\n", record.CandidateID)
	md += fmt.Sprintf("- **规则ID**: %s\n", record.RuleID)
	md += fmt.Sprintf("- **位置**: %s\n", record.Location)
	md += fmt.Sprintf("- **Token消耗**: 输入 %d + 输出 %d = %d\n\n", record.InputTokens, record.OutputTokens, record.InputTokens+record.OutputTokens)

	// System Prompt
	md += "## 系统提示词 (System Prompt)\n\n"
	md += "```\n"
	md += record.Request.SystemPrompt
	md += "\n```\n\n"

	// User Messages
	md += "## 用户消息 (User Messages)\n\n"
	for i, msg := range record.Request.Messages {
		md += fmt.Sprintf("### 消息 %d - %s\n\n", i+1, msg.Role)
		md += "```\n"
		md += msg.Content
		md += "\n```\n\n"
	}

	// Response
	md += "## LLM响应 (Response)\n\n"
	if record.Error != "" {
		md += fmt.Sprintf("**错误**: %s\n\n", record.Error)
	} else {
		respJSON, _ := json.MarshalIndent(record.Response, "", "  ")
		md += "```json\n"
		md += string(respJSON)
		md += "\n```\n\n"
	}

	return os.WriteFile(path, []byte(md), 0644)
}

// agentNameChinese returns Chinese name for agent roles.
func agentNameChinese(agent string) string {
	switch agent {
	case "prosecutor":
		return "控方/红队 (Prosecutor)"
	case "defender":
		return "辩方/蓝队 (Defender)"
	case "judge":
		return "审判官 (Judge)"
	default:
		return agent
	}
}
