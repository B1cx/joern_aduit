package report

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ChineseMarkdownGenerator produces Chinese Markdown reports.
type ChineseMarkdownGenerator struct{}

func (g *ChineseMarkdownGenerator) Format() string { return "markdown-zh" }

func (g *ChineseMarkdownGenerator) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	var b strings.Builder

	// Header
	b.WriteString("# 🛡️ 安全审计报告\n\n")
	b.WriteString(fmt.Sprintf("**生成时间**: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**会话ID**: %s\n", data.SessionID))
	b.WriteString(fmt.Sprintf("**审计目标**: %s\n", data.Target))
	b.WriteString(fmt.Sprintf("**扫描模式**: %s\n", data.ScanMode))
	b.WriteString(fmt.Sprintf("**语言**: %s\n", strings.Join(data.Languages, ", ")))
	if data.TechStack != "" {
		b.WriteString(fmt.Sprintf("**技术栈**: %s\n", data.TechStack))
	}
	b.WriteString("\n---\n\n")

	// Summary
	b.WriteString("## 📊 审计结果概览\n\n")
	b.WriteString("| 指标 | 数量 |\n")
	b.WriteString("|------|------|\n")
	b.WriteString(fmt.Sprintf("| 候选漏洞总数 | %d |\n", data.Summary.TotalCandidates))
	b.WriteString(fmt.Sprintf("| ✅ 真实漏洞 (True Positive) | %d |\n", data.Summary.TruePositives))
	b.WriteString(fmt.Sprintf("| ❌ 误报 (False Positive) | %d |\n", data.Summary.FalsePositives))
	b.WriteString(fmt.Sprintf("| 🔬 需深入分析 | %d |\n", data.Summary.NeedDeeper))
	if data.Summary.FuzzConfirmed > 0 {
		b.WriteString(fmt.Sprintf("| 🎯 Fuzz验证确认 | %d |\n", data.Summary.FuzzConfirmed))
	}
	b.WriteString("\n")

	// Severity Distribution
	b.WriteString("### 严重性分布\n\n")
	b.WriteString("| 级别 | 数量 |\n")
	b.WriteString("|------|------|\n")
	if data.Summary.Critical > 0 {
		b.WriteString(fmt.Sprintf("| 🔴 严重 (Critical) | %d |\n", data.Summary.Critical))
	}
	if data.Summary.High > 0 {
		b.WriteString(fmt.Sprintf("| 🟠 高危 (High) | %d |\n", data.Summary.High))
	}
	if data.Summary.Medium > 0 {
		b.WriteString(fmt.Sprintf("| 🟡 中危 (Medium) | %d |\n", data.Summary.Medium))
	}
	if data.Summary.Low > 0 {
		b.WriteString(fmt.Sprintf("| 🟢 低危 (Low) | %d |\n", data.Summary.Low))
	}
	if data.Summary.Info > 0 {
		b.WriteString(fmt.Sprintf("| ℹ️ 信息 (Info) | %d |\n", data.Summary.Info))
	}
	b.WriteString("\n")

	// Findings
	if len(data.Findings) > 0 {
		b.WriteString("## 🔍 漏洞详情\n\n")
		for i, f := range data.Findings {
			// Finding Header
			severityIcon := map[string]string{
				"CRITICAL": "🔴",
				"HIGH":     "🟠",
				"MEDIUM":   "🟡",
				"LOW":      "🟢",
				"INFO":     "ℹ️",
			}[f.FinalSeverity]

			b.WriteString(fmt.Sprintf("### %d. %s [%s] %s\n\n",
				i+1, severityIcon, f.FinalSeverity, f.CWE))

			b.WriteString(fmt.Sprintf("- **位置**: `%s:%d`\n", f.FilePath, f.LineNumber))
			b.WriteString(fmt.Sprintf("- **规则**: %s\n", f.RuleID))
			if f.InitialSeverity != f.FinalSeverity {
				b.WriteString(fmt.Sprintf("- **严重性**: %s → %s (LLM调整)\n", f.InitialSeverity, f.FinalSeverity))
			} else {
				b.WriteString(fmt.Sprintf("- **严重性**: %s\n", f.FinalSeverity))
			}
			b.WriteString("\n")

			// LLM Verification
			if f.LLMVerify != nil && f.LLMVerify.Judge != nil {
				j := f.LLMVerify.Judge
				b.WriteString("#### 🤖 LLM验证结果\n\n")

				verdictCN := map[string]string{
					"TRUE_POSITIVE":              "✅ 真实漏洞",
					"FALSE_POSITIVE":             "❌ 误报",
					"NEEDS_DEEPER":               "🔬 需深入分析",
					"EXPLOITABLE_WITH_CONDITION": "⚠️ 条件可利用",
				}[string(j.Verdict)]

				b.WriteString(fmt.Sprintf("**裁决**: %s (置信度: %.2f)\n\n", verdictCN, j.Confidence))
				b.WriteString(fmt.Sprintf("**推理过程**:\n> %s\n\n", j.Reasoning))

				if j.AttackVector != "" {
					b.WriteString(fmt.Sprintf("**攻击向量**:\n```\n%s\n```\n\n", j.AttackVector))
				}

				if len(j.Conditions) > 0 {
					b.WriteString("**前置条件**:\n")
					for _, cond := range j.Conditions {
						b.WriteString(fmt.Sprintf("- %s\n", cond))
					}
					b.WriteString("\n")
				}

				if len(j.EvidenceChain) > 0 {
					b.WriteString("**证据链**:\n\n```\n")
					for _, e := range j.EvidenceChain {
						roleMap := map[string]string{
							"SOURCE":      "源点",
							"PROPAGATION": "传播",
							"SINK":        "汇点",
							"SANITIZER":   "净化",
						}
						roleCN := roleMap[e.Role]
						if roleCN == "" {
							roleCN = e.Role
						}
						b.WriteString(fmt.Sprintf("[步骤%d - %s] %s:%d\n", e.Step, roleCN, e.File, e.Line))
						if e.Code != "" {
							b.WriteString(fmt.Sprintf("  代码: %s\n", e.Code))
						}
					}
					b.WriteString("```\n\n")
				}

				if f.LLMVerify.TotalTokens > 0 {
					b.WriteString(fmt.Sprintf("*Token消耗: %d*\n\n", f.LLMVerify.TotalTokens))
				}
			}

			// Fuzz Verification
			if f.FuzzVerify != nil {
				b.WriteString("#### 🎯 Fuzz验证结果\n\n")
				b.WriteString(fmt.Sprintf("- **工具**: %s\n", f.FuzzVerify.Tool))
				b.WriteString(fmt.Sprintf("- **结果**: %s\n", f.FuzzVerify.Result))
				if f.FuzzVerify.PoC != "" {
					b.WriteString(fmt.Sprintf("- **PoC**:\n```\n%s\n```\n", f.FuzzVerify.PoC))
				}
				if f.FuzzVerify.Evidence != "" {
					b.WriteString(fmt.Sprintf("- **证据**: %s\n", f.FuzzVerify.Evidence))
				}
				b.WriteString("\n")
			}

			b.WriteString("---\n\n")
		}
	}

	// Attack Chains
	if len(data.AttackChains) > 0 {
		b.WriteString("## 🔗 攻击链分析\n\n")
		b.WriteString("以下漏洞可组合形成端到端攻击路径：\n\n")
		for i, chain := range data.AttackChains {
			b.WriteString(fmt.Sprintf("### 攻击链 %d: %s\n\n", i+1, chain.Name))
			b.WriteString(fmt.Sprintf("**CVSS得分**: %.1f\n\n", chain.CVSS))
			b.WriteString("**攻击步骤**:\n")
			for j, step := range chain.Steps {
				b.WriteString(fmt.Sprintf("%d. %s\n", j+1, step))
			}
			b.WriteString("\n")
			if len(chain.FindingIDs) > 0 {
				b.WriteString(fmt.Sprintf("**关联漏洞**: %s\n", strings.Join(chain.FindingIDs, ", ")))
			}
			b.WriteString("\n")
		}
	}

	// Footer
	b.WriteString("---\n\n")
	b.WriteString("*报告由 DeepAudit 自动生成*  \n")
	b.WriteString("*基于 Joern CPG + LLM Multi-Agent 验证*\n")

	return []byte(b.String()), nil
}
