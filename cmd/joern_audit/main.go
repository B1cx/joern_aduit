package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joern-audit/joern_audit/internal/config"
	"github.com/joern-audit/joern_audit/internal/db"
	"github.com/joern-audit/joern_audit/internal/evidence"
	"github.com/joern-audit/joern_audit/internal/fuzzer"
	"github.com/joern-audit/joern_audit/internal/orchestrator"
	"github.com/joern-audit/joern_audit/internal/report"
	"github.com/spf13/cobra"
)

var cfgPath string

func main() {
	root := &cobra.Command{
		Use:     "joern_audit",
		Short:   "DeepAudit — Joern CPG + LLM 混合 SAST 引擎",
		Version: config.Version + " (built " + config.BuildTime + ")",
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "", "配置文件路径")

	root.AddCommand(scanCmd(), fuzzCmd(), statusCmd(), reportCmd(), verifyCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() *config.Config {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// ── scan ──

func scanCmd() *cobra.Command {
	var lang, mode, diffRef string
	var maxConcurrent int

	cmd := &cobra.Command{
		Use:   "scan <target-dir>",
		Short: "对目标项目执行完整安全审计",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()

			if lang != "" {
				cfg.Scan.Languages = strings.Split(lang, ",")
			}
			if mode != "" {
				cfg.Scan.Mode = mode
			}
			if diffRef != "" {
				cfg.Scan.DiffRef = diffRef
			}
			if maxConcurrent > 0 {
				cfg.LLM.MaxConcurrent = maxConcurrent
			}

			engine := orchestrator.NewEngine(cfg)
			ctx := context.Background()
			if err := engine.Run(ctx, args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "审计失败: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&lang, "lang", "", "目标语言 (java, php)")
	cmd.Flags().StringVar(&mode, "mode", "", "扫描模式 (quick, standard, deep, joern-only)")
	cmd.Flags().StringVar(&diffRef, "diff", "", "增量扫描 git ref (如 HEAD~1, main)")
	cmd.Flags().IntVar(&maxConcurrent, "concurrent", 0, "最大并发验证数")

	return cmd
}

// ── fuzz ──

func fuzzCmd() *cobra.Command {
	var reportPath, targetURL, sourceDir, cookie string
	var listEndpoints bool

	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "独立 Fuzz 验证（基于已有报告）",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()

			if targetURL != "" {
				cfg.Fuzzer.TargetURL = targetURL
			}
			if cookie != "" {
				cfg.Fuzzer.Cookie = cookie
			}

			mgr := fuzzer.NewManager(&cfg.Fuzzer)

			if sourceDir != "" {
				mgr.SetSourceRoot(sourceDir)
			}

			if listEndpoints {
				if sourceDir == "" {
					fmt.Fprintln(os.Stderr, "需要 --source 参数")
					os.Exit(1)
				}
				reg := fuzzer.ScanProject(sourceDir)
				endpoints := reg.AllEndpoints()
				if len(endpoints) == 0 {
					fmt.Println("未发现端点")
					return
				}
				fmt.Printf("发现 %d 个端点:\n", len(endpoints))
				for _, ep := range endpoints {
					fmt.Printf("  %s %s → %s.%s (%s)\n", ep.Method, ep.FullPath, ep.ClassName, ep.MethodName, ep.File)
				}
				return
			}

			if reportPath == "" {
				fmt.Fprintln(os.Stderr, "需要 --report 参数")
				os.Exit(1)
			}

			fmt.Printf("Fuzz 验证: %s → %s\n", reportPath, targetURL)
		},
	}

	cmd.Flags().StringVar(&reportPath, "report", "", "已有报告路径 (JSON)")
	cmd.Flags().StringVar(&targetURL, "target", "", "目标 URL")
	cmd.Flags().StringVar(&sourceDir, "source", "", "源码目录（端点扫描）")
	cmd.Flags().StringVar(&cookie, "cookie", "", "认证 Cookie")
	cmd.Flags().BoolVar(&listEndpoints, "list-endpoints", false, "仅列出端点，不执行 fuzz")

	return cmd
}

// ── status ──

func statusCmd() *cobra.Command {
	var sessionID string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "查看审计会话状态",
		Run: func(cmd *cobra.Command, args []string) {
			if sessionID == "" {
				listAllSessions()
				return
			}

			database, err := openSession(sessionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "打开会话失败: %v\n", err)
				os.Exit(1)
			}
			defer database.Close()

			session, err := orchestrator.LoadSession(database, sessionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "加载会话失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("会话: %s\n", session.ID)
			fmt.Printf("目标: %s\n", session.Target)
			fmt.Printf("模式: %s\n", session.Mode)
			fmt.Printf("语言: %v\n", session.Languages)
			fmt.Printf("阶段: %s\n", session.Phase)
			fmt.Printf("状态: %s\n", session.Status)
			fmt.Printf("开始: %s\n", session.StartedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("更新: %s\n", session.UpdatedAt.Format("2006-01-02 15:04:05"))

			store := evidence.NewSQLiteStore(database, sessionID)
			records, err := store.List(sessionID)
			if err == nil && len(records) > 0 {
				printVerdictSummary(records)
			}
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "会话 ID")
	return cmd
}

func printVerdictSummary(records []*evidence.Record) {
	verdicts := map[string]int{}
	severities := map[string]int{}
	for _, rec := range records {
		if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
			verdicts[string(rec.LLMVerify.Judge.Verdict)]++
			severities[rec.LLMVerify.Judge.Severity]++
		}
	}

	fmt.Printf("\n裁决分布 (%d 条记录):\n", len(records))
	for v, c := range verdicts {
		fmt.Printf("  %-30s %d\n", v, c)
	}
	fmt.Printf("\n严重性分布:\n")
	for s, c := range severities {
		fmt.Printf("  %-30s %d\n", s, c)
	}
}

// ── report ──

func reportCmd() *cobra.Command {
	var sessionID, format string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "从已有会话重新生成报告",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()

			database, sid, err := resolveSession(sessionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			defer database.Close()

			session, err := orchestrator.LoadSession(database, sid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "加载会话失败: %v\n", err)
				os.Exit(1)
			}

			store := evidence.NewSQLiteStore(database, sid)
			records, err := store.List(sid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "加载证据失败: %v\n", err)
				os.Exit(1)
			}

			formats := cfg.Report.Formats
			if format != "" {
				formats = strings.Split(format, ",")
			}

			data := report.BuildReportData(session.ID, session.Target, session.Mode, session.Languages, records)
			mgr := report.NewManager(cfg.Report.OutputDir)
			results, err := mgr.Generate(context.Background(), data, formats)
			if err != nil {
				fmt.Fprintf(os.Stderr, "生成报告失败: %v\n", err)
				os.Exit(1)
			}

			for f, path := range results {
				fmt.Printf("  ✓ %s → %s\n", f, path)
			}
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "会话 ID（默认最新）")
	cmd.Flags().StringVar(&format, "format", "", "报告格式 (markdown,json,sarif)")
	return cmd
}

// ── verify ──

func verifyCmd() *cobra.Command {
	var sessionID string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "查看待验证候选",
		Run: func(cmd *cobra.Command, args []string) {
			database, sid, err := resolveSession(sessionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			defer database.Close()

			store := evidence.NewSQLiteStore(database, sid)
			records, err := store.List(sid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "加载证据失败: %v\n", err)
				os.Exit(1)
			}

			pending := 0
			for _, rec := range records {
				if rec.LLMVerify == nil || rec.LLMVerify.Judge == nil {
					pending++
				}
			}

			fmt.Printf("会话 %s: %d 条记录, %d 条待验证\n", sid, len(records), pending)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "会话 ID（默认最新）")
	return cmd
}

// ── helpers ──

func openSession(sessionID string) (*db.DB, error) {
	reportDir := ".joern_audit/reports"
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return nil, fmt.Errorf("无法读取报告目录 %s: %w", reportDir, err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		if strings.Contains(entry.Name(), sessionID) {
			return db.Open(filepath.Join(reportDir, entry.Name()))
		}
	}

	dbPath := filepath.Join(reportDir, sessionID+".db")
	if _, err := os.Stat(dbPath); err == nil {
		return db.Open(dbPath)
	}

	return nil, fmt.Errorf("未找到会话 %s 对应的数据库", sessionID)
}

func resolveSession(sessionID string) (*db.DB, string, error) {
	if sessionID != "" {
		database, err := openSession(sessionID)
		if err != nil {
			return nil, "", err
		}
		return database, sessionID, nil
	}

	dbPath, sid := findLatestDB()
	if dbPath == "" {
		return nil, "", fmt.Errorf("未找到任何审计数据库")
	}
	database, err := db.Open(dbPath)
	if err != nil {
		return nil, "", err
	}
	return database, sid, nil
}

func findLatestDB() (string, string) {
	reportDir := ".joern_audit/reports"
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return "", ""
	}

	var latest string
	var latestTime int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().UnixNano() > latestTime {
			latestTime = info.ModTime().UnixNano()
			latest = entry.Name()
		}
	}

	if latest == "" {
		return "", ""
	}
	sid := strings.TrimSuffix(latest, ".db")
	return filepath.Join(reportDir, latest), sid
}

func listAllSessions() {
	reportDir := ".joern_audit/reports"
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		fmt.Println("未找到审计记录")
		return
	}

	found := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		dbPath := filepath.Join(reportDir, entry.Name())
		database, err := db.Open(dbPath)
		if err != nil {
			continue
		}

		sid := strings.TrimSuffix(entry.Name(), ".db")
		sessions, err := orchestrator.ListSessions(database)
		if err != nil || len(sessions) == 0 {
			info, _ := entry.Info()
			fmt.Printf("  %s  (%.1f KB)\n", sid, float64(info.Size())/1024)
		} else {
			for _, s := range sessions {
				fmt.Printf("  %s  [%s] %s  %s\n", s.ID, s.Status, s.Target, s.StartedAt.Format("2006-01-02 15:04"))
			}
		}
		database.Close()
		found = true
	}

	if !found {
		fmt.Println("未找到审计记录")
	}
}
