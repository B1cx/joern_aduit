package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joern-audit/joern_audit/internal/db"
	"github.com/joern-audit/joern_audit/internal/evidence"
)

type InitPhase struct{}

func (p *InitPhase) Name() string { return "Phase 0: 初始化" }

func (p *InitPhase) Execute(ctx context.Context, state *PipelineState) error {
	log := state.Logger
	cfg := state.Config

	dirs := []string{
		cfg.Joern.CPGDir,
		cfg.Report.OutputDir,
		".joern_audit/conversations",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	log.Progress("✓ 创建输出目录")

	dbPath := filepath.Join(cfg.Report.OutputDir, state.Session.ID+".db")
	database, err := db.Open(dbPath)
	if err != nil {
		log.Warning("SQLite 初始化失败，回退到内存存储: %v", err)
		database = nil
	}

	if database != nil {
		state.Database = database
		state.Store = evidence.NewSQLiteStore(database, state.Session.ID)
		log.Progress("✓ 初始化证据存储 (SQLite: %s)", dbPath)

		state.Session.UpdatedAt = now()
		if err := SaveSession(database, state.Session); err != nil {
			log.Warning("保存会话失败: %v", err)
		}
	} else {
		state.Store = evidence.NewMemoryStore()
		log.Progress("✓ 初始化证据存储 (内存模式)")
	}

	state.Coverage = NewCoverageMatrix()
	log.Progress("✓ 初始化覆盖率矩阵")

	return nil
}
