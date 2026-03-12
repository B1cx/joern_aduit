package orchestrator

import (
	"context"

	"github.com/joern-audit/joern_audit/internal/fuzzer"
)

type FuzzPhase struct{}

func (p *FuzzPhase) Name() string { return "Phase 3: Fuzz 验证" }

func (p *FuzzPhase) Execute(ctx context.Context, state *PipelineState) error {
	if !state.Config.Fuzzer.Enabled {
		return nil
	}

	log := state.Logger
	log.Progress("目标: %s", state.Config.Fuzzer.TargetURL)

	fuzzRecords, _ := state.Store.List(state.Session.ID)
	fuzzMgr := fuzzer.NewManager(&state.Config.Fuzzer)
	fuzzMgr.SetSourceRoot(state.Session.Target)
	confirmed, fuzzFailed, fuzzErrored := fuzzMgr.RunAll(ctx, fuzzRecords)

	for _, rec := range fuzzRecords {
		if rec.FuzzVerify != nil {
			state.Store.Save(rec)
		}
	}

	log.Progress("✓ Fuzz 完成: 确认 %d / 失败 %d / 错误 %d", confirmed, fuzzFailed, fuzzErrored)

	return nil
}
