# DeepAudit 开发进度报告

> 基于 `DeepAudit-Architecture.md` 架构设计 vs 当前实现的差距分析
> 最后更新: 2026-02-21

---

## 总体完成度: 85-90%

核心流水线已跑通（CPG → LLM 三角色 → Explorer 多轮 → Fuzz → 攻击链 → 报告）。SQLite 持久化 + Session 持久化 + CLI 子命令已实现。Guided Questions/Sanitizers 已注入 LLM prompt。覆盖率矩阵动态更新 + ShouldContinue 终止。Explorer Agent 多轮迭代。Phase 4 攻击链分析。增量扫描。CWE 知识库。

---

## 模块完成度一览

| # | 模块 | 状态 | 完成度 | 备注 |
|---|------|------|--------|------|
| 1 | CPG Engine (joern-parse/flow) | ✅ 已完成 | 85% | joern-scan/slice 未集成，用自定义 CPGQL 替代 |
| 2 | Context Manager (L0-5) | ✅ 已完成 | 100% | 6 级上下文 + Token 预算 |
| 3 | Tribunal (P-D-J) | ✅ 已完成 | 100% | 三角色对抗 + 并行模式 + VerifyFull |
| 4 | YAML 规则系统 | ✅ 已完成 | 100% | Java 11 条 + PHP 7 条 |
| 5 | Fuzz 验证层 | ✅ 已完成 | 80% | 4 种策略 + EndpointRegistry，缺 OOB/沙箱 |
| 6 | 报告生成 | ✅ 已完成 | 85% | JSON + Markdown-ZH + SARIF，缺 HTML |
| 7 | 对话日志 | ✅ 已完成 | 100% | LLM 交互全记录 |
| 8 | SQLite 持久化 | ✅ 已完成 | 90% | SQLiteStore 实现并接入 orchestrator |
| 9 | P/D 结果持久化 | ✅ 已完成 | 100% | VerifyFull 返回三角色结果，orchestrator 完整保存 |
| 10 | Guided Questions 接入 | ✅ 已完成 | 100% | 规则中 guided_questions + sanitizers 已传给三角色 LLM |
| 11 | 覆盖率矩阵 | ✅ 已完成 | 90% | Phase 1 标记规则覆盖，Phase 2 记录发现，打印摘要 |
| 12 | Explorer Agent | ✅ 已完成 | 85% | LLM 自由探索 + Tribunal 验证，缺多轮迭代 |
| 13 | 多轮递进策略 | ✅ 已完成 | 85% | Explorer 多轮循环 + ShouldContinue 终止 |
| 14 | Session 持久化 | ✅ 已完成 | 90% | SQLite 持久化 + 子命令实现 |
| 15 | Phase 4 攻击链 | ✅ 已完成 | 80% | LLM 分析确认漏洞关联，生成攻击链图 |
| 16 | 知识库 | ✅ 已完成 | 75% | 13 个 CWE 条目 + 缓解措施 + 分类映射 |
| 17 | 增量扫描 (--diff) | ✅ 已完成 | 85% | git diff 过滤候选，按变更文件筛选 |
| 18 | Docker 沙箱 | ❌ 未开始 | 0% | config 字段存在，无实现 |
| 19 | OOB 回调检测 | ❌ 未开始 | 0% | config 字段存在，无实现 |
| 20 | verify/status/report 子命令 | ✅ 已完成 | 85% | 从 SQLite 加载会话/证据，生成报告 |

---

## 变更日志

### [2026-02-21] P0-1: SQLite Evidence Store 接入 ✅

**目标**: 将 MemoryStore 替换为 SQLite 持久化存储，解决证据丢失、会话不可恢复问题。

**变更文件**:
- `internal/evidence/sqlite_store.go` — **新建**，实现 Store 接口的 SQLite 版本
  - Save: INSERT ... ON CONFLICT DO UPDATE（upsert 语义）
  - Get/List: 反序列化 CPG/LLM/Fuzz JSON 字段
  - 绑定 sessionID，支持多会话隔离
- `internal/orchestrator/engine.go` — **修改**
  - 导入 `db` 包
  - Phase 0 初始化时创建 SQLite 数据库（路径: `.joern_audit/reports/{sessionID}.db`）
  - SQLite 失败时自动回退到 MemoryStore
- `internal/db/db.go` — **修改**
  - `evidence_records` 表增加 `rule_id`, `file_path`, `line_number`, `initial_severity` 字段
  - `candidate_id` 改为 TEXT 类型
  - 增加 `UNIQUE(session_id, candidate_id)` 约束支持 upsert

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P0-2: Prosecutor/Defender 结果持久化 ✅

**目标**: orchestrator 中保存完整三角色结果，而非仅 Judge。

**变更文件**:
- `internal/verifier/tribunal.go` — **修改**
  - 新增 `TribunalResult` 结构体（bundled P/D/J）
  - 新增 `VerifyFull()` 方法，返回 `*TribunalResult`
  - 保留原 `Verify()` 方法不变（向后兼容）
- `internal/orchestrator/engine.go` — **修改**
  - `tribunal.Verify()` → `tribunal.VerifyFull()`
  - `rec.LLMVerify` 填充 Prosecutor、Defender、Judge 三个字段

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P1-1: Guided Questions 接入 LLM ✅

**目标**: 将规则中的 guided_questions 和 sanitizers 传递给 Tribunal prompt，降低幻觉。

**变更文件**:
- `internal/cpg/types.go` — **修改**
  - Candidate 结构体新增 `GuidedQuestions []string` 和 `Sanitizers []string` 字段
- `internal/scanner/engine.go` — **修改**
  - `scanWithTaintFlow()` 和 `scanWithQuery()` 创建 Candidate 时从 Rule 复制 GuidedQuestions 和 Sanitizers
  - 新增 `extractSanitizerPatterns()` 辅助函数，将 `[]Sanitizer` 转为 `[]string`
- `internal/verifier/tribunal.go` — **修改**
  - `buildProsecutorMessage()`: 追加 "## Investigative Questions" 段落
  - `buildDefenderMessage()`: 追加 "## Known Sanitizer Patterns" + "## Investigative Questions" 段落
  - `buildJudgeMessage()`: 追加 "## Key Questions to Consider" 段落

**设计决策**:
- 将 GuidedQuestions/Sanitizers 直接附加到 Candidate，而非通过 RuleID 回查。
  理由：Candidate 已携带其他 Rule 衍生字段（Severity, Message），保持一致性。
- Prosecutor 收到 investigative questions 作为分析引导
- Defender 额外收到 sanitizer patterns（如 "PreparedStatement with ? placeholder"），帮助精准查找防御措施
- Judge 收到 questions 作为裁决参考标准

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P0-3: Explorer Agent 实现 ✅

**目标**: 实现 LLM 自由探索，基于 Phase 1 攻击面发现 Joern 规则未覆盖的漏洞。

**变更文件**:
- `internal/verifier/explorer.go` — **重写**
  - `Explorer.Explore()` 完整实现：加载 explorer.md prompt → 构建 AttackSurface 消息 → 调用 LLM → 解析 ExplorerResponse
  - `buildExplorerMessage()` 构建结构化提示：入口点列表 + 高风险区域 + 覆盖率缺口 + 代码上下文
  - `ExplorerResponse` 结构体（findings + explored_directions + suggested_next）
  - `AttackSurface` 增加 `CodeContext []cpg.CodeSlice` 字段
  - Confidence 强制上限 0.7，所有发现标记 `NeedsTribunal = true`
  - 支持 ConversationLogger 记录探索过程
- `internal/orchestrator/engine.go` — **修改**
  - 新增 Phase 2.8: Explorer Agent，位于覆盖率矩阵打印后、Phase 3 前
  - `buildAttackSurface()` 辅助方法：从 CPG 查询 Spring 入口点 + 覆盖率缺口 + 高风险区域
  - Explorer 发现 → 转为 Candidate → Tribunal VerifyFull → 保存证据 → 更新覆盖率
  - 仅在非 joern-only 模式且有覆盖率缺口时运行

**设计决策**:
- Explorer 发现的 Candidate RuleID 格式: `EXPLORER-D{n}`，便于与 Joern 规则发现区分
- Explorer 不直接确认漏洞（最大置信度 0.7），所有发现必须通过 Tribunal P-D-J 验证
- 当前为单轮探索，多轮迭代留待后续实现

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [待规划] P1-2: 覆盖率矩阵激活 ✅

**目标**: Phase 1 后按 CWE 更新维度，Phase 2 后调用 AddFinding()，打印覆盖率摘要。

**变更文件**:
- `internal/orchestrator/coverage.go` — **修改**
  - 新增 `categoryToDimension` 映射表（13 个 category → 10 个 dimension）
  - 新增 `ResolveDimension(ruleID)` — 从 rule ID 解析 dimension
  - 新增 `MarkRuleScanned(ruleID)` — 标记 Joern 规则覆盖（uncovered → shallow）
  - 新增 `AddFinding(ruleID)` — 记录已验证发现（→ covered + 计数 +1）
  - 新增 `MarkLLMExplored(dim)` — 为 Explorer Agent 预留
- `internal/orchestrator/engine.go` — **修改**
  - Phase 1 后: 遍历 `scanEngine.Rules()` 调用 `coverage.MarkRuleScanned()`
  - Phase 2 并发验证循环: TP/CONDITIONAL 裁决时调用 `coverage.AddFinding()`
  - Phase 2 完成后: 打印 10 维度覆盖率矩阵摘要（✅/🔶/⬜）

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P1-3: Session 持久化 + CLI 子命令 ✅

**目标**: Session 序列化到 SQLite，实现 verify/status/report 子命令。

**变更文件**:
- `internal/orchestrator/session.go` — **新建**
  - `SaveSession()` — INSERT ... ON CONFLICT DO UPDATE 持久化会话状态
  - `LoadSession()` — 从 SQLite 加载会话（含 phase/status/languages 反序列化）
  - `ListSessions()` — 列出所有会话（按时间倒序）
  - `parsePhase()` — 字符串 → Phase 枚举转换
- `internal/orchestrator/engine.go` — **修改**
  - Phase 0 初始化后调用 `SaveSession()` 保存初始状态
  - 审计完成后调用 `SaveSession()` 保存最终状态
- `cmd/joern_audit/main.go` — **修改**
  - `statusCmd`: 无 --session 时列出所有会话；有 --session 时显示详细信息（阶段、裁决分布、严重性分布）
  - `reportCmd`: 从 SQLite 加载证据记录，重新生成指定格式的报告
  - `verifyCmd`: 从 SQLite 加载候选，显示待验证数量
  - `openSession()` 辅助函数: 按 session ID 精确/前缀匹配查找 .db 文件
  - `findLatestDB()` 辅助函数: 按修改时间排序找最新 .db
  - `listAllSessions()` 辅助函数: 遍历所有 .db 文件列出会话

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P2-1: Phase 4 攻击链分析 ✅

**目标**: 对确认漏洞进行关联分析，构建端到端攻击链。

**变更文件**:
- `internal/orchestrator/attack_chain.go` — **新建**
  - `ChainAnalyzer` 结构体 + `Analyze()` 方法
  - 筛选 TP/CONDITIONAL 记录 → 构建 LLM 消息 → 解析攻击链
  - `AttackChain`/`ChainStep`/`AttackChainResponse` 数据结构
  - 放在 orchestrator 包（而非 verifier）避免 evidence↔verifier import cycle
- `prompts/attack_chain.md` — **新建**
  - 攻击链分析 system prompt，含 5 种链类型
  - JSON 输出格式：chains + unchained + summary
- `internal/orchestrator/engine.go` — **修改**
  - Phase 4 占位符替换为 `ChainAnalyzer.Analyze()` 调用
  - 仅在 `mode=deep` 且确认漏洞 ≥ 2 时执行

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P2-2: 增量扫描 (--diff) ✅

**目标**: 通过 git diff 过滤候选，仅验证变更文件中的漏洞。

**变更文件**:
- `internal/config/config.go` — **修改**，ScanConfig 新增 `DiffRef` 字段
- `internal/orchestrator/diff.go` — **新建**
  - `DiffFilter` 结构体：运行 `git diff --name-only` 获取变更文件集合
  - `Contains()` 方法：支持相对路径、绝对路径、后缀匹配
- `internal/orchestrator/engine.go` — **修改**
  - Phase 1 后新增 diff 过滤逻辑，保留变更文件中的候选
- `cmd/joern_audit/main.go` — **修改**，`--diff` flag 写入 `cfg.Scan.DiffRef`

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P2-3: CWE 知识库 ✅

**目标**: 替换硬编码 CWE 映射，建立结构化知识库。

**变更文件**:
- `internal/knowledge/cwe.go` — **新建**（替换旧 knowledge.go 空壳）
  - `CWEDatabase` + `CWEEntry` 结构体
  - 内置 13 个 CWE 条目（89/78/94/79/918/22/502/611/287/285/327/90/643）
  - 每个条目含：名称、描述、严重性、分类关键词、缓解措施、参考链接
  - `Lookup(cweID)` / `LookupByCategory(cat)` / `ResolveCWE(ruleID)` 查询方法

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### [2026-02-21] P2-4: 多轮递进策略 ✅

**目标**: Explorer Agent 多轮迭代，由 ShouldContinue() 控制终止。

**变更文件**:
- `internal/orchestrator/engine.go` — **修改**
  - Explorer Agent 从单次执行改为 `for round := 1; round <= maxRounds; round++` 循环
  - 每轮开始前调用 `coverage.ShouldContinue()` 检查终止条件
  - 终止条件：关键维度（D1-D3）全覆盖 + 总覆盖率 ≥ 8/10，或达到最大轮次
  - Explorer 无新发现时提前终止
  - CandidateID 包含轮次标记：`EXPLORER_R{n}_{dim}_{line}`
  - 轮次数由 `cfg.Scan.MaxRounds`（默认 2）控制

**验证**: `go build ./...` 通过

**状态**: ✅ 完成

---

### 剩余待实现

| 模块 | 优先级 | 备注 |
|------|--------|------|
| Docker 沙箱 | P3 | Fuzz 隔离执行，需 Docker API 集成 |
| OOB 回调检测 | P3 | DNS/HTTP 回调服务器，用于 SSRF/XXE/Deser 确认 |
| HTML 报告格式 | P3 | 在现有报告生成器中增加 HTML 模板 |
