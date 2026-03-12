# DeepAudit — Joern CPG + LLM 多智能体 SAST 引擎

DeepAudit 是一个混合静态应用安全测试（SAST）引擎，将 [Joern](https://joern.io/) 的代码属性图（CPG）分析与 LLM 多智能体对抗验证相结合，实现高精度、低误报的自动化安全审计。

## 核心架构

```
┌────────────────────────────────────────────────────────┐
│                    DeepAudit Pipeline                   │
├──────┬──────┬──────────┬──────┬───────┬───────┬────────┤
│ Init │ CPG  │  LLM     │Explor│ Fuzz  │Attack │ Report │
│      │Build │  Verify   │  er  │Verify │Chain  │        │
│      │      │           │      │       │       │        │
│ 初始化│ 构建  │ Prosecutor│ 自由  │ 动态  │ 攻击链 │ 生成   │
│ 配置  │ 代码  │ Defender  │ 探索  │ 验证  │ 分析  │ 报告   │
│ 会话  │ 属性图 │ Judge    │ 覆盖  │ SQLMap│ CVSS  │ 多格式 │
│      │ 规则  │ 三角验证  │ 盲区  │ 反序列│ 评估  │        │
│      │ 匹配  │           │      │ 化等  │       │        │
└──────┴──────┴──────────┴──────┴───────┴───────┴────────┘
```

### 七阶段 Pipeline

| 阶段 | 说明 |
|------|------|
| **Init** | 加载配置、初始化 SQLite 会话、创建 LLM Provider |
| **CPG Build** | 调用 Joern 构建 CPG，基于 YAML 规则匹配候选漏洞 |
| **LLM Verify** | 对每个候选执行 Prosecutor-Defender-Judge 三角验证 |
| **Explorer** | LLM 自由探索覆盖矩阵中的盲区，发现规则遗漏的漏洞 |
| **Fuzz Verify** | 可选：调用 sqlmap/ysoserial 等工具动态验证 |
| **Attack Chain** | 将独立发现串联为攻击链，评估组合风险 |
| **Report** | 生成 Markdown/JSON/SARIF 多格式报告 |

### Tribunal 三角验证机制

DeepAudit 的核心创新是 **Prosecutor-Defender-Judge** 多智能体对抗验证：

```
候选漏洞 ──→ Prosecutor (红队)：论证漏洞可利用性，构建攻击路径
         ──→ Defender   (蓝队)：搜索防御措施，论证安全性
         ──→ Judge      (裁判)：综合双方证据，给出最终裁决
```

- **Prosecutor**：分析污点流、攻击前提条件、利用影响
- **Defender**：检查参数化查询、输入过滤、框架防护等缓解措施
- **Judge**：裁定 `TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_DEEPER` / `EXPLOITABLE_WITH_CONDITION`
- 对 `NEEDS_DEEPER` 的候选项，自动扩展上下文级别进行深度复查

### 10维覆盖矩阵

跟踪安全审计覆盖面，对未覆盖的维度启动 Explorer Agent 自由探索：

> Injection / Auth / AuthZ / Crypto / XSS / Deserialization / SSRF / File Ops / Config / Business Logic

## 安装

### 前置依赖

- **Go** >= 1.21
- **Joern** — [安装指南](https://docs.joern.io/installation)
- LLM API Key（支持 Claude / OpenAI / DeepSeek / Ollama）

### 构建

```bash
git clone https://github.com/B1cx/joern_aduit.git
cd joern_aduit
make build
```

编译产物位于 `bin/joern_audit`。

## 快速开始

### 1. 创建配置文件

```yaml
# joern_audit.yaml
llm:
  provider: claude          # claude / openai / deepseek / ollama
  model: claude-sonnet-4-20250514
  api_key: sk-xxx
  max_concurrent: 2
  rate_limit_rpm: 30

scan:
  mode: standard            # quick / standard / deep / joern-only
  languages:
    - java
  rules_dir: rules
  prompts_dir: prompts

report:
  output_dir: .joern_audit/reports
  formats:
    - markdown-zh
    - json
    - sarif
```

### 2. 执行安全审计

```bash
# 完整审计
./bin/joern_audit scan /path/to/java-project --config joern_audit.yaml

# 快速模式（跳过 Explorer 和 Fuzz）
./bin/joern_audit scan /path/to/project --mode quick

# 增量扫描（仅分析 git diff 变更）
./bin/joern_audit scan /path/to/project --diff HEAD~1

# 指定语言
./bin/joern_audit scan /path/to/project --lang java,php
```

### 3. 查看结果

```bash
# 列出所有审计会话
./bin/joern_audit status

# 查看指定会话详情
./bin/joern_audit status --session audit_20250309_143022

# 重新生成报告
./bin/joern_audit report --session audit_20250309_143022 --format markdown-zh,sarif
```

## CLI 命令

| 命令 | 说明 | 关键参数 |
|------|------|---------|
| `scan <dir>` | 对目标项目执行完整安全审计 | `--mode`, `--lang`, `--diff`, `--concurrent` |
| `fuzz` | 独立 Fuzz 验证（基于已有报告） | `--report`, `--target`, `--source`, `--cookie` |
| `status` | 查看审计会话状态 | `--session` |
| `report` | 从已有会话重新生成报告 | `--session`, `--format` |
| `verify` | 查看待验证候选 | `--session` |

## 扫描模式

| 模式 | CPG 分析 | LLM 验证 | Explorer | Fuzz | 适用场景 |
|------|---------|---------|----------|------|---------|
| `quick` | ✅ | ✅ (1轮) | ❌ | ❌ | CI/CD 快速检查 |
| `standard` | ✅ | ✅ (2轮) | ✅ | ❌ | 日常安全审计 |
| `deep` | ✅ | ✅ (3轮) | ✅ | ✅ | 上线前深度审计 |
| `joern-only` | ✅ | ❌ | ❌ | ❌ | 仅规则匹配，不调用 LLM |

## 规则体系

规则位于 `rules/` 目录，按语言分类，采用 YAML 格式：

```
rules/
├── java/
│   ├── sqli.yaml           # SQL 注入
│   ├── sqli-mybatis.yaml   # MyBatis SQL 注入
│   ├── xss.yaml            # 跨站脚本
│   ├── deserialization.yaml # 反序列化
│   ├── ssrf.yaml           # 服务端请求伪造
│   ├── rce.yaml            # 远程代码执行
│   ├── xxe.yaml            # XML 外部实体
│   ├── ssti.yaml           # 模板注入
│   ├── auth.yaml           # 认证缺陷
│   ├── crypto.yaml         # 弱加密
│   └── file_ops.yaml       # 文件操作
└── php/
    ├── sqli.yaml
    ├── xss.yaml
    ├── rce.yaml
    ├── lfi.yaml
    ├── ssrf.yaml
    └── deserialization.yaml
```

每条规则包含：Joern CPG 查询、Source/Sink 定义、Sanitizer 模式、Guided Questions（引导 LLM 分析的关键问题）。

## 报告格式

- **Markdown (EN/ZH)**：人类可读的详细审计报告，含证据链和攻击向量
- **JSON**：结构化数据，便于后续处理和集成
- **SARIF**：IDE 集成标准格式（VS Code、GitHub Code Scanning）

## 项目结构

```
cmd/joern_audit/        CLI 入口
internal/
├── config/             配置管理
├── cpg/                Joern CPG 交互层（构建、查询、上下文提取）
├── db/                 SQLite 持久化
├── domain/             领域模型（Finding, Verdict, Evidence）
├── evidence/           证据链存储
├── fuzzer/             动态验证（HTTP Fuzz, SQLMap, 反序列化）
├── knowledge/          CWE 知识库
├── llm/                LLM Provider 抽象层（Claude, OpenAI, Ollama）
├── orchestrator/       Pipeline 编排引擎（7 阶段）
├── output/             日志输出
├── report/             报告生成器（Markdown, JSON, SARIF）
├── scanner/            规则加载与匹配
├── shared/             共享工具（Prompt 加载、格式化）
└── verifier/           验证智能体（Tribunal, Explorer）
prompts/                LLM System Prompt 模板
rules/                  安全检测规则（YAML）
```

## License

MIT
