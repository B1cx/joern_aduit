# joern_audit — Joern CPG + LLM 混合 SAST 引擎

基于 **Joern CPG 静态分析 + LLM 多角色对抗验证** 的三层真相验证 SAST 工具。
确定性静态分析（Joern）包裹概率性语义推理（LLM），有效减少误报，发现深层漏洞。

---

## 📦 前置依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| [Joern](https://joern.io) | ≥ 4.0 | CPG 构建与查询引擎 |
| Go | ≥ 1.21 | 编译运行环境 |
| Claude / OpenAI API | — | LLM 验证（需要 API Key） |
| 网络代理（可选） | — | 访问 API 时建议配置 |

**Joern 安装**：
```bash
# macOS
brew install joern

# 或手动下载
curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | sh
```

---

## 🚀 快速开始

### 1. 编译

```bash
cd joern_audit
go build -o joern_audit ./cmd/joern_audit
```

### 2. 配置文件

复制并编辑 `joern_audit.yaml`：

```yaml
llm:
  provider: claude          # claude | openai | ollama | deepseek
  model: claude-opus-4-6
  api_key: sk-ant-xxx       # 你的 API Key
  base_url: https://api.anthropic.com/v1  # 官方 API，或自定义转发地址

  # 并发与限流（避免 429 / 防火墙策略）
  parallel_agents: false    # false = 单个候选内串行（推荐）
  max_concurrent: 2         # 最多同时验证 N 个候选（建议 1-3）
  rate_limit_rpm: 30        # 每分钟最多请求数
  max_retries: 3            # 失败自动重试次数

  token_budget:
    per_candidate: 8000     # 每个候选最多使用的 token 数
    per_explorer: 12000
    max_context_rounds: 3   # 最多扩展上下文轮数

scan:
  mode: standard            # quick | standard | deep | joern-only
  languages:
    - java                  # java | php
  rules_dir: rules
  prompts_dir: prompts
  max_rounds: 2

report:
  output_dir: .joern_audit/reports
  formats:
    - markdown-zh           # 中文 Markdown 报告
    - json                  # 结构化 JSON
    - sarif                 # SARIF（IDE 集成）
```

### 3. 设置代理（如需）

```bash
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
```

### 4. 运行扫描

```bash
# 基础用法（使用配置文件）
./joern_audit scan /path/to/target --config joern_audit.yaml

# 命令行指定参数（覆盖配置文件）
./joern_audit scan /path/to/target \
  --lang java \
  --mode standard \
  --llm claude \
  --model claude-opus-4-6 \
  --apikey sk-ant-xxx

# 仅 Joern 扫描（不使用 LLM，最快）
./joern_audit scan /path/to/target --mode joern-only

# 只扫描 git 变更文件（增量扫描）
./joern_audit scan /path/to/target --diff HEAD~1
```

---

## 📋 扫描模式说明

| 模式 | 说明 | 耗时 | 推荐场景 |
|------|------|------|---------|
| `quick` | Joern 高置信规则 + LLM 快速验证，1轮 | ~10-20分钟 | CI/CD 快速检查 |
| `standard` | 全量 Joern + Prosecutor-Defender-Judge，1-2轮 | ~30-90分钟 | 日常代码审计 |
| `deep` | Standard + Explorer Agent + Fuzz，2-4轮 | 数小时 | 深度安全评估 |
| `joern-only` | 仅 Joern 静态扫描，不调用 LLM | ~2-5分钟 | 快速预扫描 |

---

## 🤖 LLM 三角色验证原理

扫描流程中，每个候选漏洞经过三个角色的对抗性验证：

```
Prosecutor（控方/红队）
  → 尝试证明漏洞可被利用，构造攻击路径

Defender（辩方/蓝队）
  → 寻找防护措施，证明漏洞不可利用

Judge（审判官）
  → 基于双方证据做最终裁决
```

**裁决结果**：
- ✅ `TRUE_POSITIVE` — 确认为真实漏洞
- ❌ `FALSE_POSITIVE` — 确认为误报
- ⚠️ `EXPLOITABLE_WITH_CONDITION` — 有条件可利用
- 🔬 `NEEDS_DEEPER` — 证据不足，需深入分析

---

## 📁 报告文件

扫描完成后，报告保存在 `.joern_audit/reports/` 目录：

```
.joern_audit/
├── cpg/                    # Joern CPG 文件（*.bin）
├── reports/
│   ├── audit_report_<时间>.md      # 中文详细报告（推荐阅读）
│   ├── audit_report_<时间>.json    # 结构化数据（程序读取）
│   └── audit_report_<时间>.sarif   # SARIF（导入 IDE/GitHub）
└── conversations/          # LLM 对话日志（调试用）
```

---

## 📖 当前支持的检测规则

### Java 规则（`rules/java/`）

| 规则 ID | 漏洞类型 | 检测目标 |
|---------|---------|---------|
| `JAVA-SQLI-001` | SQL 注入 (JDBC) | `executeQuery` / `executeUpdate` + 字符串拼接 |
| `JAVA-SQLI-002` | SQL 注入 (MyBatis) | `${}` 参数替换（⚠️ **仅注解驱动**，XML mapper 暂不支持） |
| `JAVA-RCE-001` | 远程代码执行 | `exec` / `eval` / `ProcessBuilder.start` / SnakeYAML |
| `JAVA-DESER-001` | 不安全反序列化 | `ObjectInputStream` / Fastjson / XStream / SnakeYAML |
| `JAVA-SSRF-001` | 服务端请求伪造 | HTTP 客户端 + 用户可控 URL |
| `JAVA-FILE-001` | 文件操作漏洞 | 路径遍历 / 任意文件读写 |

### ⚠️ 重要限制

**Joern 只能读取 `.java` 源文件**，以下文件类型**无法被扫描**：

| 无法扫描的文件 | 影响 |
|---------------|------|
| MyBatis XML Mapper (`*.xml`) | ❌ 无法检测 `<select>` 标签中的 `${_parameter}` SQL 注入 |
| pom.xml | ❌ 无法检测依赖版本 CVE 漏洞 |
| application.properties / yml | ❌ 无法检测硬编码密钥、弱配置 |

**当前 MyBatis 检测能力**：
- ✅ **可检测**：注解驱动的 SQL 注入
  ```java
  @Select("select * from users where name = '${username}'")  // ✅ 能检测
  ```
- ❌ **不能检测**：XML mapper 中的 SQL 注入
  ```xml
  <!-- UserMapper.xml -->
  <select id="findUser">
      select * from users where name like '%${param}%'  <!-- ❌ 无法检测 -->
  </select>
  ```

**解决方案**：v0.3 版本将添加独立的 XML 扫描器。

---

## ⚙️ 并发与限流建议

| 场景 | 推荐配置 |
|------|---------|
| API 限制严格 / 代理不稳定 | `max_concurrent: 1`, `parallel_agents: false` |
| 普通使用（推荐） | `max_concurrent: 2`, `parallel_agents: false` |
| API 配额充足 | `max_concurrent: 3`, `parallel_agents: false` |

> ⚠️ `parallel_agents: true` 会使并发数翻倍（每个候选同时运行 Prosecutor + Defender），容易触发 429 限流，不建议开启。

---

## 🔧 命令参考

```bash
# 查看帮助
./joern_audit --help
./joern_audit scan --help

# 查看版本
./joern_audit version

# 扫描（最常用）
./joern_audit scan <目标路径> --config joern_audit.yaml
```

---

## 🗂️ 项目结构

```
joern_audit/
├── cmd/joern_audit/main.go          # CLI 入口
├── internal/
│   ├── config/config.go             # 配置管理
│   ├── cpg/                         # Joern CPG 引擎封装
│   │   ├── engine.go                # CPG 构建、索引、查询
│   │   ├── context.go               # 按需上下文提取
│   │   └── types.go                 # 数据类型定义
│   ├── scanner/                     # 规则扫描引擎
│   │   ├── engine.go                # 扫描执行
│   │   └── rule_loader.go           # YAML 规则加载
│   ├── llm/                         # LLM Provider 层
│   │   ├── claude.go                # Claude API 实现
│   │   ├── openai.go                # OpenAI 兼容 API
│   │   ├── ratelimit.go             # 令牌桶限流 + 指数退避重试
│   │   └── utils.go                 # JSON 清理、提取工具
│   ├── verifier/                    # 三角色验证系统
│   │   └── tribunal.go              # Prosecutor-Defender-Judge 调度
│   ├── evidence/                    # 证据存储
│   ├── report/                      # 报告生成
│   │   ├── markdown_zh.go           # 中文 Markdown 格式
│   │   ├── sarif.go                 # SARIF 格式
│   │   └── generator.go             # 统一生成器
│   └── orchestrator/engine.go       # 主调度引擎（六阶段流水线）
├── rules/java/                      # 漏洞检测规则（YAML）
├── prompts/                         # LLM Prompt 模板
├── joern_audit.yaml                 # 默认配置文件
└── Makefile
```

---

## 🐛 常见问题

**Q: 为什么 MyBatis XML mapper 中的 SQL 注入没有被检测到？**
```
A: Joern 的 javasrc2cpg 只解析 .java 文件，无法读取 XML。

当前能检测：
  @Select("... ${username} ...")  ← 注解中的 SQL

无法检测：
  <select id="findUser">
    select * from users where name = '${param}'  ← XML 中的 SQL
  </select>

临时方案：
  手动检查 src/main/resources/mapper/*.xml，搜索 ${

长期方案：
  v0.3 版本将添加独立的 XML 扫描器
```

**Q: API 返回 429 (Too Many Requests)**
```yaml
# 降低并发
max_concurrent: 1
rate_limit_rpm: 20
parallel_agents: false
```

**Q: 网络超时 / EOF 错误**
```bash
# 检查代理是否稳定
curl -x http://127.0.0.1:7890 https://api.anthropic.com/v1/messages
# max_retries 会自动重试最多 3 次（指数退避）
```

**Q: JSON 解析失败 (`invalid character`)**
- 通常由 LLM 在 JSON 前后输出额外文本导致
- 已内置 `extractJSON()` + `sanitizeJSON()` 自动处理
- 如仍失败，查看 `.joern_audit/conversations/` 中的原始对话

**Q: Joern 内存不足**
```bash
# 手动调大 JVM 堆内存
javasrc2cpg -J-Xmx8192m /path/to/source --output cpg.bin
```

**Q: 404 API 错误**
- 检查 `base_url` 配置，官方 API 末尾不需要 `/v1`（已内置）
- 自定义转发地址需确保路径正确（工具自动追加 `/v1/messages`）
