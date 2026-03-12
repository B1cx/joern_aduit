# DeepAudit TODO List

> 跟踪 DeepAudit 各模块的开发进度与待办事项。
> 状态标记：✅ 已完成 | 🔧 进行中 | 📋 计划中 | 💡 待评估

---

## 核心 Pipeline

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Pipeline 阶段化重构 | 将单体 engine 拆分为 7 阶段独立 PhaseRunner |
| ✅ | Init 阶段 | 配置加载、会话创建、SQLite 初始化、LLM Provider 创建 |
| ✅ | CPG Build 阶段 | Joern CPG 构建 + YAML 规则匹配 |
| ✅ | LLM Verify 阶段 | Tribunal 三角验证（并发控制 + 速率限制） |
| ✅ | Explorer 阶段 | 覆盖矩阵驱动的自由探索 |
| ✅ | Fuzz 阶段 | 动态验证集成框架 |
| ✅ | Attack Chain 阶段 | 攻击链分析与 CVSS 评估 |
| ✅ | Report 阶段 | 多格式报告生成 |
| 📋 | Pipeline 断点续跑 | 支持从任意阶段恢复中断的审计 |
| 📋 | 阶段间条件跳转 | 根据中间结果动态调整后续阶段（如无候选直接跳到报告） |

## Tribunal 验证引擎

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Prosecutor-Defender-Judge 三角验证 | 红蓝对抗 + 裁判机制 |
| ✅ | 并行/串行模式可配置 | `parallel_agents` 控制 |
| ✅ | NEEDS_DEEPER 自动扩展上下文 | 递进式深度复查 |
| ✅ | 对话日志记录 | ConversationLogger 记录完整 LLM 交互 |
| 📋 | 多轮对抗 | Prosecutor 与 Defender 间多轮交叉质证 |
| 📋 | Agent 自主请求上下文 | LLM 主动指定需要查看的文件/函数 |
| 💡 | 引入 Specialist Agent | 针对特定漏洞类型的专家角色（如 Crypto Specialist） |

## CPG 引擎

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Joern 命令行集成 | parse/scan/export/query |
| ✅ | ContextManager 多级上下文提取 | FunctionBody / Callers / DataFlow |
| ✅ | 内存索引 MemoryStore | 轻量级 CPG 索引缓存 |
| 📋 | Joern Server 模式 | 长连接模式减少启动开销 |
| 📋 | 增量 CPG 更新 | 文件变更时仅重建受影响的 CPG 子图 |
| 💡 | 自定义 Joern 查询生成 | LLM 根据漏洞类型动态生成 Joern 查询 |

## LLM 集成

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Claude Provider | Anthropic API 集成 |
| ✅ | OpenAI Provider | OpenAI / 兼容 API 集成 |
| ✅ | Rate Limiter | 令牌桶速率限制 + 自动重试 |
| ✅ | Token Budget 管理 | 按候选/Explorer 分配 token 预算 |
| 📋 | Ollama 本地模型支持 | 完善本地部署场景 |
| 📋 | DeepSeek Provider | DeepSeek API 适配 |
| 📋 | 多模型混用策略 | 快速模型初筛 + 强模型深度验证 |
| 💡 | Streaming 输出 | LLM 流式响应实时展示验证过程 |

## Fuzzer 动态验证

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Fuzzer Manager 框架 | 统一管理各类 Fuzz 策略 |
| ✅ | HTTP Fuzz 策略 | 基于端点注册表的 HTTP 请求构造 |
| ✅ | SQLi Fuzz | sqlmap 集成 |
| ✅ | XXE Fuzz | XML 外部实体测试 |
| ✅ | 反序列化 Fuzz | ysoserial / marshalsec 集成 |
| ✅ | Java 端点扫描器 | Spring Controller 端点自动发现 |
| 📋 | Docker 沙箱隔离 | Fuzz 工具容器化运行 |
| 📋 | OOB 回调检测 | Callback 服务器检测带外数据泄露 |
| 💡 | DAST 联动 | 与 OWASP ZAP / Nuclei 联动 |

## 报告系统

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Markdown 英文报告 | 标准 Markdown 格式 |
| ✅ | Markdown 中文报告 | 中文本地化报告 |
| ✅ | JSON 报告 | 结构化数据格式 |
| ✅ | SARIF 报告 | IDE / GitHub Code Scanning 集成 |
| 📋 | HTML 报告 | 交互式 HTML 报告（含图表） |
| 📋 | PDF 报告导出 | 正式安全审计文档 |
| 💡 | 差异报告 | 对比两次审计结果的差异 |

## 规则与知识库

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Java 规则集 (11条) | SQLi, XSS, Deser, SSRF, RCE, XXE, SSTI, Auth, Crypto, File |
| ✅ | PHP 规则集 (6条) | SQLi, XSS, RCE, LFI, SSRF, Deser |
| ✅ | CWE 知识库 | 漏洞类型元数据 |
| ✅ | Guided Questions | 规则级引导问题 |
| 📋 | Python 规则集 | Jinja2 SSTI, Pickle Deser, Django ORM 注入等 |
| 📋 | Go 规则集 | Template 注入, SQL 拼接, 命令注入等 |
| 📋 | 自定义规则 DSL | 简化规则编写的 DSL / GUI |
| 💡 | 规则自动生成 | 基于 CVE 描述自动生成检测规则 |

## 工程化

| 状态 | 任务 | 说明 |
|------|------|------|
| ✅ | Domain 领域模型层 | Finding / Record / Verdict 统一建模 |
| ✅ | Shared 共享工具 | PromptLoader, Formatter |
| ✅ | CI/CD Pipeline | GitHub Actions (go build/test) |
| ✅ | Makefile | build/test/lint/install |
| 📋 | 单元测试补全 | 核心模块测试覆盖率 > 70% |
| 📋 | 集成测试 | 端到端 vulnerable app 测试用例 |
| 📋 | Docker 打包 | 一键部署 Docker 镜像（含 Joern） |
| 📋 | 配置校验 | 启动时校验配置完整性并给出友好提示 |
| 💡 | Web UI | 审计结果可视化 Dashboard |
| 💡 | VS Code 插件 | IDE 内嵌审计结果展示 |

## 近期优先事项

1. **单元测试补全** — 为 Tribunal、CPG Engine、Scanner 补充测试用例
2. **Ollama 本地模型** — 完善离线/本地部署支持
3. **Pipeline 断点续跑** — 长审计会话中断后恢复能力
4. **Python 规则集** — 扩展语言支持
5. **Docker 打包** — 降低 Joern 环境配置门槛
