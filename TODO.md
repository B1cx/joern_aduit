# joern_audit — 项目进度与 TodoList

> 最后更新：2026-02-18

---

## ✅ 已完成功能

### 核心架构
- [x] **CLI 框架**（cobra）+ 配置管理（YAML）
- [x] **六阶段流水线调度引擎**（Orchestrator）
  - Phase 0: 初始化（目录 / 证据存储 / 覆盖率矩阵）
  - Phase 1: Joern CPG 构建与规则扫描
  - Phase 2: LLM 三角色验证
  - Phase 5: 报告生成
- [x] **并发控制**：Semaphore + sync.Mutex + sync.WaitGroup
- [x] **会话管理**：Session ID、状态跟踪

### CPG 引擎（Layer 1 - 确定性）
- [x] Joern CLI 调用封装（`joern-parse`, `joern`）
- [x] CPG 索引构建（Scala 查询脚本）
- [x] 内存 Index Store（函数 / 调用 / 数据流）
- [x] 按需上下文提取（Context on Demand，Level 0-2）

### 规则系统（Java）
- [x] YAML 规则加载器
- [x] **JAVA-SQLI-001**：SQL 注入（JDBC，自顶向下）
- [x] **JAVA-SQLI-002**：SQL 注入（MyBatis `${}`，自底向上）⚠️ **仅注解驱动，XML mapper 需独立扫描器**
- [x] **JAVA-RCE-001**：远程代码执行（Runtime / ProcessBuilder / ScriptEngine / SnakeYAML）
- [x] **JAVA-DESER-001**：不安全反序列化（ObjectInputStream / Fastjson / XStream）
- [x] **JAVA-SSRF-001**：服务端请求伪造
- [x] **JAVA-FILE-001**：文件操作漏洞（已存在，未充分验证）

### LLM 验证层（Layer 2 - 受控概率性）
- [x] 多 Provider 抽象接口（Claude / OpenAI 兼容）
- [x] **Prosecutor-Defender-Judge 三角色对抗验证**
- [x] Explorer Agent（自由探索架构，基础实现）
- [x] Prompt 模板系统（prosecutor.md / defender.md / judge.md / explorer.md）
- [x] **令牌桶限流**（Token Bucket，可配置 RPM）
- [x] **指数退避重试**（最多 4 次，1s → 2s → 4s → 8s）
- [x] **并行 Agent 控制**（parallel_agents 配置）
- [x] JSON 响应清理（`sanitizeJSON` / `extractJSON`）
- [x] UTF-8 安全截断（Unicode 字符边界）
- [x] HTML 错误页检测
- [x] 对话日志保存

### 证据与报告
- [x] 内存证据存储（MemoryStore）
- [x] 报告生成器（Markdown-ZH / JSON / SARIF）
- [x] 中文 Markdown 报告（漏洞详情 / 攻击向量 / 证据链）
- [x] 覆盖率矩阵（10维度，已定义结构）

---

## 🚧 进行中 / 部分完成

- [ ] **LLM Explorer Agent**：架构存在，但与主流水线的集成未完善
- [ ] **覆盖率矩阵自动更新**：结构已定义，Engine 中的更新逻辑已注释（缺 Engine.coverage 字段）
- [ ] **verify 命令**：CLI 入口已注册，逻辑未实现（`TODO`）
- [ ] **status 命令**：CLI 入口已注册，逻辑未实现（`TODO`）
- [ ] **report 命令**（独立）：CLI 入口已注册，逻辑未实现（`TODO`）

---

## ❌ 待开发功能

### Phase 3：Fuzz 验证层（高优先级）
- [ ] **PoC 模板生成器**：基于 Judge 的 `attack_vector` 自动生成测试用例
- [ ] **Fuzz 执行器**（隔离沙箱）
- [ ] **漏洞类型分策略**：
  - [ ] SQLi → sqlmap
  - [ ] XSS → dalfox
  - [ ] SSRF → interactsh callback
  - [ ] RCE → 自定义 payload + sandbox
  - [ ] XXE → OOB DTD callback
  - [ ] Deser → ysoserial gadget chain
- [ ] **Fuzz 结果状态**：CONFIRMED / UNVERIFIED / FAILED

### Phase 4：攻击链分析
- [ ] 跨模块漏洞关联
- [ ] 端到端攻击路径构建
- [ ] 组合漏洞评级

### 规则扩展：XML Mapper 扫描器（纳入现有扫描体系）

**背景**：Joern 的 `javasrc2cpg` 只解析 `.java` 文件，无法读取 MyBatis XML Mapper。独立 XML 扫描器生成标准 `Candidate`，与 Joern 候选合并后统一进入 LLM 三角色验证流水线。

- [ ] **XML Scanner 实现**（`internal/scanner/xml_scanner.go`）
  - [ ] 递归扫描目标目录下所有 `*.xml` 文件
  - [ ] 识别 MyBatis Mapper 文件（存在 `<mapper namespace="...">` 标签）
  - [ ] 解析 `<select>/<insert>/<update>/<delete>` 标签，提取 SQL 内容
  - [ ] 正则检测 `${xxx}` 不安全参数替换（区别于安全的 `#{xxx}`）
  - [ ] 生成标准 `cpg.Candidate`，RuleID 使用 `XML-SQLI-001`
  - [ ] 在 Orchestrator Phase 1 中与 Joern 候选合并
  - [ ] 为 LLM 提供充分上下文：XML SQL 语句 + Mapper 接口名

**影响范围**：
- ❌ **当前无法检测**：UserMapper.xml 中的 `findByUserNameVuln02` / `findByUserNameVuln03`
- ✅ **实现后可检测**：所有 XML Mapper 中的 `${xxx}` SQL 注入

---

### SCA（软件成分分析，未来独立模块）

> ⚠️ 以下功能与"代码漏洞"性质不同，属于依赖/配置层面的风险，计划作为独立 SCA 模块实现，不并入 Joern 规则体系。

- [ ] **pom.xml 依赖扫描**
  - [ ] 解析 `<dependency>` 版本号
  - [ ] 集成 CVE 数据库（NIST / OSV）
  - [ ] 检测已知漏洞依赖（log4j / fastjson / spring）
  - [ ] 生成供应链风险报告

- [ ] **application.properties / yml 配置检查**
  - [ ] 硬编码密钥检测（`spring.datasource.password=xxx`）
  - [ ] 不安全配置检测（`debug=true` / `management.endpoints.web.exposure.include=*`）
  - [ ] CORS / CSRF 弱配置检测（Actuators 暴露等）
  - [ ] CORS / CSRF 弱配置检测

- [ ] **web.xml / Spring Security 配置扫描**
  - [ ] 检测缺失的 `HttpOnly` / `Secure` Cookie 设置
  - [ ] 检测弱认证/授权规则

### 规则扩展
- [ ] **PHP 规则集**（JAVA-SQLI → PHP-SQLI 等移植）
- [ ] **Java 扩展规则**：
  - [ ] JAVA-AUTH-001（认证绕过 / JWT）
  - [ ] JAVA-XXE-001（独立 XXE 规则，与 DESER 解耦）
  - [ ] JAVA-CRYPTO-001（硬编码密钥 / 弱算法）
  - [ ] JAVA-IDOR-001（不安全直接对象引用）
- [ ] **规则精确度**：JAVA-DESER-001 规则 ID 错误地覆盖了 XXE 漏洞（命名混乱，需拆分）

### 多轮递进审计
- [ ] Round 2（深度追踪，针对盲区）
- [ ] Round 3（跨模块关联，仅 deep 模式）
- [ ] 三问终止法则（自动判断是否继续下一轮）

### 存储与持久化
- [ ] SQLite 持久化（替代 MemoryStore）
- [ ] 会话恢复（中断后继续）
- [ ] 历史对比（多次扫描结果 diff）

### 工程质量
- [ ] 单元测试覆盖（scanner / verifier / report 模块）
- [ ] `verify` / `status` / `report` 独立命令实现
- [ ] PHP 语言支持
- [ ] 增量扫描（`--diff` 参数，git 变更文件过滤）

### 可观测性
- [ ] 结构化日志文件（`.joern_audit/logs/`）
- [ ] 实时进度条（代替纯文本输出）
- [ ] Token 用量统计与报告
- [ ] 扫描耗时分解（CPG / LLM / Report 各阶段）

---

## 🐛 已知问题与限制

| 问题 | 严重程度 | 状态 |
|------|---------|------|
| **Joern 无法读取 XML/配置文件** | **高** | **设计限制** |
| 'ä' 等北欧字符仍导致 JSON 解析失败 | 低 | 待修复 |
| 网络 EOF / 超时时失败候选不会重新入队 | 中 | 待修复 |
| JAVA-DESER-001 规则错误覆盖了 XXE 漏洞 | 中 | 待修复 |
| 覆盖率矩阵在报告中全部显示"未覆盖" | 低 | 待修复 |
| verify / status / report 命令为空实现 | 低 | 待开发 |
| `scan_output_*.log` 临时文件未自动清理 | 低 | 待修复 |

### ⚠️ Joern 文件读取限制详情

**影响**：Joern 的 `javasrc2cpg` 工具仅解析 `.java` 源文件，无法读取以下文件类型：

| 文件类型 | 影响 | 当前检测能力 |
|---------|------|-------------|
| **MyBatis XML Mapper** (`.xml`) | ❌ 无法检测 XML 中的 `${_parameter}` SQL 注入 | 仅能检测注解驱动的 `@Select("${}")` |
| **pom.xml** | ❌ 无法扫描依赖版本，错过 CVE 漏洞 | 无法检测供应链风险（D10 维度） |
| **application.properties / yml** | ❌ 无法检测硬编码密钥、弱配置 | 无法检测配置安全问题（D8 维度） |
| **web.xml / Spring 配置** | ❌ 无法检测 Security 弱配置 | 无法检测认证/授权规则问题 |

**示例**：以下漏洞**无法被当前工具检测**：
```xml
<!-- UserMapper.xml - 当前扫描会漏掉 -->
<select id="findByUserNameVuln02" parameterType="String" resultMap="User">
    select * from users where username like '%${_parameter}%'  <!-- 漏洞！但 Joern 读不到 -->
</select>
```

**缓解措施**（当前）：
- ✅ 可检测注解驱动的 MyBatis：`@Select("... ${username} ...")`
- ⚠️ 建议在报告中添加"人工复查提示"：需手动检查 `resources/mapper/*.xml`

**长期解决方案**：
- 待开发：独立 XML 扫描器（见"待开发功能 → 配置文件扫描"）

---

## 📊 当前验证效果（java-sec-code 测试）

| 指标 | 数值 |
|------|------|
| 候选发现数 | 32 个 |
| 验证成功率 | 84.4% (27/32) |
| TRUE_POSITIVE | 15 个（7 CRITICAL + 8 HIGH）|
| FALSE_POSITIVE（正确过滤） | 9 个 |
| 误报率（相对） | ~37%（LLM 过滤后降低） |
| 典型扫描耗时 | ~1 小时（32 候选，2并发）|

---

## 🗺️ 路线图

```
v0.1（当前）：Java 基础扫描 + Prosecutor-Defender-Judge 验证
   ✅ 核心流水线运行
   ✅ 6条 Java 规则（仅注解驱动的 MyBatis）
   ✅ 3种报告格式
   ⚠️ 限制：无法扫描 XML mapper / pom.xml / properties

v0.2（下一步）：稳定性 + 工程化
   → 修复已知 Bug（Unicode / EOF / 规则命名）
   → verify / status / report 命令实现
   → SQLite 持久化
   → 单元测试

v0.3：配置文件扫描 + 规则扩展
   → MyBatis XML Mapper 扫描器（高优先级）
   → pom.xml 依赖 CVE 检测
   → application.properties/yml 配置安全检查
   → PHP 规则集移植
   → Java 扩展规则（XXE / AUTH / CRYPTO）
   → 覆盖率矩阵实际更新

v0.4：Fuzz 验证层（Phase 3）
   → PoC 自动生成
   → sqlmap / dalfox 集成

v1.0：完整三层验证 + 多轮递进
   → Fuzz 确认
   → 攻击链分析
   → Web UI
```
