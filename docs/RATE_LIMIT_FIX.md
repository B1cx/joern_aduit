# 429 Rate Limit Error - 修复说明

## 问题原因

当使用 LLM API 进行漏洞验证时，可能会遇到 `429 Too Many Requests` 错误。原因：

1. **角色并发**：Prosecutor 和 Defender 默认并行执行，同时发起 2 个请求
2. **候选密集**：大型项目可能发现几十个候选漏洞，短时间内发起大量请求
3. **API 限制**：免费或低级 API 限制通常为 20-60 RPM

## 修复内容

### 1. 智能速率限制 ✅

每个 LLM Provider 自动限流：
- **Claude**: 默认 50 RPM
- **OpenAI**: 默认 60 RPM
- **可配置**: 通过 `rate_limit_rpm` 调整

### 2. 自动重试机制 ✅

遇到 429/5xx 错误自动重试：
- **指数退避**: 1s → 2s → 4s → ...
- **最大重试**: 默认 3 次（可配置）
- **友好提示**: 显示重试进度

### 3. 串行执行模式 ✅

新增 `parallel_agents` 配置：
- **false (默认)**: Prosecutor → Defender 串行执行，避免并发
- **true**: 并行执行，更快但可能触发限制

### 4. 更好的错误信息 ✅

从：
```
invalid character '<' looking for beginning of value
```

到：
```
received HTML instead of JSON (likely an error page). Response preview: <html>...
⚠️  Attempt 1/3 failed: API error 429: Too Many Requests. Retrying in 1s...
```

## 使用方法

### 方法 1：使用配置文件（推荐）

创建 `joern_audit.yaml`：

```yaml
llm:
  provider: claude
  model: claude-opus-4-6-thinking
  api_key: sk-xxx
  base_url: https://api.aiclaude.xyz

  # 避免 429 错误的关键配置
  parallel_agents: false   # 串行执行，避免并发
  rate_limit_rpm: 30       # 降低速率（免费账户推荐 20-30）
  max_retries: 3          # 遇到 429 自动重试
```

然后运行：
```bash
./bin/joern_audit scan /path/to/project --config joern_audit.yaml
```

### 方法 2：使用命令行参数

```bash
./bin/joern_audit scan /path/to/project \
  --lang java \
  --llm claude \
  --model claude-opus-4-6-thinking \
  --apikey sk-xxx \
  --baseurl https://api.aiclaude.xyz
```

> **注意**: 命令行参数不能配置 `parallel_agents` 和 `rate_limit_rpm`，需要使用配置文件。

## 速率限制建议

| API 类型 | 推荐 RPM | parallel_agents | 说明 |
|---------|---------|-----------------|------|
| 免费账户 | 20-30 | false | 保守设置 |
| 付费低级 | 40-50 | false | 安全设置 |
| 付费高级 | 50-100 | true | 可启用并发 |
| 企业账户 | 100+ | true | 最快速度 |

## 测试建议

### 1. 先用小项目测试

```bash
# 测试单个文件
./bin/joern_audit scan /path/to/single/file.java --config config.yaml
```

### 2. 观察速率

运行时注意以下输出：
```
[1/24] 验证候选: JAVA-SQLI-001_44 (util/HttpUtils.java:44)
  ⚠️  Attempt 1/3 failed: API error 429. Retrying in 1s...
  ✅ 裁决: TRUE_POSITIVE (置信度: 0.99)
```

如果频繁出现重试，降低 `rate_limit_rpm`。

### 3. 逐步调优

```yaml
# 第一次：保守设置
rate_limit_rpm: 20
parallel_agents: false

# 稳定后：逐步提高
rate_limit_rpm: 40
parallel_agents: false

# 最后：尝试并发
rate_limit_rpm: 50
parallel_agents: true
```

## 故障排查

### 仍然遇到 429 错误？

1. **降低速率**: 将 `rate_limit_rpm` 减半（如 50 → 25）
2. **增加重试**: 设置 `max_retries: 5`
3. **禁用并发**: 确保 `parallel_agents: false`
4. **检查其他应用**: 同一 API key 在其他地方使用也会计入限制

### 扫描太慢？

1. **检查候选数量**: 如果候选太多（>50），考虑调整扫描规则
2. **提高 API 级别**: 升级到付费账户获得更高限制
3. **分批扫描**: 将大项目拆分成多个小模块分别扫描

## 技术实现

### 速率限制器（Token Bucket）

```go
rateLimiter := NewRateLimiter(50, time.Minute)  // 50 RPM
rateLimiter.Wait(ctx)  // 自动等待到有可用token
```

### 重试逻辑（Exponential Backoff）

```go
RetryWithBackoff(ctx, RetryConfig{
    MaxRetries:     3,
    InitialBackoff: 1 * time.Second,
    BackoffFactor:  2.0,
}, func() error {
    return provider.Chat(ctx, req)
})
```

### 串行/并行控制

```go
if tribunal.parallelAgents {
    // 并行执行 Prosecutor + Defender
    go func() { prosecutor.Run() }()
    go func() { defender.Run() }()
} else {
    // 串行执行
    prosecutor.Run()
    defender.Run()
}
```

## 总结

✅ **默认配置已优化**：串行执行 + 智能限流 + 自动重试
✅ **开箱即用**：无需额外配置即可避免大部分 429 错误
✅ **灵活可调**：可根据 API 级别调整性能

如有问题，请检查配置文件并参考上述建议进行调优。
