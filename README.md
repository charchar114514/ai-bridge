# AI Bridge MVP

C# REST gateway that detects selected PII, applies `allow / redact / block`, sends only tokenized prompts to an OpenAI-compatible provider, records a minimized audit event, and only restores exact tokens issued for the current request.

## Run

Install the .NET 8 SDK, then run:

```powershell
dotnet run --project .\AiBridge.Api
```

默认启用两个安全的本地 Mock：`MockGuardModel` 模拟内部 PII Detection LLM 并返回结构化发现结果；`MockExternalLlmProvider` 模拟外部业务 LLM 并返回固定的人工复核建议（会原样带回合法 token 以测试精确回填）。两者都不会发起网络调用。要调用 OpenAI-compatible Provider，将 `Provider:Mode` 设为 `OpenAiCompatible`，并通过 user secrets 或环境变量提供 `Provider:BaseUrl` 和 `Provider:ApiKey`；不要提交凭据。

Set `Audit:UseSqlServer` to `true` only after SQL Express is available and the `Audit` connection string is configured. The app creates or upgrades its `AuditEvents` table and indexes on first write. Audit stores only Token 化后的请求及外部 LLM 回填前响应（`TokenizedRequest`、`TokenizedResponse`），never source PII or token mappings.

## Test request

```powershell
$body = @{ model = 'demo-model'; messages = @(@{role='user';content='请总结客户王小明，手机号 13800138000 的资料。'}) } | ConvertTo-Json -Depth 4
Invoke-RestMethod http://localhost:5000/v1/chat/completions -Method Post -Headers @{'X-AI-Caller'='demo-client';'X-AI-Purpose'='kyc_risk_review_assist'} -ContentType 'application/json' -Body $body
```

`credential`、API key 和密码模式会被阻断；电话、邮箱和身份证号会 token 化。当前 PII 规则是 MVP 基线，生产使用前需补充内部 Guard Model、策略配置、身份认证、加密 Vault 与测试集。
