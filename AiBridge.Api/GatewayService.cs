using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.SqlClient;

namespace AiBridge.Api;

public interface IExternalLlmProvider { string Name { get; } Task<string> CompleteAsync(ChatCompletionRequest request, CancellationToken ct); }
public sealed class MockExternalLlmProvider : IExternalLlmProvider
{
    public string Name => "mock-external-llm";
    public Task<string> CompleteAsync(ChatCompletionRequest request, CancellationToken ct)
    {
        var tokens = System.Text.RegularExpressions.Regex.Matches(string.Join('\n', request.Messages.Select(x => x.Content)), @"\[\[AI_GW:[^\]]+\]\]")
            .Select(x => x.Value).Distinct();
        var suffix = tokens.Any() ? $" 已处理关联实体：{string.Join("、", tokens)}。" : string.Empty;
        return Task.FromResult("Mock 外部业务 LLM：已收到脱敏请求，建议按既定流程进行人工复核。" + suffix);
    }
}
public sealed class OpenAiCompatibleProvider(IHttpClientFactory clients, IConfiguration config) : IExternalLlmProvider
{
    public string Name => "openai-compatible";
    public async Task<string> CompleteAsync(ChatCompletionRequest request, CancellationToken ct)
    {
        var client = clients.CreateClient(); client.BaseAddress = new Uri(config["Provider:BaseUrl"]!);
        client.DefaultRequestHeaders.Authorization = new("Bearer", config["Provider:ApiKey"]);
        using var response = await client.PostAsJsonAsync("/v1/chat/completions", request, ct); response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return json.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? string.Empty;
    }
}

public interface IAuditStore { Task WriteAsync(AuditEvent audit, CancellationToken ct); }
public sealed class InMemoryAuditStore : IAuditStore
{
    private readonly List<AuditEvent> _events = []; private readonly object _lock = new();
    public Task WriteAsync(AuditEvent audit, CancellationToken ct) { lock (_lock) _events.Add(audit); return Task.CompletedTask; }
}
public sealed class SqlAuditStore(string connectionString) : IAuditStore
{
    public async Task WriteAsync(AuditEvent audit, CancellationToken ct)
    {
        await using var connection = new SqlConnection(connectionString); await connection.OpenAsync(ct);
        const string schemaSql = """
            IF OBJECT_ID('dbo.AuditEvents','U') IS NULL CREATE TABLE dbo.AuditEvents (
              Id BIGINT IDENTITY(1,1) PRIMARY KEY, RequestId NVARCHAR(64) NOT NULL, OccurredAtUtc DATETIMEOFFSET NOT NULL,
              CallerId NVARCHAR(128) NOT NULL, Purpose NVARCHAR(128) NOT NULL, Provider NVARCHAR(128) NOT NULL, Model NVARCHAR(128) NOT NULL,
              Decision NVARCHAR(16) NOT NULL, PolicyVersion NVARCHAR(64) NOT NULL, PiiTypes NVARCHAR(512) NOT NULL, PiiCount INT NOT NULL,
              RedactedRequestHash CHAR(64) NOT NULL, RedactedResponseHash CHAR(64) NULL, ProviderStatus NVARCHAR(64) NOT NULL,
              TokenizedRequest NVARCHAR(MAX) NULL, TokenizedResponse NVARCHAR(MAX) NULL,
              LatencyMs BIGINT NOT NULL, ErrorCode NVARCHAR(64) NULL);
            IF COL_LENGTH('dbo.AuditEvents', 'TokenizedRequest') IS NULL ALTER TABLE dbo.AuditEvents ADD TokenizedRequest NVARCHAR(MAX) NULL;
            IF COL_LENGTH('dbo.AuditEvents', 'TokenizedResponse') IS NULL ALTER TABLE dbo.AuditEvents ADD TokenizedResponse NVARCHAR(MAX) NULL;
            IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_AuditEvents_RequestId') CREATE INDEX IX_AuditEvents_RequestId ON dbo.AuditEvents(RequestId);
            IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_AuditEvents_OccurredAtUtc') CREATE INDEX IX_AuditEvents_OccurredAtUtc ON dbo.AuditEvents(OccurredAtUtc);
            """;
        await using (var schemaCommand = new SqlCommand(schemaSql, connection))
            await schemaCommand.ExecuteNonQueryAsync(ct);

        const string insertSql = """
            INSERT INTO dbo.AuditEvents(RequestId,OccurredAtUtc,CallerId,Purpose,Provider,Model,Decision,PolicyVersion,PiiTypes,PiiCount,RedactedRequestHash,RedactedResponseHash,TokenizedRequest,TokenizedResponse,ProviderStatus,LatencyMs,ErrorCode)
            VALUES(@RequestId,@OccurredAtUtc,@CallerId,@Purpose,@Provider,@Model,@Decision,@PolicyVersion,@PiiTypes,@PiiCount,@RedactedRequestHash,@RedactedResponseHash,@TokenizedRequest,@TokenizedResponse,@ProviderStatus,@LatencyMs,@ErrorCode);
            """;
        await using var command = new SqlCommand(insertSql, connection);
        command.Parameters.AddWithValue("@RequestId", audit.RequestId); command.Parameters.AddWithValue("@OccurredAtUtc", audit.OccurredAtUtc);
        command.Parameters.AddWithValue("@CallerId", audit.CallerId); command.Parameters.AddWithValue("@Purpose", audit.Purpose); command.Parameters.AddWithValue("@Provider", audit.Provider); command.Parameters.AddWithValue("@Model", audit.Model);
        command.Parameters.AddWithValue("@Decision", audit.Decision); command.Parameters.AddWithValue("@PolicyVersion", audit.PolicyVersion); command.Parameters.AddWithValue("@PiiTypes", string.Join(',', audit.PiiTypes)); command.Parameters.AddWithValue("@PiiCount", audit.PiiCount);
        command.Parameters.AddWithValue("@RedactedRequestHash", audit.RedactedRequestHash); command.Parameters.AddWithValue("@RedactedResponseHash", (object?)audit.RedactedResponseHash ?? DBNull.Value); command.Parameters.AddWithValue("@TokenizedRequest", (object?)audit.TokenizedRequest ?? DBNull.Value); command.Parameters.AddWithValue("@TokenizedResponse", (object?)audit.TokenizedResponse ?? DBNull.Value); command.Parameters.AddWithValue("@ProviderStatus", audit.ProviderStatus); command.Parameters.AddWithValue("@LatencyMs", audit.LatencyMs); command.Parameters.AddWithValue("@ErrorCode", (object?)audit.ErrorCode ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
    }
}

public sealed class GatewayService(IGuardModel guardModel, IPolicyEngine policy, IPiiVault vault, IExternalLlmProvider provider, IAuditStore audit)
{
    public async Task<GatewayResult> ProcessAsync(ChatCompletionRequest request, string caller, string purpose, CancellationToken ct)
    {
        if (request.Stream) return new(true, "Streaming is not supported in this MVP.", null);
        var requestId = "gwreq_" + Guid.NewGuid().ToString("N"); var timer = Stopwatch.StartNew();
        IReadOnlyList<PiiFinding>[] findingsByMessage;
        try
        {
            findingsByMessage = await Task.WhenAll(request.Messages.Select(async x => NormalizeFindings(await guardModel.DetectAsync(x.Content, ct))));
        }
        catch (PiiDetectorUnavailableException ex)
        {
            await audit.WriteAsync(new(requestId, DateTimeOffset.UtcNow, caller, purpose, provider.Name, request.Model, "block", "mvp-v1", [], 0, Hashing.Sha256("pii-detector-unavailable"), null, null, null, "not_called", timer.ElapsedMilliseconds, "PII_DETECTOR_UNAVAILABLE"), ct);
            return new(true, ex.Message, null, "PII_DETECTOR_UNAVAILABLE");
        }
        var findings = findingsByMessage.SelectMany(x => x)
            .GroupBy(x => new { x.Type, x.Value, x.RiskLevel })
            .Select(x => x.First()).ToArray();
        var decision = policy.Decide(caller, purpose, findings);
        if (decision.Action == "block")
        {
            await audit.WriteAsync(new(requestId, DateTimeOffset.UtcNow, caller, purpose, provider.Name, request.Model, "block", decision.PolicyVersion, findings.Select(x => x.Type).Distinct().ToArray(), findings.Length, Hashing.Sha256("blocked"), null, null, null, "not_called", timer.ElapsedMilliseconds, "DATA_EGRESS_BLOCKED"), ct);
            return new(true, decision.Reason ?? "Request blocked by data-egress policy.", null);
        }
        var sanitizedMessages = request.Messages.Select((message, index) =>
        {
            var messageFindings = findingsByMessage[index];
            return message with { Content = messageFindings.Count == 0 ? message.Content : vault.Tokenize(requestId, message.Content, messageFindings) };
        }).ToArray();
        var sanitized = request with { Messages = sanitizedMessages };
        try
        {
            var raw = await provider.CompleteAsync(sanitized, ct); var responseFindings = await guardModel.DetectAsync(raw, ct);
            var restored = vault.Restore(requestId, raw); var response = new ChatCompletionResponse(requestId, [new(new("assistant", restored.Content))], new(decision.Action, decision.PolicyVersion, findings.Select(x => x.Type).Distinct().ToArray(), restored.Values, true));
            var tokenizedRequest = string.Join('\n', sanitizedMessages.Select(x => x.Content));
            await audit.WriteAsync(new(requestId, DateTimeOffset.UtcNow, caller, purpose, provider.Name, request.Model, decision.Action, decision.PolicyVersion, findings.Select(x => x.Type).Distinct().ToArray(), findings.Length, Hashing.Sha256(tokenizedRequest), Hashing.Sha256(raw), tokenizedRequest, raw, responseFindings.Count == 0 ? "ok" : "response_flagged", timer.ElapsedMilliseconds, null), ct);
            return new(false, null, response);
        }
        catch (Exception)
        {
            var tokenizedRequest = string.Join('\n', sanitizedMessages.Select(x => x.Content));
            await audit.WriteAsync(new(requestId, DateTimeOffset.UtcNow, caller, purpose, provider.Name, request.Model, decision.Action, decision.PolicyVersion, findings.Select(x => x.Type).Distinct().ToArray(), findings.Length, Hashing.Sha256(tokenizedRequest), null, tokenizedRequest, null, "failed", timer.ElapsedMilliseconds, "PROVIDER_ERROR"), ct);
            throw;
        }
        finally { vault.Remove(requestId); }
    }

    private static IReadOnlyList<PiiFinding> NormalizeFindings(IReadOnlyList<PiiFinding> findings)
    {
        var selected = new List<PiiFinding>();
        foreach (var finding in findings
            .OrderByDescending(x => x.Length)
            .ThenByDescending(x => x.RiskLevel)
            .ThenBy(x => x.Type, StringComparer.Ordinal))
        {
            var overlaps = selected.Any(existing => finding.Start < existing.Start + existing.Length && existing.Start < finding.Start + finding.Length);
            if (!overlaps) selected.Add(finding);
        }
        return selected.OrderBy(x => x.Start).ToArray();
    }
}
