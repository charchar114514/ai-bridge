using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AiBridge.Api;

public interface IPiiDetector { IReadOnlyList<PiiFinding> Detect(string input); }
public sealed class CompositePiiDetector : IPiiDetector
{
    private static readonly (string Type, Regex Pattern, int Risk)[] Rules =
    {
        ("email", new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled), 1),
        ("phone", new Regex(@"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)", RegexOptions.Compiled), 2),
        ("identity_number", new Regex(@"(?<!\d)\d{17}[0-9Xx](?!\d)", RegexOptions.Compiled), 2),
        ("credential", new Regex(@"(?i)(?:api[_ -]?key|password|secret)\s*[:=]\s*[^\s,;]+", RegexOptions.Compiled), 3)
    };
    public IReadOnlyList<PiiFinding> Detect(string input) => Rules.SelectMany(rule => rule.Pattern.Matches(input).Select(m => new PiiFinding(rule.Type, m.Index, m.Length, m.Value, rule.Risk))).OrderBy(x => x.Start).ToArray();
}

public interface IGuardModel { Task<IReadOnlyList<PiiFinding>> DetectAsync(string input, CancellationToken ct); }
public sealed class PiiDetectorUnavailableException(string message, Exception? inner = null) : Exception(message, inner);
public sealed class LocalPiiEngineGuardModel(IHttpClientFactory clients) : IGuardModel
{
    public async Task<IReadOnlyList<PiiFinding>> DetectAsync(string input, CancellationToken ct)
    {
        try
        {
            var client = clients.CreateClient("PiiDetectEngine");
            using var response = await client.PostAsJsonAsync("/analyze", new LocalPiiAnalyzeRequest(input, "en", true), ct);
            response.EnsureSuccessStatusCode();
            var payload = await response.Content.ReadFromJsonAsync<LocalPiiAnalyzeResponse>(cancellationToken: ct)
                ?? throw new PiiDetectorUnavailableException("PII Detect Engine returned an empty response.");
            return payload.Entities
                .Where(x => x.Start >= 0 && x.End > x.Start && x.End <= input.Length)
                .Select(x => new PiiFinding(x.Type, x.Start, x.End - x.Start, input[x.Start..x.End], RiskFor(x.Type)))
                .ToArray();
        }
        catch (PiiDetectorUnavailableException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new PiiDetectorUnavailableException("Local PII Detect Engine is unavailable; request was not sent to an external model.", ex);
        }
    }

    private static int RiskFor(string type) => type.ToLowerInvariant() switch
    {
        "credential" or "api_key" or "password" or "secret" or "access_token" or "private_key" => 3,
        "email" => 1,
        _ => 2,
    };
    private sealed record LocalPiiAnalyzeRequest(string Text, string Language, bool IncludeNer);
    private sealed record LocalPiiAnalyzeResponse(IReadOnlyList<LocalPiiEntity> Entities);
    private sealed record LocalPiiEntity(string Type, int Start, int End, double Score, string Source);
}

public interface IPolicyEngine { PolicyDecision Decide(string caller, string purpose, IReadOnlyList<PiiFinding> findings); }
public sealed class PolicyEngine : IPolicyEngine
{
    public PolicyDecision Decide(string caller, string purpose, IReadOnlyList<PiiFinding> findings)
    {
        if (string.IsNullOrWhiteSpace(purpose)) return new("block", "mvp-v1", "Purpose is required.");
        if (findings.Any(x => x.RiskLevel >= 3)) return new("block", "mvp-v1", "High-risk data cannot be sent to an external model.");
        return findings.Count == 0 ? new("allow", "mvp-v1") : new("redact", "mvp-v1");
    }
}

public interface IPiiVault { string Tokenize(string requestId, string input, IReadOnlyList<PiiFinding> findings); RestoredContent Restore(string requestId, string input); void Remove(string requestId); }
public sealed class InMemoryPiiVault(IConfiguration configuration) : IPiiVault
{
    private readonly ConcurrentDictionary<string, VaultEntry> _entries = new();
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(configuration.GetValue<int?>("PiiVault:TtlMinutes") ?? 10);
    public string Tokenize(string requestId, string input, IReadOnlyList<PiiFinding> findings)
    {
        var map = new Dictionary<string, string>(); var output = input;
        foreach (var finding in findings.OrderByDescending(x => x.Start))
        {
            var token = $"[[AI_GW:{finding.Type}:{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}]]";
            output = output.Remove(finding.Start, finding.Length).Insert(finding.Start, token); map[token] = finding.Value;
        }
        _entries.AddOrUpdate(
            requestId,
            _ => new VaultEntry(DateTimeOffset.UtcNow.Add(_ttl), map),
            (_, previous) => new VaultEntry(
                DateTimeOffset.UtcNow.Add(_ttl),
                previous.Map.Concat(map).ToDictionary(x => x.Key, x => x.Value)));
        return output;
    }
    public RestoredContent Restore(string requestId, string input)
    {
        if (!_entries.TryGetValue(requestId, out var entry) || entry.ExpiresAt < DateTimeOffset.UtcNow) { _entries.TryRemove(requestId, out _); return new(input, []); }

        var restoredValues = new List<string>();
        foreach (var pair in entry.Map)
        {
            if (!input.Contains(pair.Key, StringComparison.Ordinal)) continue;
            input = input.Replace(pair.Key, pair.Value, StringComparison.Ordinal);
            restoredValues.Add(pair.Value);
        }
        return new(input, restoredValues.Distinct(StringComparer.Ordinal).ToArray());
    }
    public void Remove(string requestId) => _entries.TryRemove(requestId, out _);
    private sealed record VaultEntry(DateTimeOffset ExpiresAt, IReadOnlyDictionary<string, string> Map);
}

public static class Hashing { public static string Sha256(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant(); }
