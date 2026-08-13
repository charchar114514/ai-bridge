using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
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

// Internal PII-detection LLM boundary. The MVP uses this deterministic mock so no data leaves the process.
public interface IGuardModel { Task<IReadOnlyList<PiiFinding>> DetectAsync(string input, CancellationToken ct); }
public sealed class MockGuardModel(IPiiDetector detector) : IGuardModel
{
    public Task<IReadOnlyList<PiiFinding>> DetectAsync(string input, CancellationToken ct)
    {
        // Represents the structured JSON that a future internal Guard LLM must return.
        // It intentionally returns the same known findings as the baseline detector for repeatable tests.
        IReadOnlyList<PiiFinding> findings = detector.Detect(input);
        return Task.FromResult(findings);
    }
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

public interface IPiiVault { string Tokenize(string requestId, string input, IReadOnlyList<PiiFinding> findings); string Restore(string requestId, string input); void Remove(string requestId); }
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
    public string Restore(string requestId, string input)
    {
        if (!_entries.TryGetValue(requestId, out var entry) || entry.ExpiresAt < DateTimeOffset.UtcNow) { _entries.TryRemove(requestId, out _); return input; }
        foreach (var pair in entry.Map) input = input.Replace(pair.Key, pair.Value, StringComparison.Ordinal);
        return input;
    }
    public void Remove(string requestId) => _entries.TryRemove(requestId, out _);
    private sealed record VaultEntry(DateTimeOffset ExpiresAt, IReadOnlyDictionary<string, string> Map);
}

public static class Hashing { public static string Sha256(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant(); }
