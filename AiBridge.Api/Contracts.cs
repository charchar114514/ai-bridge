namespace AiBridge.Api;

public sealed record ChatCompletionRequest(string Model, IReadOnlyList<ChatMessage> Messages, bool Stream = false, double? Temperature = null, int? MaxTokens = null);
public sealed record ChatMessage(string Role, string Content);
public sealed record ChatCompletionResponse(string Id, IReadOnlyList<ChatChoice> Choices, GatewayMetadata Gateway);
public sealed record ChatChoice(ChatMessage Message, string FinishReason = "stop");
public sealed record GatewayMetadata(string Decision, string PolicyVersion, IReadOnlyList<string> RedactedTypes, bool ExternalProviderCalled);
public sealed record ApiError(ErrorBody Error)
{
    public static ApiError Create(string code, string message) => new(new ErrorBody(code, message));
}
public sealed record ErrorBody(string Code, string Message);
public sealed record PiiFinding(string Type, int Start, int Length, string Value, int RiskLevel);
public sealed record PolicyDecision(string Action, string PolicyVersion, string? Reason = null);
public sealed record GatewayResult(bool Blocked, string? BlockReason, ChatCompletionResponse? Response);
public sealed record AuditEvent(string RequestId, DateTimeOffset OccurredAtUtc, string CallerId, string Purpose, string Provider, string Model, string Decision, string PolicyVersion, IReadOnlyList<string> PiiTypes, int PiiCount, string RedactedRequestHash, string? RedactedResponseHash, string? TokenizedRequest, string? TokenizedResponse, string ProviderStatus, long LatencyMs, string? ErrorCode);
