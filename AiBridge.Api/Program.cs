using AiBridge.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options => options.AddPolicy("TauriDev", policy => policy
    .WithOrigins("http://localhost:1420", "http://127.0.0.1:1420")
    .AllowAnyHeader()
    .AllowAnyMethod()));
builder.Services.AddSingleton<IPiiDetector, CompositePiiDetector>();
builder.Services.AddSingleton<IGuardModel, MockGuardModel>();
builder.Services.AddSingleton<IPolicyEngine, PolicyEngine>();
builder.Services.AddSingleton<IPiiVault, InMemoryPiiVault>();
builder.Services.AddSingleton<IExternalLlmProvider>(sp =>
    builder.Configuration["Provider:Mode"]?.Equals("OpenAiCompatible", StringComparison.OrdinalIgnoreCase) == true
        ? new OpenAiCompatibleProvider(sp.GetRequiredService<IHttpClientFactory>(), builder.Configuration)
        : new MockExternalLlmProvider());
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IAuditStore>(sp =>
    builder.Configuration.GetValue<bool>("Audit:UseSqlServer")
        ? new SqlAuditStore(builder.Configuration.GetConnectionString("Audit")!)
        : new InMemoryAuditStore());
builder.Services.AddSingleton<GatewayService>();

var app = builder.Build();
app.UseCors("TauriDev");
app.MapPost("/v1/chat/completions", async (ChatCompletionRequest request, HttpRequest http, GatewayService gateway, CancellationToken ct) =>
{
    var caller = http.Headers["X-AI-Caller"].FirstOrDefault();
    var purpose = http.Headers["X-AI-Purpose"].FirstOrDefault();
    if (string.IsNullOrWhiteSpace(caller) || string.IsNullOrWhiteSpace(purpose))
        return Results.BadRequest(ApiError.Create("MISSING_GATEWAY_CONTEXT", "X-AI-Caller and X-AI-Purpose are required."));

    var result = await gateway.ProcessAsync(request, caller, purpose, ct);
    return result.Blocked
        ? Results.Json(ApiError.Create("DATA_EGRESS_BLOCKED", result.BlockReason!), statusCode: StatusCodes.Status403Forbidden)
        : Results.Ok(result.Response);
});
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.Run();
