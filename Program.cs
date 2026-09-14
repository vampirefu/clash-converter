using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ClashConverter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// ---- Port: env PORT > first arg > 5000 (mirrors Python behaviour) ----
var portStr = Environment.GetEnvironmentVariable("PORT")
    ?? (args.Length > 0 ? args[0] : null)
    ?? "5000";
if (!int.TryParse(portStr, out var port))
    port = 5000;

// ---- Encryption key: env ENCRYPTION_KEY > appsettings:EncryptionKey > ephemeral ----
var encKey = Environment.GetEnvironmentVariable("ENCRYPTION_KEY")
    ?? builder.Configuration["EncryptionKey"];
Crypto.Initialize(encKey);

builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors();

var app = builder.Build();

// Trust reverse proxy (Caddy/Nginx) forwarded proto & host, so subscription
// links are generated with the correct https:// scheme and domain.
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
});
app.UseCors(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
app.UseDefaultFiles();
app.UseStaticFiles();

// Swagger / OpenAPI — interactive API docs at /swagger
app.UseSwagger();
app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Clash Converter API v1"));

app.MapGet("/", () => Results.Redirect("/index.html"));

// ------------------------------------------------------------------
// POST /api/convert  { url } -> { protocol, yaml, filename, sub_url }
// ------------------------------------------------------------------
app.MapPost("/api/convert", (ConvertReq req, HttpContext ctx) =>
{
    if (req.Url is null)
        return Results.BadRequest(new { error = "请提供代理链接" });
    var url = req.Url.Trim();
    if (url.Length == 0)
        return Results.BadRequest(new { error = "链接不能为空" });

    try
    {
        var (proto, yaml, name) = Converter.ProxyUrlToYaml(url);
        var scheme = ctx.Request.Scheme;
        var host = ctx.Request.Host.Value?.TrimEnd('/') ?? "";
        var encrypted = Crypto.Encrypt(url);
        var subUrl = $"{scheme}://{host}/api/sub?d={encrypted}";

        return Results.Ok(new
        {
            protocol = proto,
            yaml,
            filename = $"clash_{name}.yaml",
            sub_url = subUrl,
        });
    }
    catch (Exception e)
    {
        return Results.BadRequest(new { error = e.Message });
    }
})
.Accepts<ConvertReq>("application/json")
.Produces<object>(StatusCodes.Status200OK, "application/json")
.Produces<object>(StatusCodes.Status400BadRequest, "application/json");

// ------------------------------------------------------------------
// POST /api/to-url  { yaml } -> { proxies: [{name,type,url}], total }
// ------------------------------------------------------------------
app.MapPost("/api/to-url", (ToUrlReq req) =>
{
    if (req.Yaml is null)
        return Results.BadRequest(new { error = "请提供 YAML 内容" });
    var yaml = req.Yaml.Trim();
    if (yaml.Length == 0)
        return Results.BadRequest(new { error = "YAML 内容不能为空" });

    try
    {
        var results = Converter.YamlToProxyUrls(yaml);
        return Results.Ok(new { proxies = results, total = results.Count });
    }
    catch (YamlDotNet.Core.YamlException ye)
    {
        return Results.BadRequest(new { error = $"YAML 解析失败: {ye.Message}" });
    }
    catch (Exception e)
    {
        return Results.BadRequest(new { error = e.Message });
    }
})
.Accepts<ToUrlReq>("application/json")
.Produces<object>(StatusCodes.Status200OK, "application/json")
.Produces<object>(StatusCodes.Status400BadRequest, "application/json");

// ------------------------------------------------------------------
// GET /api/sub?d=<encrypted>  (also supports legacy ?url=<plain>)
// Returns proxies-only YAML, stateless.
// ------------------------------------------------------------------
app.MapGet("/api/sub", async (HttpContext ctx) =>
{
    var d = ctx.Request.Query["d"].ToString();
    var urlParam = ctx.Request.Query["url"].ToString();

    string rawUrl;
    if (!string.IsNullOrEmpty(d))
    {
        try
        {
            rawUrl = Crypto.Decrypt(d);
        }
        catch (Exception e)
        {
            ctx.Response.StatusCode = 400;
            ctx.Response.ContentType = "text/plain; charset=utf-8";
            await ctx.Response.WriteAsync($"解密失败: {e.Message}");
            return;
        }
    }
    else if (!string.IsNullOrEmpty(urlParam))
    {
        rawUrl = urlParam;
    }
    else
    {
        ctx.Response.StatusCode = 400;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync("错误: 缺少 url 参数");
        return;
    }

    string yaml;
    try
    {
        yaml = Converter.ProxyUrlToSubYaml(rawUrl);
    }
    catch (Exception e)
    {
        ctx.Response.StatusCode = 400;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync($"错误: {e.Message}");
        return;
    }

    ctx.Response.ContentType = "text/plain; charset=utf-8";
    ctx.Response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
    ctx.Response.Headers["Subscription-Userinfo"] = "upload=0; download=0; total=0; expire=0";
    await ctx.Response.WriteAsync(yaml);
});

// Legacy /api/sub/<id> format -> instruct to regenerate.
app.MapGet("/api/sub/{*fallback}", async (HttpContext ctx) =>
{
    ctx.Response.StatusCode = 400;
    ctx.Response.ContentType = "text/plain; charset=utf-8";
    await ctx.Response.WriteAsync("错误: 订阅链接格式已更新，请重新生成");
});

app.Run();

// Request DTOs
record ConvertReq(string? Url);
record ToUrlReq(string? Yaml);
