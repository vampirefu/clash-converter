using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ClashConverter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

// ============================================================================
// 程序入口：使用 ASP.NET Core Minimal API（top-level statement）搭建的
// Clash 订阅转换 Web 服务。
//
// 提供三个 HTTP 端点：
//   1. POST /api/convert —— 代理分享链接 -> 完整 Clash YAML + 加密订阅链接
//   2. POST /api/to-url  —— Clash YAML -> 代理分享链接列表（反向转换）
//   3. GET  /api/sub     —— 订阅端点，返回仅含 proxies 的 YAML（供客户端订阅）
//
// 前端静态页面位于 wwwroot/，由 UseDefaultFiles/UseStaticFiles 托管。
// ============================================================================
var builder = WebApplication.CreateBuilder(args);

// ---- 监听地址解析（按以下优先级依次判定）：
//        1) PORT 环境变量             -> http://0.0.0.0:{PORT}
//        2) 第一个纯数字命令行参数     -> http://0.0.0.0:{参数值}（对齐原 Python 版 CLI 行为）
//        3) launchSettings / ASPNETCORE_URLS / --urls -> 原样尊重，不覆盖
//        4) 兜底                      -> http://0.0.0.0:5000
//      正确处理 ASPNETCORE_URLS 才能让 Visual Studio 的 launchSettings 配置生效。
var portStr = Environment.GetEnvironmentVariable("PORT");
// PORT 环境变量未设置时，尝试把第一个命令行参数当作端口（如 `dotnet run 8080`）。
if (string.IsNullOrEmpty(portStr) && args.Length > 0 && int.TryParse(args[0], out _))
    portStr = args[0];

if (!string.IsNullOrEmpty(portStr))
{
    // 解析端口失败则回退到默认 5000，避免启动时抛异常。
    if (!int.TryParse(portStr, out var port)) port = 5000;
    builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
}
else if (string.IsNullOrEmpty(builder.Configuration["urls"]))
{
    // 外部（launchSettings / ASPNETCORE_URLS / --urls）均未指定监听地址时，
    // 使用裸机部署的默认端口 5000。
    builder.WebHost.UseUrls("http://0.0.0.0:5000");
}

// ---- 加密密钥的来源优先级：环境变量 ENCRYPTION_KEY > appsettings 的 EncryptionKey > 临时密钥 ----
var encKey = Environment.GetEnvironmentVariable("ENCRYPTION_KEY")
    ?? builder.Configuration["EncryptionKey"];
Crypto.Initialize(encKey);

// ---- 可选的订阅访问密钥（防滥用）。设置 ACCESS_KEY 后，/api/sub 必须携带该密钥才能访问。 ----
var accessKey = Environment.GetEnvironmentVariable("ACCESS_KEY");

// 注册 Swagger/OpenAPI 服务（用于生成接口文档）以及 CORS 服务。
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors();

var app = builder.Build();

// 信任反向代理（Caddy/Nginx）转发的协议与主机头（X-Forwarded-Proto / X-Forwarded-Host），
// 这样生成的订阅链接才能带上正确的 https:// 协议和对外域名，而不是内网地址。
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
});
// 允许任意来源的跨域请求（本服务为公开工具，前端与 API 可能分离部署）。
app.UseCors(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
// 托管 wwwroot 下的静态文件，并支持默认文档（index.html）。
app.UseDefaultFiles();
app.UseStaticFiles();

// Swagger / OpenAPI —— 开发环境下在 /swagger 提供可交互的 API 文档
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Clash Converter API v1"));
}

// ------------------------------------------------------------------
// POST /api/convert
// 请求体：{ url: "vless://..." } 代理分享链接
// 响应体：{ protocol, yaml, filename, sub_url }
//   - protocol：识别出的协议类型（vless/vmess/ss/ssr/trojan）
//   - yaml：完整 Clash 配置 YAML 文本
//   - filename：建议的下载文件名（clash_节点名.yaml）
//   - sub_url：加密后的订阅链接，可添加到 Clash 客户端长期使用
// ------------------------------------------------------------------
app.MapPost("/api/convert", (ConvertReq req, HttpContext ctx) =>
{
    // 参数校验：url 必填且非空。
    if (req.Url is null)
        return Results.BadRequest(new { error = "请提供代理链接" });
    var url = req.Url.Trim();
    if (url.Length == 0)
        return Results.BadRequest(new { error = "链接不能为空" });

    try
    {
        // 核心转换：分享链接 -> (协议类型, Clash YAML, 节点名)
        var (proto, yaml, name) = Converter.ProxyUrlToYaml(url);
        // 拼接订阅链接：scheme://host 来自当前请求（已含反向代理修正）。
        var scheme = ctx.Request.Scheme;
        var host = ctx.Request.Host.Value?.TrimEnd('/') ?? "";
        // 用对称加密包裹原始链接，避免明文暴露节点信息在订阅 URL 中。
        var encrypted = Crypto.Encrypt(url);
        var subUrl = $"{scheme}://{host}/api/sub?d={encrypted}";
        // 配置了 ACCESS_KEY 时，把密钥附加到订阅链接上供客户端携带。
        if (!string.IsNullOrEmpty(accessKey))
            subUrl += $"&key={accessKey}";

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
        // 解析/转换失败（不支持的协议、格式错误等）统一以 400 返回错误消息。
        return Results.BadRequest(new { error = e.Message });
    }
})
.Accepts<ConvertReq>("application/json")
.Produces<object>(StatusCodes.Status200OK, "application/json")
.Produces<object>(StatusCodes.Status400BadRequest, "application/json");

// ------------------------------------------------------------------
// POST /api/to-url —— 反向转换
// 请求体：{ yaml: "proxies: ..." } Clash 配置 YAML
// 响应体：{ proxies: [{name, type, url}], total }
//   每个节点尽量还原为分享链接；单个节点转换失败不影响整体，
//   失败项的 url 为 null 并附带 error 字段。
// ------------------------------------------------------------------
app.MapPost("/api/to-url", (ToUrlReq req) =>
{
    // 参数校验：yaml 必填且非空。
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
        // YAML 语法本身不合法时给出更明确的错误提示。
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
// GET /api/sub?d=<加密串>（同时兼容旧版 ?url=<明文链接> 参数）
// 返回仅含 proxies 列表的 YAML 文本（无状态，不做缓存），
// 可直接作为 Clash 客户端的订阅地址。
// ------------------------------------------------------------------
// ⚠️ d / url / key 三个参数**必须声明为可空（string?）**，切勿"顺手"改成非可空。
// 原因：Minimal API 会把「非可空 + 无默认值」的参数视为必填，在进入本委托之前就由框架
// 返回 400（空响应体），从而顶掉下面这些自定义中文提示；更严重的是，只带
// ?url=<明文链接> 的旧版订阅请求中 d 天然缺失，会被框架整体拦掉，导致旧订阅全部失效。
// 可空声明只影响「参数缺席」这一种情况（框架 400 → 交回本方法自行判断）；
// 参数存在时取到的值与原先手写 ctx.Request.Query[...] 完全一致（已实测：真实 114 字符
// 密文逐字一致，含空串 / 重复值 / 特殊字符等边界场景）。
app.MapGet("/api/sub", async (HttpContext ctx, string? d, string? url, string? key) =>
{
    // 防滥用校验：若配置了 ACCESS_KEY，则要求请求通过 ?key= 查询参数
    // 或 X-Access-Key 请求头携带匹配的密钥，否则返回 401。
    if (!string.IsNullOrEmpty(accessKey))
    {
        var provided = key;
        if (string.IsNullOrEmpty(provided))
            provided = ctx.Request.Headers["X-Access-Key"].ToString();
        if (provided != accessKey)
        {
            ctx.Response.StatusCode = 401;
            ctx.Response.ContentType = "text/plain; charset=utf-8";
            await ctx.Response.WriteAsync("错误: 访问密钥无效");
            return;
        }
    }

    // 优先使用加密参数 d；不存在时回退到旧版明文 url 参数。
    string rawUrl;
    if (!string.IsNullOrEmpty(d))
    {
        try
        {
            // 解密得到原始代理分享链接。
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
    else if (!string.IsNullOrEmpty(url))
    {
        // 兼容旧版明文订阅链接。
        rawUrl = url;
    }
    else
    {
        ctx.Response.StatusCode = 400;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync("错误: 缺少 url 参数");
        return;
    }

    // 将代理链接转为仅含 proxies 的订阅 YAML。
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

    // 以纯文本返回 YAML；禁用缓存保证订阅内容总是最新；
    // Subscription-Userinfo 头用于向客户端声明流量信息（此处均为占位 0）。
    ctx.Response.ContentType = "text/plain; charset=utf-8";
    ctx.Response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
    ctx.Response.Headers["Subscription-Userinfo"] = "upload=0; download=0; total=0; expire=0";
    await ctx.Response.WriteAsync(yaml);
})
// 以下元数据声明用于让本端点出现在 Swagger/OpenAPI 文档中，并暴露 d / url / key 三个查询参数。
// 必要性：本端点完全手写 ctx.Response，委托返回非泛型 Task 且无返回值，若没有这些元数据，
// Swashbuckle 既拿不到 ProducesResponseTypeMetadata 也无法从返回类型推断，
// 会直接跳过该端点（表现为"README 里有介绍、Swagger 里却找不到"）。
// 注：.Produces<>() 只影响文档生成，不会接管响应类型（实测即使请求带
// Accept: application/json，响应仍是 text/plain; charset=utf-8，无内容协商）。
.Produces<string>(StatusCodes.Status200OK, "text/plain")
.Produces<string>(StatusCodes.Status400BadRequest, "text/plain")
.Produces<string>(StatusCodes.Status401Unauthorized, "text/plain")
.WithSummary("订阅端点：返回仅含 proxies 的 Clash 订阅 YAML")
.WithDescription("优先使用加密参数 d（AES-256-GCM，URL-safe Base64）；" +
                 "兼容旧版明文参数 url；配置 ACCESS_KEY 后需通过 ?key= 或 X-Access-Key 请求头携带。" +
                 "响应为纯文本 YAML，可直接作为 Clash 客户端的订阅地址。");

// 旧版 /api/sub/<id> 路径格式的兼容端点：直接提示用户重新生成订阅链接。
// ExcludeFromDescription：该端点仅为兜底提示，不应出现在 Swagger 文档中误导使用者。
app.MapGet("/api/sub/{*fallback}", async (HttpContext ctx) =>
{
    ctx.Response.StatusCode = 400;
    ctx.Response.ContentType = "text/plain; charset=utf-8";
    await ctx.Response.WriteAsync("错误: 订阅链接格式已更新，请重新生成");
})
.ExcludeFromDescription();

app.Run();

// ---------------------------------------------------------------------------
// 请求 DTO（Data Transfer Objects）：与前端 JSON 请求体一一对应。
// ---------------------------------------------------------------------------

/// <summary>POST /api/convert 的请求体：待转换的代理分享链接。</summary>
record ConvertReq(string? Url);

/// <summary>POST /api/to-url 的请求体：待反向转换的 Clash YAML 文本。</summary>
record ToUrlReq(string? Yaml);
