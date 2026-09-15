using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;

namespace ClashConverter;

/// <summary>
/// 核心转换引擎：实现代理分享链接 ↔ Clash 配置的双向转换，
/// 覆盖 VLESS / VMess / SS / SSR / Trojan 五种协议。
///
/// 行为与字段映射完全对齐原 Python 版实现（clash-converter）。
///
/// 数据流：
///   正向：分享链接 URL → Parse*() → 节点字典 → BuildClashConfig() → YAML
///   反向：Clash YAML → YamlToProxyUrls() → 节点字典 → ProxyTo*() → 分享链接 URL
/// </summary>
public static class Converter
{
    // ------------------------------------------------------------------
    // YAML 序列化器（默认配置即可满足本项目需求）
    // ------------------------------------------------------------------
    private static readonly ISerializer YamlSer = new SerializerBuilder().Build();
    private static readonly IDeserializer YamlDeser = new DeserializerBuilder().Build();

    /// <summary>把任意对象序列化为 YAML 文本。</summary>
    private static string ToYaml(object obj) => YamlSer.Serialize(obj);

    // ------------------------------------------------------------------
    // Base64 辅助方法
    // 同时兼容标准 Base64 与 URL-safe Base64（- 和 _ 替代 + 和 /），
    // 且容忍缺失的尾部填充符 '='。
    // ------------------------------------------------------------------

    /// <summary>
    /// 宽容模式的 Base64 解码为 UTF-8 字符串：
    /// 先把 URL-safe 字符还原为标准字符，再补齐填充符后解码。
    /// </summary>
    private static string B64DecodeString(string s)
    {
        // URL-safe 变体还原为标准字符集。
        var rev = s.Replace('-', '+').Replace('_', '/');
        // 补齐 Base64 长度要求（必须是 4 的倍数）。
        var pad = (4 - rev.Length % 4) % 4;
        if (pad > 0)
            rev = rev.PadRight(rev.Length + pad, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(rev));
    }

    /// <summary>编码为 URL-safe Base64（无填充符），用于 SSR / 订阅加密等出现在 URL 中的场景。</summary>
    private static string UrlSafeB64(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    // ------------------------------------------------------------------
    // 查询字符串解析
    // 行为对齐 Python 的 urllib.parse.parse_qsl：
    //   - 按 '&' 分隔、按第一个 '=' 分割键值
    //   - 键和值均做 URL 解码（%XX 与 + 空格等）
    //   - 重复键时后出现的值覆盖先前的值
    // ------------------------------------------------------------------
    private static Dictionary<string, string> ParseQsl(string qs)
    {
        var dict = new Dictionary<string, string>();
        foreach (var pair in qs.Split('&'))
        {
            if (pair.Length == 0)
                continue;
            // 最多按 '=' 分割一次，避免值中含 '=' 时被截断。
            var kv = pair.Split('=', 2);
            var k = Uri.UnescapeDataString(kv[0]);
            var v = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
            dict[k] = v; // 重复键时后者覆盖，与 parse_qsl 行为一致
        }

        return dict;
    }

    // ------------------------------------------------------------------
    // 字典访问辅助方法
    // 节点信息统一用 Dictionary&lt;string, object?&gt; 承载（与反序列化后的
    // YAML 结构一致），以下扩展方法提供类型安全的取值。
    // ------------------------------------------------------------------

    /// <summary>从字符串字典取值，缺失时返回默认值。</summary>
    private static string Q(this Dictionary<string, string> d, string k, string def = "")
        => d.TryGetValue(k, out var v) ? v : def;

    /// <summary>取字符串值，缺失时返回 null。</summary>
    private static string? Str(this Dictionary<string, object?> d, string key)
        => d.TryGetValue(key, out var v) ? v?.ToString() : null;

    /// <summary>取布尔值：直接兼容 bool / 字符串 "true"/"1" / 非 0 整数三种形态。</summary>
    private static bool Bool(this Dictionary<string, object?> d, string key)
    {
        if (d.TryGetValue(key, out var v))
        {
            if (v is bool b) return b;
            if (v is string s) return s == "true" || s == "1";
            if (v is int i) return i != 0;
        }

        return false;
    }

    /// <summary>取整数值：兼容 int / long / 数字字符串，缺失时返回默认值。</summary>
    private static int Int(this Dictionary<string, object?> d, string key, int def = 0)
    {
        if (d.TryGetValue(key, out var v))
        {
            if (v is int i) return i;
            if (v is long l) return (int)l;
            if (v is string s && int.TryParse(s, out var pi)) return pi;
        }

        return def;
    }

    /// <summary>取嵌套子字典（如 ws-opts / reality-opts），类型不符时返回 null。</summary>
    private static Dictionary<string, object?>? Sub(this Dictionary<string, object?> d, string key)
        => d.TryGetValue(key, out var v) && v is Dictionary<string, object?> dd ? dd : null;

    /// <summary>取 ALPN 列表值（兼容 List&lt;object?&gt; 与 List&lt;string&gt;），过滤空字符串项。</summary>
    private static List<string> Alpn(this Dictionary<string, object?> d, string key)
    {
        if (d.TryGetValue(key, out var v))
        {
            if (v is List<object?> lo)
                return lo.Select(x => x?.ToString() ?? "").Where(s => s != "").ToList();
            if (v is List<string> ls)
                return ls.Where(s => s != "").ToList();
        }

        return new List<string>();
    }

    // ------------------------------------------------------------------
    // 协议识别
    // 按前缀匹配；注意 ssr 必须排在 ss 之前检测才不会被误判（当前
    // 顺序下 ssr:// 不会命中 "ss://" 前缀，前缀本身已含结尾的 ://）。
    // ------------------------------------------------------------------
    private static readonly (string Prefix, string Name)[] Prefixes =
    {
        ("vless://", "vless"),
        ("vmess://", "vmess"),
        ("ss://", "ss"),
        ("ssr://", "ssr"),
        ("trojan://", "trojan"),
    };

    /// <summary>
    /// 根据链接前缀识别协议类型。
    /// </summary>
    /// <param name="url">代理分享链接。</param>
    /// <returns>协议名（vless/vmess/ss/ssr/trojan）；无法识别时返回 null。</returns>
    public static string? DetectProtocol(string url)
    {
        foreach (var (prefix, name) in Prefixes)
            if (url.StartsWith(prefix, StringComparison.Ordinal))
                return name;
        return null;
    }

    // ------------------------------------------------------------------
    // 正向解析：分享链接 URL → Clash 节点字典
    // ------------------------------------------------------------------

    /// <summary>
    /// 解析任意支持的分享链接为 Clash 节点字典（自动识别协议并分发）。
    /// </summary>
    /// <exception cref="Exception">协议无法识别时抛出。</exception>
    public static Dictionary<string, object?> Parse(string url)
    {
        var proto = DetectProtocol(url) ?? throw new Exception("不支持的协议类型");
        return proto switch
        {
            "vless" => ParseVless(url),
            "vmess" => ParseVmess(url),
            "ss" => ParseSs(url),
            "ssr" => ParseSsr(url),
            "trojan" => ParseTrojan(url),
            _ => throw new Exception("不支持的协议类型")
        };
    }

    /// <summary>
    /// 解析 VLESS 分享链接。
    /// 链接格式：vless://UUID@host:port?type=tcp&amp;security=tls&amp;sni=...#备注
    /// 支持 tls / reality 传输层安全，以及 ws / grpc / h2 传输层选项。
    /// </summary>
    public static Dictionary<string, object?> ParseVless(string url)
    {
        // 去掉 "vless://" 前缀（长度 8）。
        var raw = url.Substring(8);

        // 第一步：剥离 '#' 之后的备注（节点名），需 URL 解码。
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

        // 第二步：剥离 '?' 之后的查询参数，剩余部分为主体 "UUID@host:port"。
        Dictionary<string, string> prm;
        var qIdx = raw.IndexOf('?');
        string main;
        if (qIdx >= 0)
        {
            main = raw.Substring(0, qIdx);
            prm = ParseQsl(raw.Substring(qIdx + 1));
        }
        else
        {
            main = raw;
            prm = new Dictionary<string, string>();
        }

        // 第三步：用正则从主体提取 UUID、主机、端口。
        var m = Regex.Match(main, @"^([^@]+)@([^:]+):(\d+)");
        if (!m.Success)
            throw new Exception("无法解析 VLESS 链接的主机信息");
        var uid = m.Groups[1].Value;
        var host = m.Groups[2].Value;
        var port = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);

        // 第四步：逐个提取传输层/安全层参数。
        var network = Q(prm, "type", "tcp");        // 传输层：tcp/ws/grpc/h2
        var security = Q(prm, "security", "none");  // 安全层：none/tls/reality
        var flow = Q(prm, "flow");                  // XTLS flow 控制（如 xtls-rprx-vision）
        var sni = Q(prm, "sni");                    // TLS SNI
        var fp = Q(prm, "fp");                      // 客户端 TLS 指纹
        var pbk = Q(prm, "pbk");                    // REALITY 公钥
        var sid = Q(prm, "sid");                    // REALITY short-id
        var spx = Q(prm, "spx");                    // REALITY spider-x
        var pathVal = Q(prm, "path");               // ws/h2 路径
        var hostVal = Q(prm, "host");               // ws Host 头
        var svc = Q(prm, "serviceName");            // gRPC 服务名

        // reality 安全层隐含启用 TLS。
        var isTls = security is "tls" or "reality";
        var isReality = security == "reality";

        // 构建节点字典：通用字段必填，可选字段仅在有值时写入，
        // 这样生成的 YAML 才干净、不含空键。
        var proxy = new Dictionary<string, object?>
        {
            // 无备注时用 UUID 前 8 位作为默认节点名。
            ["name"] = string.IsNullOrEmpty(remark)
                ? $"VLESS-{(uid.Length >= 8 ? uid.Substring(0, 8) : uid)}"
                : remark,
            ["type"] = "vless",
            ["server"] = host,
            ["port"] = port,
            ["uuid"] = uid,
            ["network"] = network,
            ["tls"] = isTls,
            ["udp"] = true,
        };

        // SNI：优先使用显式 sni；否则在启用 TLS 时回退到主机名。
        if (!string.IsNullOrEmpty(flow)) proxy["flow"] = flow;
        if (!string.IsNullOrEmpty(sni)) proxy["servername"] = sni;
        else if (!string.IsNullOrEmpty(host) && (isTls || isReality)) proxy["servername"] = host;
        if (!string.IsNullOrEmpty(fp)) proxy["client-fingerprint"] = fp;

        // REALITY 专属选项：public-key / short-id / spider-x。
        if (isReality)
        {
            var ro = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pbk)) ro["public-key"] = pbk;
            if (!string.IsNullOrEmpty(sid)) ro["short-id"] = sid;
            if (!string.IsNullOrEmpty(spx)) ro["spider-x"] = spx;
            if (ro.Count > 0) proxy["reality-opts"] = ro;
        }

        // WebSocket 传输选项：path + headers.Host。
        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal)) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        // gRPC 传输选项：服务名。
        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        // HTTP/2 传输选项：路径。
        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    /// <summary>
    /// 解析 VMess 分享链接，兼容两种主流格式：
    ///   1. Base64 编码的 JSON（v2rayN 传统格式）：
    ///      vmess://base64({"v":"2","ps":..,"add":..,"port":..,"id":..,..})
    ///   2. 与 VLESS 类似的明文 URL（vmess://UUID@host:port?...，部分客户端使用）
    /// </summary>
    public static Dictionary<string, object?> ParseVmess(string url)
    {
        // 去掉 "vmess://" 前缀。
        var raw = url.Substring(8);
        // 含 '@' 时是明文 URL 格式，走 VLESS 风格的解析路径。
        if (raw.Contains('@'))
            return ParseVmessLikeVless(raw);

        // 传统格式：主体为 Base64 编码的 JSON 配置。
        string decoded;
        try
        {
            decoded = B64DecodeString(raw);
        }
        catch (Exception ex)
        {
            throw new Exception($"VMess Base64 解码失败: {ex.Message}");
        }

        using var doc = JsonDocument.Parse(decoded);
        var data = doc.RootElement;

        // 提取 JSON 字段（字段名取 v2rayN 约定，部分字段有别名兼容）。
        var server = JsonStr(data, "add") ?? JsonStr(data, "address") ?? "";
        var port = JsonInt(data, "port", 0);
        var uuid = JsonStr(data, "id") ?? "";
        var alterId = JsonInt(data, "aid", JsonInt(data, "alterId", 0));
        var remark = JsonStr(data, "ps") ?? JsonStr(data, "remarks") ?? $"VMess-{server}";
        var network = JsonStr(data, "net") ?? JsonStr(data, "network") ?? "tcp";
        var tlsRaw = JsonStr(data, "tls") ?? "none";
        var isTls = tlsRaw == "tls";
        var hostVal = JsonStr(data, "host") ?? "";
        var pathVal = JsonStr(data, "path") ?? "";
        var sni = JsonStr(data, "sni") ?? hostVal;
        var alpnRaw = JsonStr(data, "alpn") ?? "";

        var proxy = new Dictionary<string, object?>
        {
            ["name"] = string.IsNullOrEmpty(remark) ? $"VMess-{server}" : remark,
            ["type"] = "vmess",
            ["server"] = server,
            ["port"] = port,
            ["uuid"] = uuid,
            ["alterId"] = alterId,
            ["cipher"] = "auto",
            ["network"] = network,
            ["tls"] = isTls,
            ["udp"] = true,
        };

        // 仅在启用 TLS 且有 SNI 时写入 servername。
        if (!string.IsNullOrEmpty(sni) && isTls) proxy["servername"] = sni;
        // ALPN：逗号分隔字符串 → 列表。
        if (!string.IsNullOrEmpty(alpnRaw))
            proxy["alpn"] = alpnRaw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0)
                .Cast<object?>().ToList();

        // WebSocket 传输选项；Host 与 SNI 相同时不必重复写入头。
        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal) && hostVal != sni) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        // gRPC 传输选项。
        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            var svc = JsonStr(data, "serviceName") ?? "";
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        // HTTP/2 传输选项。
        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    /// <summary>
    /// 解析 "明文 URL 风格" 的 VMess 链接（vmess://UUID@host:port?...），
    /// 解析逻辑与 VLESS 基本一致，仅字段集合略有差异（无 reality/fingerprint，
    /// alterId 来自 aid 参数）。
    /// </summary>
    private static Dictionary<string, object?> ParseVmessLikeVless(string raw)
    {
        // 剥离 '#' 之后的备注。
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

        // 剥离查询参数。
        Dictionary<string, string> prm;
        var qIdx = raw.IndexOf('?');
        string main;
        if (qIdx >= 0)
        {
            main = raw.Substring(0, qIdx);
            prm = ParseQsl(raw.Substring(qIdx + 1));
        }
        else
        {
            main = raw;
            prm = new Dictionary<string, string>();
        }

        // 提取 UUID、主机、端口。
        var m = Regex.Match(main, @"^([^@]+)@([^:]+):(\d+)");
        if (!m.Success)
            throw new Exception("无法解析 VMess 链接的主机信息");
        var uid = m.Groups[1].Value;
        var host = m.Groups[2].Value;
        var port = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);

        var network = Q(prm, "type", "tcp");
        var isTls = Q(prm, "security", "none") == "tls";
        var pathVal = Q(prm, "path");
        var hostVal = Q(prm, "host");
        var sni = Q(prm, "sni");

        var proxy = new Dictionary<string, object?>
        {
            ["name"] = string.IsNullOrEmpty(remark)
                ? $"VMess-{(uid.Length >= 8 ? uid.Substring(0, 8) : uid)}"
                : remark,
            ["type"] = "vmess",
            ["server"] = host,
            ["port"] = port,
            ["uuid"] = uid,
            // alterId 来自 aid 查询参数，缺省为 0。
            ["alterId"] = int.Parse(Q(prm, "aid", "0"), CultureInfo.InvariantCulture),
            ["cipher"] = "auto",
            ["network"] = network,
            ["tls"] = isTls,
            ["udp"] = true,
        };

        if (!string.IsNullOrEmpty(sni)) proxy["servername"] = sni;

        // WebSocket 传输选项。
        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal)) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        // gRPC 传输选项。
        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            var svc = Q(prm, "serviceName");
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        // HTTP/2 传输选项。
        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    /// <summary>
    /// 解析 Shadowsocks (SS) 分享链接，兼容两种格式：
    ///   1. SIP002 明文主机格式（ userinfo 部分仍是 Base64 的 method:password）：
    ///      ss://base64(method:password)@host:port#备注
    ///   2. 全 Base64 传统格式：
    ///      ss://base64(method:password@host:port)#备注
    /// </summary>
    public static Dictionary<string, object?> ParseSs(string url)
    {
        // 去掉 "ss://" 前缀。
        var raw = url.Substring(5);

        // 剥离 '#' 之后的备注。
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

        // 剥离查询参数（目前只关心 plugin，如 simple-obfs/v2ray-plugin）。
        string plugin = "";
        var qIdx = raw.IndexOf('?');
        if (qIdx >= 0)
        {
            var qs = raw.Substring(qIdx + 1);
            raw = raw.Substring(0, qIdx);
            var q = ParseQsl(qs);
            plugin = Q(q, "plugin");
        }

        string method;    // 加密方法（cipher）
        string password;  // 密码
        string server;    // 服务器地址
        int port;         // 端口

        if (raw.Contains('@'))
        {
            // SIP002 格式：base64(method:password)@host:port
            var parts = raw.Split('@', 2);
            var decoded = B64DecodeString(parts[0]);
            var mp = decoded.Split(':', 2);
            method = mp[0];
            password = mp.Length > 1 ? mp[1] : "";
            // 从最后一个 ':' 分割，兼容 IPv6 地址形式的主机。
            var sp = SplitLast(parts[1], ':');
            server = sp.Key;
            port = int.Parse(sp.Value, CultureInfo.InvariantCulture);
        }
        else
        {
            // 传统全 Base64 格式：base64(method:password@host:port)
            var decoded = B64DecodeString(raw);
            var mp = SplitLast(decoded, '@');
            var methodPass = mp.Key;
            var serverPort = mp.Value;
            var mm = methodPass.Split(':', 2);
            method = mm[0];
            password = mm.Length > 1 ? mm[1] : "";
            var sp = SplitLast(serverPort, ':');
            server = sp.Key;
            port = int.Parse(sp.Value, CultureInfo.InvariantCulture);
        }

        var proxy = new Dictionary<string, object?>
        {
            ["name"] = string.IsNullOrEmpty(remark) ? $"SS-{server}" : remark,
            ["type"] = "ss",
            ["server"] = server,
            ["port"] = port,
            ["cipher"] = method,
            ["password"] = password,
        };
        if (!string.IsNullOrEmpty(plugin)) proxy["plugin"] = plugin;

        return proxy;
    }

    /// <summary>
    /// 解析 ShadowsocksR (SSR) 分享链接。SSR 格式较特殊，存在两种约定：
    ///   约定 #1（现代客户端）：ssr://base64(主体)?remarks=base64&amp;protoparam=base64...
    ///     —— base64 主体在 '?' 之前，查询参数各自单独 base64 编码；
    ///   约定 #2（旧版遗留）：ssr://base64(主体?remarks=...&amp;...)（整体编码）。
    /// base64 主体解码后为 "host:port:protocol:cipher:obfs:base64(password)" 六段式。
    /// </summary>
    public static Dictionary<string, object?> ParseSsr(string url)
    {
        // 去掉 "ssr://" 前缀。
        var raw = url.Substring(6);
        var prm = new Dictionary<string, string>();
        string base64Payload;

        var topQ = raw.IndexOf('?');
        if (topQ < 0)
        {
            // 没有查询字符串：剩余整体就是 base64 主体。
            base64Payload = raw;
        }
        else
        {
            // 约定 #1（现代客户端）：ssr://base64(payload)?remarks=..&..
            // base64 主体在 '?' 之前，查询参数分别做了 base64 编码。
            try
            {
                B64DecodeString(raw.Substring(0, topQ)); // 先探测该段是否为合法 base64
                base64Payload = raw.Substring(0, topQ);
                foreach (var kv in ParseQsl(raw.Substring(topQ + 1)))
                    prm[kv.Key] = TryB64(kv.Value);
            }
            catch
            {
                // 约定 #2（旧版遗留）：包括 '?...' 在内的整个剩余部分都是 base64。
                string decoded;
                try
                {
                    decoded = B64DecodeString(raw);
                }
                catch (Exception ex)
                {
                    throw new Exception($"SSR Base64 解码失败: {ex.Message}");
                }

                // 整体解码后再在明文内部寻找 '?' 分隔的参数。
                var innerQ = decoded.IndexOf('?');
                if (innerQ >= 0)
                {
                    base64Payload = decoded.Substring(0, innerQ);
                    foreach (var kv in ParseQsl(decoded.Substring(innerQ + 1)))
                        prm[kv.Key] = TryB64(kv.Value);
                }
                else
                {
                    base64Payload = decoded;
                }
            }
        }

        // 解码 base64 主体为明文六段式。
        string decodedPayload;
        try
        {
            decodedPayload = B64DecodeString(base64Payload);
        }
        catch (Exception ex)
        {
            throw new Exception($"SSR Base64 解码失败: {ex.Message}");
        }

        var parts = decodedPayload.Split(':');
        if (parts.Length < 6)
            throw new Exception("SSR 链接格式不完整");

        // 依次提取六个字段：host:port:protocol:cipher:obfs:base64(password)。
        var server = parts[0];
        var port = int.Parse(parts[1]!, CultureInfo.InvariantCulture);
        var protocol = parts[2];
        var cipher = parts[3];
        var obfs = parts[4];
        // 密码段按约定是 base64 编码；遇到不规范链接时回退使用原文。
        string password;
        try
        {
            password = B64DecodeString(parts[5]);
        }
        catch
        {
            password = parts[5];
        }

        var remark = Q(prm, "remarks", "");
        if (string.IsNullOrEmpty(remark)) remark = $"SSR-{server}";

        return new Dictionary<string, object?>
        {
            ["name"] = remark,
            ["type"] = "ssr",
            ["server"] = server,
            ["port"] = port,
            ["cipher"] = cipher,
            ["password"] = password,
            ["protocol"] = protocol,
            ["protocol-param"] = Q(prm, "protoparam", ""),
            ["obfs"] = obfs,
            ["obfs-param"] = Q(prm, "obfsparam", ""),
            ["udp"] = true,
        };
    }

    /// <summary>
    /// 尝试按 base64 解码，失败时原样返回。
    /// 用于 SSR 查询参数——它们可能编码也可能未编码，无统一约定。
    /// </summary>
    private static string TryB64(string s)
    {
        try
        {
            return B64DecodeString(s);
        }
        catch
        {
            return s;
        }
    }

    /// <summary>
    /// 解析 Trojan 分享链接。
    /// 链接格式：trojan://password@host:port?sni=...&amp;allowInsecure=1#备注
    /// </summary>
    public static Dictionary<string, object?> ParseTrojan(string url)
    {
        // 去掉 "trojan://" 前缀。
        var raw = url.Substring(9);

        // 剥离 '#' 之后的备注。
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

        // 剥离查询参数。
        Dictionary<string, string> prm;
        var qIdx = raw.IndexOf('?');
        string main;
        if (qIdx >= 0)
        {
            main = raw.Substring(0, qIdx);
            prm = ParseQsl(raw.Substring(qIdx + 1));
        }
        else
        {
            main = raw;
            prm = new Dictionary<string, string>();
        }

        // 主体为 "password@host:port"（Trojan 用密码代替 UUID）。
        var m = Regex.Match(main, @"^([^@]+)@([^:]+):(\d+)");
        if (!m.Success)
            throw new Exception("无法解析 Trojan 链接的主机信息");
        var password = m.Groups[1].Value;
        var host = m.Groups[2].Value;
        var port = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);

        var sni = Q(prm, "sni");
        var allowInsecure = Q(prm, "allowInsecure", "0");
        var alpnRaw = Q(prm, "alpn");
        var flow = Q(prm, "flow");

        var proxy = new Dictionary<string, object?>
        {
            ["name"] = string.IsNullOrEmpty(remark) ? $"Trojan-{host}" : remark,
            ["type"] = "trojan",
            ["server"] = host,
            ["port"] = port,
            ["password"] = password,
            ["udp"] = true,
        };

        // SNI：显式 sni 优先，否则回退到主机名。
        if (!string.IsNullOrEmpty(sni)) proxy["sni"] = sni;
        else if (!string.IsNullOrEmpty(host)) proxy["sni"] = host;
        // allowInsecure=1/true 表示跳过证书校验（映射为 Clash 的 skip-cert-verify）。
        if (allowInsecure is "1" or "true") proxy["skip-cert-verify"] = true;
        // ALPN：逗号分隔字符串 → 列表。
        if (!string.IsNullOrEmpty(alpnRaw))
            proxy["alpn"] = alpnRaw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0)
                .Cast<object?>().ToList();
        if (!string.IsNullOrEmpty(flow)) proxy["flow"] = flow;

        return proxy;
    }

    // ------------------------------------------------------------------
    // 反向构建：Clash 节点字典 → 分享链接 URL
    // ------------------------------------------------------------------

    /// <summary>
    /// 将 Clash 节点字典还原为对应的分享链接（按 type 字段分发）。
    /// </summary>
    /// <exception cref="Exception">type 不在支持列表中时抛出。</exception>
    public static string ProxyToUrl(Dictionary<string, object?> p)
    {
        var type = Str(p, "type") ?? "";
        return type switch
        {
            "vless" => ProxyToVless(p),
            "vmess" => ProxyToVmess(p),
            "ss" => ProxyToSs(p),
            "ssr" => ProxyToSsr(p),
            "trojan" => ProxyToTrojan(p),
            _ => throw new Exception($"不支持的协议: {type}")
        };
    }

    /// <summary>
    /// 将 VLESS 节点字典还原为分享链接：
    ///   vless://uuid@host:port?type=..&amp;security=..&amp;sni=..#备注
    /// reality-opts 存在时 security 设为 reality 并携带 pbk/sid/spx。
    /// </summary>
    public static string ProxyToVless(Dictionary<string, object?> p)
    {
        var uid = Str(p, "uuid") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";
        var network = Str(p, "network") ?? "tcp";
        var tls = Bool(p, "tls");
        var reality = Sub(p, "reality-opts");

        // 收集查询参数：type 必填，security 由 tls/reality 推导。
        var q = new Dictionary<string, string> { ["type"] = network };
        if (tls) q["security"] = reality != null ? "reality" : "tls";
        var flow = Str(p, "flow");
        if (!string.IsNullOrEmpty(flow)) q["flow"] = flow;
        var sni = Str(p, "servername");
        if (!string.IsNullOrEmpty(sni)) q["sni"] = sni;
        var fp = Str(p, "client-fingerprint");
        if (!string.IsNullOrEmpty(fp)) q["fp"] = fp;

        // REALITY 选项回填到查询参数。
        if (reality != null)
        {
            if (reality.TryGetValue("public-key", out var pbk) && pbk != null) q["pbk"] = pbk.ToString()!;
            if (reality.TryGetValue("short-id", out var sid) && sid != null) q["sid"] = sid.ToString()!;
            if (reality.TryGetValue("spider-x", out var spx) && spx != null) q["spx"] = spx.ToString()!;
        }

        // WebSocket 选项回填：path 与 Host 头。
        if (network == "ws" && p.TryGetValue("ws-opts", out var wo) && wo is Dictionary<string, object?> wd)
        {
            if (wd.TryGetValue("path", out var wp) && wp != null) q["path"] = wp.ToString()!;
            if (wd.TryGetValue("headers", out var wh) && wh is Dictionary<string, object?> hd &&
                hd.TryGetValue("Host", out var hv) && hv != null)
                q["host"] = hv.ToString()!;
        }

        // gRPC 选项回填：服务名。
        if (network == "grpc" && p.TryGetValue("grpc-opts", out var go) && go is Dictionary<string, object?> gd &&
            gd.TryGetValue("grpc-service-name", out var gsv) && gsv != null)
            q["serviceName"] = gsv.ToString()!;

        // HTTP/2 选项回填：路径。
        if (network == "h2" && p.TryGetValue("h2-opts", out var ho) && ho is Dictionary<string, object?> hd2 &&
            hd2.TryGetValue("path", out var hp) && hp != null)
            q["path"] = hp.ToString()!;

        // 拼接最终 URL：查询参数做 URL 编码，备注放 '#' 之后。
        var qs = string.Join("&", q.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        var url = $"vless://{uid}@{server}:{port}?{qs}";
        if (!string.IsNullOrEmpty(name)) url += "#" + Uri.EscapeDataString(name);
        return url;
    }

    /// <summary>
    /// 将 VMess 节点字典还原为分享链接：
    /// 序列化为 v2rayN 约定的 JSON（v:"2"），整体 base64 编码后拼接 "vmess://" 前缀。
    /// JSON 序列化使用宽松转义器，避免中文节点名被转义为 \uXXXX。
    /// </summary>
    public static string ProxyToVmess(Dictionary<string, object?> p)
    {
        var name = Str(p, "name") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var uuid = Str(p, "uuid") ?? "";
        var alterId = Int(p, "alterId", 0);
        var network = Str(p, "network") ?? "tcp";
        var isTls = Bool(p, "tls");
        var sni = Str(p, "servername");
        var alpn = p.Alpn("alpn");

        // v2rayN JSON 格式的固定字段结构。
        var data = new Dictionary<string, object?>
        {
            ["v"] = "2",
            ["ps"] = name,
            ["add"] = server,
            ["port"] = port,
            ["id"] = uuid,
            ["aid"] = alterId,
            ["net"] = network,
            ["type"] = "none",
            ["tls"] = isTls ? "tls" : "none",
        };

        // 提取 ws / grpc / h2 传输选项回填到 JSON 字段。
        string host = "", path = "";
        if (network == "ws" && p.TryGetValue("ws-opts", out var wo) && wo is Dictionary<string, object?> wd)
        {
            if (wd.TryGetValue("path", out var wp) && wp != null) path = wp.ToString()!;
            if (wd.TryGetValue("headers", out var wh) && wh is Dictionary<string, object?> hd &&
                hd.TryGetValue("Host", out var hv) && hv != null)
                host = hv.ToString()!;
        }

        if (network == "grpc" && p.TryGetValue("grpc-opts", out var go) && go is Dictionary<string, object?> gd &&
            gd.TryGetValue("grpc-service-name", out var gsv) && gsv != null)
            data["serviceName"] = gsv.ToString()!;

        if (network == "h2" && p.TryGetValue("h2-opts", out var ho) && ho is Dictionary<string, object?> hd2 &&
            hd2.TryGetValue("path", out var hp) && hp != null)
            path = hp.ToString()!;

        data["host"] = host;
        data["path"] = path;
        if (!string.IsNullOrEmpty(sni)) data["sni"] = sni;
        if (alpn.Count > 0) data["alpn"] = string.Join(",", alpn);

        // 宽松 JSON 转义：保留非 ASCII 字符原样输出，base64 后信息无损。
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        return "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    /// <summary>
    /// 将 SS 节点字典还原为分享链接（SIP002 格式）：
    ///   ss://base64(method:password)@host:port?plugin=..#备注
    /// userinfo 的 base64 去掉填充符（SIP002 约定）。
    /// </summary>
    public static string ProxyToSs(Dictionary<string, object?> p)
    {
        var method = Str(p, "cipher") ?? "";
        var password = Str(p, "password") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";

        // method:password 整体 base64 后作为 userinfo。
        var up = $"{method}:{password}";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(up)).TrimEnd('=');
        var url = $"ss://{encoded}@{server}:{port}";
        var plugin = Str(p, "plugin");
        if (!string.IsNullOrEmpty(plugin)) url += "?plugin=" + Uri.EscapeDataString(plugin);
        if (!string.IsNullOrEmpty(name)) url += "#" + Uri.EscapeDataString(name);
        return url;
    }

    /// <summary>
    /// 将 SSR 节点字典还原为分享链接：
    ///   ssr://base64(host:port:protocol:cipher:obfs:base64(password))?remarks=base64&amp;...
    /// 两层 base64 均为 URL-safe 且无填充；查询参数与正向解析约定 #1 对应。
    /// </summary>
    public static string ProxyToSsr(Dictionary<string, object?> p)
    {
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var protocol = Str(p, "protocol") ?? "";
        var cipher = Str(p, "cipher") ?? "";
        var obfs = Str(p, "obfs") ?? "";
        var password = Str(p, "password") ?? "";
        var name = Str(p, "name") ?? "";

        // 第一层：密码单独 base64；第二层：整体六段式再 base64。
        var b64pass = UrlSafeB64(Encoding.UTF8.GetBytes(password));
        var raw = $"{server}:{port}:{protocol}:{cipher}:{obfs}:{b64pass}";
        var encoded = UrlSafeB64(Encoding.UTF8.GetBytes(raw));

        // 可选查询参数：remarks / protoparam / obfsparam（各自 base64 编码）。
        var q = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(name)) q["remarks"] = UrlSafeB64(Encoding.UTF8.GetBytes(name));
        var pp = Str(p, "protocol-param");
        if (!string.IsNullOrEmpty(pp)) q["protoparam"] = UrlSafeB64(Encoding.UTF8.GetBytes(pp));
        var op = Str(p, "obfs-param");
        if (!string.IsNullOrEmpty(op)) q["obfsparam"] = UrlSafeB64(Encoding.UTF8.GetBytes(op));

        var url = "ssr://" + encoded;
        if (q.Count > 0)
            url += "?" + string.Join("&", q.Select(kv => $"{kv.Key}={kv.Value}"));
        return url;
    }

    /// <summary>
    /// 将 Trojan 节点字典还原为分享链接：
    ///   trojan://password@host:port?sni=..&amp;allowInsecure=1#备注
    /// skip-cert-verify=true 映射回 allowInsecure=1。
    /// </summary>
    public static string ProxyToTrojan(Dictionary<string, object?> p)
    {
        var password = Str(p, "password") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";

        var q = new Dictionary<string, string>();
        // SNI：显式 sni 优先，否则回退到服务器地址（与正向解析对称）。
        var sni = Str(p, "sni");
        if (!string.IsNullOrEmpty(sni)) q["sni"] = sni;
        else if (!string.IsNullOrEmpty(server)) q["sni"] = server;
        if (Bool(p, "skip-cert-verify")) q["allowInsecure"] = "1";
        var alpn = p.Alpn("alpn");
        if (alpn.Count > 0) q["alpn"] = string.Join(",", alpn);
        var flow = Str(p, "flow");
        if (!string.IsNullOrEmpty(flow)) q["flow"] = flow;

        var url = $"trojan://{password}@{server}:{port}";
        if (q.Count > 0)
            url += "?" + string.Join("&", q.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        if (!string.IsNullOrEmpty(name)) url += "#" + Uri.EscapeDataString(name);
        return url;
    }

    // ------------------------------------------------------------------
    // Clash 配置构建
    // ------------------------------------------------------------------

    /// <summary>
    /// 构建完整的单节点 Clash 配置：常用全局参数 + 单节点代理组 + 兜底规则。
    /// 生成结果可直接导入 Clash 作为可运行配置。
    /// </summary>
    public static Dictionary<string, object?> BuildClashConfig(Dictionary<string, object?> proxy)
    {
        return new Dictionary<string, object?>
        {
            ["port"] = 7890,          // HTTP 代理端口
            ["socks-port"] = 7891,    // SOCKS5 代理端口
            ["allow-lan"] = true,     // 允许局域网连接
            ["mode"] = "rule",        // 规则模式
            ["log-level"] = "warning",
            ["proxies"] = new List<object?> { proxy },
            // 单节点选择组，供 rules 引用。
            ["proxy-groups"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["name"] = "Proxy",
                    ["type"] = "select",
                    ["proxies"] = new List<object?> { proxy["name"] },
                },
            },
            // 兜底规则：全部流量走 Proxy 组。
            ["rules"] = new List<object?> { "MATCH,Proxy" },
        };
    }

    /// <summary>
    /// 构建仅含 proxies 列表的最小配置，用于订阅端点 /api/sub 的返回内容。
    /// </summary>
    public static Dictionary<string, object?> BuildSubConfig(Dictionary<string, object?> proxy)
    {
        return new Dictionary<string, object?>
        {
            ["proxies"] = new List<object?> { proxy },
        };
    }

    /// <summary>
    /// 正向转换入口：分享链接 → (协议类型, 完整 Clash YAML, 节点名)。
    /// 供 POST /api/convert 使用。
    /// </summary>
    /// <exception cref="Exception">协议无法识别或解析失败时抛出。</exception>
    public static (string proto, string yaml, string name) ProxyUrlToYaml(string url)
    {
        var proto = DetectProtocol(url) ?? throw new Exception("不支持的协议类型");
        var proxy = Parse(url);
        var cfg = BuildClashConfig(proxy);
        return (proto, ToYaml(cfg), proxy["name"]?.ToString() ?? "config");
    }

    /// <summary>
    /// 正向转换入口（订阅版）：分享链接 → 仅含 proxies 的 YAML 文本。
    /// 供 GET /api/sub 使用。
    /// </summary>
    /// <exception cref="Exception">协议无法识别或解析失败时抛出。</exception>
    public static string ProxyUrlToSubYaml(string url)
    {
        var proto = DetectProtocol(url) ?? throw new Exception("不支持的协议类型");
        var proxy = Parse(url);
        var cfg = BuildSubConfig(proxy);
        return ToYaml(cfg);
    }

    // ------------------------------------------------------------------
    // 反向转换：Clash YAML → 分享链接列表
    // ------------------------------------------------------------------

    /// <summary>
    /// 解析 Clash 配置 YAML，把其中的每个节点还原为分享链接。
    /// 兼容三种输入形态：proxies 列表本身、含 proxies 键的完整配置、
    /// 含 proxy 键（部分旧版/非标配置）。单个节点转换失败不影响其他节点，
    /// 失败项以 url=null + error 字段表示。
    /// </summary>
    /// <exception cref="Exception">YAML 为空、语法错误或找不到节点列表时抛出。</exception>
    public static List<Dictionary<string, object?>> YamlToProxyUrls(string yaml)
    {
        // 反序列化为弱类型树（object 树），后续统一归一化处理。
        object? data;
        try
        {
            data = YamlDeser.Deserialize<object>(yaml);
        }
        catch (YamlDotNet.Core.YamlException ye)
        {
            throw new Exception($"YAML 解析失败: {ye.Message}");
        }

        if (data == null)
            throw new Exception("YAML 内容为空");

        // 归一化：把 YamlDotNet 产出的 Dictionary<object,object> 统一转为
        // Dictionary<string,object?>（键不区分大小写），便于后续取值。
        var norm = Normalize(data);

        // 定位节点列表：三种兼容形态。
        List<Dictionary<string, object?>> proxies;
        if (norm is List<object?> list)
        {
            // 输入本身就是节点列表。
            proxies = list.OfType<Dictionary<string, object?>>().ToList();
        }
        else if (norm is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("proxies", out var pv) && pv is List<object?> pl)
                proxies = pl.OfType<Dictionary<string, object?>>().ToList();
            else if (dict.TryGetValue("proxy", out var pv2) && pv2 is List<object?> pl2)
                proxies = pl2.OfType<Dictionary<string, object?>>().ToList();
            else
                throw new Exception("未找到 proxies 配置");
        }
        else
        {
            throw new Exception("未找到 proxies 配置");
        }

        if (proxies.Count == 0)
            throw new Exception("未找到 proxies 配置");

        // 逐节点转换；单个节点失败不中断整体流程。
        var results = new List<Dictionary<string, object?>>();
        foreach (var proxy in proxies)
        {
            var type = Str(proxy, "type") ?? "";
            var name = Str(proxy, "name") ?? "";
            try
            {
                var url = ProxyToUrl(proxy);
                results.Add(new Dictionary<string, object?>
                {
                    ["name"] = name,
                    ["type"] = type,
                    ["url"] = url,
                });
            }
            catch (Exception e)
            {
                // 失败项记录错误信息，url 置空。
                results.Add(new Dictionary<string, object?>
                {
                    ["name"] = name,
                    ["type"] = type,
                    ["url"] = null,
                    ["error"] = e.Message,
                });
            }
        }

        return results;
    }

    // ------------------------------------------------------------------
    // 内部辅助方法
    // ------------------------------------------------------------------

    /// <summary>
    /// 递归归一化 YamlDotNet 的反序列化产物：
    /// Dictionary&lt;object,object&gt; → Dictionary&lt;string,object?&gt;（键忽略大小写），
    /// List&lt;object&gt; → List&lt;object?&gt;，标量原样返回。
    /// </summary>
    private static object? Normalize(object? node)
    {
        return node switch
        {
            null => null,
            Dictionary<object, object> d => d.ToDictionary(
                kv => kv.Key?.ToString() ?? "",
                kv => Normalize(kv.Value),
                StringComparer.OrdinalIgnoreCase),
            List<object> l => l.Select(Normalize).ToList(),
            _ => node
        };
    }

    /// <summary>从 VMess JSON 元素取字符串值；数字字段按原文返回字符串形态。</summary>
    private static string? JsonStr(JsonElement e, string key)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.String) return v.GetString();
            if (v.ValueKind == JsonValueKind.Number) return v.GetRawText();
        }

        return null;
    }

    /// <summary>从 VMess JSON 元素取整数值；兼容数字与数字字符串两种形态，缺失时返回默认值。</summary>
    private static int JsonInt(JsonElement e, string key, int def = 0)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number)
                return v.GetInt32();
            if (v.ValueKind == JsonValueKind.String &&
                int.TryParse(v.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var si))
                return si;
        }

        return def;
    }

    /// <summary>在分隔符“最后一次出现”处切分字符串，返回 (前段, 后段)。用于兼容含 ':' 的 IPv6 地址等情况。</summary>
    private static (string Key, string Value) SplitLast(string s, char sep)
    {
        var idx = s.LastIndexOf(sep);
        if (idx < 0) return (s, "");
        return (s.Substring(0, idx), s.Substring(idx + 1));
    }
}
