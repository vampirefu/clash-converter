using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;

namespace ClashConverter;

/// <summary>
/// Core conversion engine: proxy URL <-> Clash YAML, covering VLESS / VMess / SS / SSR / Trojan.
/// Mirrors the original Python implementation's behaviour and field mapping.
/// </summary>
public static class Converter
{
    // ------------------------------------------------------------------
    // Serialization
    // ------------------------------------------------------------------
    private static readonly ISerializer YamlSer = new SerializerBuilder().Build();
    private static readonly IDeserializer YamlDeser = new DeserializerBuilder().Build();

    private static string ToYaml(object obj) => YamlSer.Serialize(obj);

    // ------------------------------------------------------------------
    // Base64 helpers (accept both standard and url-safe, with/without padding)
    // ------------------------------------------------------------------
    private static string B64DecodeString(string s)
    {
        var rev = s.Replace('-', '+').Replace('_', '/');
        var pad = (4 - rev.Length % 4) % 4;
        if (pad > 0)
            rev = rev.PadRight(rev.Length + pad, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(rev));
    }

    private static string UrlSafeB64(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    // ------------------------------------------------------------------
    // Query string parsing (mirrors urllib.parse.parse_qsl)
    // ------------------------------------------------------------------
    private static Dictionary<string, string> ParseQsl(string qs)
    {
        var dict = new Dictionary<string, string>();
        foreach (var pair in qs.Split('&'))
        {
            if (pair.Length == 0)
                continue;
            var kv = pair.Split('=', 2);
            var k = Uri.UnescapeDataString(kv[0]);
            var v = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
            dict[k] = v; // last value wins, same as parse_qsl
        }

        return dict;
    }

    // ------------------------------------------------------------------
    // Dictionary access helpers (proxy is a Dictionary<string, object?>)
    // ------------------------------------------------------------------
    private static string Q(this Dictionary<string, string> d, string k, string def = "")
        => d.TryGetValue(k, out var v) ? v : def;

    private static string? Str(this Dictionary<string, object?> d, string key)
        => d.TryGetValue(key, out var v) ? v?.ToString() : null;

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

    private static Dictionary<string, object?>? Sub(this Dictionary<string, object?> d, string key)
        => d.TryGetValue(key, out var v) && v is Dictionary<string, object?> dd ? dd : null;

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
    // Protocol detection
    // ------------------------------------------------------------------
    private static readonly (string Prefix, string Name)[] Prefixes =
    {
        ("vless://", "vless"),
        ("vmess://", "vmess"),
        ("ss://", "ss"),
        ("ssr://", "ssr"),
        ("trojan://", "trojan"),
    };

    public static string? DetectProtocol(string url)
    {
        foreach (var (prefix, name) in Prefixes)
            if (url.StartsWith(prefix, StringComparison.Ordinal))
                return name;
        return null;
    }

    // ------------------------------------------------------------------
    // Forward parsers: proxy URL -> Clash proxy dict
    // ------------------------------------------------------------------
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

    public static Dictionary<string, object?> ParseVless(string url)
    {
        var raw = url.Substring(8);
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

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

        var m = Regex.Match(main, @"^([^@]+)@([^:]+):(\d+)");
        if (!m.Success)
            throw new Exception("无法解析 VLESS 链接的主机信息");
        var uid = m.Groups[1].Value;
        var host = m.Groups[2].Value;
        var port = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);

        var network = Q(prm, "type", "tcp");
        var security = Q(prm, "security", "none");
        var flow = Q(prm, "flow");
        var sni = Q(prm, "sni");
        var fp = Q(prm, "fp");
        var pbk = Q(prm, "pbk");
        var sid = Q(prm, "sid");
        var spx = Q(prm, "spx");
        var pathVal = Q(prm, "path");
        var hostVal = Q(prm, "host");
        var svc = Q(prm, "serviceName");

        var isTls = security is "tls" or "reality";
        var isReality = security == "reality";

        var proxy = new Dictionary<string, object?>
        {
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

        if (!string.IsNullOrEmpty(flow)) proxy["flow"] = flow;
        if (!string.IsNullOrEmpty(sni)) proxy["servername"] = sni;
        else if (!string.IsNullOrEmpty(host) && (isTls || isReality)) proxy["servername"] = host;
        if (!string.IsNullOrEmpty(fp)) proxy["client-fingerprint"] = fp;

        if (isReality)
        {
            var ro = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pbk)) ro["public-key"] = pbk;
            if (!string.IsNullOrEmpty(sid)) ro["short-id"] = sid;
            if (!string.IsNullOrEmpty(spx)) ro["spider-x"] = spx;
            if (ro.Count > 0) proxy["reality-opts"] = ro;
        }

        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal)) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    public static Dictionary<string, object?> ParseVmess(string url)
    {
        var raw = url.Substring(8);
        if (raw.Contains('@'))
            return ParseVmessLikeVless(raw);

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

        if (!string.IsNullOrEmpty(sni) && isTls) proxy["servername"] = sni;
        if (!string.IsNullOrEmpty(alpnRaw))
            proxy["alpn"] = alpnRaw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0)
                .Cast<object?>().ToList();

        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal) && hostVal != sni) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            var svc = JsonStr(data, "serviceName") ?? "";
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    private static Dictionary<string, object?> ParseVmessLikeVless(string raw)
    {
        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

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
            ["alterId"] = int.Parse(Q(prm, "aid", "0"), CultureInfo.InvariantCulture),
            ["cipher"] = "auto",
            ["network"] = network,
            ["tls"] = isTls,
            ["udp"] = true,
        };

        if (!string.IsNullOrEmpty(sni)) proxy["servername"] = sni;

        if (network == "ws")
        {
            var wo = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(pathVal)) wo["path"] = pathVal;
            var hd = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(hostVal)) hd["Host"] = hostVal;
            if (hd.Count > 0) wo["headers"] = hd;
            if (wo.Count > 0) proxy["ws-opts"] = wo;
        }

        if (network == "grpc")
        {
            var go = new Dictionary<string, object?>();
            var svc = Q(prm, "serviceName");
            if (!string.IsNullOrEmpty(svc)) go["grpc-service-name"] = svc;
            if (go.Count > 0) proxy["grpc-opts"] = go;
        }

        if (network == "h2" && !string.IsNullOrEmpty(pathVal))
            proxy["h2-opts"] = new Dictionary<string, object?> { ["path"] = pathVal };

        return proxy;
    }

    public static Dictionary<string, object?> ParseSs(string url)
    {
        var raw = url.Substring(5);

        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

        string plugin = "";
        var qIdx = raw.IndexOf('?');
        if (qIdx >= 0)
        {
            var qs = raw.Substring(qIdx + 1);
            raw = raw.Substring(0, qIdx);
            var q = ParseQsl(qs);
            plugin = Q(q, "plugin");
        }

        string method;
        string password;
        string server;
        int port;

        if (raw.Contains('@'))
        {
            var parts = raw.Split('@', 2);
            var decoded = B64DecodeString(parts[0]);
            var mp = decoded.Split(':', 2);
            method = mp[0];
            password = mp.Length > 1 ? mp[1] : "";
            var sp = SplitLast(parts[1], ':');
            server = sp.Key;
            port = int.Parse(sp.Value, CultureInfo.InvariantCulture);
        }
        else
        {
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

    public static Dictionary<string, object?> ParseSsr(string url)
    {
        var raw = url.Substring(6);
        var prm = new Dictionary<string, string>();
        string base64Payload;

        var topQ = raw.IndexOf('?');
        if (topQ < 0)
        {
            // No query string: the whole remainder is the base64 payload.
            base64Payload = raw;
        }
        else
        {
            // Convention #1 (modern clients): ssr://base64(payload)?remarks=..&..
            // The base64 payload sits before '?'; the query carries base64-encoded params.
            try
            {
                B64DecodeString(raw.Substring(0, topQ)); // probe validity
                base64Payload = raw.Substring(0, topQ);
                foreach (var kv in ParseQsl(raw.Substring(topQ + 1)))
                    prm[kv.Key] = TryB64(kv.Value);
            }
            catch
            {
                // Convention #2 (legacy): the entire remainder (incl. "?...") is base64.
                string decoded;
                try
                {
                    decoded = B64DecodeString(raw);
                }
                catch (Exception ex)
                {
                    throw new Exception($"SSR Base64 解码失败: {ex.Message}");
                }

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

        var server = parts[0];
        var port = int.Parse(parts[1]!, CultureInfo.InvariantCulture);
        var protocol = parts[2];
        var cipher = parts[3];
        var obfs = parts[4];
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

    // Decode as base64 if possible, otherwise return the original string.
    // Used for SSR query params which may or may not be base64-encoded.
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

    public static Dictionary<string, object?> ParseTrojan(string url)
    {
        var raw = url.Substring(9);

        string remark = "";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            remark = Uri.UnescapeDataString(raw.Substring(hashIdx + 1));
            raw = raw.Substring(0, hashIdx);
        }

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

        if (!string.IsNullOrEmpty(sni)) proxy["sni"] = sni;
        else if (!string.IsNullOrEmpty(host)) proxy["sni"] = host;
        if (allowInsecure is "1" or "true") proxy["skip-cert-verify"] = true;
        if (!string.IsNullOrEmpty(alpnRaw))
            proxy["alpn"] = alpnRaw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0)
                .Cast<object?>().ToList();
        if (!string.IsNullOrEmpty(flow)) proxy["flow"] = flow;

        return proxy;
    }

    // ------------------------------------------------------------------
    // Reverse builders: Clash proxy dict -> proxy URL
    // ------------------------------------------------------------------
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

    public static string ProxyToVless(Dictionary<string, object?> p)
    {
        var uid = Str(p, "uuid") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";
        var network = Str(p, "network") ?? "tcp";
        var tls = Bool(p, "tls");
        var reality = Sub(p, "reality-opts");

        var q = new Dictionary<string, string> { ["type"] = network };
        if (tls) q["security"] = reality != null ? "reality" : "tls";
        var flow = Str(p, "flow");
        if (!string.IsNullOrEmpty(flow)) q["flow"] = flow;
        var sni = Str(p, "servername");
        if (!string.IsNullOrEmpty(sni)) q["sni"] = sni;
        var fp = Str(p, "client-fingerprint");
        if (!string.IsNullOrEmpty(fp)) q["fp"] = fp;

        if (reality != null)
        {
            if (reality.TryGetValue("public-key", out var pbk) && pbk != null) q["pbk"] = pbk.ToString()!;
            if (reality.TryGetValue("short-id", out var sid) && sid != null) q["sid"] = sid.ToString()!;
            if (reality.TryGetValue("spider-x", out var spx) && spx != null) q["spx"] = spx.ToString()!;
        }

        if (network == "ws" && p.TryGetValue("ws-opts", out var wo) && wo is Dictionary<string, object?> wd)
        {
            if (wd.TryGetValue("path", out var wp) && wp != null) q["path"] = wp.ToString()!;
            if (wd.TryGetValue("headers", out var wh) && wh is Dictionary<string, object?> hd &&
                hd.TryGetValue("Host", out var hv) && hv != null)
                q["host"] = hv.ToString()!;
        }

        if (network == "grpc" && p.TryGetValue("grpc-opts", out var go) && go is Dictionary<string, object?> gd &&
            gd.TryGetValue("grpc-service-name", out var gsv) && gsv != null)
            q["serviceName"] = gsv.ToString()!;

        if (network == "h2" && p.TryGetValue("h2-opts", out var ho) && ho is Dictionary<string, object?> hd2 &&
            hd2.TryGetValue("path", out var hp) && hp != null)
            q["path"] = hp.ToString()!;

        var qs = string.Join("&", q.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        var url = $"vless://{uid}@{server}:{port}?{qs}";
        if (!string.IsNullOrEmpty(name)) url += "#" + Uri.EscapeDataString(name);
        return url;
    }

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

        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        return "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public static string ProxyToSs(Dictionary<string, object?> p)
    {
        var method = Str(p, "cipher") ?? "";
        var password = Str(p, "password") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";

        var up = $"{method}:{password}";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(up)).TrimEnd('=');
        var url = $"ss://{encoded}@{server}:{port}";
        var plugin = Str(p, "plugin");
        if (!string.IsNullOrEmpty(plugin)) url += "?plugin=" + Uri.EscapeDataString(plugin);
        if (!string.IsNullOrEmpty(name)) url += "#" + Uri.EscapeDataString(name);
        return url;
    }

    public static string ProxyToSsr(Dictionary<string, object?> p)
    {
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var protocol = Str(p, "protocol") ?? "";
        var cipher = Str(p, "cipher") ?? "";
        var obfs = Str(p, "obfs") ?? "";
        var password = Str(p, "password") ?? "";
        var name = Str(p, "name") ?? "";

        var b64pass = UrlSafeB64(Encoding.UTF8.GetBytes(password));
        var raw = $"{server}:{port}:{protocol}:{cipher}:{obfs}:{b64pass}";
        var encoded = UrlSafeB64(Encoding.UTF8.GetBytes(raw));

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

    public static string ProxyToTrojan(Dictionary<string, object?> p)
    {
        var password = Str(p, "password") ?? "";
        var server = Str(p, "server") ?? "";
        var port = Int(p, "port", 0);
        var name = Str(p, "name") ?? "";

        var q = new Dictionary<string, string>();
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
    // Clash config builders
    // ------------------------------------------------------------------
    public static Dictionary<string, object?> BuildClashConfig(Dictionary<string, object?> proxy)
    {
        return new Dictionary<string, object?>
        {
            ["port"] = 7890,
            ["socks-port"] = 7891,
            ["allow-lan"] = true,
            ["mode"] = "rule",
            ["log-level"] = "warning",
            ["proxies"] = new List<object?> { proxy },
            ["proxy-groups"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["name"] = "Proxy",
                    ["type"] = "select",
                    ["proxies"] = new List<object?> { proxy["name"] },
                },
            },
            ["rules"] = new List<object?> { "MATCH,Proxy" },
        };
    }

    public static Dictionary<string, object?> BuildSubConfig(Dictionary<string, object?> proxy)
    {
        return new Dictionary<string, object?>
        {
            ["proxies"] = new List<object?> { proxy },
        };
    }

    public static (string proto, string yaml, string name) ProxyUrlToYaml(string url)
    {
        var proto = DetectProtocol(url) ?? throw new Exception("不支持的协议类型");
        var proxy = Parse(url);
        var cfg = BuildClashConfig(proxy);
        return (proto, ToYaml(cfg), proxy["name"]?.ToString() ?? "config");
    }

    public static string ProxyUrlToSubYaml(string url)
    {
        var proto = DetectProtocol(url) ?? throw new Exception("不支持的协议类型");
        var proxy = Parse(url);
        var cfg = BuildSubConfig(proxy);
        return ToYaml(cfg);
    }

    // ------------------------------------------------------------------
    // Reverse: Clash YAML -> proxy URLs
    // ------------------------------------------------------------------
    public static List<Dictionary<string, object?>> YamlToProxyUrls(string yaml)
    {
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

        var norm = Normalize(data);

        List<Dictionary<string, object?>> proxies;
        if (norm is List<object?> list)
        {
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
    // Internal helpers
    // ------------------------------------------------------------------
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

    private static string? JsonStr(JsonElement e, string key)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.String) return v.GetString();
            if (v.ValueKind == JsonValueKind.Number) return v.GetRawText();
        }

        return null;
    }

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

    // Split on the LAST occurrence of sep, returning (before, after).
    private static (string Key, string Value) SplitLast(string s, char sep)
    {
        var idx = s.LastIndexOf(sep);
        if (idx < 0) return (s, "");
        return (s.Substring(0, idx), s.Substring(idx + 1));
    }
}
