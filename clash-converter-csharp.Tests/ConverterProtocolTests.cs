using System;
using System.Collections.Generic;
using System.Text;
using ClashConverter;
using Xunit;

namespace ClashConverter.Tests;

public class ConverterProtocolTests
{
    // ---- protocol detection -------------------------------------------------
    [Theory]
    [InlineData("vless://x@y:1", "vless")]
    [InlineData("vmess://x", "vmess")]
    [InlineData("ss://x", "ss")]
    [InlineData("ssr://x", "ssr")]
    [InlineData("trojan://x", "trojan")]
    public void DetectProtocol_KnownPrefixes(string url, string expected)
        => Assert.Equal(expected, Converter.DetectProtocol(url));

    [Fact]
    public void DetectProtocol_Unknown_ReturnsNull()
        => Assert.Null(Converter.DetectProtocol("http://example.com"));

    [Fact]
    public void Parse_Unsupported_Throws()
        => Assert.Throws<Exception>(() => Converter.Parse("ftp://nope"));

    // ---- VLESS --------------------------------------------------------------
    [Fact]
    public void Parse_Vless_RealityWs()
    {
        var url = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=ws&security=reality&pbk=ABCDEF&sid=0123&spx=%2F&path=%2Fws&flow=xtls-rprx-vision&sni=example.com&fp=chrome#MyVLESS";
        var p = Converter.Parse(url);
        Assert.Equal("MyVLESS", p["name"]);
        Assert.Equal("vless", p["type"]);
        Assert.Equal("1.2.3.4", p["server"]);
        Assert.Equal(443, (int)p["port"]!);
        Assert.Equal("11111111-2222-3333-4444-555555555555", p["uuid"]);
        Assert.Equal("ws", p["network"]);
        Assert.True((bool)p["tls"]!);
        Assert.Equal("xtls-rprx-vision", p["flow"]);
        Assert.Equal("example.com", p["servername"]);
        Assert.Equal("chrome", p["client-fingerprint"]);

        var reality = Assert.IsType<Dictionary<string, object?>>(p["reality-opts"]);
        Assert.Equal("ABCDEF", reality["public-key"]);
        Assert.Equal("0123", reality["short-id"]);
        Assert.Equal("/", reality["spider-x"]);

        var ws = Assert.IsType<Dictionary<string, object?>>(p["ws-opts"]);
        Assert.Equal("/ws", ws["path"]);
    }

    // ---- VMess (standard base64 JSON) --------------------------------------
    [Fact]
    public void Parse_Vmess_Standard()
    {
        var json = "{\"v\":\"2\",\"ps\":\"MyVMess\",\"add\":\"5.6.7.8\",\"port\":\"443\",\"id\":\"22222222-2222-2222-2222-222222222222\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"example.com\",\"path\":\"/ws\",\"tls\":\"tls\"}";
        var url = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
        var p = Converter.Parse(url);

        Assert.Equal("MyVMess", p["name"]);
        Assert.Equal("vmess", p["type"]);
        Assert.Equal("5.6.7.8", p["server"]);
        Assert.Equal(443, (int)p["port"]!);            // string port is handled
        Assert.Equal("22222222-2222-2222-2222-222222222222", p["uuid"]);
        Assert.Equal(0, (int)p["alterId"]!);
        Assert.Equal("ws", p["network"]);
        Assert.True((bool)p["tls"]!);
        Assert.Equal("example.com", p["servername"]);

        var ws = Assert.IsType<Dictionary<string, object?>>(p["ws-opts"]);
        Assert.Equal("/ws", ws["path"]);
    }

    [Fact]
    public void Parse_Vmess_LikeVless()
    {
        var url = "vmess://22222222-2222-2222-2222-222222222222@5.6.7.8:443?type=ws&security=tls&path=%2Fws&host=example.com#MyVMess2";
        var p = Converter.Parse(url);
        Assert.Equal("MyVMess2", p["name"]);
        Assert.Equal("vmess", p["type"]);
        Assert.Equal("5.6.7.8", p["server"]);
        Assert.Equal(443, (int)p["port"]!);
        Assert.True((bool)p["tls"]!);
        Assert.Equal("ws", p["network"]);
    }

    // ---- Shadowsocks (SIP002) ----------------------------------------------
    [Fact]
    public void Parse_Ss_Sip002()
    {
        var user = TestHelpers.UrlSafeB64("aes-256-gcm:pass");
        var url = $"ss://{user}@9.10.11.12:8388#MySS";
        var p = Converter.Parse(url);
        Assert.Equal("MySS", p["name"]);
        Assert.Equal("ss", p["type"]);
        Assert.Equal("9.10.11.12", p["server"]);
        Assert.Equal(8388, (int)p["port"]!);
        Assert.Equal("aes-256-gcm", p["cipher"]);
        Assert.Equal("pass", p["password"]);
    }

    [Fact]
    public void Parse_Ss_Traditional()
    {
        // ss://base64(method:pass@server:port)
        var inner = TestHelpers.B64("aes-256-cfb:secret@9.10.11.12:8388");
        var url = $"ss://{inner}#MySS2";
        var p = Converter.Parse(url);
        Assert.Equal("ss", p["type"]);
        Assert.Equal("9.10.11.12", p["server"]);
        Assert.Equal(8388, (int)p["port"]!);
        Assert.Equal("aes-256-cfb", p["cipher"]);
        Assert.Equal("secret", p["password"]);
    }

    // ---- ShadowsocksR -------------------------------------------------------
    [Fact]
    public void Parse_Ssr()
    {
        var raw = $"13.14.15.16:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{TestHelpers.UrlSafeB64("ssrpass")}";
        var encoded = TestHelpers.UrlSafeB64(raw);
        var url = $"ssr://{encoded}?remarks={TestHelpers.UrlSafeB64("MySSR")}&protoparam={TestHelpers.UrlSafeB64("pp")}&obfsparam={TestHelpers.UrlSafeB64("op")}";
        var p = Converter.Parse(url);

        Assert.Equal("MySSR", p["name"]);
        Assert.Equal("ssr", p["type"]);
        Assert.Equal("13.14.15.16", p["server"]);
        Assert.Equal(8388, (int)p["port"]!);
        Assert.Equal("aes-256-cfb", p["cipher"]);
        Assert.Equal("ssrpass", p["password"]);
        Assert.Equal("auth_aes128_md5", p["protocol"]);
        Assert.Equal("pp", p["protocol-param"]);
        Assert.Equal("tls1.2_ticket_auth", p["obfs"]);
        Assert.Equal("op", p["obfs-param"]);
        Assert.True((bool)p["udp"]!);
    }

    // ---- Trojan -------------------------------------------------------------
    [Fact]
    public void Parse_Trojan()
    {
        var url = "trojan://tp@17.18.19.20:443?sni=example.com&allowInsecure=1&alpn=http%2F1.1%2Ch2#MyTrojan";
        var p = Converter.Parse(url);
        Assert.Equal("MyTrojan", p["name"]);
        Assert.Equal("trojan", p["type"]);
        Assert.Equal("17.18.19.20", p["server"]);
        Assert.Equal(443, (int)p["port"]!);
        Assert.Equal("tp", p["password"]);
        Assert.Equal("example.com", p["sni"]);
        Assert.True((bool)p["skip-cert-verify"]!);

        var alpn = Assert.IsType<List<object?>>(p["alpn"]!);
        Assert.Equal(2, alpn.Count);
        Assert.Equal("http/1.1", alpn[0]);
        Assert.Equal("h2", alpn[1]);
    }
}
