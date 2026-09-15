using ClashConverter;
using Xunit;

namespace ClashConverter.Tests;

/// <summary>
/// Round-trip: proxy URL -> Clash dict -> proxy URL -> Clash dict.
/// Asserts the identity fields that must survive the cycle for each protocol.
/// </summary>
public class ConverterRoundTripTests
{
    [Fact]
    public void Vless_RoundTrip()
    {
        var url = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=ws&security=reality&pbk=ABCDEF&sid=0123&spx=%2F&flow=xtls-rprx-vision&sni=example.com&fp=chrome#MyVLESS";
        var p1 = Converter.Parse(url);
        var url2 = Converter.ProxyToUrl(p1);
        var p2 = Converter.Parse(url2);

        Assert.Equal(p1["server"], p2["server"]);
        Assert.Equal(p1["port"], p2["port"]);
        Assert.Equal(p1["uuid"], p2["uuid"]);
        Assert.Equal(p1["type"], p2["type"]);
        Assert.Equal(p1["name"], p2["name"]);
    }

    [Fact]
    public void Vmess_RoundTrip()
    {
        var json = "{\"v\":\"2\",\"ps\":\"MyVMess\",\"add\":\"5.6.7.8\",\"port\":\"443\",\"id\":\"22222222-2222-2222-2222-222222222222\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"example.com\",\"path\":\"/ws\",\"tls\":\"tls\"}";
        var url = "vmess://" + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));
        var p1 = Converter.Parse(url);
        var url2 = Converter.ProxyToUrl(p1);
        var p2 = Converter.Parse(url2);

        Assert.Equal(p1["server"], p2["server"]);
        Assert.Equal(p1["port"], p2["port"]);
        Assert.Equal(p1["uuid"], p2["uuid"]);
        Assert.Equal(p1["type"], p2["type"]);
    }

    [Fact]
    public void Shadowsocks_RoundTrip()
    {
        var user = TestHelpers.UrlSafeB64("aes-256-gcm:pass");
        var url = $"ss://{user}@9.10.11.12:8388#MySS";
        var p1 = Converter.Parse(url);
        var url2 = Converter.ProxyToUrl(p1);
        var p2 = Converter.Parse(url2);

        Assert.Equal(p1["server"], p2["server"]);
        Assert.Equal(p1["port"], p2["port"]);
        Assert.Equal(p1["cipher"], p2["cipher"]);
        Assert.Equal(p1["password"], p2["password"]);
        Assert.Equal(p1["type"], p2["type"]);
    }

    [Fact]
    public void Ssr_RoundTrip()
    {
        var raw = $"13.14.15.16:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{TestHelpers.UrlSafeB64("ssrpass")}";
        var url = $"ssr://{TestHelpers.UrlSafeB64(raw)}?remarks={TestHelpers.UrlSafeB64("MySSR")}";
        var p1 = Converter.Parse(url);
        var url2 = Converter.ProxyToUrl(p1);
        var p2 = Converter.Parse(url2);

        Assert.Equal(p1["server"], p2["server"]);
        Assert.Equal(p1["port"], p2["port"]);
        Assert.Equal(p1["protocol"], p2["protocol"]);
        Assert.Equal(p1["obfs"], p2["obfs"]);
        Assert.Equal(p1["password"], p2["password"]);
    }

    [Fact]
    public void Trojan_RoundTrip()
    {
        var url = "trojan://tp@17.18.19.20:443?sni=example.com&allowInsecure=1&alpn=http%2F1.1%2Ch2#MyTrojan";
        var p1 = Converter.Parse(url);
        var url2 = Converter.ProxyToUrl(p1);
        var p2 = Converter.Parse(url2);

        Assert.Equal(p1["server"], p2["server"]);
        Assert.Equal(p1["port"], p2["port"]);
        Assert.Equal(p1["password"], p2["password"]);
        Assert.Equal(p1["type"], p2["type"]);
        Assert.Equal(p1["sni"], p2["sni"]);
    }
}
