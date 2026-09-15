using System.Collections.Generic;
using ClashConverter;
using Xunit;

namespace ClashConverter.Tests;

public class YamlTests
{
    private const string VlessUrl =
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=ws&security=reality&pbk=ABCDEF&sid=0123&flow=xtls-rprx-vision&sni=example.com#YamlVLESS";

    [Fact]
    public void ProxyUrlToYaml_ContainsFullConfig()
    {
        var (proto, yaml, name) = Converter.ProxyUrlToYaml(VlessUrl);

        Assert.Equal("vless", proto);
        Assert.Equal("YamlVLESS", name);
        Assert.Contains("proxies:", yaml);
        Assert.Contains("proxy-groups:", yaml);
        Assert.Contains("rules:", yaml);
        Assert.Contains("1.2.3.4", yaml);
        Assert.Contains("MATCH,Proxy", yaml);
    }

    [Fact]
    public void YamlToProxyUrls_RecoversProxy()
    {
        var (_, yaml, _) = Converter.ProxyUrlToYaml(VlessUrl);
        var results = Converter.YamlToProxyUrls(yaml);

        Assert.Single(results);
        Assert.Equal("YamlVLESS", results[0]["name"]);
        var url = results[0]["url"]?.ToString();
        Assert.NotNull(url);
        Assert.StartsWith("vless://", url);
        Assert.Contains("1.2.3.4", url);
    }

    [Fact]
    public void ProxyUrlToSubYaml_ProxiesOnly()
    {
        var yaml = Converter.ProxyUrlToSubYaml(VlessUrl);

        Assert.Contains("proxies:", yaml);
        Assert.DoesNotContain("proxy-groups:", yaml);
        Assert.DoesNotContain("rules:", yaml);
        Assert.Contains("1.2.3.4", yaml);
    }

    [Fact]
    public void YamlToProxyUrls_UnknownType_ReturnsErrorEntry()
    {
        const string yaml = "proxies:\n  - name: Bad\n    type: unknown\n    server: 1.2.3.4\n    port: 1\n";
        var results = Converter.YamlToProxyUrls(yaml);

        Assert.Single(results);
        Assert.NotNull(results[0]["error"]);
        Assert.Null(results[0]["url"]);
    }

    [Fact]
    public void YamlToProxyUrls_Empty_Throws()
        => Assert.Throws<Exception>(() => Converter.YamlToProxyUrls("not: valid: yaml: ["));
}
