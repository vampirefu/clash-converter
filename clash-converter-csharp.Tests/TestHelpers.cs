using System;
using System.Text;

namespace ClashConverter.Tests;

/// <summary>
/// Small helpers mirroring the converter's URL-safe base64 so tests can build
/// realistic proxy links without hard-coding long encoded blobs.
/// </summary>
internal static class TestHelpers
{
    public static string UrlSafeB64(string s)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static string B64(string s)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
}
