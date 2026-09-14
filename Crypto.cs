using System;
using System.Security.Cryptography;
using System.Text;

namespace ClashConverter;

/// <summary>
/// AES-256-GCM symmetric encryption for protecting proxy info inside subscription links.
/// Binary layout of ciphertext: [12B nonce][16B GCM tag][ciphertext], then URL-safe base64 (no padding).
/// Key is derived from ENCRYPTION_KEY via SHA-256 into a 32-byte AES key.
/// </summary>
public static class Crypto
{
    private static byte[]? _key;

    public static void Initialize(string? keyMaterial)
    {
        var raw = keyMaterial?.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            raw = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            Console.Error.WriteLine("============================================================");
            Console.Error.WriteLine("WARNING: ENCRYPTION_KEY not set. Generated ephemeral key.");
            Console.Error.WriteLine("Subscription links will be invalid after server restart!");
            Console.Error.WriteLine("Set ENCRYPTION_KEY in environment to persist (any string).");
            Console.Error.WriteLine("============================================================");
        }

        _key = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    }

    public static string Encrypt(string plaintext)
    {
        var key = _key ?? throw new InvalidOperationException("Crypto not initialized");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        var combined = new byte[12 + 16 + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, 12);
        Buffer.BlockCopy(tag, 0, combined, 12, 16);
        Buffer.BlockCopy(cipherBytes, 0, combined, 28, cipherBytes.Length);

        return Base64Url(combined);
    }

    public static string Decrypt(string s)
    {
        var key = _key ?? throw new InvalidOperationException("Crypto not initialized");
        var raw = Base64UrlDecode(s);
        if (raw.Length < 28)
            throw new Exception("密文长度不足");

        var nonce = raw[..12];
        var tag = raw[12..28];
        var cipherBytes = raw[28..];
        var plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    private static string Base64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        var pad = (4 - padded.Length % 4) % 4;
        if (pad > 0)
            padded = padded.PadRight(padded.Length + pad, '=');
        return Convert.FromBase64String(padded);
    }
}
