using System;
using System.Security.Cryptography;
using System.Text;

namespace ClashConverter;

/// <summary>
/// 基于 AES-256-GCM 的对称加密，用于保护订阅链接中的代理节点信息，
/// 避免明文链接直接暴露在 URL 中。
///
/// 密文二进制布局：[12 字节 nonce][16 字节 GCM 认证标签][密文主体]，
/// 整体再做 URL-safe Base64 编码（无填充符），可直接作为 URL 查询参数。
///
/// 密钥派生：将 ENCRYPTION_KEY（任意字符串）经 SHA-256 哈希为 32 字节 AES 密钥。
/// </summary>
public static class Crypto
{
    /// <summary>缓存的全局密钥（32 字节）；由 <see cref="Initialize"/> 初始化。</summary>
    private static byte[]? _key;

    /// <summary>
    /// 初始化加密密钥。必须在应用启动时（加密/解密操作前）调用一次。
    /// </summary>
    /// <param name="keyMaterial">用户配置的密钥原文（如环境变量 ENCRYPTION_KEY 的值）。</param>
    /// <remarks>
    /// 若未提供密钥，则生成临时随机密钥：服务重启后已发出的订阅链接将全部失效。
    /// 此时向标准错误流输出醒目警告，提示用户设置 ENCRYPTION_KEY 以持久化。
    /// </remarks>
    public static void Initialize(string? keyMaterial)
    {
        var raw = keyMaterial?.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            // 生成临时密钥（两个 GUID 拼接，64 个十六进制字符），仅本次进程有效。
            raw = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            Console.Error.WriteLine("============================================================");
            Console.Error.WriteLine("WARNING: ENCRYPTION_KEY not set. Generated ephemeral key.");
            Console.Error.WriteLine("Subscription links will be invalid after server restart!");
            Console.Error.WriteLine("Set ENCRYPTION_KEY in environment to persist (any string).");
            Console.Error.WriteLine("============================================================");
        }

        // SHA-256 把任意长度字符串稳定映射为 32 字节，满足 AES-256 密钥长度要求。
        _key = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    }

    /// <summary>
    /// 加密明文字符串。
    /// </summary>
    /// <param name="plaintext">待加密明文（如代理分享链接）。</param>
    /// <returns>URL-safe Base64 编码的密文（[nonce][tag][ciphertext] 布局）。</returns>
    /// <exception cref="InvalidOperationException">尚未调用 <see cref="Initialize"/> 时抛出。</exception>
    public static string Encrypt(string plaintext)
    {
        var key = _key ?? throw new InvalidOperationException("Crypto not initialized");

        // GCM 要求每次加密使用唯一 nonce（12 字节随机数），重复使用会破坏安全性。
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16]; // GCM 认证标签固定 16 字节

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // 按 [12B nonce][16B tag][密文] 顺序拼接为单一缓冲区。
        var combined = new byte[12 + 16 + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, 12);
        Buffer.BlockCopy(tag, 0, combined, 12, 16);
        Buffer.BlockCopy(cipherBytes, 0, combined, 28, cipherBytes.Length);

        return Base64Url(combined);
    }

    /// <summary>
    /// 解密 <see cref="Encrypt"/> 生成的密文字符串。
    /// </summary>
    /// <param name="s">URL-safe Base64 编码的密文。</param>
    /// <returns>解密后的明文。</returns>
    /// <exception cref="InvalidOperationException">尚未调用 <see cref="Initialize"/> 时抛出。</exception>
    /// <exception cref="Exception">密文长度不足或 GCM 认证失败（密钥不匹配/被篡改）时抛出。</exception>
    public static string Decrypt(string s)
    {
        var key = _key ?? throw new InvalidOperationException("Crypto not initialized");
        var raw = Base64UrlDecode(s);
        // 最小合法长度 = 12(nonce) + 16(tag) + 0(密文) = 28 字节。
        if (raw.Length < 28)
            throw new Exception("密文长度不足");

        // 按约定布局切分出 nonce、tag 与密文主体。
        var nonce = raw[..12];
        var tag = raw[12..28];
        var cipherBytes = raw[28..];
        var plainBytes = new byte[cipherBytes.Length];

        // GCM 解密时会校验认证标签，篡改或不匹配的密钥会在此抛出异常。
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>编码为 URL-safe Base64：+ → -，/ → _，并去掉尾部填充符 '='。</summary>
    private static string Base64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// URL-safe Base64 解码：还原标准字符集并补齐缺失的填充符后解码，
    /// 与 <see cref="Base64Url"/> 互为逆操作。
    /// </summary>
    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        // 补齐到 4 的倍数长度。
        var pad = (4 - padded.Length % 4) % 4;
        if (pad > 0)
            padded = padded.PadRight(padded.Length + pad, '=');
        return Convert.FromBase64String(padded);
    }
}
