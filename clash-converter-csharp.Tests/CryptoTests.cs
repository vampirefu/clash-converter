using System;
using System.Security.Cryptography;
using ClashConverter;
using Xunit;

namespace ClashConverter.Tests;

public class CryptoTests
{
    [Fact]
    public void RoundTrip_EncryptDecrypt()
    {
        Crypto.Initialize("a-fixed-test-key");
        const string plain = "vless://abc-1234@1.2.3.4:443";
        var enc = Crypto.Encrypt(plain);
        Assert.NotEqual(plain, enc);
        Assert.Equal(plain, Crypto.Decrypt(enc));
    }

    [Fact]
    public void EmptyString_RoundTrips()
    {
        Crypto.Initialize("key");
        var enc = Crypto.Encrypt("");
        Assert.Equal("", Crypto.Decrypt(enc));
    }

    [Fact]
    public void SamePlain_DifferentCipherEachCall_NonceIsRandom()
    {
        Crypto.Initialize("key");
        var a = Crypto.Encrypt("payload");
        var b = Crypto.Encrypt("payload");
        Assert.NotEqual(a, b); // 12-byte random nonce -> different ciphertext every time
        Assert.Equal("payload", Crypto.Decrypt(a));
        Assert.Equal("payload", Crypto.Decrypt(b));
    }

    [Fact]
    public void WrongKey_Throws()
    {
        Crypto.Initialize("key-one");
        var enc = Crypto.Encrypt("secret");
        Crypto.Initialize("key-two");
        Assert.ThrowsAny<CryptographicException>(() => Crypto.Decrypt(enc));
    }

    [Fact]
    public void SameKey_DeterministicAcrossInitialization()
    {
        Crypto.Initialize("same-material");
        var enc = Crypto.Encrypt("data");
        Crypto.Initialize("same-material"); // re-init with identical material
        Assert.Equal("data", Crypto.Decrypt(enc));
    }
}
