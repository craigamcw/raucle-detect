using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Raucle.Provenance;
using Xunit;

namespace Raucle.Provenance.Tests;

public class ReceiptTests
{
    private static (Ed25519PrivateKeyParameters priv, Ed25519PublicKeyParameters pub) Key()
    {
        var gen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        return ((Ed25519PrivateKeyParameters)kp.Private, (Ed25519PublicKeyParameters)kp.Public);
    }

    private static JObj BasePayload()
    {
        return new JObj()
            .Set("iat", JVal.Of(1700000001))
            .Set("agent_id", JVal.Of("agent:test.scanner"))
            .Set("agent_key_id", JVal.Of("k_test01"))
            .Set("operation", JVal.Of("user_input"))
            .Set("parents", JVal.Arr(Array.Empty<string>()))
            .Set("input_hash", JVal.Of("sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef"))
            .Set("taint", JVal.Arr(new[] { "untrusted_user" }));
    }

    [Fact]
    public void EmitVerifyRoundtrip()
    {
        var (priv, pub) = Key();
        var r = Receipt.Emit(BasePayload(), priv);
        var parsed = Receipt.Verify(r.Jws, pub);
        Assert.Equal("agent:test.scanner", parsed.Payload.Str("agent_id"));
        Assert.Equal(r.Id, parsed.Id);
        Assert.StartsWith("sha256:", r.Id);
        Assert.Equal("raucle-detect/provenance", parsed.Payload.Str("iss"));
        Assert.Equal("provenance-receipt/v1", parsed.Payload.Str("typ"));
    }

    [Fact]
    public void VerifyRejectsDifferentKey()
    {
        var (priv, _) = Key();
        var (_, otherPub) = Key();
        var r = Receipt.Emit(BasePayload(), priv);
        Assert.Throws<ProvException>(() => Receipt.Verify(r.Jws, otherPub));
    }

    [Fact]
    public void VerifyRejectsWrongAlg()
    {
        var (priv, pub) = Key();
        var r = Receipt.Emit(BasePayload(), priv);
        var parts = r.Jws.Split('.');
        var badHeader = new JObj()
            .Set("alg", JVal.Of("HS256")).Set("typ", JVal.Of("provenance-receipt/v1"))
            .Set("kid", JVal.Of("k_test01")).Set("crit", JVal.Arr(new[] { "raucle/v1" }))
            .Set("raucle/v1", JVal.Of("provenance"));
        var hb = Receipt.B64UrlEncode(Canonical.Encode(badHeader));
        Assert.Throws<ProvException>(() => Receipt.Verify($"{hb}.{parts[1]}.{parts[2]}", pub));
    }

    [Fact]
    public void VerifyRequiresCrit()
    {
        var (priv, pub) = Key();
        var r = Receipt.Emit(BasePayload(), priv);
        var parts = r.Jws.Split('.');
        var badHeader = new JObj()
            .Set("alg", JVal.Of("EdDSA")).Set("typ", JVal.Of("provenance-receipt/v1"))
            .Set("kid", JVal.Of("k_test01")).Set("crit", JVal.Arr(Array.Empty<string>()))
            .Set("raucle/v1", JVal.Of("provenance"));
        var hb = Receipt.B64UrlEncode(Canonical.Encode(badHeader));
        Assert.Throws<ProvException>(() => Receipt.Verify($"{hb}.{parts[1]}.{parts[2]}", pub));
    }

    [Fact]
    public void NonUserInputRequiresParents()
    {
        var (priv, _) = Key();
        var p = BasePayload()
            .Set("operation", JVal.Of("model_call"))
            .Set("parents", JVal.Arr(Array.Empty<string>()))
            .Set("model", JVal.Of("test-model-v1"));
        Assert.Throws<ProvException>(() => Receipt.Emit(p, priv));
    }

    [Fact]
    public void RejectsReservedUnknownField()
    {
        var (priv, _) = Key();
        var p = BasePayload().Set("rogue", JVal.Of("x"));
        Assert.Throws<ProvException>(() => Receipt.Emit(p, priv));
    }

    [Fact]
    public void AllowsXExtension()
    {
        var (priv, pub) = Key();
        var p = BasePayload().Set("x_trace", JVal.Of("abc"));
        var r = Receipt.Emit(p, priv);
        var parsed = Receipt.Verify(r.Jws, pub);
        Assert.Equal("abc", parsed.Payload.Str("x_trace"));
    }

    [Fact]
    public void ChainTopoAndClosure()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("model_call"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("model", JVal.Of("test-model-v1"));
        var r2 = Receipt.Emit(p2, priv);
        var chain = Chain.Build(new[] { r1, r2 });
        Assert.Equal(2, chain.Count);
    }

    [Fact]
    public void ChainRejectsTopoBreak()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("model_call"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("model", JVal.Of("test-model-v1"));
        var r2 = Receipt.Emit(p2, priv);
        Assert.Throws<ChainException>(() => Chain.Build(new[] { r2, r1 }));
    }

    [Fact]
    public void ChainRejectsSilentTaintLoss()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("model_call"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("taint", JVal.Arr(Array.Empty<string>()))
            .Set("model", JVal.Of("test-model-v1"));
        var r2 = Receipt.Emit(p2, priv);
        Assert.Throws<ChainException>(() => Chain.Build(new[] { r1, r2 }));
    }

    [Fact]
    public void SanitisationRemovesTagViaCorpus()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("sanitisation"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("taint", JVal.Arr(Array.Empty<string>()))
            .Set("tool", JVal.Of("redactor:pii-v1"))
            .Set("corpus", JVal.Of("removed:untrusted_user"));
        var r2 = Receipt.Emit(p2, priv);
        var chain = Chain.Build(new[] { r1, r2 });
        Assert.Equal(2, chain.Count);
    }

    [Fact]
    public void SanitisationUndeclaredDropFails()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("sanitisation"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("taint", JVal.Arr(Array.Empty<string>()))
            .Set("tool", JVal.Of("redactor:pii-v1"))
            .Set("corpus", JVal.Of("removed:something_else"));
        var r2 = Receipt.Emit(p2, priv);
        Assert.Throws<ChainException>(() => Chain.Build(new[] { r1, r2 }));
    }

    [Fact]
    public void CanonicalParity()
    {
        var obj = new JObj()
            .Set("iss", JVal.Of("x"))
            .Set("iat", JVal.Of(1))
            .Set("parents", JVal.Arr(new[] { "a", "b" }))
            .Set("taint", JVal.Arr(new[] { "a_t", "z_t" }));
        var got = Canonical.EncodeString(obj);
        Assert.Equal("{\"iat\":1,\"iss\":\"x\",\"parents\":[\"a\",\"b\"],\"taint\":[\"a_t\",\"z_t\"]}", got);
    }

    // ── shared cross-language conformance: the published test vectors ──

    private static byte[] HexToBytes(string s)
    {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);
        return b;
    }

    private static string VectorsPath()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !Directory.Exists(Path.Combine(d.FullName, "docs", "spec", "provenance")))
            d = d.Parent;
        if (d == null)
            throw new DirectoryNotFoundException("could not locate repo docs/ from " + AppContext.BaseDirectory);
        return Path.Combine(d.FullName, "docs", "spec", "provenance", "v1", "test-vectors.json");
    }

    [Fact]
    public void SpecVectors()
    {
        var raw = File.ReadAllText(VectorsPath());
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;

        var seed = HexToBytes(root.GetProperty("fixed_seed_hex").GetString()!);
        var priv = new Ed25519PrivateKeyParameters(seed, 0);
        var pub = priv.GeneratePublicKey();

        var vectors = root.GetProperty("vectors").EnumerateArray().ToList();
        Assert.NotEmpty(vectors);

        foreach (var v in vectors)
        {
            var name = v.GetProperty("name").GetString()!;
            var expectedJws = v.GetProperty("expected_jws").GetString()!;
            var expectedHash = v.GetProperty("expected_receipt_hash").GetString()!;

            // (a) Verify the published JWS + recompute its content id.
            var r = Receipt.Verify(expectedJws, pub);
            Assert.True(r.Id == expectedHash, $"{name}: receipt_hash mismatch: {r.Id} != {expectedHash}");

            // (b) Re-emit from the fixed seed; the C# JWS + id MUST be
            //     byte-identical to the published vector.
            var payloadB64 = expectedJws.Split('.')[1];
            using var pdoc = JsonDocument.Parse(Receipt.B64UrlDecode(payloadB64));
            var payload = (JObj)JVal.FromJsonElement(pdoc.RootElement);
            var emitted = Receipt.Emit(payload, priv);
            Assert.True(emitted.Jws == expectedJws, $"{name}: emitted JWS differs");
            Assert.True(emitted.Id == expectedHash, $"{name}: emitted id differs");
        }
    }
}
