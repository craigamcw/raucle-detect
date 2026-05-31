using System.Security.Cryptography;
using System.Text;
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

    private static string Sha(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static JObj BasePayload()
    {
        var h = Sha("hello");
        return new JObj()
            .Set("iss", JVal.Of("https://test.example/raucle"))
            .Set("iat", JVal.Of(1748505600))
            .Set("agent_id", JVal.Of("agent:test.scanner"))
            .Set("agent_key_id", JVal.Of("k_test01"))
            .Set("operation", JVal.Of("user_input"))
            .Set("parents", JVal.Arr(Array.Empty<string>()))
            .Set("input_hash", JVal.Of(h))
            .Set("output_hash", JVal.Of(h))
            .Set("taint", JVal.Arr(new[] { "untrusted_user" }))
            .Set("guardrail_verdict", JVal.Of("NA"));
    }

    [Fact]
    public void EmitVerifyRoundtrip()
    {
        var (priv, pub) = Key();
        var r = Receipt.Emit(BasePayload(), priv);
        var parsed = Receipt.Verify(r.Jws, pub);
        Assert.Equal("agent:test.scanner", parsed.Payload.Str("agent_id"));
        Assert.Equal(r.Id, parsed.Id);
        Assert.Equal(64, r.Id.Length);
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
            .Set("kid", JVal.Of("k_test01")).Set("crit", JVal.Arr(new[] { "raucle/v1" }));
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
            .Set("kid", JVal.Of("k_test01")).Set("crit", JVal.Arr(Array.Empty<string>()));
        var hb = Receipt.B64UrlEncode(Canonical.Encode(badHeader));
        Assert.Throws<ProvException>(() => Receipt.Verify($"{hb}.{parts[1]}.{parts[2]}", pub));
    }

    [Fact]
    public void RejectsUnsortedTaint()
    {
        var (priv, _) = Key();
        var p = BasePayload().Set("taint", JVal.Arr(new[] { "z_x", "a_y" }));
        Assert.Throws<ProvException>(() => Receipt.Emit(p, priv));
    }

    [Fact]
    public void NonUserInputRequiresParents()
    {
        var (priv, _) = Key();
        var p = BasePayload()
            .Set("operation", JVal.Of("model_call"))
            .Set("parents", JVal.Arr(Array.Empty<string>()))
            .Set("model", new JObj().Set("provider", JVal.Of("t")).Set("name", JVal.Of("e")).Set("version", JVal.Of("1")));
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
            .Set("model", new JObj().Set("provider", JVal.Of("t")).Set("name", JVal.Of("e")).Set("version", JVal.Of("1")));
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
            .Set("model", new JObj().Set("provider", JVal.Of("t")).Set("name", JVal.Of("e")).Set("version", JVal.Of("1")));
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
            .Set("model", new JObj().Set("provider", JVal.Of("t")).Set("name", JVal.Of("e")).Set("version", JVal.Of("1")));
        var r2 = Receipt.Emit(p2, priv);
        Assert.Throws<ChainException>(() => Chain.Build(new[] { r1, r2 }));
    }

    [Fact]
    public void SanitisationMustDeclareRemovedTaint()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("sanitisation"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("taint", JVal.Arr(Array.Empty<string>()))
            .Set("ruleset_hash", JVal.Of(Sha("rules-v1")));
        var r2 = Receipt.Emit(p2, priv);
        Assert.Throws<ChainException>(() => Chain.Build(new[] { r1, r2 }));
    }

    [Fact]
    public void SanitisationWithDeclaredRemovedPasses()
    {
        var (priv, _) = Key();
        var r1 = Receipt.Emit(BasePayload(), priv);
        var p2 = BasePayload()
            .Set("operation", JVal.Of("sanitisation"))
            .Set("parents", JVal.Arr(new[] { r1.Id }))
            .Set("taint", JVal.Arr(Array.Empty<string>()))
            .Set("ruleset_hash", JVal.Of(Sha("rules-v1")))
            .Set("x_removed_taint", JVal.Arr(new[] { "untrusted_user" }));
        var r2 = Receipt.Emit(p2, priv);
        var chain = Chain.Build(new[] { r1, r2 });
        Assert.Equal(2, chain.Count);
    }

    [Fact]
    public void CanonicalParity()
    {
        // Locks output to the exact bytes the Python/TS/Go/Rust encoders produce.
        var obj = new JObj()
            .Set("iss", JVal.Of("x"))
            .Set("iat", JVal.Of(1))
            .Set("parents", JVal.Arr(new[] { "a", "b" }))
            .Set("taint", JVal.Arr(new[] { "a_t", "z_t" }));
        var got = Canonical.EncodeString(obj);
        Assert.Equal("{\"iat\":1,\"iss\":\"x\",\"parents\":[\"a\",\"b\"],\"taint\":[\"a_t\",\"z_t\"]}", got);
    }
}
