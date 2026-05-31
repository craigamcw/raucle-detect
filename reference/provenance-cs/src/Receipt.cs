using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Raucle.Provenance;

/// <summary>
/// Raucle Provenance Receipt v1 — C# reference implementation.
/// Spec: https://raucle.com/spec/provenance/v1
///
/// Mirrors the Python/TS/Go/Rust reference impls: same JWS envelope,
/// same canonical-JSON bytes, same content-addressed identifiers. A
/// receipt emitted by any implementation verifies in the others.
///
/// Ed25519 comes from BouncyCastle (the .NET BCL has no Ed25519);
/// SHA-256 + base64url from the BCL.
/// </summary>
public static class Receipt
{
    private const string JwsTyp = "provenance-receipt/v1";

    private static readonly HashSet<string> ValidOperations = new()
    {
        "user_input", "model_call", "tool_call", "retrieval",
        "guardrail_scan", "agent_handoff", "sanitisation", "merge",
    };
    private static readonly HashSet<string> ValidVerdicts = new()
    {
        "ALLOW", "BLOCK", "SANITISE", "NA",
    };
    private static readonly HashSet<string> KnownFields = new()
    {
        "iss", "iat", "agent_id", "agent_key_id", "operation", "parents",
        "input_hash", "output_hash", "taint", "ruleset_hash",
        "guardrail_verdict", "model", "tool", "corpus", "tenant",
    };

    private static readonly Regex AgentId = new(@"^agent:[a-z0-9][a-z0-9_\-./]{0,127}$");
    private static readonly Regex TaintTag = new(@"^[a-z][a-z0-9_:\-]{0,63}$");
    private static readonly Regex Hex256 = new(@"^[0-9a-f]{64}$");

    // ── base64url ──────────────────────────────────────────────────

    public static string B64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    public static string Sha256Hex(byte[] b) =>
        Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    // ── validation (§4) ────────────────────────────────────────────

    public static void Validate(JObj p)
    {
        foreach (var k in p.Members.Keys)
            if (!KnownFields.Contains(k) && !k.StartsWith("x_"))
                throw new ProvException($"reserved/unknown field: {k} (§14)");

        var op = p.Str("operation") ?? "";
        if (!ValidOperations.Contains(op)) throw new ProvException($"unknown operation: {op}");
        var verdict = p.Str("guardrail_verdict") ?? "NA";
        if (!ValidVerdicts.Contains(verdict)) throw new ProvException($"unknown verdict: {verdict}");
        if (!AgentId.IsMatch(p.Str("agent_id") ?? "")) throw new ProvException("invalid agent_id");
        if (!Hex256.IsMatch(p.Str("input_hash") ?? "")) throw new ProvException("input_hash must be 64-hex SHA-256");
        if (!Hex256.IsMatch(p.Str("output_hash") ?? "")) throw new ProvException("output_hash must be 64-hex SHA-256");

        var ruleset = p.Str("ruleset_hash");
        if (ruleset != null && !Hex256.IsMatch(ruleset)) throw new ProvException("ruleset_hash must be 64-hex SHA-256");
        if ((op is "guardrail_scan" or "sanitisation") && ruleset == null)
            throw new ProvException($"{op} requires ruleset_hash (§5)");
        if (op == "guardrail_scan" && verdict == "NA")
            throw new ProvException("guardrail_scan requires a concrete verdict");

        var parents = p.StrArray("parents") ?? new List<string>();
        if (op == "user_input" && parents.Count > 0) throw new ProvException("user_input must have no parents");
        if (op != "user_input" && parents.Count == 0) throw new ProvException($"{op} requires at least one parent");

        var taint = p.StrArray("taint") ?? new List<string>();
        foreach (var t in taint)
            if (!TaintTag.IsMatch(t)) throw new ProvException($"invalid taint tag: {t}");
        var sorted = taint.OrderBy(x => x, StringComparer.Ordinal).ToList();
        if (!taint.SequenceEqual(sorted)) throw new ProvException("taint MUST be sorted (§4)");

        if (op == "model_call" && !p.Members.ContainsKey("model")) throw new ProvException("model_call requires .model");
        if (op == "tool_call" && !p.Members.ContainsKey("tool")) throw new ProvException("tool_call requires .tool");
        if (op == "retrieval" && !p.Members.ContainsKey("corpus")) throw new ProvException("retrieval requires .corpus");
    }

    // ── emit / verify ──────────────────────────────────────────────

    public static SignedReceipt Emit(JObj payload, Ed25519PrivateKeyParameters privateKey)
    {
        // Default guardrail_verdict to NA so signed bytes are explicit
        // (matches the other reference impls).
        if (!payload.Members.ContainsKey("guardrail_verdict"))
            payload.Set("guardrail_verdict", JVal.Of("NA"));

        Validate(payload);
        var kid = payload.Str("agent_key_id") ?? throw new ProvException("missing agent_key_id");

        var header = new JObj()
            .Set("alg", JVal.Of("EdDSA"))
            .Set("typ", JVal.Of(JwsTyp))
            .Set("kid", JVal.Of(kid))
            .Set("crit", JVal.Arr(new[] { "raucle/v1" }));

        var headerB = Canonical.Encode(header);
        var payloadB = Canonical.Encode(payload);
        var signingInput = B64UrlEncode(headerB) + "." + B64UrlEncode(payloadB);

        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        var msg = Encoding.ASCII.GetBytes(signingInput);
        signer.BlockUpdate(msg, 0, msg.Length);
        var sig = signer.GenerateSignature();

        var jws = signingInput + "." + B64UrlEncode(sig);
        return new SignedReceipt(jws, payload, Sha256Hex(Encoding.ASCII.GetBytes(jws)));
    }

    public static SignedReceipt Verify(string jws, Ed25519PublicKeyParameters publicKey)
    {
        var parts = jws.Split('.');
        if (parts.Length != 3) throw new ProvException("JWS must have three segments");
        var (headerB, payloadB, sigB) = (parts[0], parts[1], parts[2]);

        using var headerDoc = JsonDocument.Parse(B64UrlDecode(headerB));
        var header = headerDoc.RootElement;
        if (GetStr(header, "alg") != "EdDSA") throw new ProvException("unsupported alg");
        if (GetStr(header, "typ") != JwsTyp) throw new ProvException("unexpected typ");
        var critOk = header.TryGetProperty("crit", out var crit)
                     && crit.ValueKind == JsonValueKind.Array
                     && crit.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == "raucle/v1");
        if (!critOk) throw new ProvException("crit must include 'raucle/v1'");

        var signingInput = Encoding.ASCII.GetBytes(headerB + "." + payloadB);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(signingInput, 0, signingInput.Length);
        if (!verifier.VerifySignature(B64UrlDecode(sigB))) throw new ProvException("signature invalid");

        using var payloadDoc = JsonDocument.Parse(B64UrlDecode(payloadB));
        var payload = (JObj)JVal.FromJsonElement(payloadDoc.RootElement);
        foreach (var k in payload.Members.Keys)
            if (!KnownFields.Contains(k) && !k.StartsWith("x_"))
                throw new ProvException($"reserved unknown field: {k}");
        Validate(payload);

        if (GetStr(header, "kid") != payload.Str("agent_key_id"))
            throw new ProvException("header.kid != payload.agent_key_id (§3)");

        return new SignedReceipt(jws, payload, Sha256Hex(Encoding.ASCII.GetBytes(jws)));
    }

    private static string? GetStr(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>A signed receipt: the Compact JWS, the parsed payload, and the content-addressed id.</summary>
public sealed record SignedReceipt(string Jws, JObj Payload, string Id);

public sealed class ProvException : Exception
{
    public ProvException(string message) : base(message) { }
}
