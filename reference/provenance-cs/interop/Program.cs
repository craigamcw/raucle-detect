using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Raucle.Provenance;

// Conformance-harness mode: read {"seed_hex","payload"} JSON lines from
// stdin, write {"jws","id"} lines to stdout. See reference/conformance.py.
if (args.Length > 0 && args[0] == "--harness")
{
    static byte[] Hex(string s)
    {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);
        return b;
    }
    string? line;
    while ((line = Console.ReadLine()) != null)
    {
        if (string.IsNullOrWhiteSpace(line)) continue;
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        var hseed = Hex(root.GetProperty("seed_hex").GetString()!);
        var sk = new Ed25519PrivateKeyParameters(hseed, 0);
        var payload = (JObj)JVal.FromJsonElement(root.GetProperty("payload"));
        var rec = Receipt.Emit(payload, sk);
        Console.WriteLine(JsonSerializer.Serialize(new { jws = rec.Jws, id = rec.Id }));
    }
    return;
}

// Verify-rejection conformance: read {"jws","public_key_hex"} lines, write
// {"verdict":"ACCEPT","id":...} | {"verdict":"REJECT"}. ANY error (bad key, bad
// signature, non-canonical bytes, duplicate key) is a REJECT.
if (args.Length > 0 && args[0] == "--verify")
{
    // Exactly 64 hex chars (32 bytes). Reject odd/over-length so a trailing nibble
    // can't truncate back to a valid key (matches Go's strict decode).
    static byte[] HexV(string s)
    {
        if (s.Length != 64) throw new FormatException("public_key_hex must be 64 hex chars");
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);
        return b;
    }
    string? vline;
    while ((vline = Console.ReadLine()) != null)
    {
        if (string.IsNullOrWhiteSpace(vline)) continue;
        object verdict;
        try
        {
            using var doc = JsonDocument.Parse(vline);
            var root = doc.RootElement;
            var jws = root.GetProperty("jws").GetString()!;
            var vpub = new Ed25519PublicKeyParameters(
                HexV(root.GetProperty("public_key_hex").GetString()!), 0);
            var rec = Receipt.Verify(jws, vpub);
            verdict = new { verdict = "ACCEPT", id = rec.Id };
        }
        catch
        {
            verdict = new { verdict = "REJECT" };
        }
        Console.WriteLine(JsonSerializer.Serialize(verdict));
    }
    return;
}

// Canonicalisation cross-check (key ordering): read {"obj": <value>} lines,
// write {"hex": "<utf8 hex of canonical bytes>"} lines.
if (args.Length > 0 && args[0] == "--canon")
{
    string? line;
    while ((line = Console.ReadLine()) != null)
    {
        if (string.IsNullOrWhiteSpace(line)) continue;
        using var doc = JsonDocument.Parse(line);
        var obj = JVal.FromJsonElement(doc.RootElement.GetProperty("obj"));
        var bytes = Canonical.Encode(obj);
        Console.WriteLine(JsonSerializer.Serialize(
            new { hex = Convert.ToHexString(bytes).ToLowerInvariant() }));
    }
    return;
}

// Deterministic key (32 bytes of 0x07) for a reproducible interop fixture.
var seed = new byte[32]; for (int i = 0; i < 32; i++) seed[i] = 7;
var priv = new Ed25519PrivateKeyParameters(seed, 0);
var pub = priv.GeneratePublicKey();
var p = new JObj()
  .Set("iat", JVal.Of(1700000001))
  .Set("agent_id", JVal.Of("agent:x")).Set("agent_key_id", JVal.Of("k1"))
  .Set("operation", JVal.Of("user_input")).Set("parents", JVal.Arr(Array.Empty<string>()))
  .Set("input_hash", JVal.Of("sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef"))
  .Set("taint", JVal.Arr(new[] { "untrusted_user" }));
var r = Receipt.Emit(p, priv);
Console.WriteLine(r.Jws);
Console.WriteLine(Convert.ToHexString(pub.GetEncoded()).ToLowerInvariant());
