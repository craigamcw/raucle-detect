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
