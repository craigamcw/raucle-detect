using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Raucle.Provenance;
// Deterministic key (32 bytes of 0x07) for a reproducible interop fixture.
var seed = new byte[32]; for (int i=0;i<32;i++) seed[i]=7;
var priv = new Ed25519PrivateKeyParameters(seed, 0);
var pub = priv.GeneratePublicKey();
string Sha(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
var h = Sha("hello");
var p = new JObj()
  .Set("iss", JVal.Of("https://x/raucle")).Set("iat", JVal.Of(1748505600))
  .Set("agent_id", JVal.Of("agent:x")).Set("agent_key_id", JVal.Of("k1"))
  .Set("operation", JVal.Of("user_input")).Set("parents", JVal.Arr(Array.Empty<string>()))
  .Set("input_hash", JVal.Of(h)).Set("output_hash", JVal.Of(h))
  .Set("taint", JVal.Arr(new[]{"untrusted_user"})).Set("guardrail_verdict", JVal.Of("NA"));
var r = Receipt.Emit(p, priv);
Console.WriteLine(r.Jws);
Console.WriteLine(Convert.ToHexString(pub.GetEncoded()).ToLowerInvariant());
