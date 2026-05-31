# Raucle.Provenance — C# / .NET reference implementation

A C# implementation of the
[Raucle Provenance Receipt v1 spec](https://raucle.com/spec/provenance/v1).

The fifth cross-language reference implementation (Python, TypeScript,
Go, Rust, C#). All emit the same wire format and compute identical
content-addressed IDs — verified end-to-end: a receipt emitted here
verifies in the Python implementation (and produces the same id as the
Rust impl for the same key + payload).

**Cross-platform + free.** .NET is open-source and runs on macOS,
Linux, and Windows — no Windows licence or VM needed. Ed25519 comes
from [BouncyCastle](https://www.bouncycastle.org/) (MIT); SHA-256 and
base64url from the .NET base class library.

## Use

```csharp
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Raucle.Provenance;

var gen = new Ed25519KeyPairGenerator();
gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
var kp = gen.GenerateKeyPair();
var priv = (Ed25519PrivateKeyParameters)kp.Private;
var pub  = (Ed25519PublicKeyParameters)kp.Public;

var payload = new JObj()
    .Set("iss", JVal.Of("https://acme.example/raucle"))
    .Set("iat", JVal.Of(1748505600))
    .Set("agent_id", JVal.Of("agent:acme.scanner"))
    .Set("agent_key_id", JVal.Of("k_1"))
    .Set("operation", JVal.Of("guardrail_scan"))
    .Set("parents", JVal.Arr(parentIds))
    .Set("input_hash", JVal.Of(inputHashHex))
    .Set("output_hash", JVal.Of(outputHashHex))
    .Set("taint", JVal.Arr(new[] { "untrusted_user" }))
    .Set("ruleset_hash", JVal.Of(rulesetHashHex))
    .Set("guardrail_verdict", JVal.Of("ALLOW"));

var r = Receipt.Emit(payload, priv);
var parsed = Receipt.Verify(r.Jws, pub);
// r.Id is the content-addressed identifier.

// Multi-receipt graph:
var chain = Chain.Build(new[] { r1, r2, r3 });
```

`Chain.Build` enforces DAG closure, acyclicity, and taint monotonicity
(§7–§9); `Receipt.Emit`/`Verify` enforce the envelope (§3) and payload
(§4) rules, including the `crit=raucle/v1` JWT-confusion guard.

## Develop

```bash
dotnet test test/Raucle.Provenance.Tests.csproj
dotnet run --project interop        # emit a receipt; pipe to the Python verifier
```

The library targets `net8.0` (LTS). The test + interop projects set
`<RollForward>Major</RollForward>` so they also run under a newer
installed runtime (e.g. .NET 10).

`CanonicalParity` locks the canonical-JSON output to the exact bytes
the Python, TypeScript, Go, and Rust encoders produce. 14 tests total.

## License

MIT.
