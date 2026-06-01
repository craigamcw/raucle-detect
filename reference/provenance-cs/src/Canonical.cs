using System.Globalization;
using System.Text;

namespace Raucle.Provenance;

/// <summary>
/// Canonical-JSON encoder (RFC 8785 JCS, minimal subset).
///
/// Produces byte-identical output to the Python, TypeScript, Go, and
/// Rust reference encoders: sorted object keys, no insignificant
/// whitespace, UTF-8. Floats are rejected — the v1 payload schema does
/// not use them, and float canonicalisation is the hard part of JCS.
///
/// Operates over a small value model (<see cref="JVal"/>) so the same
/// bytes are produced regardless of the host JSON library.
/// </summary>
public static class Canonical
{
    public static byte[] Encode(JVal value)
    {
        var sb = new StringBuilder();
        Write(sb, value);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public static string EncodeString(JVal value)
    {
        var sb = new StringBuilder();
        Write(sb, value);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JVal v)
    {
        switch (v)
        {
            case JNull:
                sb.Append("null");
                break;
            case JBool b:
                sb.Append(b.Value ? "true" : "false");
                break;
            case JInt i:
                // Portable safe-integer range (§8.10 #6): the TS port stores
                // numbers as IEEE-754 doubles, exact only to ±(2^53-1). Bound
                // every integer so the canonical bytes match across all five
                // implementations.
                const long maxSafe = (1L << 53) - 1;
                if (i.Value < -maxSafe || i.Value > maxSafe)
                    throw new InvalidOperationException(
                        "canonical-JSON: integer outside the portable safe range [-(2^53-1), 2^53-1]");
                sb.Append(i.Value.ToString(CultureInfo.InvariantCulture));
                break;
            case JStr s:
                WriteString(sb, s.Value);
                break;
            case JArr a:
                sb.Append('[');
                for (var k = 0; k < a.Items.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    Write(sb, a.Items[k]);
                }
                sb.Append(']');
                break;
            case JObj o:
                var keys = new List<string>(o.Members.Keys);
                keys.Sort(StringComparer.Ordinal);
                sb.Append('{');
                for (var k = 0; k < keys.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    WriteString(sb, keys[k]);
                    sb.Append(':');
                    Write(sb, o.Members[keys[k]]);
                }
                sb.Append('}');
                break;
            default:
                throw new InvalidOperationException($"canonical-JSON: unsupported node {v.GetType().Name}");
        }
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20)
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}
