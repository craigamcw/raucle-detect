namespace Raucle.Provenance;

/// <summary>
/// Chain DAG verifier — §7 taint monotonicity, §8 acyclicity + closure.
/// A chain is a topologically-ordered, closed-under-parents list of
/// already-verified receipts.
/// </summary>
public static class Chain
{
    public static IReadOnlyList<SignedReceipt> Build(IReadOnlyList<SignedReceipt> receipts)
    {
        var byId = new Dictionary<string, SignedReceipt>();

        foreach (var r in receipts)
        {
            if (byId.ContainsKey(r.Id))
                throw new ChainException($"duplicate receipt id in chain: {r.Id}");
            foreach (var p in Parents(r))
                if (!byId.ContainsKey(p))
                    throw new ChainException(
                        $"receipt {r.Id} references parent {p} not earlier in the chain " +
                        "(topo or closure violation)");
            byId[r.Id] = r;
        }

        foreach (var r in receipts)
        {
            var parentTaint = new HashSet<string>();
            foreach (var p in Parents(r))
                foreach (var t in Taint(byId[p])) parentTaint.Add(t);
            var childTaint = new HashSet<string>(Taint(r));
            var op = r.Payload.Str("operation") ?? "";

            if (op == "sanitisation")
            {
                var removed = new HashSet<string>(
                    r.Payload.StrArray("x_removed_taint") ?? new List<string>());
                var missing = parentTaint.Where(t => !childTaint.Contains(t) && !removed.Contains(t))
                    .OrderBy(x => x, StringComparer.Ordinal).ToList();
                if (missing.Count > 0)
                    throw new ChainException(
                        $"sanitisation receipt {r.Id} dropped tags without declaring them " +
                        $"in x_removed_taint: {string.Join(", ", missing)}");
            }
            else
            {
                var missing = parentTaint.Where(t => !childTaint.Contains(t))
                    .OrderBy(x => x, StringComparer.Ordinal).ToList();
                if (missing.Count > 0)
                    throw new ChainException(
                        $"taint monotonicity violation at {r.Id}: missing {string.Join(", ", missing)}");
            }
        }

        return receipts;
    }

    private static IReadOnlyList<string> Parents(SignedReceipt r) =>
        r.Payload.StrArray("parents") ?? new List<string>();

    private static IReadOnlyList<string> Taint(SignedReceipt r) =>
        r.Payload.StrArray("taint") ?? new List<string>();
}

public sealed class ChainException : Exception
{
    public ChainException(string message) : base(message) { }
}
