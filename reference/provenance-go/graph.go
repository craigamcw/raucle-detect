package provenance

import (
	"fmt"
	"sort"
	"strings"
)

// ChainError is returned when a chain violates the spec.
type ChainError struct{ msg string }

func (e *ChainError) Error() string { return e.msg }

func chainErr(format string, a ...any) *ChainError {
	return &ChainError{msg: fmt.Sprintf(format, a...)}
}

// Chain is a topologically-ordered, closed-under-parents list of
// receipts (§8).
type Chain struct {
	Receipts []Receipt
	ByID     map[string]Receipt
}

// BuildChain validates an ordered slice of already-verified receipts:
// DAG closure + acyclicity (§8) and taint monotonicity (§7). Mirrors the
// Python verifier: sanitisation may drop tags it lists in its `corpus`
// field as "removed:<comma-separated>".
func BuildChain(receipts []Receipt) (*Chain, error) {
	byID := make(map[string]Receipt, len(receipts))

	for _, r := range receipts {
		if _, dup := byID[r.ID]; dup {
			return nil, chainErr("duplicate receipt id in chain: %s", r.ID)
		}
		for _, p := range r.Payload.Parents {
			if _, ok := byID[p]; !ok {
				return nil, chainErr(
					"receipt %s references parent %s not earlier in the chain "+
						"(topo or closure violation)", r.ID, p)
			}
		}
		byID[r.ID] = r
	}

	for _, r := range receipts {
		if len(r.Payload.Parents) == 0 {
			continue
		}
		parentTaint := map[string]bool{}
		for _, p := range r.Payload.Parents {
			for _, t := range byID[p].Payload.Taint {
				parentTaint[t] = true
			}
		}
		childTaint := map[string]bool{}
		for _, t := range r.Payload.Taint {
			childTaint[t] = true
		}

		if r.Payload.Operation == "sanitisation" {
			removed := map[string]bool{}
			if strings.HasPrefix(r.Payload.Corpus, "removed:") {
				for _, s := range strings.Split(r.Payload.Corpus[len("removed:"):], ",") {
					if s != "" {
						removed[s] = true
					}
				}
			}
			// expected = inherited - removed; child taint MUST equal it.
			var bad []string
			for t := range parentTaint {
				if !removed[t] && !childTaint[t] {
					bad = append(bad, t)
				}
			}
			for t := range childTaint {
				if !parentTaint[t] {
					bad = append(bad, "+"+t)
				}
			}
			if len(bad) > 0 {
				sort.Strings(bad)
				return nil, chainErr(
					"sanitisation receipt %s taint mismatch vs corpus removed-set: %v",
					r.ID, bad)
			}
		} else {
			var missing []string
			for t := range parentTaint {
				if !childTaint[t] {
					missing = append(missing, t)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				return nil, chainErr(
					"taint monotonicity violation at %s: missing %v", r.ID, missing)
			}
		}
	}

	return &Chain{Receipts: receipts, ByID: byID}, nil
}
