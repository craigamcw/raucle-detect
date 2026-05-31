package provenance

import (
	"fmt"
	"sort"
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
// DAG closure + acyclicity (§8) and taint monotonicity (§7).
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
			if rv, ok := r.Payload.Extra["x_removed_taint"].([]any); ok {
				for _, e := range rv {
					if s, ok := e.(string); ok {
						removed[s] = true
					}
				}
			}
			var missing []string
			for t := range parentTaint {
				if !childTaint[t] && !removed[t] {
					missing = append(missing, t)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				return nil, chainErr(
					"sanitisation receipt %s dropped tags without declaring "+
						"them in x_removed_taint: %v", r.ID, missing)
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
