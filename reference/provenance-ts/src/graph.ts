/**
 * Chain DAG verifier — §7 (taint monotonicity) + §8 (acyclicity +
 * closure) + §9 (verifier obligations).
 *
 * Mirrors graph.py. A Chain is a topologically-ordered, closed-under-
 * parents list of receipts. `verifyChain` checks every cross-receipt
 * invariant the spec requires.
 */

import type { Receipt } from './receipt.js'

export class ChainError extends Error {}

export interface Chain {
  receipts: Receipt[]
  byId: Map<string, Receipt>
}

/**
 * Build + validate a chain from an ordered list of already-verified
 * receipts (verify each JWS with `verify()` first).
 */
export function buildChain(receipts: Receipt[]): Chain {
  const byId = new Map<string, Receipt>()

  for (const r of receipts) {
    if (byId.has(r.id)) {
      throw new ChainError(`duplicate receipt id in chain: ${r.id}`)
    }
    // Closure under parents (§8): every parent must appear earlier in
    // the topo-ordered list. This also makes cycles unrepresentable.
    for (const p of r.payload.parents) {
      if (!byId.has(p)) {
        throw new ChainError(
          `receipt ${r.id} references parent ${p} not earlier in the chain ` +
            '(topo or closure violation)',
        )
      }
    }
    byId.set(r.id, r)
  }

  // Taint monotonicity (§7).
  for (const r of receipts) {
    const parentTaint = new Set<string>()
    for (const p of r.payload.parents) {
      for (const t of byId.get(p)!.payload.taint) parentTaint.add(t)
    }
    const childTaint = new Set(r.payload.taint)

    if (r.payload.operation === 'sanitisation') {
      const removed = new Set<string>(
        (r.payload['x_removed_taint'] as string[] | undefined) ?? [],
      )
      const missing = [...parentTaint].filter(
        (t) => !childTaint.has(t) && !removed.has(t),
      )
      if (missing.length > 0) {
        throw new ChainError(
          `sanitisation receipt ${r.id} dropped tags without declaring ` +
            `them in x_removed_taint: ${missing.sort().join(', ')}`,
        )
      }
    } else {
      const missing = [...parentTaint].filter((t) => !childTaint.has(t))
      if (missing.length > 0) {
        throw new ChainError(
          `taint monotonicity violation at ${r.id}: missing ${missing
            .sort()
            .join(', ')}`,
        )
      }
    }
  }

  return { receipts, byId }
}
