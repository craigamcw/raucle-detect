/**
 * Canonical-JSON encoder (RFC 8785 JCS, minimal subset).
 *
 * The bytes produced here are the bytes that get signed and hashed, so
 * any drift between this and the other reference implementations
 * (Python, Go, Rust) is a spec-conformance bug. Keep it boring:
 * sorted keys, no insignificant whitespace, UTF-8. Floats are rejected
 * — the v1 payload schema doesn't use them, and float canonicalisation
 * is the one genuinely hard part of JCS.
 */

/**
 * Sort strings by UTF-16 code unit — the ordering RFC 8785 (JCS) mandates for
 * object keys, and the ordering JavaScript's default `Array.prototype.sort()`
 * already uses for strings. Provided EXPLICITLY (rather than a bare `.sort()`)
 * so the cross-language byte-identity contract is visible and lint-clean.
 *
 * DO NOT replace with `localeCompare`: it is locale-aware, does not match
 * code-unit ordering, and would silently break byte-identity with the Python /
 * Go / Rust / C# reference implementations.
 */
export const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

export function canonicalEncode(value: unknown): Uint8Array {
  check(value)
  return new TextEncoder().encode(canonicalString(value))
}

export function canonicalString(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    // Number.isSafeInteger (not isInteger): rejects non-integers AND integers
    // outside ±(2^53-1), which are lossy as IEEE-754 doubles and would not
    // round-trip byte-identically against the Go/Rust/C# 64-bit ports (§8.10 #6).
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(
        'canonical-JSON: only safe integers (|n| <= 2^53-1) are supported in v1',
      )
    }
    return String(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalString(v)).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort(byCodeUnit)
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + canonicalString(obj[k]))
        .join(',') +
      '}'
    )
  }
  throw new TypeError(`canonical-JSON: unsupported type ${typeof value}`)
}

function check(value: unknown): void {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string'
  )
    return
  if (typeof value === 'number') {
    // Number.isSafeInteger (not isInteger): reject floats AND integers outside
    // ±(2^53-1), matching canonicalString() and the Go/Rust/C#/Python ports, so
    // this validator never accepts material the encoder would reject.
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(
        'canonical-JSON: only safe integers (|n| <= 2^53-1) are supported in v1',
      )
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach(check)
    return
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof k !== 'string') throw new TypeError('non-string key')
      check(v)
    }
    return
  }
  throw new TypeError(`canonical-JSON: unsupported type ${typeof value}`)
}
