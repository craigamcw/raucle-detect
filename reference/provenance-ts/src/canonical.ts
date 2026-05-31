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

export function canonicalEncode(value: unknown): Uint8Array {
  check(value)
  return new TextEncoder().encode(canonicalString(value))
}

export function canonicalString(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new TypeError('canonical-JSON: only integer numbers are supported in v1')
    }
    return String(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalString(v)).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
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
    if (!Number.isInteger(value)) {
      throw new TypeError('canonical-JSON: floats are not supported in v1')
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
