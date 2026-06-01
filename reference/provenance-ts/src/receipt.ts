/**
 * Raucle Provenance Receipt v1 — TypeScript reference implementation.
 *
 * Spec: https://raucle.com/spec/provenance/v1
 *
 * Mirrors the canonical Python reference (raucle_detect/provenance.py)
 * byte-for-byte: same JOSE header (incl. the `"raucle/v1": "provenance"`
 * tag), same payload field set, string-typed model/tool/corpus,
 * sha256:-prefixed hashes, and the same content-addressed id
 * (`"sha256:" + hex(sha256(jws))`). A receipt emitted here verifies in
 * the other reference implementations and yields the identical id.
 *
 * Zero runtime dependencies — uses Node's webcrypto for Ed25519 and
 * SHA-256.
 */

import { webcrypto } from 'node:crypto'
import { byCodeUnit, canonicalEncode } from './canonical.js'

const subtle = webcrypto.subtle

export const VALID_OPERATIONS = new Set([
  'user_input',
  'model_call',
  'tool_call',
  'retrieval',
  'guardrail_scan',
  'agent_handoff',
  'sanitisation',
  'merge',
])

const JWS_TYP = 'provenance-receipt/v1'
const ISS = 'raucle-detect/provenance'
const JWS_CRIT = ['raucle/v1']

export interface ReceiptPayload {
  iat: number
  agent_id: string
  agent_key_id: string
  operation: string
  parents: string[]
  taint: string[]
  input_hash?: string
  output_hash?: string
  model?: string
  tool?: string
  corpus?: string
  ruleset_hash?: string
  guardrail_verdict?: string
  tenant?: string
  /** Injected by emit; present on parsed payloads. */
  iss?: string
  typ?: string
  /** Extension fields; keys MUST be prefixed `x_` (spec §14). */
  [extra: string]: unknown
}

const KNOWN_FIELDS = new Set([
  'iss', 'typ', 'iat', 'agent_id', 'agent_key_id', 'operation', 'parents',
  'taint', 'input_hash', 'output_hash', 'model', 'tool', 'corpus',
  'ruleset_hash', 'guardrail_verdict', 'tenant',
])

export interface Receipt {
  /** The Compact JWS string. */
  jws: string
  /** Parsed payload. */
  payload: ReceiptPayload
  /** Content-addressed id: "sha256:" + hex SHA-256 of the JWS ASCII (§8). */
  id: string
}

// ── base64url ────────────────────────────────────────────────────

function b64uEncode(bytes: Uint8Array): string {
  const s = Buffer.from(bytes).toString('base64')
  // String#replaceAll with literal args: no regex (avoids a ReDoS-shaped
  // pattern) and byte-identical for base64 (padding '=' is trailing-only).
  return s.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function b64uDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  const buf = Buffer.from(b64, 'base64')
  const out = new Uint8Array(buf.length)
  out.set(buf)
  return out
}

function enc(s: string): Uint8Array<ArrayBuffer> {
  const u = new TextEncoder().encode(s)
  const out = new Uint8Array(u.length)
  out.set(u)
  return out
}

async function sha256Hex(s: string): Promise<string> {
  const digest = await subtle.digest('SHA-256', enc(s))
  return Buffer.from(digest).toString('hex')
}

// ── validation ───────────────────────────────────────────────────
// Lenient where the Python reference is lenient: enforces structural
// invariants (typ literal, required fields per operation, parent rules),
// not value shapes.

export function validatePayload(p: ReceiptPayload): void {
  for (const k of Object.keys(p)) {
    if (!KNOWN_FIELDS.has(k) && !k.startsWith('x_')) {
      throw new Error(`reserved/unknown field: ${k} (§14)`)
    }
  }
  if (p.typ !== undefined && p.typ !== JWS_TYP) {
    throw new Error(`payload typ must be ${JWS_TYP}`)
  }
  if (!VALID_OPERATIONS.has(p.operation)) {
    throw new Error(`unknown operation: ${p.operation}`)
  }
  const has = (k: keyof ReceiptPayload) =>
    typeof p[k] === 'string' && (p[k] as string).length > 0
  if (p.operation === 'guardrail_scan' && !has('guardrail_verdict')) {
    throw new Error('guardrail_scan requires guardrail_verdict (§4)')
  }
  if (p.operation === 'guardrail_scan' && !has('ruleset_hash')) {
    throw new Error('guardrail_scan requires ruleset_hash (§4)')
  }
  if (p.operation === 'model_call' && !has('model')) {
    throw new Error('model_call requires model (§4)')
  }
  if ((p.operation === 'tool_call' || p.operation === 'sanitisation') && !has('tool')) {
    throw new Error(`${p.operation} requires tool (§4)`)
  }
  if ((p.operation === 'retrieval' || p.operation === 'sanitisation') && !has('corpus')) {
    throw new Error(`${p.operation} requires corpus (§4)`)
  }
  if (p.operation === 'user_input' && p.parents.length > 0) {
    throw new Error('user_input must have no parents')
  }
  if (p.operation !== 'user_input' && p.parents.length === 0) {
    throw new Error(`${p.operation} requires at least one parent`)
  }
}

/**
 * Build the canonical payload object, injecting the constant iss/typ and
 * sorting parents+taint, exactly as Python's
 * ProvenanceReceipt.payload() does. Empty optional string fields are
 * omitted.
 */
function payloadToObject(p: ReceiptPayload): Record<string, unknown> {
  const out: Record<string, unknown> = {
    iss: ISS,
    typ: JWS_TYP,
    iat: p.iat,
    agent_id: p.agent_id,
    agent_key_id: p.agent_key_id,
    operation: p.operation,
    parents: [...p.parents].sort(byCodeUnit),
    taint: [...p.taint].sort(byCodeUnit),
  }
  const optional: (keyof ReceiptPayload)[] = [
    'input_hash', 'output_hash', 'model', 'tool', 'corpus',
    'ruleset_hash', 'guardrail_verdict',
  ]
  for (const k of optional) {
    const v = p[k]
    if (typeof v === 'string' && v.length > 0) out[k] = v
  }
  if (p.tenant !== undefined) out.tenant = p.tenant
  for (const [k, v] of Object.entries(p)) {
    if (k.startsWith('x_')) out[k] = v
  }
  return out
}

// ── emit + verify ─────────────────────────────────────────────────

export async function emit(
  payload: ReceiptPayload,
  privateKey: webcrypto.CryptoKey,
): Promise<Receipt> {
  validatePayload(payload)
  const obj = payloadToObject(payload)

  const header = {
    alg: 'EdDSA',
    typ: JWS_TYP,
    kid: payload.agent_key_id,
    crit: [...JWS_CRIT],
    'raucle/v1': 'provenance',
  }
  const headerB = canonicalEncode(header)
  const payloadB = canonicalEncode(obj)
  const signingInput = b64uEncode(headerB) + '.' + b64uEncode(payloadB)

  const sig = new Uint8Array(
    await subtle.sign('Ed25519', privateKey, enc(signingInput)),
  )
  const jws = signingInput + '.' + b64uEncode(sig)
  const id = 'sha256:' + (await sha256Hex(jws))
  return { jws, payload: obj as ReceiptPayload, id }
}

export async function verify(
  jws: string,
  publicKey: webcrypto.CryptoKey,
): Promise<Receipt> {
  const parts = jws.split('.')
  if (parts.length !== 3) throw new Error('JWS must have three segments')
  const [headerB, payloadB, sigB] = parts
  const header = JSON.parse(new TextDecoder().decode(b64uDecode(headerB)))

  if (header.alg !== 'EdDSA') throw new Error(`unsupported alg: ${header.alg}`)
  if (header.typ !== JWS_TYP) throw new Error(`unexpected typ: ${header.typ}`)
  if (!Array.isArray(header.crit) || header.crit.length !== 1 || header.crit[0] !== 'raucle/v1') {
    throw new Error("crit must be exactly ['raucle/v1']")
  }
  if (header['raucle/v1'] !== 'provenance') {
    throw new Error("header 'raucle/v1' must be 'provenance'")
  }
  const allowedHeaderKeys = new Set(['alg', 'typ', 'kid', 'crit', 'raucle/v1'])
  for (const k of Object.keys(header)) {
    if (!allowedHeaderKeys.has(k)) throw new Error(`unexpected JOSE header key: ${k}`)
  }

  const signingInput = enc(headerB + '.' + payloadB)
  const ok = await subtle.verify('Ed25519', publicKey, b64uDecode(sigB), signingInput)
  if (!ok) throw new Error('signature invalid')

  const payloadObj = JSON.parse(
    new TextDecoder().decode(b64uDecode(payloadB)),
  ) as ReceiptPayload
  validatePayload(payloadObj)

  if (header.kid !== payloadObj.agent_key_id) {
    throw new Error('header.kid != payload.agent_key_id (§3)')
  }

  const id = 'sha256:' + (await sha256Hex(jws))
  return { jws, payload: payloadObj, id }
}
