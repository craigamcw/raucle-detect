/**
 * Raucle Provenance Receipt v1 — TypeScript reference implementation.
 *
 * Spec: https://raucle.com/spec/provenance/v1
 *
 * Mirrors the Python reference impl in promptguard.provenance. Same
 * field semantics, same JWS envelope, same content-addressing rule.
 * Zero runtime dependencies — uses Node's webcrypto for Ed25519 and
 * SHA-256.
 */

import { webcrypto } from 'node:crypto'
import { canonicalEncode } from './canonical.js'

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
export const VALID_VERDICTS = new Set(['ALLOW', 'BLOCK', 'SANITISE', 'NA'])

const AGENT_ID = /^agent:[a-z0-9][a-z0-9_\-./]{0,127}$/
const TAINT_TAG = /^[a-z][a-z0-9_:\-]{0,63}$/
const HEX256 = /^[0-9a-f]{64}$/
const JWS_TYP = 'provenance-receipt/v1'
const JWS_CRIT = ['raucle/v1']

export interface ReceiptPayload {
  iss: string
  iat: number
  agent_id: string
  agent_key_id: string
  operation: string
  parents: string[]
  input_hash: string
  output_hash: string
  taint: string[]
  ruleset_hash?: string
  guardrail_verdict?: string
  model?: Record<string, unknown>
  tool?: Record<string, unknown>
  corpus?: Record<string, unknown>
  tenant?: string
  /** Extension fields; keys MUST be prefixed `x_` (spec §14). */
  [extra: string]: unknown
}

const KNOWN_FIELDS = new Set([
  'iss', 'iat', 'agent_id', 'agent_key_id', 'operation', 'parents',
  'input_hash', 'output_hash', 'taint', 'ruleset_hash',
  'guardrail_verdict', 'model', 'tool', 'corpus', 'tenant',
])

export interface Receipt {
  /** The Compact JWS string. */
  jws: string
  /** Parsed payload. */
  payload: ReceiptPayload
  /** Content-addressed id: hex SHA-256 of the JWS ASCII bytes (§8). */
  id: string
}

// ── base64url ────────────────────────────────────────────────────

function b64uEncode(bytes: Uint8Array): string {
  let s = Buffer.from(bytes).toString('base64')
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64uDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  const buf = Buffer.from(b64, 'base64')
  // Copy into a fresh ArrayBuffer-backed view so the type is
  // Uint8Array<ArrayBuffer> (what webcrypto's BufferSource expects),
  // not Uint8Array<ArrayBufferLike> which Node's Buffer yields.
  const out = new Uint8Array(buf.length)
  out.set(buf)
  return out
}

/**
 * UTF-8 encode into an ArrayBuffer-backed view. Node's
 * `TextEncoder().encode` yields `Uint8Array<ArrayBufferLike>`, which
 * webcrypto's `BufferSource` parameter rejects under strict types —
 * so we copy into a fresh ArrayBuffer-backed array.
 */
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

export function validatePayload(p: ReceiptPayload): void {
  if (!VALID_OPERATIONS.has(p.operation)) {
    throw new Error(`unknown operation: ${p.operation}`)
  }
  const verdict = p.guardrail_verdict ?? 'NA'
  if (!VALID_VERDICTS.has(verdict)) {
    throw new Error(`unknown verdict: ${verdict}`)
  }
  if (!AGENT_ID.test(p.agent_id)) throw new Error(`invalid agent_id: ${p.agent_id}`)
  if (!HEX256.test(p.input_hash)) throw new Error('input_hash must be 64-hex SHA-256')
  if (!HEX256.test(p.output_hash)) throw new Error('output_hash must be 64-hex SHA-256')
  if (p.ruleset_hash !== undefined && !HEX256.test(p.ruleset_hash)) {
    throw new Error('ruleset_hash must be 64-hex SHA-256')
  }
  if (
    (p.operation === 'guardrail_scan' || p.operation === 'sanitisation') &&
    !p.ruleset_hash
  ) {
    throw new Error(`${p.operation} requires ruleset_hash (§5)`)
  }
  if (p.operation === 'guardrail_scan' && verdict === 'NA') {
    throw new Error('guardrail_scan requires a concrete verdict')
  }
  if (p.operation === 'user_input' && p.parents.length > 0) {
    throw new Error('user_input must have no parents')
  }
  if (p.operation !== 'user_input' && p.parents.length === 0) {
    throw new Error(`${p.operation} requires at least one parent`)
  }
  for (const t of p.taint) {
    if (!TAINT_TAG.test(t)) throw new Error(`invalid taint tag: ${t}`)
  }
  const sorted = [...p.taint].sort()
  if (JSON.stringify(sorted) !== JSON.stringify(p.taint)) {
    throw new Error('taint MUST be sorted (§4)')
  }
  if (p.operation === 'model_call' && !p.model) throw new Error('model_call requires .model')
  if (p.operation === 'tool_call' && !p.tool) throw new Error('tool_call requires .tool')
  if (p.operation === 'retrieval' && !p.corpus) throw new Error('retrieval requires .corpus')
  for (const k of Object.keys(p)) {
    if (!KNOWN_FIELDS.has(k) && !k.startsWith('x_')) {
      throw new Error(`reserved/unknown field: ${k} (§14)`)
    }
  }
}

function payloadToObject(p: ReceiptPayload): Record<string, unknown> {
  const out: Record<string, unknown> = {
    iss: p.iss,
    iat: p.iat,
    agent_id: p.agent_id,
    agent_key_id: p.agent_key_id,
    operation: p.operation,
    parents: p.parents,
    input_hash: p.input_hash,
    output_hash: p.output_hash,
    taint: p.taint,
    guardrail_verdict: p.guardrail_verdict ?? 'NA',
  }
  if (p.ruleset_hash !== undefined) out.ruleset_hash = p.ruleset_hash
  if (p.model !== undefined) out.model = p.model
  if (p.tool !== undefined) out.tool = p.tool
  if (p.corpus !== undefined) out.corpus = p.corpus
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

  const header = {
    alg: 'EdDSA',
    typ: JWS_TYP,
    kid: payload.agent_key_id,
    crit: [...JWS_CRIT],
  }
  const headerB = canonicalEncode(header)
  const payloadB = canonicalEncode(payloadToObject(payload))
  const signingInput = b64uEncode(headerB) + '.' + b64uEncode(payloadB)

  const sig = new Uint8Array(
    await subtle.sign('Ed25519', privateKey, enc(signingInput)),
  )
  const jws = signingInput + '.' + b64uEncode(sig)
  const id = await sha256Hex(jws)
  return { jws, payload, id }
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
  if (!Array.isArray(header.crit) || !header.crit.includes('raucle/v1')) {
    throw new Error("crit must include 'raucle/v1'")
  }

  const signingInput = enc(headerB + '.' + payloadB)
  const ok = await subtle.verify('Ed25519', publicKey, b64uDecode(sigB), signingInput)
  if (!ok) throw new Error('signature invalid')

  const payloadObj = JSON.parse(
    new TextDecoder().decode(b64uDecode(payloadB)),
  ) as ReceiptPayload
  // Reject reserved unknown fields per §14.
  for (const k of Object.keys(payloadObj)) {
    if (!KNOWN_FIELDS.has(k) && !k.startsWith('x_')) {
      throw new Error(`reserved unknown field: ${k}`)
    }
  }
  validatePayload(payloadObj)

  if (header.kid !== payloadObj.agent_key_id) {
    throw new Error('header.kid != payload.agent_key_id (§3)')
  }

  const id = await sha256Hex(jws)
  return { jws, payload: payloadObj, id }
}
