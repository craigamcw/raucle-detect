import { test } from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'

import { emit, verify, type ReceiptPayload } from '../src/receipt.js'
import { buildChain, ChainError } from '../src/graph.js'
import { canonicalString } from '../src/canonical.js'

const subtle = webcrypto.subtle

async function genKey(): Promise<webcrypto.CryptoKeyPair> {
  return (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as unknown as webcrypto.CryptoKeyPair
}

async function sha256Hex(s: string): Promise<string> {
  const d = await subtle.digest('SHA-256', new TextEncoder().encode(s))
  return Buffer.from(d).toString('hex')
}

async function basePayload(
  over: Partial<ReceiptPayload> = {},
): Promise<ReceiptPayload> {
  const h = await sha256Hex('hello')
  return {
    iss: 'https://test.example/raucle',
    iat: 1748505600,
    agent_id: 'agent:test.scanner',
    agent_key_id: 'k_test01',
    operation: 'user_input',
    parents: [],
    input_hash: h,
    output_hash: h,
    taint: ['untrusted_user'],
    guardrail_verdict: 'NA',
    ...over,
  }
}

// ── canonical ────────────────────────────────────────────────────

test('canonical sorts keys and rejects floats', () => {
  assert.equal(canonicalString({ b: 1, a: 2 }), '{"a":2,"b":1}')
  assert.throws(() => canonicalString(1.5), /integer/)
})

// ── emit/verify roundtrip ────────────────────────────────────────

test('emit/verify roundtrip preserves payload + stable id', async () => {
  const { privateKey, publicKey } = await genKey()
  const p = await basePayload()
  const r = await emit(p, privateKey)
  const parsed = await verify(r.jws, publicKey)
  assert.equal(parsed.payload.agent_id, p.agent_id)
  assert.equal(parsed.id, r.id)
  assert.equal(parsed.id.length, 64)
})

test('verify rejects a different key', async () => {
  const a = await genKey()
  const b = await genKey()
  const r = await emit(await basePayload(), a.privateKey)
  await assert.rejects(() => verify(r.jws, b.publicKey), /signature invalid/)
})

test('verify rejects wrong alg', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(await basePayload(), privateKey)
  const [, payloadB, sigB] = r.jws.split('.')
  const badHeader = Buffer.from(
    JSON.stringify({ alg: 'HS256', typ: 'provenance-receipt/v1', kid: 'k_test01', crit: ['raucle/v1'] }),
  )
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  await assert.rejects(
    () => verify(`${badHeader}.${payloadB}.${sigB}`, publicKey),
    /unsupported alg/,
  )
})

test('verify requires crit raucle/v1', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(await basePayload(), privateKey)
  const [, payloadB, sigB] = r.jws.split('.')
  const badHeader = Buffer.from(
    JSON.stringify({ alg: 'EdDSA', typ: 'provenance-receipt/v1', kid: 'k_test01', crit: [] }),
  )
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  await assert.rejects(
    () => verify(`${badHeader}.${payloadB}.${sigB}`, publicKey),
    /crit/,
  )
})

// ── payload validation ───────────────────────────────────────────

test('rejects unsorted taint', async () => {
  const { privateKey } = await genKey()
  const p = await basePayload({ taint: ['z_x', 'a_y'] })
  await assert.rejects(() => emit(p, privateKey), /sorted/)
})

test('non-user_input requires parents', async () => {
  const { privateKey } = await genKey()
  const p = await basePayload({
    operation: 'model_call',
    parents: [],
    model: { provider: 't', name: 'e', version: '1' },
  })
  await assert.rejects(() => emit(p, privateKey), /parent/)
})

test('rejects reserved unknown field on emit', async () => {
  const { privateKey } = await genKey()
  const p = await basePayload()
  ;(p as Record<string, unknown>)['rogue'] = true
  await assert.rejects(() => emit(p, privateKey), /reserved|unknown/)
})

test('allows x_ extension field', async () => {
  const { privateKey, publicKey } = await genKey()
  const p = await basePayload()
  ;(p as Record<string, unknown>)['x_trace'] = 'abc'
  const r = await emit(p, privateKey)
  const parsed = await verify(r.jws, publicKey)
  assert.equal(parsed.payload['x_trace'], 'abc')
})

// ── chain DAG + taint ────────────────────────────────────────────

test('chain validates topo + closure', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(await basePayload(), privateKey)
  const r2 = await emit(
    await basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: ['untrusted_user'],
      model: { provider: 't', name: 'e', version: '1' },
    }),
    privateKey,
  )
  const chain = buildChain([r1, r2])
  assert.deepEqual(chain.receipts.map((r) => r.id), [r1.id, r2.id])
})

test('chain rejects topo break', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(await basePayload(), privateKey)
  const r2 = await emit(
    await basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: ['untrusted_user'],
      model: { provider: 't', name: 'e', version: '1' },
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r2, r1]), ChainError)
})

test('chain rejects silent taint loss', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(await basePayload(), privateKey)
  const r2 = await emit(
    await basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: [],
      model: { provider: 't', name: 'e', version: '1' },
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r1, r2]), /monotonicity/)
})

test('sanitisation must declare removed taint', async () => {
  const { privateKey } = await genKey()
  const rh = await sha256Hex('rules-v1')
  const r1 = await emit(await basePayload(), privateKey)
  const bad = await emit(
    await basePayload({
      operation: 'sanitisation',
      parents: [r1.id],
      taint: [],
      ruleset_hash: rh,
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r1, bad]), /x_removed_taint/)
})

test('sanitisation with declared removed taint passes', async () => {
  const { privateKey } = await genKey()
  const rh = await sha256Hex('rules-v1')
  const r1 = await emit(await basePayload(), privateKey)
  const p = await basePayload({
    operation: 'sanitisation',
    parents: [r1.id],
    taint: [],
    ruleset_hash: rh,
  })
  ;(p as Record<string, unknown>)['x_removed_taint'] = ['untrusted_user']
  const ok = await emit(p, privateKey)
  const chain = buildChain([r1, ok])
  assert.equal(chain.receipts.length, 2)
})
