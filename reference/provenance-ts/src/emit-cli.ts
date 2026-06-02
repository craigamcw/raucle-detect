/**
 * Conformance-harness helper: reads JSON requests
 * {"seed_hex":"...","payload":{...}} (one per line) from stdin and writes
 * {"jws":"...","id":"..."} (one per line) to stdout, using the TS
 * reference implementation. See reference/conformance.py.
 */
import { webcrypto } from 'node:crypto'
import { createInterface } from 'node:readline'
import { emit, type ReceiptPayload } from './receipt.js'
import { canonicalEncode } from './canonical.js'

const subtle = webcrypto.subtle

const canonMode = process.argv[2] === '--canon'

async function importSeedKey(seedHex: string): Promise<webcrypto.CryptoKey> {
  const seed = Buffer.from(seedHex, 'hex')
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  const pkcs8 = Buffer.concat([prefix, seed])
  return subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
}

const rl = createInterface({ input: process.stdin })
for await (const line of rl) {
  if (!line.trim()) continue
  const req = JSON.parse(line)
  if (canonMode) {
    // Canonicalisation cross-check (key ordering): {"obj": <value>} ->
    // {"hex": "<utf8 hex of canonical bytes>"}.
    const bytes = canonicalEncode(req.obj)
    process.stdout.write(
      JSON.stringify({ hex: Buffer.from(bytes).toString('hex') }) + '\n',
    )
    continue
  }
  const key = await importSeedKey(req.seed_hex)
  const r = await emit(req.payload as ReceiptPayload, key)
  process.stdout.write(JSON.stringify({ jws: r.jws, id: r.id }) + '\n')
}
