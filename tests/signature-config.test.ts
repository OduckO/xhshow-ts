import assert from 'node:assert/strict'
import test from 'node:test'

import { Base64Encoder, CryptoConfig, Xhshow, xRapParam } from '../src/index'

const cookies = { a1: 'a'.repeat(52), web_session: 'test-session' }
const encoder = new Base64Encoder()

function decodeXsCommon (client: Xhshow): Record<string, unknown> {
  return JSON.parse(encoder.decode(client.signXsCommon(cookies)))
}

test('x-s-common encodes the captured web client versions', () => {
  const common = decodeXsCommon(new Xhshow())

  assert.equal(common.x1, '4.4.3')
  assert.equal(common.x4, '6.53.4')
  assert.equal(common.x5, cookies.a1)
})

test('x-s-common refreshes request time while keeping the module session timestamp', (t) => {
  let now = Date.now() + 1000
  t.mock.method(Date, 'now', () => now)
  const client = new Xhshow()
  const first = decodeXsCommon(client)

  assert.equal(typeof first.x12, 'string')
  const [requestTime, sessionStart] = String(first.x12).split(';').map(Number)
  assert.equal(requestTime, now)
  assert.ok(Number.isSafeInteger(sessionStart) && sessionStart > 0 && sessionStart <= now)

  now += 100
  assert.equal(decodeXsCommon(client).x12, `${now};${sessionStart}`)
  assert.equal(decodeXsCommon(new Xhshow()).x12, `${now};${sessionStart}`)
})

test('x-rap-param encodes SDK version 10301 in the envelope header', () => {
  const value = xRapParam('/api/sns/web/v1/feed', { source_note_id: 'test-note' })

  assert.equal(Buffer.from(value, 'base64').readUInt32BE(20), 10301)
})

test('x-rap-param preserves an explicit SDK version override', () => {
  const value = xRapParam('/api/sns/web/v1/feed', {}, { sdkVersion: 10300 })

  assert.equal(Buffer.from(value, 'base64').readUInt32BE(20), 10300)
})

test('x-s-common preserves an explicit template override', () => {
  const defaults = new CryptoConfig()
  const config = defaults.withOverrides({
    SIGNATURE_XSCOMMON_TEMPLATE: {
      ...defaults.SIGNATURE_XSCOMMON_TEMPLATE,
      x1: 'custom-version',
      x4: 'custom-build',
      x12: '100;50'
    }
  })
  const common = decodeXsCommon(new Xhshow(config))

  assert.equal(common.x1, 'custom-version')
  assert.equal(common.x4, 'custom-build')
  assert.equal(common.x12, '100;50')
})
