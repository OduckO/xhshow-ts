import assert from 'node:assert/strict'
import { createCipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto'
import test from 'node:test'

import {
  buildBrowserSearchBody,
  buildResourceDecryptBody,
  buildSskProof,
  createWebSskExchange,
  extractEncryptedSsk,
  isBlockedByBwsGateway,
  parseWebSsk,
  SessionManager,
  Xhshow
} from '../src/index'

const A1 = 'a'.repeat(52)
// 合成 SSK：48 字节 0x00..0x2f，覆盖「超出 32 字节的尾部拼进 x7」这条分支
const SSK = Buffer.from(Array.from({ length: 48 }, (_, i) => i)).toString('base64')
const md5 = (text: string) => createHash('md5').update(text, 'utf8').digest('hex')
const sha1 = (data: Buffer) => createHash('sha1').update(data).digest()

test('buildSskProof matches an independently computed vector', () => {
  // 期望值用 Python hashlib 按 x7 = nonce ‖ sha1(ssk ‖ nonce) ‖ ssk[32:]、
  // x6 = sha1(md5 ‖ x7) 独立算出
  const proof = buildSskProof('0123456789abcdef0123456789abcdef', { 'xhs-pc-web': SSK }, new Uint8Array([1, 2, 3, 4]))

  assert.deepEqual(proof, {
    x6: { 'xhs-pc-web': 'uSE+IMqd6IfdntT+kqUKmrUPlUU=' },
    x7: { 'xhs-pc-web': 'AQIDBOtFX6WD3D95chxCB0MP/uB59yIxICEiIyQlJicoKSorLC0uLw==' }
  })
})

test('buildSskProof skips short keys and returns null when nothing is usable', () => {
  const short = Buffer.alloc(31).toString('base64')

  assert.equal(buildSskProof(md5('x'), {}), null)
  assert.equal(buildSskProof(md5('x'), { 'xhs-pc-web': short }), null)
  assert.deepEqual(Object.keys(buildSskProof(md5('x'), { 'xhs-pc-web': SSK, other: short })!.x6), ['xhs-pc-web'])
  assert.throws(() => buildSskProof('not-md5', { 'xhs-pc-web': SSK }))
  assert.throws(() => buildSskProof(md5('x'), { 'xhs-pc-web': SSK }, new Uint8Array(3)))
})

test('parseWebSsk accepts the localStorage JSON string and tolerates garbage', () => {
  assert.deepEqual(parseWebSsk(JSON.stringify({ 'xhs-pc-web': SSK })), { 'xhs-pc-web': SSK })
  assert.deepEqual(parseWebSsk({ 'xhs-pc-web': SSK }), { 'xhs-pc-web': SSK })
  assert.deepEqual(parseWebSsk('not json'), {})
  assert.deepEqual(parseWebSsk('[1,2]'), {})
  assert.deepEqual(parseWebSsk(null), {})
})

test('signXs fills x4/x5 like seccore_signv2', () => {
  const client = new Xhshow()
  const params = { note_id: 'abc', cursor: '' }
  const body = { note_id: 'abc', num: 10 }

  const get = client.decodeXs(client.signXsGet('/api/sns/web/v2/comment/page', A1, 'xhs-pc-web', params))
  assert.equal(get.x4, '')
  assert.equal(get.x5, md5('/api/sns/web/v2/comment/page?note_id=abc&cursor='))

  const post = client.decodeXs(client.signXsPost('/api/sns/web/v1/feed', A1, 'xhs-pc-web', body))
  assert.equal(post.x4, 'object')
  assert.equal(post.x5, md5('/api/sns/web/v1/feed' + JSON.stringify(body)))

  // 没有 webSsk 时不出现 x6/x7，与前端一致
  assert.equal('x6' in post, false)
  assert.equal('x7' in post, false)
})

test('signXs adds x6/x7 bound to x5 when the session carries webSsk', () => {
  const client = new Xhshow()
  const session = new SessionManager(undefined, { webSsk: JSON.stringify({ 'xhs-pc-web': SSK }) })
  const xs = client.decodeXs(client.signXsPost('/api/sns/web/v1/feed', A1, 'xhs-pc-web', { a: 1 }, undefined, session))

  const encSsk = Buffer.from(xs.x7['xhs-pc-web'], 'base64')
  const nonce = encSsk.subarray(0, 4)
  const ssk = Buffer.from(SSK, 'base64')
  assert.deepEqual(encSsk.subarray(4, 24), sha1(Buffer.concat([ssk, nonce])))
  assert.deepEqual(encSsk.subarray(24), ssk.subarray(32))
  assert.equal(xs.x6['xhs-pc-web'], sha1(Buffer.concat([Buffer.from(xs.x5, 'hex'), encSsk])).toString('base64'))

  session.setWebSsk(null)
  const cleared = client.decodeXs(client.signXsPost('/api/sns/web/v1/feed', A1, 'xhs-pc-web', { a: 1 }, undefined, session))
  assert.equal('x6' in cleared, false)
})

test('createWebSskExchange decrypts what a simulated server issues', () => {
  const server = generateKeyPairSync('x25519')
  const serverRaw = Buffer.from(server.publicKey.export({ format: 'jwk' }).x as string, 'base64url')
  const exchange = createWebSskExchange(serverRaw.toString('base64'))

  // 服务端：X25519(服务端私钥, 客户端公钥) 直接当 AES-256-GCM 密钥，下发 nonce ‖ 密文 ‖ tag
  const clientKey = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(exchange.clientPublicKeyBase64, 'base64').toString('base64url') },
    format: 'jwk'
  })
  const shared = diffieHellman({ privateKey: server.privateKey, publicKey: clientKey })
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', shared, iv)
  const ssk = randomBytes(48)
  const encrypted = Buffer.concat([iv, cipher.update(ssk), cipher.final(), cipher.getAuthTag()]).toString('base64')

  const response = { code: 0, data: { login_info: { ssk: encrypted } } }
  assert.equal(extractEncryptedSsk(response), encrypted)
  assert.equal(exchange.acceptEncryptedSsk(extractEncryptedSsk(response)!), ssk.toString('base64'))

  const tampered = Buffer.from(encrypted, 'base64')
  tampered[20] ^= 1
  assert.throws(() => exchange.acceptEncryptedSsk(tampered.toString('base64')))
})

test('extractEncryptedSsk follows the front-end lookup order', () => {
  assert.equal(extractEncryptedSsk({ ssk: 'a', data: { ssk: 'b' } }), 'a')
  assert.equal(extractEncryptedSsk({ data: { loginInfo: { ssk: 'c' } } }), 'c')
  assert.equal(extractEncryptedSsk({ data: { ext: { ssk: 'd' } } }), 'd')
  assert.equal(extractEncryptedSsk({ data: { ssk: '' } }), undefined)
  assert.equal(extractEncryptedSsk(null), undefined)
})

test('bws request bodies carry the fields the gateway silently requires', () => {
  const body = buildBrowserSearchBody({ keyword: '猫', page: 2, pageSize: 10, searchId: 'sid' })
  assert.equal(body.xhsBrowserChannel, 'default')
  assert.equal(body.pagePos, 10)
  assert.equal(body.requestId, 'sid')
  assert.equal(buildBrowserSearchBody({ keyword: '猫', channel: 'x' }).xhsBrowserChannel, 'x')

  assert.deepEqual(buildResourceDecryptBody('enc'), { resourceId: 'enc', resourceType: 1 })

  assert.equal(isBlockedByBwsGateway(''), true)
  assert.equal(isBlockedByBwsGateway('Mozilla/5.0 Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0'), false)
})
