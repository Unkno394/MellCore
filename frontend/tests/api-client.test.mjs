import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiClient, ApiError } from '../src/api/client.ts'

test('adds bearer token, JSON body and parses a successful response', async () => {
  let request
  const client = new ApiClient({
    baseUrl: 'http://mellcore.test/api/v1', getToken: () => 'test-jwt',
    fetchImpl: async (url, init) => {
      request = { url, init }
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })
  assert.deepEqual(await client.request('/profiles', { method: 'POST', body: { name: 'ssh' } }), { ok: true })
  assert.equal(request.url, 'http://mellcore.test/api/v1/profiles')
  assert.equal(request.init.headers.get('authorization'), 'Bearer test-jwt')
  assert.equal(request.init.body, JSON.stringify({ name: 'ssh' }))
  assert.equal(request.init.credentials, 'same-origin')
})

test('refresh rejection does not clear a still-valid access session', async () => {
  let unauthorized = 0
  const client = new ApiClient({
    baseUrl: 'http://mellcore.test/api/v1', getToken: () => 'old-jwt',
    onUnauthorized: () => { unauthorized += 1 },
    fetchImpl: async () => new Response(JSON.stringify({ error: { code: 'unauthorized' } }), { status: 401 }),
  })
  await assert.rejects(client.request('/auth/refresh', { method: 'POST' }), (error) => error instanceof ApiError && error.status === 401)
  assert.equal(unauthorized, 0)
})

test('surfaces backend request ID and invokes the unauthorized callback', async () => {
  let unauthorized = 0
  const client = new ApiClient({
    baseUrl: 'http://mellcore.test/api/v1', getToken: () => 'expired-jwt', onUnauthorized: () => { unauthorized += 1 },
    fetchImpl: async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'Invalid token', request_id: 'req-42' } }), { status: 401 }),
  })
  await assert.rejects(client.request('/auth/me'), (error) => {
    assert.ok(error instanceof ApiError)
    assert.equal(error.status, 401)
    assert.equal(error.code, 'unauthorized')
    assert.equal(error.requestId, 'req-42')
    return true
  })
  assert.equal(unauthorized, 1)
})

test('aborts requests at the configured timeout', async () => {
  const client = new ApiClient({
    baseUrl: 'http://mellcore.test/api/v1', timeoutMs: 5,
    fetchImpl: async (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })),
  })
  await assert.rejects(client.request('/slow'), (error) => error instanceof ApiError && error.code === 'request_timeout')
})
