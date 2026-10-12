import assert from 'node:assert/strict'
import test from 'node:test'
import { clearSession, createSession, loadSession, saveSession } from '../src/auth/session.ts'

function memoryStorage() {
  const data = new Map()
  return { getItem: (key) => data.get(key) ?? null, setItem: (key, value) => data.set(key, value), removeItem: (key) => data.delete(key) }
}

const user = { id: 'u1', username: 'legacy', name: 'Operator', email: 'operator@example.com', email_verified_at: null, role: 'user', is_active: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }

test('creates and restores a non-expired JWT session', () => {
  const storage = memoryStorage()
  const session = createSession({ user, access_token: 'jwt', token_type: 'Bearer', expires_in: 60 }, 1_000)
  saveSession(session, storage)
  assert.deepEqual(loadSession(storage, 2_000), session)
  clearSession(storage)
  assert.equal(loadSession(storage, 2_000), null)
})

test('removes an expired session instead of using a stale JWT', () => {
  const storage = memoryStorage()
  saveSession(createSession({ user, access_token: 'jwt', token_type: 'Bearer', expires_in: 1 }, 1_000), storage)
  assert.equal(loadSession(storage, 2_001), null)
})
