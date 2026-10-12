import type { TokenResponse, User } from '../api/types'

const SESSION_KEY = 'mellcore-auth-session'

export type AuthSession = {
  token: string
  expiresAt: number
  user: User
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

function browserStorage(): StorageLike | null {
  return typeof window === 'undefined' ? null : window.sessionStorage
}

export function createSession(response: TokenResponse, now = Date.now()): AuthSession {
  return {
    token: response.access_token,
    expiresAt: now + response.expires_in * 1000,
    user: response.user,
  }
}

export function saveSession(session: AuthSession, storage = browserStorage()): void {
  storage?.setItem(SESSION_KEY, JSON.stringify(session))
}

export function loadSession(
  storage = browserStorage(),
  now = Date.now(),
): AuthSession | null {
  const raw = storage?.getItem(SESSION_KEY)
  if (!raw) return null
  try {
    const session = JSON.parse(raw) as AuthSession
    if (!session.token || !session.user || !Number.isFinite(session.expiresAt)) {
      throw new Error('invalid session')
    }
    if (session.expiresAt <= now) {
      storage?.removeItem(SESSION_KEY)
      return null
    }
    return session
  } catch {
    storage?.removeItem(SESSION_KEY)
    return null
  }
}

export function clearSession(storage = browserStorage()): void {
  storage?.removeItem(SESSION_KEY)
}
