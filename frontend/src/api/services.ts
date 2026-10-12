import { ApiClient } from './client'
import type {
  AttackEvent,
  CursorPage,
  PortReservation,
  Profile,
  ProfileInput,
  Server,
  ServerInput,
  TokenResponse,
  Trap,
  TrapInput,
  User,
} from './types'

export function createApi(client: ApiClient) {
  return {
    auth: {
      login: (email: string, password: string) =>
        client.request<TokenResponse>('/auth/login', {
          method: 'POST',
          body: { email, password },
        }),
      register: (name: string, email: string, password: string) =>
        client.request<User>('/auth/register', {
          method: 'POST',
          body: { name, email, password },
        }),
      me: () => client.request<{ user: User }>('/auth/me'),
      logout: () => client.request<void>('/auth/logout', { method: 'POST' }),
      forgotPassword: (email: string) =>
        client.request<{ message: string }>('/auth/forgot-password', {
          method: 'POST',
          body: { email },
        }),
      resetPassword: (token: string, password: string) =>
        client.request<void>('/auth/reset-password', {
          method: 'POST',
          body: { token, password },
        }),
      verifyEmail: (token: string) =>
        client.request<void>('/auth/verify-email', {
          method: 'POST',
          body: { token },
        }),
      resendVerification: (email: string) =>
        client.request<{ message: string }>('/auth/resend-verification', {
          method: 'POST',
          body: { email },
        }),
    },
    profiles: {
      list: () => collectPages<Profile>(client, '/profiles'),
      create: (profile: ProfileInput) =>
        client.request<Profile>('/profiles', { method: 'POST', body: profile }),
      update: (profile: Profile, input: ProfileInput) =>
        client.request<Profile>(`/profiles/${profile.id}`, {
          method: 'PUT',
          body: { expected_version: profile.version, profile: input },
        }),
      delete: (id: string) =>
        client.request<void>(`/profiles/${id}`, { method: 'DELETE' }),
    },
    servers: {
      list: () => collectPages<Server>(client, '/servers'),
      create: (server: ServerInput) =>
        client.request<Server>('/servers', { method: 'POST', body: server }),
      update: (server: Server, input: ServerInput) =>
        client.request<Server>(`/servers/${server.server_id}`, {
          method: 'PUT',
          body: { expected_version: server.version, server: input },
        }),
      delete: (id: string) =>
        client.request<void>(`/servers/${id}`, { method: 'DELETE' }),
      ports: (id: string) =>
        client.request<PortReservation[]>(`/servers/${id}/ports`),
    },
    traps: {
      list: () => collectPages<Trap>(client, '/traps'),
      create: (serverId: string, trap: TrapInput) =>
        client.request<Trap>('/traps', {
          method: 'POST',
          body: { server_id: serverId, trap },
        }),
      update: (trap: Trap, input: TrapInput) =>
        client.request<Trap>(`/traps/${trap.trap_id}`, {
          method: 'PUT',
          body: { expected_version: trap.version, trap: input },
        }),
      delete: (id: string) =>
        client.request<void>(`/traps/${id}`, { method: 'DELETE' }),
      events: (id: string) =>
        client.request<CursorPage<AttackEvent>>(`/traps/${id}/events?limit=100`),
    },
  }
}

async function collectPages<T>(client: ApiClient, path: string): Promise<T[]> {
  const items: T[] = []
  let after: string | null = null
  for (let page = 0; page < 100; page += 1) {
    const separator = path.includes('?') ? '&' : '?'
    const cursor: string = after ? `&after=${encodeURIComponent(after)}` : ''
    const result: CursorPage<T> = await client.request<CursorPage<T>>(
      `${path}${separator}limit=100${cursor}`,
    )
    items.push(...result.items)
    after = result.next_cursor
    if (!after) return items
  }
  return items
}

export type MellCoreApi = ReturnType<typeof createApi>
