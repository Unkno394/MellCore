import { ApiClient } from './client'
import type {
  AttackEvent,
  AttackGraphMatch,
  AuditEntry,
  BaitEngagement,
  BootstrapProgress,
  BootstrapServerInput,
  CursorPage,
  IncomingEvent,
  HighIsoUploadResponse,
  PortReservation,
  Profile,
  ProfileInput,
  EffectiveAccess,
  Invitation,
  InvitationCreated,
  MeResponse,
  PermissionInfo,
  RoleInput,
  RoleView,
  Server,
  ServerPresence,
  DeleteServerResult,
  ServerActionProgress,
  ServerInput,
  TokenResponse,
  Trap,
  TrapAction,
  TrapActionProgress,
  TrapInput,
  User,
} from './types'

// The management API flattens IncomingEvent into each stored event record.
type StoredAttackEvent = Omit<AttackEvent, 'event'> & IncomingEvent

export function createApi(client: ApiClient) {
  return {
    auth: {
      login: (email: string, password: string) =>
        client.request<TokenResponse>('/auth/login', {
          method: 'POST',
          body: { email, password },
        }),
      refresh: () => client.request<TokenResponse>('/auth/refresh', { method: 'POST' }),
      register: (name: string, email: string, password: string) =>
        client.request<User>('/auth/register', {
          method: 'POST',
          body: { name, email, password },
        }),
      acceptInvitation: (token: string, name: string, password: string) =>
        client.request<User>('/auth/accept-invitation', {
          method: 'POST',
          body: { token, name, password },
        }),
      me: () => client.request<MeResponse>('/auth/me'),
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
      changeEmail: (currentPassword: string, newEmail: string) =>
        client.request<{ message: string }>('/auth/change-email', {
          method: 'POST',
          body: { current_password: currentPassword, new_email: newEmail },
        }),
      changePassword: (currentPassword: string, newPassword: string) =>
        client.request<void>('/auth/change-password', {
          method: 'POST',
          body: { current_password: currentPassword, new_password: newPassword },
        }),
    },
    users: {
      list: () => collectPages<User>(client, '/users'),
      access: (id: string) => client.request<EffectiveAccess>(`/users/${id}/permissions`),
      assignRoles: (id: string, roleIds: string[]) =>
        client.request<EffectiveAccess>(`/users/${id}/roles`, { method: 'PUT', body: { role_ids: roleIds } }),
    },
    roles: {
      permissions: () => client.request<PermissionInfo[]>('/permissions'),
      list: () => client.request<RoleView[]>('/roles'),
      create: (input: RoleInput) => client.request<RoleView>('/roles', { method: 'POST', body: input }),
      update: (id: string, input: RoleInput) => client.request<RoleView>(`/roles/${id}`, { method: 'PUT', body: input }),
      copy: (id: string, name: string, description?: string) =>
        client.request<RoleView>(`/roles/${id}/copy`, { method: 'POST', body: { name, description } }),
      delete: (id: string) => client.request<void>(`/roles/${id}`, { method: 'DELETE' }),
    },
    invitations: {
      list: () => client.request<Invitation[]>('/invitations'),
      create: (email: string, roleIds: string[], expiresInHours = 72) =>
        client.request<InvitationCreated>('/invitations', {
          method: 'POST',
          body: { email, role_ids: roleIds, expires_in_hours: expiresInHours },
        }),
      revoke: (id: string) => client.request<void>(`/invitations/${id}`, { method: 'DELETE' }),
    },
    audit: {
      roles: (limit = 50) => client.request<AuditEntry[]>(`/audit/roles?limit=${limit}`),
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
      presence: (serverId: string) => client.request<ServerPresence>(`/servers/${serverId}/presence`),
      bootstrap: (input: BootstrapServerInput) =>
        client.request<BootstrapProgress>('/servers/bootstrap', { method: 'POST', body: input }),
      bootstrapStatus: (serverId: string) =>
        client.request<BootstrapProgress>(`/servers/${serverId}/bootstrap`),
      create: (server: ServerInput) =>
        client.request<Server>('/servers', { method: 'POST', body: server }),
      update: (server: Server, input: ServerInput) =>
        client.request<Server>(`/servers/${server.server_id}`, {
          method: 'PUT',
          body: { expected_version: server.version, server: input },
        }),
      delete: (id: string) =>
        client.request<DeleteServerResult>(`/servers/${id}`, { method: 'DELETE', timeoutMs: 60_000 }),
      action: (id: string, action: 'reboot') =>
        client.request<ServerActionProgress>(`/servers/${id}/actions`, { method: 'POST', body: { action } }),
      actionStatus: (serverId: string, actionId: string) =>
        client.request<ServerActionProgress>(`/servers/${serverId}/actions/${actionId}`),
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
      uploadHighIso: (file: File) =>
        client.uploadFile<HighIsoUploadResponse>('/high-iso-upload', file),
      update: (trap: Trap, input: TrapInput) =>
        client.request<Trap>(`/traps/${trap.trap_id}`, {
          method: 'PUT',
          body: { expected_version: trap.version, trap: input },
        }),
      delete: (id: string) =>
        client.request<void>(`/traps/${id}`, { method: 'DELETE' }),
      events: async (id: string, after: string | null = null, limit = 100, q = ''): Promise<CursorPage<AttackEvent>> => {
        const params = new URLSearchParams({ limit: String(limit) })
        if (after) params.set('after', after)
        if (q.trim()) params.set('q', q.trim())
        const page = await client.request<CursorPage<StoredAttackEvent>>(`/traps/${id}/events?${params}`)
        return {
          ...page,
          items: page.items.map(({ schema_version, agent_id, server_id, received_at, expires_at, ...event }) => ({
            schema_version, agent_id, server_id, received_at, expires_at, event,
          })),
        }
      },
      event: async (id: string, eventId: string): Promise<AttackEvent> => {
        const { schema_version, agent_id, server_id, received_at, expires_at, ...event } = await client.request<StoredAttackEvent>(`/traps/${id}/events/${eventId}`)
        return { schema_version, agent_id, server_id, received_at, expires_at, event }
      },
      attackMatches: (id: string) =>
        client.request<AttackGraphMatch[]>(`/traps/${id}/attack-matches`),
      baitEngagement: (id: string) =>
        client.request<BaitEngagement[]>(`/traps/${id}/bait-engagement`),
      action: (id: string, action: TrapAction) =>
        client.request<TrapActionProgress>(`/traps/${id}/actions`, { method: 'POST', body: { action } }),
      actionStatus: (trapId: string, actionId: string) =>
        client.request<TrapActionProgress>(`/traps/${trapId}/actions/${actionId}`),
      sharePort: (trapId: string, listenerPort: number, members: { trap_id: string; weight: number }[]) =>
        client.request<TrapActionProgress>(`/traps/${trapId}/share-port`, {
          method: 'POST', body: { listener_port: listenerPort, members },
        }),
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
