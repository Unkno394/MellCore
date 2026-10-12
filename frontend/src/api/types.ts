export type Role = 'admin' | 'viewer' | 'user'
export type TrapLevel = 'low' | 'medium'
export type ServerStatus = 'unknown' | 'online' | 'offline' | 'error'
export type TrapDesiredState = 'running' | 'stopped'
export type TrapAction = 'start' | 'stop' | 'restart' | 'remove'
export type TrapActionProgress = { action_id: string; status: 'queued' | 'succeeded' | 'failed'; detail: string | null }
export type ActualState =
  | 'unknown'
  | 'installing'
  | 'running'
  | 'stopped'
  | 'failed'
  | 'removed'
export type Transport = 'tcp' | 'udp'
export type RouteMode = 'direct' | 'dispatcher_backend'

export type User = {
  id: string
  username: string
  name: string
  email: string | null
  email_verified_at: string | null
  role: Role
  is_active: boolean
  created_at: string
  updated_at: string
}

export type TokenResponse = {
  user: User
  access_token: string
  token_type: string
  expires_in: number
}

export type ProfileInput = {
  name: string
  description: string
  level: TrapLevel
  honeypot_type: string
  service_type: string
  config: Record<string, unknown>
}

export type Profile = ProfileInput & {
  id: string
  version: number
  created_at: string
  updated_at: string
}

export type ServerSettings = {
  cpu_limit?: number | null
  memory_limit_mb?: number | null
}

export type ServerInput = {
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  credential_ref: string | null
  dispatcher_port: number | null
  settings: ServerSettings
}

export type Server = ServerInput & {
  server_id: string
  user_id: string
  status: ServerStatus
  version: number
  created_at: string
  updated_at: string
}

export type BootstrapServerInput = {
  server: ServerInput
  ssh_password: string | null
  ssh_private_key: string | null
  ssh_key_passphrase: string | null
}

export type BootstrapProgress = {
  server_id: string
  agent_id: string
  status: 'running' | 'succeeded' | 'failed'
  registered: boolean
  message: string | null
}

export type PortBinding = {
  transport: Transport
  host_port: number
  target_port: number
  route_mode: RouteMode
}

export type PortReservation = {
  server_id: string
  transport: Transport
  host_port: number
  purpose: 'ssh' | 'dispatcher' | 'trap'
  trap_id: string | null
  target_port: number | null
  route_mode: RouteMode | null
}

export type TrapInput = {
  name: string
  profile_id: string
  config: Record<string, unknown>
  desired_state: TrapDesiredState
  ports: PortBinding[]
}

export type Trap = {
  trap_id: string
  server_id: string
  user_id: string
  name: string
  profile_id: string
  profile_version: number
  profile_snapshot: Profile
  config: Record<string, unknown>
  effective_config: Record<string, unknown>
  desired_state: TrapDesiredState
  actual_state: ActualState
  version: number
  ports: PortBinding[]
  created_at: string
  updated_at: string
}

export type IncomingEvent = {
  event_id: string
  trap_id: string
  session_id: string | null
  sequence_no: number | null
  event_type: string
  occurred_at: string
  source_ip: string | null
  source_port: number | null
  destination_port: number | null
  protocol: string
  service_type: string
  payload: unknown
  metadata: unknown
}

export type AttackEvent = {
  schema_version: number
  agent_id: string
  server_id: string
  event: IncomingEvent
  received_at: string
  expires_at: string
}

export type AttackGraphMatch = {
  session_key: string
  evidence_domain: string
  technique_key: string
  technique_name: string
  status: 'candidate' | 'attempt' | 'confirmed' | string
  similarity: number
  evidence_event_ids: string[]
  updated_at: string
}

export type CursorPage<T> = {
  items: T[]
  next_cursor: string | null
}

export type ErrorResponse = {
  error?: {
    code?: string
    message?: string
    request_id?: string
  }
}
