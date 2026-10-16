export type Role = 'admin' | 'viewer' | 'user'
export type TrapLevel = 'low' | 'medium' | 'high'
export type ServerStatus = 'unknown' | 'online' | 'offline' | 'error'
export type TrapDesiredState = 'running' | 'stopped'
export type MiddleSshAuthMode = 'realistic' | 'adaptive'
export type SshCredential = { username: string; password: string }
export type TrapAction = 'start' | 'stop' | 'restart' | 'remove'
export type HighTrapProgressState = 'DOWNLOADING' | 'VM_CREATED' | 'INSTALLING' | 'REBOOTING' | 'CONFIGURING' | 'READY' | 'FAILED'
export type TrapActionProgress = { action_id: string; status: 'queued' | 'succeeded' | 'failed'; detail: string | null; progress?: HighTrapProgressState }
export type BaitKind =
  | 'account' | 'file' | 'credential' | 'database' | 'backup'
  | 'network_service' | 'web_interface' | 'process' | 'system_config'
  | 'source_code' | 'cloud_infrastructure' | 'network_pivot' | 'windows'
  | 'canary' | 'history'
export type BaitImplementation = 'virtual_file' | 'virtual_account' | 'virtual_process'
export type VirtualShell = 'bash' | 'sh' | 'nologin'
export type CredentialFormat = 'api_token' | 'ssh_key' | 'password' | 'environment_variables'
export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'kubernetes'
export type WindowsArtifact = 'powershell_script' | 'configuration' | 'document' | 'registry_export'
export type DatabaseFormat = 'sql_dump' | 'sqlite' | 'csv' | 'json'
export type BackupFormat = 'sql_dump' | 'manifest' | 'tar_listing' | 'zip_listing'
export type SystemConfigFormat = 'systemd_unit' | 'cron' | 'ssh_config' | 'application_config'
export type HistoryFormat = 'bash_history' | 'application_log' | 'system_log'
export type VirtualAccountConfig = { login: string; uid?: number | null; home_directory?: string | null; shell?: VirtualShell | null }
export type BaitFileConfig = {
  account?: VirtualAccountConfig
  credential_format?: CredentialFormat
  cloud_provider?: CloudProvider
  windows_artifact?: WindowsArtifact
  database_format?: DatabaseFormat
  backup_format?: BackupFormat
  canary_marker?: string
  system_config_format?: SystemConfigFormat
  history_format?: HistoryFormat
}
export type BaitFile = {
  id: string
  name: string
  path?: string | null
  content: string
  category?: Exclude<BaitKind, 'process'>
  /** Legacy configuration alias, read for traps created before category/implementation split. */
  kind?: Exclude<BaitKind, 'process'>
  implementation?: 'virtual_file' | 'virtual_account'
  config?: BaitFileConfig
}
export type VirtualProcess = {
  id: string
  title?: string
  category?: Extract<BaitKind, 'process' | 'database' | 'network_service' | 'web_interface'>
  /** Legacy configuration alias. */
  kind?: Extract<BaitKind, 'process' | 'database' | 'network_service' | 'web_interface'>
  implementation?: 'virtual_process'
  name: string
  user: string
  command: string
  running: boolean
  listen_port: number | null
  config?: { protocol?: 'tcp' | 'udp' }
}
export type BaitEngagement = { bait_id: string; opens: number; sessions: number; last_opened_at: string }
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
  resources: ContainerResourceLimits
}

export type ContainerResourceLimits = {
  cpu_cores: number
  memory_mb: number
  pids: number
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
  host_inventory: HostInventory | null
  inventory_updated_at: string | null
  version: number
  created_at: string
  updated_at: string
}

export type ServerPresence = { registered: boolean; connected: boolean; can_reboot: boolean; can_uninstall: boolean; can_share_tcp_ports: boolean; last_heartbeat_age_ms: number | null }
export type DeleteServerResult = { remote_cleanup: 'scheduled' | 'unreachable' | 'unsupported' | 'unconfirmed' | 'not_installed' }

export type HostInventory = {
  schema_version: number
  collected_at_unix_ms: number
  static_info: {
    cpu: { vendor: string | null; model: string | null; architecture: string; physical_cores: number | null; logical_threads: number | null; frequency_mhz: number | null; flags: string[] }
    memory: { ram_total_bytes: number | null; swap_total_bytes: number | null }
    disks: Array<{ name: string; model: string | null; size_bytes: number | null; rotational: boolean | null; removable: boolean | null }>
    gpus: Array<{ vendor: string | null; model: string | null; pci_address: string | null; driver: string | null }>
    network: Array<{ name: string; state: string | null; mtu: number | null; speed_mbps: number | null; duplex: string | null; addresses: string[]; virtual_interface: boolean | null }>
    operating_system: { name: string | null; version: string | null; distribution_id: string | null; kernel_release: string | null }
    virtualization: { cpu_virtualization: 'intel_vtx' | 'amd_v' | null; kvm: HostComponentCapability; qemu: HostComponentCapability; libvirt: HostComponentCapability; nested_virtualization: boolean | null; guest_architectures: string[] }
  }
  dynamic: {
    uptime_seconds: number | null
    load_average_1m: number | null
    load_average_5m: number | null
    load_average_15m: number | null
    cpu_utilization_percent: number | null
    ram_used_bytes: number | null
    ram_available_bytes: number | null
    swap_used_bytes: number | null
    filesystems: Array<{ mount_point: string; total_bytes: number | null; available_bytes: number | null }>
    network: Array<{ name: string; received_bytes: number | null; transmitted_bytes: number | null }>
  }
}

export type HostComponentCapability = {
  installed: boolean | null
  usable: boolean | null
  version: string | null
}

export type BootstrapServerInput = {
  server: ServerInput
  ssh_password: string | null
  ssh_private_key: string | null
  ssh_key_passphrase: string | null
  sudo_password: string | null
}

export type BootstrapProgress = {
  server_id: string
  agent_id: string
  status: 'running' | 'succeeded' | 'failed'
  registered: boolean
  message: string | null
}

export type ServerActionProgress = {
  action_id: string
  action: 'reboot'
  status: 'queued' | 'succeeded' | 'failed'
  detail: string | null
}

export type PortBinding = {
  transport: Transport
  host_port: number
  target_port: number
  route_mode: RouteMode
  weight?: number | null
}

export type PortReservation = {
  server_id: string
  transport: Transport
  host_port: number
  purpose: 'ssh' | 'dispatcher' | 'trap'
  trap_id: string | null
  target_port: number | null
  route_mode: RouteMode | null
  weight: number | null
}

export type TrapInput = {
  name: string
  profile_id: string
  config: Record<string, unknown>
  resources?: ContainerResourceLimits
  desired_state: TrapDesiredState
  ports: PortBinding[]
}

export type HighImageSource = {
  url: string
  sha256: string
  format: 'iso'
  architecture: 'x86_64'
}

export type HighIsoUploadResponse = {
  image_source: HighImageSource
  size_bytes: number
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
  resources: ContainerResourceLimits
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
  scenario_id: string
  trap_id: string
  session_key: string
  evidence_domain: string
  technique_key: string
  technique_name: string
  status: 'candidate' | 'attempt' | 'confirmed' | string
  similarity: number
  coverage: number
  evidence_event_ids: string[]
  matched_event_ids: string[]
  nodes: AttackGraphNode[]
  edges: AttackGraphEdge[]
  updated_at: string
}

export type AttackGraphNode = {
  node_id: string
  node_key: string
  action_kind: string
  process_class: string
  resource_class: string
  status: 'matched' | 'missing' | 'legacy_unattributed' | 'outcome_mismatch' | 'observed_unlinked'
  matched_event_ids: string[]
  observed_outcome: string | null
  expected_outcome: string
}

export type AttackGraphEdge = {
  from_node: string
  to_node: string
  status: 'matched' | 'missing' | 'legacy_unattributed'
  matched_event_ids: string[]
  observed_outcome: string | null
  expected_outcome: string
  time_delta_ms: number | null
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
