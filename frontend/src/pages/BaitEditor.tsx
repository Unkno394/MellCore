import type { ReactNode } from 'react'
import type {
  BackupFormat,
  BaitImplementation,
  BaitKind,
  CloudProvider,
  CredentialFormat,
  DatabaseFormat,
  HistoryFormat,
  SystemConfigFormat,
  VirtualShell,
  WindowsArtifact,
} from '../api/types'

export type BaitDraft = {
  id: string | null
  source: 'file' | 'process' | null
  category: BaitKind
  implementation: BaitImplementation
  title: string
  path: string
  content: string
  login: string
  uid: string
  homeDirectory: string
  shell: VirtualShell
  credentialFormat: CredentialFormat
  cloudProvider: CloudProvider
  windowsArtifact: WindowsArtifact
  databaseFormat: DatabaseFormat
  backupFormat: BackupFormat
  canaryMarker: string
  systemConfigFormat: SystemConfigFormat
  historyFormat: HistoryFormat
  processName: string
  user: string
  command: string
  running: boolean
  listenPort: string
  protocol: 'tcp' | 'udp'
}

export type BaitCategoryDefinition = {
  id: BaitKind
  group: 'access' | 'data' | 'infrastructure' | 'activity'
  label: string
  description: string
  implementation: BaitImplementation
  path?: string
}

export const baitCategories: BaitCategoryDefinition[] = [
  { id: 'account', group: 'access', label: 'Учётная запись', implementation: 'virtual_account', description: 'Виртуальный Linux-пользователь появляется в /etc/passwd. Middle фиксирует SSH-аутентификацию с этим логином; пароль не задаётся.', path: '' },
  { id: 'credential', group: 'access', label: 'Учётные данные', implementation: 'virtual_file', description: 'Фиктивный секрет хранится в виртуальном файле. Middle фиксирует чтение файла, но не использование значения в стороннем сервисе.', path: '/srv/billing-api/.env.decoy' },
  { id: 'cloud_infrastructure', group: 'access', label: 'Облачная инфраструктура', implementation: 'virtual_file', description: 'Файл выглядит как конфигурация облака или Kubernetes. Настоящего подключения к провайдеру нет.', path: '/root/.aws/credentials' },
  { id: 'windows', group: 'access', label: 'Windows-артефакт', implementation: 'virtual_file', description: 'Файл в виртуальной системе Middle. В Windows-профиле доступен через PowerShell; настоящая Windows VM не запускается.', path: '/opt/decoys/windows/admin.ps1' },
  { id: 'file', group: 'data', label: 'Файл или документ', implementation: 'virtual_file', description: 'Файл создаётся в виртуальной файловой системе Middle. Чтение фиксируется с ID приманки.', path: '/home/admin/Documents/internal-report.txt' },
  { id: 'database', group: 'data', label: 'База данных или дамп', implementation: 'virtual_file', description: 'Создаётся SQL, CSV, JSON или SQLite-подобный файл. Это не отдельная СУБД и пользовательские данные не меняют встроенный макет psql.', path: '/var/backups/billing.sql' },
  { id: 'backup', group: 'data', label: 'Резервная копия', implementation: 'virtual_file', description: 'Файл с данными, манифестом или примером списка архива. ZIP/TAR-архив автоматически не создаётся.', path: '/var/backups/db-backup.sql' },
  { id: 'source_code', group: 'data', label: 'Проект и исходный код', implementation: 'virtual_file', description: 'Один виртуальный файл проекта. Редактор дерева каталогов и нескольких файлов пока не поддерживается.', path: '/srv/billing-api/config.yaml' },
  { id: 'canary', group: 'data', label: 'Honeytoken / Canary', implementation: 'virtual_file', description: 'Уникальный маркер хранится в файле; чтение создаёт событие с ID приманки. Обращения к маркеру вне Middle не отслеживаются.', path: '/home/admin/private/credentials.txt' },
  { id: 'network_service', group: 'infrastructure', label: 'Сетевая служба', implementation: 'virtual_process', description: 'Виртуальный процесс можно увидеть через ps, ss и systemctl. Настоящий TCP/UDP listener не создаётся.', path: '/etc/decoys/services.conf' },
  { id: 'web_interface', group: 'infrastructure', label: 'Веб-интерфейс / API', implementation: 'virtual_process', description: 'Виртуальный процесс показывает предполагаемую веб-службу в системных командах. HTTP-маршруты и ответы не обслуживаются.', path: '/srv/billing-api/docs/admin-panel.html' },
  { id: 'process', group: 'infrastructure', label: 'Процесс или приложение', implementation: 'virtual_process', description: 'Строка процесса отображается в виртуальных ps/top. Команда записывается как данные и не запускается.', path: '' },
  { id: 'system_config', group: 'infrastructure', label: 'Системная конфигурация', implementation: 'virtual_file', description: 'Файл конфигурации внутри гостевой модели. Он не меняет systemd, cron или настройки хоста.', path: '/etc/systemd/system/billing.service' },
  { id: 'network_pivot', group: 'infrastructure', label: 'Сетевой переход', implementation: 'virtual_file', description: 'Файл с фиктивными внутренними адресами и SSH-настройками. Реальные маршруты и переходы не создаются.', path: '/home/admin/.ssh/config.decoy' },
  { id: 'history', group: 'activity', label: 'История активности', implementation: 'virtual_file', description: 'Текстовая история или журнал в виртуальном файле. Содержимое можно задать построчно.', path: '/home/admin/Documents/old-bash-history.txt' },
]

const categoryMap = new Map(baitCategories.map((category) => [category.id, category]))
const groups = [
  { id: 'access', label: 'Доступ и учётные данные' },
  { id: 'data', label: 'Данные и проекты' },
  { id: 'infrastructure', label: 'Службы и инфраструктура' },
  { id: 'activity', label: 'Следы активности' },
] as const

function markerValue() {
  return `MELLCORE-CANARY-${crypto.randomUUID().replaceAll('-', '').slice(0, 16).toUpperCase()}`
}

function templateFor(category: BaitKind, subtype = ''): string {
  switch (category) {
    case 'credential':
      if (subtype === 'ssh_key') return '-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY_ONLY_NOT_A_REAL_KEY\n-----END OPENSSH PRIVATE KEY-----\n'
      if (subtype === 'password') return 'username=backup-reader\npassword=DECOY_ONLY_CHANGE_ME\n'
      if (subtype === 'api_token') return 'API_TOKEN=DECOY_ONLY_REPLACE_WITH_FAKE_VALUE\n'
      return 'APP_ENV=production\nDATABASE_URL=postgres://billing_ro:DECOY_ONLY@db-internal/billing\nAPI_TOKEN=DECOY_ONLY_REPLACE_WITH_FAKE_VALUE\n'
    case 'cloud_infrastructure':
      if (subtype === 'azure') return '# Fake Azure profile\nsubscription_id = 00000000-0000-0000-0000-000000000000\ntenant_id = 00000000-0000-0000-0000-000000000000\nclient_secret = DECOY_ONLY\n'
      if (subtype === 'gcp') return '{\n  "type": "service_account",\n  "project_id": "decoy-billing",\n  "private_key_id": "DECOY_ONLY",\n  "client_email": "billing-reader@example.invalid"\n}\n'
      if (subtype === 'kubernetes') return 'apiVersion: v1\nkind: Config\nclusters:\n  - name: internal-staging\n    cluster:\n      server: https://k8s.internal.example.invalid\nusers: []\n'
      return '[default]\naws_access_key_id = DECOYONLY000000000000\naws_secret_access_key = DECOY_ONLY_NOT_A_REAL_SECRET\nregion = eu-north-1\n'
    case 'windows':
      if (subtype === 'powershell_script') return 'Get-Service | Where-Object {$_.Status -eq "Running"}\n'
      if (subtype === 'registry_export') return 'Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Billing]\n"Environment"="staging"\n'
      if (subtype === 'document') return 'Internal Windows operations note\nEnvironment: staging\nOwner: it-operations\n'
      return '[BillingService]\nImagePath=C:\\Program Files\\Billing\\worker.exe\nStart=2\n'
    case 'database':
      if (subtype === 'csv') return 'id,email,role\n101,ops@example.invalid,operator\n102,finance@example.invalid,reader\n'
      if (subtype === 'json') return '{\n  "database": "billing",\n  "users": [{"id": 101, "email": "ops@example.invalid", "role": "operator"}]\n}\n'
      if (subtype === 'sqlite') return 'SQLite database artifact placeholder\nThis is a virtual text file, not an SQLite database image.\n'
      return '-- Fake SQL dump for the virtual filesystem\nCREATE TABLE customers (id INT, email TEXT);\nINSERT INTO customers VALUES (101, \'ops@example.invalid\');\n'
    case 'backup':
      if (subtype === 'tar_listing') return 'billing-2026-10-01/\nbilling-2026-10-01/database.sql\nbilling-2026-10-01/manifest.txt\n'
      if (subtype === 'zip_listing') return 'Archive: billing-release.zip\n  Length      Name\n---------     ----\n      842     database.sql\n      190     restore-notes.txt\n'
      if (subtype === 'manifest') return 'backup_id: billing-2026-10-01\ncreated_at: 2026-10-01T02:15:00Z\ncontents:\n  - database.sql\n  - application-config.yaml\n'
      return '-- Fake backup data\n-- created_at: 2026-10-01T02:15:00Z\nCREATE TABLE customers (id INT, email TEXT);\n'
    case 'system_config':
      if (subtype === 'cron') return '15 2 * * * app /opt/billing/bin/reconcile --quiet\n'
      if (subtype === 'ssh_config') return 'Host db-internal\n  HostName 10.20.0.15\n  User billing_ro\n  IdentityFile ~/.ssh/id_billing_ro\n'
      if (subtype === 'application_config') return '[database]\nhost = db-internal\nname = billing\nuser = billing_ro\n'
      return '[Unit]\nDescription=Billing background worker\n\n[Service]\nUser=app\nExecStart=/opt/billing/bin/worker\n'
    case 'history':
      if (subtype === 'application_log') return '2026-10-12T08:14:03Z INFO billing-api started\n2026-10-12T08:16:22Z WARN fallback credentials loaded\n'
      if (subtype === 'system_log') return 'Oct 12 08:14:03 srv-app-01 systemd[1]: Started billing-api.service\nOct 12 08:16:22 srv-app-01 billing-api[842]: fallback credentials loaded\n'
      return 'systemctl status billing-api\npsql -h db-internal -U billing_ro -d billing -c "select count(*) from users;"\ncat /srv/billing-api/.env\n'
    case 'network_service':
      return '# Virtual service notes\nredis 6379/tcp\n'
    case 'web_interface':
      return '<title>Billing Admin</title>\n<h1>Internal billing console</h1>\n'
    case 'network_pivot':
      return 'Host internal-db\n  HostName 10.20.0.15\n  User billing_ro\n\nHost staging-api\n  HostName 10.20.4.34\n  User deploy\n'
    case 'source_code':
      return 'DATABASE_URL = "postgres://billing_ro:DECOY_ONLY@db-internal/billing"\n'
    case 'canary':
      return `Internal support credentials.\nMarker: ${subtype}\n`
    case 'file':
      return 'Internal operations note\nClassification: confidential\nOwner: finance-ops\n'
    default:
      return ''
  }
}

export function newBaitDraft(category: BaitKind = 'file'): BaitDraft {
  const definition = categoryMap.get(category) ?? categoryMap.get('file')!
  const marker = category === 'canary' ? markerValue() : ''
  const subtype = category === 'credential' ? 'environment_variables' : category === 'history' ? 'bash_history' : ''
  const content = templateFor(category, category === 'canary' ? marker : subtype)
  return {
    id: null,
    source: null,
    category,
    implementation: definition.implementation,
    title: '',
    path: definition.path ?? '',
    content,
    login: 'backup-admin',
    uid: '1002',
    homeDirectory: '/home/backup-admin',
    shell: 'bash',
    credentialFormat: 'environment_variables',
    cloudProvider: 'aws',
    windowsArtifact: 'powershell_script',
    databaseFormat: 'sql_dump',
    backupFormat: 'manifest',
    canaryMarker: marker,
    systemConfigFormat: 'systemd_unit',
    historyFormat: 'bash_history',
    processName: category === 'network_service' ? 'internal-redis' : category === 'web_interface' ? 'billing-dashboard' : 'billing-worker',
    user: 'app',
    command: category === 'network_service' ? 'redis-server *:6379' : category === 'web_interface' ? '/usr/bin/node /opt/dashboard/server.js' : '/app/billing-worker --queue invoices',
    running: true,
    listenPort: category === 'network_service' ? '6379' : category === 'web_interface' ? '8080' : '',
    protocol: 'tcp',
  }
}

function windowsTemplate(category: BaitKind): string | null {
  switch (category) {
    case 'credential': return 'SERVICE_USER=svc-backup\nSERVICE_TOKEN=DECOY_ONLY_WINDOWS_TOKEN\n'
    case 'cloud_infrastructure': return '[default]\nregion=us-east-1\naws_access_key_id=DECOYONLY0000000000\naws_secret_access_key=DECOY_ONLY\n'
    case 'database': return 'id,email,role\n101,ops@example.invalid,operator\n'
    case 'backup': return 'Windows backup manifest\nSource: C:\\ProgramData\\Billing\nStatus: completed\n'
    case 'system_config': return '[BillingService]\nImagePath=C:\\Program Files\\Billing\\worker.exe\nStart=2\n'
    case 'source_code': return '$connectionString = "Server=internal-db;User Id=billing;Password=DECOY_ONLY"\n'
    case 'history': return 'Get-Service Billing\nGet-Content C:\\ProgramData\\Billing\\config.ini\n'
    case 'network_pivot': return 'Internal database: db-internal.example.invalid\nAddress: 10.20.0.15\n'
    default: return null
  }
}

export function draftFromFile(bait: import('../api/types').BaitFile): BaitDraft {
  const category = bait.category ?? bait.kind ?? 'file'
  const draft = newBaitDraft(category)
  const config = bait.config ?? {}
  const account = config.account
  return {
    ...draft,
    id: bait.id,
    source: 'file',
    implementation: bait.implementation ?? (category === 'account' ? 'virtual_account' : 'virtual_file'),
    title: bait.name,
    path: bait.path ?? draft.path,
    content: bait.content,
    login: account?.login ?? (category === 'account' ? bait.name : draft.login),
    uid: account?.uid == null ? draft.uid : String(account.uid),
    homeDirectory: account?.home_directory ?? draft.homeDirectory,
    shell: account?.shell ?? draft.shell,
    credentialFormat: config.credential_format ?? draft.credentialFormat,
    cloudProvider: config.cloud_provider ?? draft.cloudProvider,
    windowsArtifact: config.windows_artifact ?? draft.windowsArtifact,
    databaseFormat: config.database_format ?? draft.databaseFormat,
    backupFormat: config.backup_format ?? draft.backupFormat,
    canaryMarker: config.canary_marker ?? draft.canaryMarker,
    systemConfigFormat: config.system_config_format ?? draft.systemConfigFormat,
    historyFormat: config.history_format ?? draft.historyFormat,
  }
}

export function draftFromProcess(process: import('../api/types').VirtualProcess): BaitDraft {
  const category = process.category ?? process.kind ?? 'process'
  const draft = newBaitDraft(category)
  return {
    ...draft,
    id: process.id,
    source: 'process',
    implementation: 'virtual_process',
    title: process.title || process.name,
    processName: process.name,
    user: process.user,
    command: process.command,
    running: process.running,
    listenPort: process.listen_port == null ? '' : String(process.listen_port),
    protocol: category === 'web_interface' ? 'tcp' : process.config?.protocol ?? 'tcp',
  }
}

type Props = {
  draft: BaitDraft
  windows: boolean
  busy: boolean
  error: string
  onChange: (draft: BaitDraft) => void
  onSave: () => void
  onCancel: () => void
}

function inputClass() {
  return 'mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm text-white/90 outline-none focus:border-orange-300/50'
}

function selectClass() {
  return 'mt-2 w-full rounded-lg border border-white/10 bg-[#160e0c] px-3 py-3 text-sm text-white/90 outline-none focus:border-orange-300/50'
}

function textareaClass() {
  return `${inputClass()} min-h-40 resize-y font-mono text-xs leading-5`
}

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="block text-xs text-white/60">{label}{children}{hint && <span className="mt-2 block text-[11px] leading-5 text-white/35">{hint}</span>}</label>
}

export default function BaitEditor({ draft, windows, busy, error, onChange, onSave, onCancel }: Props) {
  const definition = categoryMap.get(draft.category)!
  const update = (changes: Partial<BaitDraft>) => onChange({ ...draft, ...changes })
  const changeCategory = (category: BaitKind) => {
    const next = newBaitDraft(category)
    onChange({ ...next, path: windows && next.implementation === 'virtual_file' ? `/C/Users/Public/Documents/${next.path.split('/').at(-1) || 'decoy.txt'}` : next.path, homeDirectory: windows && next.implementation === 'virtual_account' ? `/C/Users/${next.login}` : next.homeDirectory, content: windows ? windowsTemplate(category) ?? next.content : next.content, command: windows && next.implementation === 'virtual_process' ? `C:\\Program Files\\${next.processName}\\${next.processName}.exe` : next.command, id: draft.id, source: draft.source, title: draft.title })
  }
  const isProcess = draft.implementation === 'virtual_process'
  const isAccount = draft.implementation === 'virtual_account'
  const implementationChoices: BaitImplementation[] = draft.category === 'network_service' || draft.category === 'web_interface'
    ? ['virtual_process', 'virtual_file']
    : draft.category === 'account' && draft.implementation === 'virtual_file'
      ? ['virtual_account', 'virtual_file']
    : draft.category === 'database' && draft.implementation === 'virtual_process'
      ? ['virtual_file', 'virtual_process']
      : [definition.implementation]
  const processCategory = isProcess
  const pathLabel = draft.category === 'history' ? 'Путь к истории / журналу' : draft.category === 'backup' ? 'Путь к файлу резервной копии' : draft.category === 'canary' ? 'Путь к Canary-файлу' : 'Виртуальный путь'
  const contentLabel = draft.category === 'history' ? 'Записи истории · одна запись на строку' : draft.category === 'credential' ? 'Фиктивные данные' : draft.category === 'database' ? 'Данные / SQL' : draft.category === 'backup' ? 'Содержимое файла' : 'Содержимое'
  const processPreview = windows ? `PS> Get-Process\n${draft.processName || 'example'}  2100  ${draft.running ? 'Running' : 'Stopped'}` : `${draft.running ? '$ ps aux\n' : '$ systemctl list-units\n'}${draft.user || 'app'}  4000  ${draft.command || '/usr/bin/example-service'}${draft.listenPort ? `\n$ ss -lntup\n${draft.protocol} LISTEN 0 128 0.0.0.0:${draft.listenPort} users:((${JSON.stringify(draft.processName || 'example')},pid=4000,fd=3))` : ''}`
  const accountPreview = windows ? `PS> Get-LocalUser ${draft.login || 'backup-admin'}\nName: ${draft.login || 'backup-admin'}\nEnabled: True\nHome: ${draft.homeDirectory || '/C/Users/backup-admin'}` : `${draft.login || 'backup-admin'}:x:${draft.uid || '1002'}:${draft.uid || '1002'}:Service account:${draft.homeDirectory || '/home/backup-admin'}:${draft.shell === 'nologin' ? '/usr/sbin/nologin' : `/bin/${draft.shell || 'bash'}`}`
  const filePreview = windows ? `PS> Get-Content ${draft.path.startsWith('/C/') ? `C:${draft.path.slice(2).replaceAll('/', '\\')}` : draft.path}\n${draft.content || '(пустой файл)'}` : `$ ls -l ${draft.path || '/path/to/decoy'}\n-rw-r--r-- 1 admin admin ${new TextEncoder().encode(draft.content).length} ${draft.path?.split('/').at(-1) || 'decoy'}\n$ cat ${draft.path || '/path/to/decoy'}\n${draft.content || '(пустой файл)'}`

  function generateTemplate() {
    const subtype = draft.category === 'credential' ? draft.credentialFormat
      : draft.category === 'cloud_infrastructure' ? draft.cloudProvider
        : draft.category === 'windows' ? draft.windowsArtifact
          : draft.category === 'database' ? draft.databaseFormat
            : draft.category === 'backup' ? draft.backupFormat
              : draft.category === 'system_config' ? draft.systemConfigFormat
                : draft.category === 'history' ? draft.historyFormat : ''
    const content = templateFor(draft.category, subtype)
    update({ content })
  }

  function regenerateMarker() {
    const marker = markerValue()
    update({ canaryMarker: marker, content: `Internal support credentials.\nMarker: ${marker}\n` })
  }

  function fileFields() {
    return <div className="grid gap-4">
      <Field label={pathLabel} hint="Путь существует только в виртуальной файловой системе гостя Middle.">
        <input value={draft.path} onChange={(event) => update({ path: event.target.value })} placeholder={windows ? '/C/Users/Public/Documents/decoy.txt' : definition.path || '/home/admin/Documents/decoy.txt'} className={inputClass()} />
      </Field>
      <Field label={contentLabel} hint={windows ? "До 4096 байт. Чтение через Get-Content фиксируется с ID приманки." : "До 4096 байт. Чтение через cat, head, tail или grep фиксируется с ID приманки."}>
        <textarea maxLength={4096} rows={9} value={draft.content} onChange={(event) => update({ content: event.target.value })} className={textareaClass()} />
        <span className="mt-1 block text-right text-[10px] text-white/30">{new TextEncoder().encode(draft.content).length} / 4096 байт</span>
      </Field>
    </div>
  }

  function processFields() {
    return <div className="grid gap-4 sm:grid-cols-2">
      <Field label={draft.category === 'network_service' ? 'Название службы' : draft.category === 'web_interface' ? 'Имя веб-службы' : 'Имя процесса'}>
        <input maxLength={48} value={draft.processName} onChange={(event) => update({ processName: event.target.value })} placeholder="billing-worker" className={inputClass()} />
      </Field>
      <Field label="Виртуальный пользователь"><input maxLength={32} value={draft.user} onChange={(event) => update({ user: event.target.value })} placeholder="app" className={inputClass()} /></Field>
      <Field label="Команда процесса" hint="Команда отображается в виртуальных командах Middle и никогда не выполняется."><input maxLength={256} value={draft.command} onChange={(event) => update({ command: event.target.value })} placeholder="/usr/bin/billing-worker --queue invoices" className={inputClass()} /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Порт · виртуальный"><input type="number" min={1} max={65535} value={draft.listenPort} onChange={(event) => update({ listenPort: event.target.value })} placeholder="не задан" className={inputClass()} /></Field>
        <Field label="Протокол"><select value={draft.category === 'web_interface' ? 'tcp' : draft.protocol} disabled={draft.category === 'web_interface'} onChange={(event) => update({ protocol: event.target.value as 'tcp' | 'udp' })} className={selectClass()}><option value="tcp">TCP</option>{draft.category !== 'web_interface' && <option value="udp">UDP</option>}</select></Field>
      </div>
      <label className="flex items-center gap-2 text-xs text-white/65"><input type="checkbox" checked={draft.running} onChange={(event) => update({ running: event.target.checked })} className="accent-orange-400" />Состояние: running</label>
    </div>
  }

  return <section className="rounded-xl border border-orange-300/20 bg-[#160e0c]/90 p-4 sm:p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-orange-300/60">Middle · виртуальная Linux-система</p><h3 className="mt-1 text-xl font-semibold">{draft.id ? 'Изменить приманку' : 'Создать приманку'}</h3><p className="mt-1 text-xs text-white/40">Настройка виртуального объекта Middle Honeypot</p></div>
      <button type="button" onClick={onCancel} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-white/55">Отмена</button>
    </div>

    <div className="mt-5 grid gap-4 sm:grid-cols-2">
      <Field label="Категория приманки">
        <select value={draft.category} onChange={(event) => changeCategory(event.target.value as BaitKind)} className={selectClass()}>
          {groups.map((group) => <optgroup key={group.id} label={group.label}>{baitCategories.filter((item) => item.group === group.id).map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</optgroup>)}
        </select>
      </Field>
      {implementationChoices.length > 1 && <Field label="Реализация">
        <select value={draft.implementation} onChange={(event) => update({ implementation: event.target.value as BaitImplementation, path: windows && event.target.value === 'virtual_file' && !draft.path.startsWith('/C/') ? `/C/Users/Public/Documents/${draft.path.split('/').at(-1) || 'decoy.txt'}` : draft.path })} className={selectClass()}>
          {implementationChoices.map((implementation) => <option key={implementation} value={implementation}>{implementation === 'virtual_process' ? 'Виртуальный процесс' : 'Виртуальный файл'}</option>)}
        </select>
      </Field>}
      <div className="sm:col-span-2">
        <Field label="Название приманки" hint="Внутреннее название в панели MellCore.">
          <input maxLength={80} value={draft.title} onChange={(event) => update({ title: event.target.value })} placeholder="Например, Production API Credentials" className={inputClass()} />
        </Field>
      </div>
    </div>

    <div className="mt-4 rounded-lg border border-sky-300/15 bg-sky-300/[0.04] p-3 text-xs leading-5 text-sky-100/70"><span className="font-semibold">Как работает эта приманка</span><p className="mt-1">{processCategory ? (draft.category === 'web_interface' ? 'Веб-служба отображается в виртуальных процессах и списке портов. HTTP-сервер и маршруты не создаются.' : 'Виртуальная служба отображается в системных командах. Реальный TCP/UDP listener не создаётся.') : isAccount ? 'Создаётся виртуальная запись пользователя. Middle фиксирует SSH-аутентификацию с указанным логином; пароль и вход в ОС не настраиваются.' : definition.description}</p></div>

    <div className="mt-5 space-y-4">
      {draft.category === 'account' && !isAccount && !isProcess && <>{fileFields()}<p className="text-[11px] text-amber-200/70">Это совместимый старый вариант категории «Учётная запись» как виртуального файла. Для моделирования пользователя выбери реализацию «Виртуальная учётная запись».</p></>}
      {isAccount && <>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Логин"><input maxLength={32} value={draft.login} onChange={(event) => update({ login: event.target.value, homeDirectory: draft.homeDirectory === `${windows ? '/C/Users' : '/home'}/${draft.login}` ? `${windows ? '/C/Users' : '/home'}/${event.target.value}` : draft.homeDirectory })} placeholder="backup-admin" className={inputClass()} /></Field>
          {!windows && <Field label="UID · от 1001"><input type="number" min={1001} max={65535} value={draft.uid} onChange={(event) => update({ uid: event.target.value })} className={inputClass()} /></Field>}
          <Field label="Домашний каталог"><input value={draft.homeDirectory} onChange={(event) => update({ homeDirectory: event.target.value })} placeholder={`${windows ? '/C/Users' : '/home'}/${draft.login || 'backup-admin'}`} className={inputClass()} /></Field>
          {!windows && <Field label="Командная оболочка"><select value={draft.shell} onChange={(event) => update({ shell: event.target.value as VirtualShell })} className={selectClass()}><option value="bash">/bin/bash</option><option value="sh">/bin/sh</option><option value="nologin">/usr/sbin/nologin</option></select></Field>}
        </div>
        {draft.path && <p className="text-[11px] text-amber-200/70">У этой старой учётной приманки есть прикреплённый файл {draft.path}; он сохранится при обновлении.</p>}
      </>}

      {draft.category === 'credential' && !isProcess && <>
        <Field label="Тип фиктивного секрета"><select value={draft.credentialFormat} onChange={(event) => update({ credentialFormat: event.target.value as CredentialFormat })} className={selectClass()}><option value="api_token">API Token</option><option value="ssh_key">SSH key · текстовый макет</option><option value="password">Пароль · фиктивная строка</option><option value="environment_variables">Environment Variables (.env)</option></select></Field>
        {fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить безопасный фиктивный шаблон</button>
      </>}
      {draft.category === 'cloud_infrastructure' && !isProcess && <>
        <Field label="Провайдер"><select value={draft.cloudProvider} onChange={(event) => update({ cloudProvider: event.target.value as CloudProvider })} className={selectClass()}><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP</option><option value="kubernetes">Kubernetes</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить фиктивную конфигурацию</button>
      </>}
      {draft.category === 'windows' && !isProcess && <>
        <Field label="Тип Windows-артефакта"><select value={draft.windowsArtifact} onChange={(event) => update({ windowsArtifact: event.target.value as WindowsArtifact })} className={selectClass()}><option value="powershell_script">PowerShell-скрипт</option><option value="configuration">Конфигурация</option><option value="document">Документ</option><option value="registry_export">Экспорт реестра (.reg)</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить пример</button>
      </>}
      {draft.category === 'database' && !isProcess && <>
        <Field label="Формат виртуального файла"><select value={draft.databaseFormat} onChange={(event) => update({ databaseFormat: event.target.value as DatabaseFormat })} className={selectClass()}><option value="sql_dump">SQL dump</option><option value="sqlite">SQLite-подобный файл · текстовый макет</option><option value="csv">CSV</option><option value="json">JSON</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить пример данных</button>
      </>}
      {draft.category === 'backup' && !isProcess && <>
        <Field label="Вид содержимого"><select value={draft.backupFormat} onChange={(event) => update({ backupFormat: event.target.value as BackupFormat })} className={selectClass()}><option value="sql_dump">SQL dump</option><option value="manifest">Манифест</option><option value="tar_listing">Список содержимого TAR</option><option value="zip_listing">Список содержимого ZIP</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить пример</button>
      </>}
      {draft.category === 'canary' && !isProcess && <>
        <Field label="Уникальный маркер"><input maxLength={128} value={draft.canaryMarker} onChange={(event) => update({ canaryMarker: event.target.value })} className={inputClass()} /></Field>
        <button type="button" onClick={regenerateMarker} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Сгенерировать новый маркер</button>{fileFields()}
        <p className="text-[11px] text-white/40">Маркер должен находиться в содержимом файла. ID приманки и маркер будут видны в событиях чтения внутри Middle.</p>
      </>}
      {draft.category === 'system_config' && !isProcess && <>
        <Field label="Тип конфигурации"><select value={draft.systemConfigFormat} onChange={(event) => update({ systemConfigFormat: event.target.value as SystemConfigFormat })} className={selectClass()}><option value="systemd_unit">systemd unit</option><option value="cron">cron</option><option value="ssh_config">SSH config</option><option value="application_config">Конфигурация приложения</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить пример</button>
      </>}
      {draft.category === 'history' && !isProcess && <>
        <Field label="Тип записей"><select value={draft.historyFormat} onChange={(event) => update({ historyFormat: event.target.value as HistoryFormat })} className={selectClass()}><option value="bash_history">Bash history</option><option value="application_log">Журнал приложения</option><option value="system_log">Системный журнал</option></select></Field>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Подставить несколько записей</button>
      </>}
      {['file', 'source_code', 'network_pivot'].includes(draft.category) && !isProcess && <>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Вставить пример содержимого</button></>}
      {['network_service', 'web_interface'].includes(draft.category) && !isProcess && <>{fileFields()}<button type="button" onClick={generateTemplate} className="w-fit rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100">Вставить пример содержимого</button></>}
      {processCategory && processFields()}
      {draft.category === 'database' && isProcess && <><p className="text-xs text-amber-200/70">Совместимость со старой конфигурацией: это только виртуальная строка процесса, не пользовательская база данных. Для SQL-дампа выбери реализацию «Виртуальный файл».</p>{processFields()}</>}
    </div>

    <section className="mt-5 rounded-lg border border-white/[0.08] bg-black/20 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><h4 className="text-xs font-semibold text-white/75">Предпросмотр в виртуальной системе</h4><span className="text-[10px] uppercase tracking-wide text-white/30">пример, не живой вывод</span></div>
      <pre className="mt-3 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md bg-black/30 p-3 font-mono text-[11px] leading-5 text-emerald-100/70">{isAccount ? accountPreview : processCategory ? processPreview : filePreview}</pre>
      <p className="mt-2 text-[11px] leading-5 text-white/40">Фиксируемое действие: {isAccount ? 'SSH-аутентификация с логином или чтение виртуального /etc/passwd' : processCategory ? 'просмотр процесса/службы в поддерживаемых командах' : 'чтение виртуального файла'}. Реальные команды, службы и сетевые порты на сервере не запускаются.</p>
    </section>

    {error && <p role="alert" className="mt-4 rounded-lg border border-red-400/20 bg-red-500/5 p-3 text-sm text-red-300">{error}</p>}
    <div className="mt-5 flex flex-wrap justify-end gap-2"><button type="button" onClick={onCancel} className="rounded-lg border border-white/10 px-4 py-3 text-sm text-white/60">Отмена</button><button type="button" disabled={busy} onClick={onSave} className="rounded-lg bg-orange-500 px-5 py-3 text-sm font-semibold text-[#1a0d08] disabled:opacity-50">{busy ? 'Применяем…' : draft.id ? 'Сохранить изменения' : 'Создать приманку'}</button></div>
  </section>
}
