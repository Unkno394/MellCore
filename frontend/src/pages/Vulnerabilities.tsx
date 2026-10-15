import { useState } from 'react'
import {
  Database,
  FolderLock,
  Globe,
  LockKeyhole,
  Search,
  Server,
  Terminal,
  type LucideIcon,
} from 'lucide-react'
import { scenarioEndpoints, windowsScenarioOptions } from '../vulnerabilities/scenarioCatalog'
import type { MellCoreApi } from '../api/services'
import type { Trap } from '../api/types'
import TrapScenarioEditor from './TrapScenarioEditor'

type Phase = 1 | 2
type Status = 'basis' | 'planned' | 'complex'
type VulnerabilityProfile = {
  number: number
  id: string
  configId: string
  name: string
  protocol: string
  port: string
  phase: Phase
  status: Status
  description: string
  implementation: string
  currentState: string
  icon: LucideIcon
}

const linuxProfiles: VulnerabilityProfile[] = [
  {
    number: 1, id: 'ssh-weak-credentials', configId: 'ssh_weak_credentials', name: 'SSH Weak Credentials', protocol: 'SSH', port: '22 / TCP', phase: 1, status: 'basis',
    description: 'Вход в виртуальные учётные записи со слабыми паролями.',
    implementation: 'russh, список виртуальных пользователей и настраиваемые слабые пары логин/пароль.',
    currentState: 'russh проверяет короткий список слабых пар для основного виртуального пользователя и аккаунтов-приманок. Пароли в телеметрию не записываются.',
    icon: LockKeyhole,
  },
  {
    number: 2, id: 'ssh-root-login', configId: 'ssh_root_login_enabled', name: 'SSH Root Login Enabled', protocol: 'SSH', port: '22 / TCP', phase: 1, status: 'basis',
    description: 'Разрешён виртуальный вход по SSH под root с журналированием попыток.',
    implementation: 'Отдельная политика профиля разрешает root только внутри виртуальной модели и пишет успешные и неуспешные попытки.',
    currentState: 'root разрешён как дополнительный виртуальный SSH-пользователь только при включённом профиле; попытки входа журналируются.',
    icon: Terminal,
  },
  {
    number: 3, id: 'redis-unauthenticated', configId: 'redis_unauthenticated_access', name: 'Redis Unauthenticated Access', protocol: 'Redis / RESP', port: '6379 / TCP', phase: 1, status: 'basis',
    description: 'Redis доступен по сети без аутентификации.',
    implementation: 'RESP-эмулятор с виртуальным хранилищем и безопасным набором базовых Redis-команд.',
    currentState: 'Отдельный RESP listener обслуживает базовые команды и меняет только виртуальное хранилище.',
    icon: Database,
  },
  {
    number: 4, id: 'docker-api-exposed', configId: 'docker_api_exposed', name: 'Docker API Exposed', protocol: 'HTTP / Docker API', port: '2375 / TCP', phase: 1, status: 'basis',
    description: 'Открытый API Docker Engine с фиктивными контейнерами.',
    implementation: 'HTTP-эмулятор ограниченного набора Docker API endpoints; ответы и контейнеры существуют только в виртуальном состоянии.',
    currentState: 'Отдельный HTTP endpoint отвечает на основные запросы Docker API фиктивными контейнерами; exec/create действия только журналируются.',
    icon: Server,
  },
  {
    number: 5, id: 'http-admin-panel', configId: 'http_admin_panel_exposure', name: 'HTTP Admin Panel Exposure', protocol: 'HTTP', port: '80 / 8080 · TCP', phase: 1, status: 'basis',
    description: 'Веб-панель управления со слабой аутентификацией и виртуальными действиями.',
    implementation: 'HTTP-эмулятор с маршрутами, формой входа и действиями над фиктивными данными; без запуска команд ОС.',
    currentState: 'HTTP listener показывает виртуальную форму входа, принимает заданный список слабых пар и пишет результат без хранения пароля.',
    icon: Globe,
  },
  {
    number: 6, id: 'sql-weak-credentials', configId: 'sql_database_weak_credentials', name: 'SQL Database Weak Credentials', protocol: 'MySQL / PostgreSQL', port: '3306 / 5432 · TCP', phase: 2, status: 'basis',
    description: 'Доступ к виртуальной базе данных с простыми учётными данными.',
    implementation: 'MySQL- или PostgreSQL-совместимый сетевой протокол, виртуальные пользователи, таблицы и ограниченный набор запросов.',
    currentState: 'MySQL native-password и PostgreSQL startup/auth обмениваются по сети; запросы работают с виртуальными таблицами users и sessions.',
    icon: Database,
  },
  {
    number: 7, id: 'ftp-anonymous', configId: 'ftp_anonymous_login', name: 'FTP Anonymous Login', protocol: 'FTP', port: '21 / TCP', phase: 2, status: 'basis',
    description: 'Анонимный FTP-доступ к фиктивным файлам.',
    implementation: 'FTP-эмулятор с командами входа и навигацией по изолированной виртуальной файловой системе.',
    currentState: 'Анонимный вход, виртуальные каталоги и файлы обслуживаются через отдельный пассивный data endpoint; доступ к диску хоста отсутствует.',
    icon: FolderLock,
  },
  {
    number: 11, id: 'web-path-traversal', configId: 'web_path_traversal', name: 'Web Path Traversal', protocol: 'HTTP', port: '80 / 8080 · TCP', phase: 1, status: 'basis',
    description: 'Обнаружение обращений к виртуальным файлам вне разрешённого каталога.',
    implementation: 'HTTP-эмулятор с виртуальными файлами и контролируемыми ответами; реальные файлы хоста недоступны.',
    currentState: 'HTTP обработчик распознаёт traversal-пути и возвращает только заранее заданные виртуальные файлы.',
    icon: FolderLock,
  },
  {
    number: 12, id: 'web-command-injection', configId: 'web_command_injection', name: 'Web Command Injection', protocol: 'HTTP', port: '80 / 8080 · TCP', phase: 1, status: 'basis',
    description: 'Имитация результатов внедрённой команды через веб-запрос.',
    implementation: 'HTTP-обработчик с заранее заданными виртуальными ответами; команды и процессы хоста не запускаются.',
    currentState: 'Опасные символы запускают только виртуальный ответ. Обработчик не запускает процессы ОС.',
    icon: Terminal,
  },
]

type WindowsProfile = {
  number: number
  id: string
  name: string
  protocol: string
  port: string
  middle: string
  high: string
  complex?: boolean
}

const windowsProfiles: WindowsProfile[] = [
  { number: 1, id: 'win-smb-ms17-010', name: 'SMB MS17-010 (EternalBlue)', protocol: 'SMB', port: '445 / TCP', middle: 'Эмуляция признаков уязвимой конфигурации и попыток эксплуатации.', high: 'Специальная уязвимая Windows VM.', complex: true },
  { number: 2, id: 'win-rdp-bluekeep', name: 'RDP BlueKeep (CVE-2019-0708)', protocol: 'RDP', port: '3389 / TCP', middle: 'Эмуляция RDP и обнаружение попыток эксплуатации.', high: 'Специальная уязвимая Windows VM.', complex: true },
  { number: 3, id: 'win-smb-guest', name: 'SMB Guest Access', protocol: 'SMB', port: '445 / TCP', middle: 'Виртуальные общие папки.', high: 'Настоящие SMB-шары внутри Windows VM.' },
  { number: 4, id: 'win-weak-credentials', name: 'Windows Weak Credentials', protocol: 'Windows Auth', port: 'Профильный', middle: 'Виртуальные учётные записи.', high: 'Реальные локальные пользователи Windows VM.' },
  { number: 5, id: 'win-rdp-weak-credentials', name: 'RDP Weak Credentials', protocol: 'RDP', port: '3389 / TCP', middle: 'Имитация RDP-аутентификации.', high: 'Настоящий RDP в Windows VM.' },
  { number: 6, id: 'winrm-exposed', name: 'WinRM Exposed', protocol: 'WinRM / WS-Man', port: '5985 / 5986 · TCP', middle: 'Эмуляция WinRM/WS-Man.', high: 'Настоящий WinRM в Windows VM.' },
  { number: 7, id: 'iis-misconfiguration', name: 'IIS Misconfiguration', protocol: 'HTTP / IIS', port: '80 / 443 · TCP', middle: 'Эмуляция IIS и виртуальных веб-файлов.', high: 'Настоящий IIS с тестовой конфигурацией.' },
  { number: 8, id: 'mssql-weak-credentials', name: 'MSSQL Weak Credentials', protocol: 'MSSQL / TDS', port: '1433 / TCP', middle: 'Эмуляция SQL Server.', high: 'Настоящий SQL Server в Windows VM.' },
  { number: 9, id: 'ad-misconfiguration', name: 'Active Directory Misconfiguration', protocol: 'LDAP / Kerberos', port: '389, 636, 88 · TCP/UDP', middle: 'Эмуляция LDAP/Kerberos и виртуальных объектов домена.', high: 'Настоящий тестовый Active Directory.', complex: true },
  { number: 10, id: 'ad-cs-misconfiguration', name: 'AD CS Misconfiguration', protocol: 'AD CS / RPC', port: '135 + динамические RPC', middle: 'Эмуляция обнаружения службы сертификатов.', high: 'Настоящая тестовая AD CS.', complex: true },
]

type Props = { api: MellCoreApi; traps: Trap[]; readOnly: boolean; onChanged: () => Promise<void> }

export default function Vulnerabilities({ api, traps, readOnly, onChanged }: Props) {
  const [view, setView] = useState<'catalog' | 'edit'>('catalog')
  const [query, setQuery] = useState('')
  const [osCategory, setOsCategory] = useState<'linux' | 'windows'>('linux')
  const [selectedId, setSelectedId] = useState(linuxProfiles[0].id)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [publicPortDraft, setPublicPortDraft] = useState<Record<number, string>>({})
  const [copied, setCopied] = useState(false)
  const selectedProfile = linuxProfiles.find((profile) => profile.id === selectedId) ?? linuxProfiles[0]
  const normalizedQuery = query.trim().toLocaleLowerCase('ru')
  const visibleLinuxProfiles = linuxProfiles.filter((profile) =>
    `${profile.name} ${profile.protocol} ${profile.port} ${profile.description}`.toLocaleLowerCase('ru').includes(normalizedQuery))
  const visibleWindowsProfiles = windowsProfiles.filter((profile) =>
    `${profile.name} ${profile.protocol} ${profile.port} ${profile.middle}`.toLocaleLowerCase('ru').includes(normalizedQuery))
  const endpoints = scenarioEndpoints[selectedProfile.configId] ?? []
  const previewConfig = {
    config: {
      hostname: 'srv-app-01',
      username: 'admin',
      distribution: 'ubuntu',
      vulnerability_profiles: [selectedProfile.configId],
    },
    ports: [
      { transport: 'tcp', host_port: 2222, target_port: 2222, route_mode: 'direct' },
      ...endpoints.map((endpoint) => ({
        transport: 'tcp',
        host_port: Number(publicPortDraft[endpoint.targetPort] || endpoint.defaultPublicPort),
        target_port: endpoint.targetPort,
        route_mode: 'direct',
      })),
    ],
  }
  const configuredPreviewPorts = endpoints.map((endpoint) => Number(publicPortDraft[endpoint.targetPort] ?? endpoint.defaultPublicPort))
  const validPreviewPorts = endpoints.every((endpoint) => {
    const port = Number(publicPortDraft[endpoint.targetPort] ?? endpoint.defaultPublicPort)
    return Number.isInteger(port) && port >= 1 && port <= 65535
  }) && new Set([2222, ...configuredPreviewPorts]).size === 1 + configuredPreviewPorts.length

  async function copyConfig() {
    try {
      if (!validPreviewPorts) return
      await navigator.clipboard.writeText(JSON.stringify(previewConfig, null, 2))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch { setCopied(false) }
  }

  return <section className="space-y-5 p-6">
    <header>
      <h2 className="text-2xl font-semibold">Сценарии уязвимостей</h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-white/55">Каталог сценариев для Linux Middle и отдельная форма для изменения уже созданной ловушки.</p>
    </header>

    <div role="tablist" aria-label="Каталог и настройка сценариев" className="inline-flex rounded-lg border border-white/10 bg-black/20 p-1">
      <button type="button" role="tab" aria-selected={view === 'catalog'} onClick={() => setView('catalog')} className={`rounded-md px-4 py-2 text-sm transition ${view === 'catalog' ? 'bg-orange-400/15 text-orange-100' : 'text-white/50 hover:text-white/80'}`}>Каталог</button>
      <button type="button" role="tab" aria-selected={view === 'edit'} onClick={() => setView('edit')} className={`rounded-md px-4 py-2 text-sm transition ${view === 'edit' ? 'bg-orange-400/15 text-orange-100' : 'text-white/50 hover:text-white/80'}`}>Настроить существующую ловушку</button>
    </div>

    {view === 'edit' ? <TrapScenarioEditor api={api} traps={traps} readOnly={readOnly} onChanged={onChanged}/> : <>

    <div className="flex flex-wrap items-center gap-3">
      <div role="tablist" aria-label="Операционная система" className="inline-flex rounded-lg border border-white/10 bg-black/20 p-1">
        {(['linux', 'windows'] as const).map((os) => <button key={os} type="button" role="tab" aria-selected={osCategory === os} onClick={() => setOsCategory(os)} className={`rounded-md px-4 py-2 text-sm transition ${osCategory === os ? 'bg-orange-400/15 text-orange-100' : 'text-white/50 hover:text-white/80'}`}>{os === 'linux' ? 'Linux' : 'Windows'}</button>)}
      </div>
      <label className="relative block w-full max-w-sm flex-1">
        <Search aria-hidden="true" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35"/>
        <span className="sr-only">Поиск сценария</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Поиск сценария" className="w-full rounded-lg border border-white/10 bg-black/20 py-2.5 pl-10 pr-3 text-sm text-white outline-none placeholder:text-white/35 focus:border-orange-400/40"/>
      </label>
    </div>

    {osCategory === 'linux' ? <div className="grid gap-4 xl:grid-cols-[minmax(260px,0.9fr)_minmax(0,1.1fr)]">
      <div className="space-y-2" aria-label="Сценарии Linux">
        {visibleLinuxProfiles.map((profile) => {
          const Icon = profile.icon
          return <button key={profile.id} type="button" onClick={() => { setSelectedId(profile.id); setPublicPortDraft({}); setCopied(false) }} aria-pressed={selectedProfile.id === profile.id} className={`flex w-full items-start gap-3 rounded-xl border p-4 text-left transition ${selectedProfile.id === profile.id ? 'border-orange-400/35 bg-orange-400/[0.07]' : 'border-white/10 bg-[#160e0c]/70 hover:border-white/20'}`}>
            <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-orange-200/70"/>
            <span className="min-w-0 flex-1"><span className="block text-sm font-medium text-white/85">{profile.name}</span><span className="mt-1 block text-xs text-white/45">{profile.protocol} · {profile.port}</span></span>
            <span className="text-xs text-white/35">Сценарий</span>
          </button>
        })}
        {visibleLinuxProfiles.length === 0 && <p className="rounded-xl border border-white/10 p-6 text-sm text-white/45">По вашему запросу сценарии не найдены.</p>}
      </div>
      <article className="h-fit rounded-xl border border-white/10 bg-[#160e0c]/70 p-5 xl:sticky xl:top-5">
        <p className="text-xs font-medium uppercase tracking-wider text-orange-100/55">Linux Middle · доступен</p>
        <h3 className="mt-2 text-lg font-semibold">{selectedProfile.name}</h3>
        <p className="mt-3 text-sm leading-6 text-white/70">{selectedProfile.description}</p>
        <div className="mt-5 border-t border-white/10 pt-4"><h4 className="text-sm font-medium text-white/80">Что увидит посетитель</h4><p className="mt-2 text-sm leading-6 text-white/55">{selectedProfile.currentState}</p></div>
        <div className="mt-5 rounded-lg border border-white/10 bg-black/10 p-3"><h4 className="text-xs font-medium uppercase tracking-wider text-white/45">Настройки по умолчанию</h4><p className="mt-2 text-sm leading-6 text-white/60">{selectedProfile.protocol} · {selectedProfile.port}. Значения безопасно имитируются; команды и обращения к реальным данным хоста не выполняются.</p></div>
        <button type="button" onClick={() => setSettingsOpen((open) => !open)} className="mt-5 rounded-lg bg-orange-400 px-4 py-2.5 text-sm font-medium text-black transition hover:bg-orange-300">{settingsOpen ? 'Скрыть настройки' : 'Настроить сценарий'}</button>
        {settingsOpen && <div className="mt-4 space-y-4 rounded-xl border border-white/10 bg-black/15 p-4">
          <div><h4 className="text-sm font-medium text-white/80">Параметры предпросмотра</h4><p className="mt-1 text-xs leading-5 text-white/40">Здесь показан пример конфигурации. Чтобы включить сценарий, открой вкладку «Настроить существующую ловушку», выбери Linux Middle и примени настройки там.</p></div>
          {endpoints.length ? <div className="grid gap-3 sm:grid-cols-2">{endpoints.map((endpoint) => <label key={endpoint.targetPort} className="text-xs text-white/65">Публичный порт · {endpoint.service}<input type="number" min="1" max="65535" value={publicPortDraft[endpoint.targetPort] ?? endpoint.defaultPublicPort} onChange={(event) => setPublicPortDraft((current) => ({ ...current, [endpoint.targetPort]: event.target.value }))} className="mt-1.5 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2.5 text-sm"/><span className="mt-1 block text-[10px] text-white/35">Внутренний порт контейнера: {endpoint.targetPort}</span></label>)}</div> : <p className="text-xs leading-5 text-white/50">Использует SSH endpoint основной Middle-ловушки; дополнительный порт не нужен.</p>}
          {selectedProfile.configId === 'docker_api_exposed' && <div className="rounded-lg border border-white/5 bg-black/15 p-3 text-xs leading-5 text-white/50"><p>Фиктивные контейнеры: 3.</p><p>Попытки create/exec получают виртуальный ответ и событие телеметрии; команда на сервере не выполняется.</p><p className="mt-1 text-white/35">Эти значения сейчас заданы в эмуляторе и не редактируются.</p></div>}
          <div className="flex items-center justify-between gap-3"><span className="text-[10px] text-white/35">Пример конфигурации</span><button type="button" onClick={() => void copyConfig()} disabled={!validPreviewPorts} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100/80 disabled:opacity-40">{copied ? 'Скопировано' : 'Копировать конфигурацию'}</button></div>
          <pre className="max-h-48 overflow-auto rounded-lg border border-white/5 bg-black/25 p-3 text-[10px] leading-5 text-white/50">{JSON.stringify(previewConfig, null, 2)}</pre>
        </div>}
      </article>
    </div> : <section className="space-y-3">
      <p className="rounded-lg border border-sky-300/15 bg-sky-300/[0.04] p-4 text-sm leading-6 text-sky-100/75">Сценарии Windows Middle работают в виртуальной оболочке. Включи их во вкладке «Настроить существующую ловушку». Сетевые SMB, RDP и WinRM listener пока не реализованы.</p>
      <div className="grid gap-2 lg:grid-cols-2">{windowsScenarioOptions.filter((profile) => `${profile.name} ${profile.protocol} ${profile.description}`.toLocaleLowerCase('ru').includes(normalizedQuery)).map((profile) => <article key={profile.id} className="rounded-xl border border-emerald-300/15 bg-emerald-300/[0.04] p-4"><div className="flex items-start justify-between gap-3"><h3 className="text-sm font-medium text-white/85">{profile.name}</h3><span className="rounded-full border border-emerald-300/20 px-2 py-0.5 text-[10px] text-emerald-100/75">Доступен</span></div><p className="mt-1 text-xs text-white/40">{profile.protocol}</p><p className="mt-3 text-xs leading-5 text-white/55">{profile.description}</p></article>)}</div>
      <div className="grid gap-2 lg:grid-cols-2">
        {visibleWindowsProfiles.map((profile) => <article key={profile.id} className="rounded-xl border border-white/10 bg-[#160e0c]/70 p-4"><div className="flex items-start justify-between gap-3"><h3 className="text-sm font-medium text-white/85">{profile.name}</h3><span className="shrink-0 rounded-full border border-amber-300/15 px-2 py-0.5 text-[10px] text-amber-100/70">План</span></div><p className="mt-1 text-xs text-white/40">{profile.protocol} · {profile.port}</p><p className="mt-3 text-xs leading-5 text-white/55">{profile.middle}</p></article>)}
        {visibleWindowsProfiles.length === 0 && <p className="rounded-xl border border-white/10 p-6 text-sm text-white/45">По вашему запросу сценарии не найдены.</p>}
      </div>
    </section>}
    </>}
  </section>
}
