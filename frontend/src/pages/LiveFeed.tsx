import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  ChevronRight,
  Clock,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react'
import { eventLabel, dateTime } from '../i18n/labels'
import type { MellCoreApi } from '../api/services'
import type { AttackEvent, AttackGraphMatch, Trap } from '../api/types'

type Props = {
  api: MellCoreApi
  events: AttackEvent[]
  traps: Trap[]
  initialTrapId?: string | null
  loading: boolean
  error: string
  onRefresh: () => Promise<void>
}

type Attack = {
  key: string
  sessionId: string | null
  events: AttackEvent[]
  first: string
  last: string
  trapId: string
  sourceIp: string | null
  match: AttackGraphMatch | null
}

type VulnerabilityEvidence = { item: AttackEvent; profileId: string }

const vulnerabilityNames: Record<string, string> = {
  ssh_weak_credentials: 'SSH: слабые учётные данные',
  ssh_root_login_enabled: 'SSH: вход root',
  redis_unauthenticated_access: 'Redis без пароля',
  docker_api_exposed: 'Открытый Docker API',
  http_admin_panel_exposure: 'Открытая панель управления',
  sql_database_weak_credentials: 'SQL: слабые учётные данные',
  ftp_anonymous_login: 'Анонимный FTP',
  web_path_traversal: 'Обход пути на сайте',
  web_command_injection: 'Внедрение команды на сайте',
  win_autologon_credentials: 'Windows: учётные данные автологина',
  win_always_install_elevated: 'Windows: AlwaysInstallElevated',
  win_writable_service_binary: 'Windows: доступный для записи сервис',
  win_guest_share: 'Windows: гостевая общая папка',
}

type DetailSection = 'summary' | 'timeline' | 'scenario' | 'comparison' | 'logs'

const DETAIL_TABS: { id: DetailSection; label: string }[] = [
  { id: 'summary', label: 'Сводка' },
  { id: 'timeline', label: 'Ход событий' },
  { id: 'scenario', label: 'Разбор сценария' },
  { id: 'comparison', label: 'Сравнение' },
  { id: 'logs', label: 'Все логи' },
]

type IconName = 'activity' | 'alert' | 'search' | 'refresh' | 'chevron' | 'shield' | 'network' | 'clock' | 'close'

const icons: Record<IconName, LucideIcon> = {
  activity: Activity,
  alert: TriangleAlert,
  search: Search,
  refresh: RefreshCw,
  chevron: ChevronRight,
  shield: ShieldCheck,
  network: Network,
  clock: Clock,
  close: X,
}

function Icon({ name, className = 'h-5 w-5' }: { name: IconName; className?: string }) {
  const LucideIcon = icons[name]
  return <LucideIcon aria-hidden="true" className={className} strokeWidth={1.7} />
}

function matchStatus(match: AttackGraphMatch | null) {
  if (!match) return { label: 'События', tone: 'border-white/10 bg-white/5 text-white/55' }
  if (match.status === 'confirmed') return { label: 'Подтверждённый инцидент', tone: 'border-red-400/25 bg-red-400/10 text-red-300' }
  if (match.status === 'attempt') return { label: 'Активное подозрение', tone: 'border-amber-300/25 bg-amber-300/10 text-amber-200' }
  return { label: 'Кандидат сценария', tone: 'border-sky-300/25 bg-sky-300/10 text-sky-200' }
}

function eventDetail(item: AttackEvent) {
  const payload = item.event.payload && typeof item.event.payload === 'object' ? item.event.payload as Record<string, unknown> : {}
  const command = item.event.event_type === 'command.executed' && typeof payload.input === 'string'
    ? payload.input
    : typeof payload.command === 'string' ? payload.command : typeof payload.input === 'string' ? payload.input : null
  const path = typeof payload.path === 'string' ? payload.path : null
  const resource = typeof payload.resource === 'string' ? payload.resource : null
  return command || path || resource || null
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {}
}

function profilesForEvent(item: AttackEvent, traps: Trap[]): string[] {
  const payload = objectValue(item.event.payload)
  if (item.event.event_type === 'vulnerability.exploit_attempt') {
    return typeof payload.profile_id === 'string' ? [payload.profile_id] : []
  }
  if (item.event.event_type !== 'command.executed') return []
  const trap = traps.find((candidate) => candidate.trap_id === item.event.trap_id)
  const configured = trap?.effective_config.vulnerability_profiles
  const enabled = Array.isArray(configured) ? configured.filter((value): value is string => typeof value === 'string') : []
  const input = typeof payload.input === 'string' ? payload.input.toLowerCase() : ''
  const eventCommand = typeof payload.command === 'string' ? payload.command.toLowerCase().split('/').at(-1) ?? '' : ''
  const command = eventCommand === 'sudo' ? input.trim().split(/\s+/)[1]?.split('/').at(-1) ?? 'sudo' : eventCommand
  if ((command === 'redis-cli' || command === 'valkey-cli') && enabled.includes('redis_unauthenticated_access')) return ['redis_unauthenticated_access']
  if (['psql', 'mysql', 'mariadb'].includes(command) && enabled.includes('sql_database_weak_credentials')) return ['sql_database_weak_credentials']
  if (command === 'ftp' && enabled.includes('ftp_anonymous_login')) return ['ftp_anonymous_login']
  if (command === 'docker' && enabled.includes('docker_api_exposed') && input.includes('tcp://')) return ['docker_api_exposed']
  if (command !== 'curl') return []
  if (input.includes('ftp://') && enabled.includes('ftp_anonymous_login')) return ['ftp_anonymous_login']
  if (input.includes(':2375') && enabled.includes('docker_api_exposed')) return ['docker_api_exposed']
  if ((input.includes('../') || input.includes('%2e%2e') || input.includes('..%2f')) && enabled.includes('web_path_traversal')) return ['web_path_traversal']
  if ((input.includes('cmd=') || input.includes('host='))
    && (/[;|]|%3b|%7c/.test(input) || /cmd=(echo|id|whoami|uname)/.test(input))
    && enabled.includes('web_command_injection')) return ['web_command_injection']
  if ((input.includes('http://') || input.includes('https://')) && enabled.includes('http_admin_panel_exposure')) return ['http_admin_panel_exposure']
  return []
}

function vulnerabilityEvidence(items: AttackEvent[], traps: Trap[]): VulnerabilityEvidence[] {
  const explicit = items.filter((item) => item.event.event_type === 'vulnerability.exploit_attempt')
  const explicitBySession = new Set(explicit.flatMap((item) => profilesForEvent(item, traps).map((profileId) => `${item.event.trap_id}:${item.event.session_id ?? item.event.event_id}:${profileId}`)))
  const evidence: VulnerabilityEvidence[] = explicit.flatMap((item) => profilesForEvent(item, traps).map((profileId) => ({ item, profileId })))
  for (const item of items) {
    if (item.event.event_type !== 'command.executed') continue
    for (const profileId of profilesForEvent(item, traps)) {
      const key = `${item.event.trap_id}:${item.event.session_id ?? item.event.event_id}:${profileId}`
      if (!explicitBySession.has(key)) evidence.push({ item, profileId })
    }
  }
  return evidence
}

function vulnerabilityStatus(item: AttackEvent) {
  const payload = objectValue(item.event.payload)
  const details = objectValue(payload.details)
  const accepted = typeof payload.accepted === 'boolean' ? payload.accepted : details.accepted
  if (item.event.event_type === 'command.executed') {
    const input = typeof payload.input === 'string' ? payload.input : ''
    if (input.includes('<_>')) return 'Shell отверг синтаксис; endpoint не проверен'
    if (payload.exit_status !== 0) return 'Команда завершилась до ответа сервиса'
    return 'Команда выполнена в виртуальной оболочке'
  }
  if (details.probe_status === 'client_unavailable') return 'Клиент отсутствует; endpoint не проверен'
  if (details.probe_status === 'invalid_shell_syntax') return 'Shell отверг синтаксис; endpoint не проверен'
  if (accepted === true) return 'Виртуальная модель приняла попытку'
  if (accepted === false) return 'Виртуальная модель отказала'
  return 'Попытка записана в виртуальном сценарии'
}

function actionClass(item: AttackEvent) {
  const type = item.event.event_type
  const detail = eventDetail(item)?.toLowerCase() ?? ''
  if (type.startsWith('auth.')) return 'SSH-аутентификация'
  if (type === 'connection.opened' || type === 'connection') return 'SSH-подключение'
  if (type === 'session.started') return 'Запуск сессии'
  if (type === 'session.ended') return 'Завершение сессии'
  if (type === 'filesystem.accessed') return detail.includes('read') || detail.includes('cat') ? 'Чтение файлов' : 'Обзор файлов'
  if (type === 'bait.opened') return 'Открытие приманки'
  if (type === 'vulnerability.exploit_attempt') return 'Проверка уязвимости'
  if (type === 'command.executed') {
    if (/\b(curl|wget|fetch)\b/.test(detail)) return 'Загрузка из сети'
    if (/\b(sudo|su|pkexec|capsh|setcap)\b/.test(detail)) return 'Повышение привилегий'
    if (/shadow|passwd|secret|credential|authorized_keys/.test(detail)) return 'Поиск чувствительных данных'
    if (/\b(ls|find|ps|id|whoami|pwd|uname|netstat|ss)\b/.test(detail)) return 'Разведка системы'
    return 'Выполнение команды'
  }
  if (type.startsWith('security.') || type.includes('resource')) return 'Доступ к ресурсу'
  return eventLabel(type)
}

function jaccard(left: Attack, right: Attack) {
  const a = new Set(left.events.map(actionClass))
  const b = new Set(right.events.map(actionClass))
  const intersection = [...a].filter((item) => b.has(item)).length
  const union = new Set([...a, ...b]).size
  return union ? intersection / union : 0
}

function outcome(item: AttackEvent) {
  const payload = item.event.payload as Record<string, unknown>
  const details = objectValue(payload?.details)
  if (item.event.event_type === 'vulnerability.exploit_attempt') {
    const accepted = typeof payload?.accepted === 'boolean' ? payload.accepted : details.accepted
    if (accepted === true) return 'виртуальный сервис принял попытку'
    if (accepted === false) return 'виртуальный сервис отказал'
    return 'попытка'
  }
  if (payload?.accepted === false || item.event.event_type === 'auth.failed' || payload?.outcome === 'denied_or_failed') return 'отказ'
  if (payload?.success === false) return 'ошибка'
  if (typeof payload?.exit_status === 'number' && payload.exit_status !== 0) return 'ошибка'
  if (payload?.accepted === true || payload?.exit_status === 0 || payload?.outcome === 'succeeded' || item.event.event_type === 'auth.succeeded' || item.event.event_type === 'bait.opened') return 'успех'
  return 'неизвестно'
}

function sequence(attack: Attack) {
  return attack.events.map((item) => ({ kind: actionClass(item), result: outcome(item), at: Date.parse(item.event.occurred_at) }))
}

function sequenceSimilarity(left: Attack, right: Attack) {
  const a = sequence(left).slice(0, 100)
  const b = sequence(right).slice(0, 100)
  if (!a.length || !b.length) return { score: 0, timing: null as number | null }
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index)
  for (let i = 1; i <= a.length; i++) {
    const current = [i]
    for (let j = 1; j <= b.length; j++) {
      const substitution = a[i - 1].kind === b[j - 1].kind ? (a[i - 1].result === b[j - 1].result ? 0 : 0.65) : 1
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + substitution)
    }
    previous = current
  }
  const score = Math.max(0, 1 - previous[b.length] / Math.max(a.length, b.length))
  const intervalCount = Math.min(a.length, b.length) - 1
  const timing = intervalCount > 0 ? Array.from({ length: intervalCount }, (_, i) => {
    const leftDelta = Math.max(0, a[i + 1].at - a[i].at)
    const rightDelta = Math.max(0, b[i + 1].at - b[i].at)
    return Math.abs(leftDelta - rightDelta) / Math.max(1000, leftDelta, rightDelta)
  }).reduce((sum, value) => sum + value, 0) / intervalCount : null
  return { score, timing }
}

export default function LiveFeed({ api, events, traps, initialTrapId = null, loading, error, onRefresh }: Props) {
  const eventsPerPage = 10
  const [search, setSearch] = useState('')
  const [service, setService] = useState('Все сервисы')
  const [trapFilter, setTrapFilter] = useState(initialTrapId ?? 'all')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [matches, setMatches] = useState<AttackGraphMatch[]>([])
  const [matchesLoading, setMatchesLoading] = useState(false)
  const [matchesUnavailable, setMatchesUnavailable] = useState(false)
  const [eventPage, setEventPage] = useState(0)
  const [highlightedEventIds, setHighlightedEventIds] = useState<string[]>([])
  const [extraEvents, setExtraEvents] = useState<AttackEvent[]>([])
  const [evidenceError, setEvidenceError] = useState('')
  const [detailSection, setDetailSection] = useState<DetailSection>('summary')
  const [logQuery, setLogQuery] = useState('')
  const [appliedLogQuery, setAppliedLogQuery] = useState('')
  const [logCursors, setLogCursors] = useState<(string | null)[]>([null])
  const [logPage, setLogPage] = useState(0)
  const [logEvents, setLogEvents] = useState<AttackEvent[]>([])
  const [logNextCursor, setLogNextCursor] = useState<string | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)
  const [logsError, setLogsError] = useState('')
  const timelineRef = useRef<HTMLDivElement | null>(null)
  const trapNames = useMemo(() => new Map(traps.map((trap) => [trap.trap_id, trap.name])), [traps])
  const trapIds = useMemo(() => traps.map((trap) => trap.trap_id), [traps])
  const services = useMemo(() => [...new Set(events.map((item) => item.event.service_type))].sort(), [events])

  useEffect(() => {
    setTrapFilter(initialTrapId ?? 'all')
    setSelectedKey(null)
  }, [initialTrapId])

  useEffect(() => {
    let cancelled = false
    if (trapIds.length === 0) { setMatches([]); setMatchesUnavailable(false); return }
    setMatchesLoading(true)
    void Promise.allSettled(trapIds.map((id) => api.traps.attackMatches(id))).then((results) => {
      if (cancelled) return
      const ok = results.flatMap((result) => result.status === 'fulfilled' ? result.value : [])
      setMatches(ok)
      setMatchesUnavailable(results.some((result) => result.status === 'rejected'))
    }).finally(() => { if (!cancelled) setMatchesLoading(false) })
    return () => { cancelled = true }
  }, [api, trapIds])

  const attacks = useMemo(() => {
    const grouped = new Map<string, AttackEvent[]>()
    for (const item of [...events, ...extraEvents]) {
      const sessionId = item.event.session_id
      const key = sessionId ? `${item.event.trap_id}:session:${sessionId}` : `${item.event.trap_id}:event:${item.event.event_id}`
      const current = grouped.get(key) ?? []
      if (!current.some((existing) => existing.event.event_id === item.event.event_id)) grouped.set(key, [...current, item])
    }
    return [...grouped.entries()].map(([key, items]): Attack => {
      const sorted = [...items].sort((a, b) => a.event.occurred_at.localeCompare(b.event.occurred_at)
        || (a.event.sequence_no ?? 0) - (b.event.sequence_no ?? 0)
        || a.event.event_id.localeCompare(b.event.event_id))
      const eventIds = new Set(sorted.map((item) => item.event.event_id))
      const match = matches.filter((candidate) => candidate.trap_id === sorted[0].event.trap_id
        && (candidate.evidence_event_ids.some((id) => eventIds.has(id))
          || (sorted[0].event.session_id && candidate.session_key.endsWith(`:session:${sorted[0].event.session_id}`))))
        .sort((a, b) => b.similarity - a.similarity)[0] ?? null
      return {
        key,
        sessionId: sorted[0].event.session_id,
        events: sorted,
        first: sorted[0].event.occurred_at,
        last: sorted.at(-1)!.event.occurred_at,
        trapId: sorted[0].event.trap_id,
        sourceIp: sorted.find((item) => item.event.source_ip)?.event.source_ip ?? null,
        match,
      }
    }).sort((a, b) => b.last.localeCompare(a.last))
  }, [events, extraEvents, matches])

  const filtered = useMemo(() => attacks.filter((attack) => {
    const haystack = `${attack.match?.technique_name ?? ''} ${attack.match?.technique_key ?? ''} ${attack.sourceIp ?? ''} ${trapNames.get(attack.trapId) ?? ''} ${attack.events.map((item) => item.event.service_type).join(' ')}`.toLowerCase()
    return haystack.includes(search.toLowerCase())
      && (service === 'Все сервисы' || attack.events.some((item) => item.event.service_type === service))
      && (trapFilter === 'all' || attack.trapId === trapFilter)
  }), [attacks, search, service, trapFilter, trapNames])
  useEffect(() => {
    if (filtered.length > 0 && !filtered.some((attack) => attack.key === selectedKey)) {
      setSelectedKey(filtered[0].key)
    }
  }, [filtered, selectedKey])
  const selected = filtered.find((attack) => attack.key === selectedKey) ?? null
  const eventPageCount = selected ? Math.max(1, Math.ceil(selected.events.length / eventsPerPage)) : 1
  const visibleEvents = selected?.events.slice(eventPage * eventsPerPage, (eventPage + 1) * eventsPerPage) ?? []
  useEffect(() => {
    setEventPage(0)
    setHighlightedEventIds([])
    setDetailSection('summary')
  }, [selectedKey])
  useEffect(() => {
    const timer = window.setTimeout(() => setAppliedLogQuery(logQuery.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [logQuery])
  useEffect(() => {
    setLogPage(0)
    setLogCursors([null])
  }, [appliedLogQuery, selected?.trapId])
  const currentLogCursor = logCursors[logPage] ?? null
  useEffect(() => {
    if (detailSection !== 'logs' || !selected) return
    let cancelled = false
    setLogsLoading(true)
    setLogsError('')
    void api.traps.events(selected.trapId, currentLogCursor, 50, appliedLogQuery)
      .then((page) => {
        if (cancelled) return
        setLogEvents(page.items)
        setLogNextCursor(page.next_cursor)
      })
      .catch(() => { if (!cancelled) setLogsError('Не удалось загрузить логи') })
      .finally(() => { if (!cancelled) setLogsLoading(false) })
    return () => { cancelled = true }
  }, [api, detailSection, selected?.trapId, currentLogCursor, appliedLogQuery])
  useEffect(() => {
    if (eventPage >= eventPageCount) setEventPage(eventPageCount - 1)
  }, [eventPage, eventPageCount])
  useEffect(() => {
    timelineRef.current?.scrollTo({ top: 0 })
  }, [eventPage, selectedKey])
  useEffect(() => {
    if (!highlightedEventIds.length) return
    const frame = requestAnimationFrame(() => timelineRef.current?.querySelector('[data-highlighted="true"]')?.scrollIntoView({ block: 'center', behavior: 'smooth' }))
    return () => cancelAnimationFrame(frame)
  }, [highlightedEventIds, eventPage])
  useEffect(() => {
    if (!selected || !highlightedEventIds.length) return
    const index = selected.events.findIndex((item) => highlightedEventIds.includes(item.event.event_id))
    if (index >= 0) setEventPage((page) => page === Math.floor(index / eventsPerPage) ? page : Math.floor(index / eventsPerPage))
  }, [selected, highlightedEventIds])
  const showEvidence = async (ids: string[]) => {
    if (!selected || !ids.length) return
    setDetailSection('timeline')
    setEvidenceError('')
    setHighlightedEventIds(ids)
    const index = selected.events.findIndex((item) => ids.includes(item.event.event_id))
    if (index >= 0) { setEventPage(Math.floor(index / eventsPerPage)); return }
    try {
      const item = await api.traps.event(selected.trapId, ids[0])
      if (item.event.session_id !== selected.sessionId) throw new Error('Событие относится к другой сессии')
      setExtraEvents((current) => current.some((existing) => existing.event.event_id === item.event.event_id) ? current : [...current, item])
    } catch { setEvidenceError('Не удалось загрузить подтверждающее событие') }
  }
  const comparison = selected ? attacks.filter((attack) => attack.key !== selected.key)
    .map((attack) => ({ attack, jaccard: jaccard(selected, attack) }))
    .sort((a, b) => b.jaccard - a.jaccard).slice(0, 5)
    .map((candidate) => ({ ...candidate, ...sequenceSimilarity(selected, candidate.attack) }))
    .sort((a, b) => b.score - a.score)[0] ?? null : null
  const matched = attacks.filter((attack) => attack.match)
  const confirmedCount = matched.filter((attack) => attack.match?.status === 'confirmed').length
  const suspicionCount = matched.filter((attack) => attack.match?.status === 'attempt' || attack.match?.status === 'candidate').length
  const scenarios = useMemo(() => {
    const counts = new Map<string, number>()
    for (const attack of matched) if (attack.match) counts.set(attack.match.technique_name, (counts.get(attack.match.technique_name) ?? 0) + 1)
    return [...counts].sort((a, b) => b[1] - a[1]).slice(0, 3)
  }, [matched])
  const vulnerabilityAttempts = useMemo(
    () => vulnerabilityEvidence([...events, ...extraEvents], traps),
    [events, extraEvents, traps],
  )
  const vulnerabilityProfileCount = new Set(vulnerabilityAttempts.map((item) => item.profileId)).size
  const selectedVulnerabilities = selected ? vulnerabilityEvidence(selected.events, traps) : []

  return <section className="space-y-6 p-5 sm:p-7">
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[0.2em] text-orange-300/70">Центр наблюдения</p><h2 className="mt-2 text-3xl font-semibold tracking-tight">События</h2><p className="mt-2 max-w-2xl text-sm text-white/45">Сессии, совпадения со сценариями и последовательность действий в ловушках.</p></div>
      <button type="button" disabled={loading} onClick={() => void onRefresh()} className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm text-white/75 transition hover:border-orange-400/30 hover:text-orange-200 disabled:opacity-50"><Icon name="refresh" className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />{loading ? 'Обновление…' : 'Обновить'}</button>
    </header>
    {error && <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/5 px-4 py-3 text-sm text-red-300">{error}</p>}

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <Metric icon="activity" label="Атакующие сессии" value={attacks.length} detail="Сгруппировано по сеансам" color="text-orange-300" />
      <Metric icon="alert" label="Подтверждённые инциденты" value={confirmedCount} detail="Есть подтверждающие события" color="text-red-300" />
      <Metric icon="shield" label="Активные подозрения" value={suspicionCount} detail="Кандидаты и попытки по графу" color="text-amber-200" />
      <Metric icon="alert" label="Попытки уязвимостей" value={vulnerabilityAttempts.length} detail={`${vulnerabilityProfileCount} сценариев · по телеметрии и командам`} color="text-violet-200" />
      <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 shadow-lg shadow-black/10"><div className="flex items-center gap-2 text-white/45"><Icon name="network" className="h-4 w-4 text-violet-300"/><span className="text-xs">Частые сценарии</span></div>{scenarios.length ? <div className="mt-3 space-y-2">{scenarios.map(([name, count]) => <div key={name} className="flex items-center justify-between gap-3"><span className="truncate text-sm text-white/80">{name}</span><span className="rounded-md bg-violet-300/10 px-2 py-0.5 text-xs text-violet-200">{count}</span></div>)}</div> : <p className="mt-3 text-sm text-white/35">Пока нет совпадений</p>}</section>
    </div>

    {matchesUnavailable && <p className="text-xs text-amber-200/70">Часть совпадений графа недоступна; список событий всё ещё отображается.</p>}
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.35fr)]">
      <section className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/75 shadow-lg shadow-black/10">
        <div className="border-b border-white/5 p-4 sm:p-5"><div className="flex items-center justify-between gap-3"><div><h3 className="font-semibold">Сессии и инциденты</h3><p className="mt-1 text-xs text-white/40">{filtered.length} записей</p></div>{matchesLoading && <span className="text-xs text-white/35">Сверяю граф…</span>}</div>
          <div className="mt-4 grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(130px,0.7fr)_minmax(130px,0.7fr)]"><label className="relative min-w-0"><span className="sr-only">Поиск атак</span><Icon name="search" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/30"/><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Сценарий, IP или ловушка" className="w-full rounded-lg border border-white/10 bg-black/20 py-2.5 pl-9 pr-3 text-sm outline-none focus:border-orange-400/40"/></label><select aria-label="Фильтр по ловушке" value={trapFilter} onChange={(event) => { setTrapFilter(event.target.value); setSelectedKey(null) }} className="min-w-0 rounded-lg border border-white/10 bg-[#160e0c] px-3 py-2 text-sm text-white/70"><option value="all">Все ловушки</option>{traps.map((trap) => <option key={trap.trap_id} value={trap.trap_id}>{trap.name}</option>)}</select><select aria-label="Фильтр по сервису" value={service} onChange={(event) => setService(event.target.value)} className="min-w-0 rounded-lg border border-white/10 bg-[#160e0c] px-3 py-2 text-sm text-white/70"><option>Все сервисы</option>{services.map((item) => <option key={item}>{item}</option>)}</select></div>
        </div>
        <div className="max-h-[760px] space-y-2 overflow-y-auto p-3">
          {filtered.map((attack, index) => {
            const state = matchStatus(attack.match)
            const active = selectedKey === attack.key
            const title = attack.match?.technique_name ?? (attack.sessionId ? 'SSH-сеанс' : eventLabel(attack.events[0].event.event_type))
            return <button key={attack.key} type="button" onClick={() => setSelectedKey(attack.key)} className={`group w-full rounded-lg border p-4 text-left transition ${active ? 'border-orange-400/35 bg-orange-400/[0.07]' : 'border-white/5 bg-white/[0.015] hover:border-white/15 hover:bg-white/[0.035]'}`}>
              <div className="flex items-start gap-3"><span className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${attack.match?.status === 'confirmed' ? 'bg-red-400/10 text-red-300' : attack.match ? 'bg-amber-300/10 text-amber-200' : 'bg-white/5 text-white/40'}`}><Icon name={attack.match?.status === 'confirmed' ? 'alert' : 'activity'} className="h-[18px] w-[18px]"/></span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-xs font-mono text-white/35">#{String(attacks.length - index).padStart(3, '0')}</span><span className={`rounded-full border px-2 py-0.5 text-[10px] ${state.tone}`}>{state.label}</span></div><h4 className="mt-2 truncate text-sm font-semibold text-white/90">{title}</h4><div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-white/40"><span>{trapNames.get(attack.trapId) ?? 'Ловушка'}</span><span className="font-mono">{attack.sourceIp ?? 'IP неизвестен'}</span><span>{attack.events.length} событий</span></div><div className="mt-3 flex items-center justify-between text-[11px] text-white/35"><span className="inline-flex items-center gap-1"><Icon name="clock" className="h-3.5 w-3.5"/>{dateTime(attack.last)}</span>{attack.match && <span className="text-violet-200/80">{Math.round(attack.match.similarity * 100)}% · покрытие графа</span>}</div></div><Icon name="chevron" className={`mt-1 h-4 w-4 shrink-0 transition ${active ? 'text-orange-300' : 'text-white/20 group-hover:text-white/50'}`}/></div>
            </button>
          })}
          {!loading && filtered.length === 0 && <div className="px-4 py-12 text-center"><Icon name="search" className="mx-auto h-7 w-7 text-white/20"/><p className="mt-3 text-sm text-white/50">Атак пока нет</p><p className="mt-1 text-xs text-white/30">Новые сессии появятся здесь после поступления телеметрии.</p></div>}
        </div>
      </section>

      <section className="min-h-[420px] rounded-xl border border-white/10 bg-[#160e0c]/75 shadow-lg shadow-black/10">
        {!selected ? <div className="flex min-h-[420px] flex-col items-center justify-center px-6 text-center"><div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-violet-300/15 bg-violet-300/[0.06] text-violet-200"><Icon name="network" className="h-7 w-7"/></div><h3 className="mt-4 font-semibold">Граф атаки</h3><p className="mt-2 max-w-sm text-sm leading-6 text-white/40">Выберите сессию слева, чтобы увидеть последовательность действий и совпадение с известным сценарием.</p></div> : <>
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/5 p-5 sm:p-6"><div className="min-w-0"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-violet-200/70">Детали атаки</p><h3 className="mt-2 text-xl font-semibold">{selected.match?.technique_name ?? 'Наблюдаемая последовательность'}</h3><p className="mt-1 break-all font-mono text-xs text-white/35">{selected.sessionId ?? 'Событие без ID сессии'}</p></div><span className={`rounded-full border px-3 py-1.5 text-xs ${matchStatus(selected.match).tone}`}>{matchStatus(selected.match).label}</span></div>
          <nav role="tablist" aria-label="Разделы деталей атаки" className="flex gap-1 overflow-x-auto border-b border-white/5 px-3 py-2">{DETAIL_TABS.map((tab) => <button key={tab.id} type="button" role="tab" aria-selected={detailSection === tab.id} onClick={() => setDetailSection(tab.id)} className={`shrink-0 rounded-lg px-3 py-2 text-xs transition ${detailSection === tab.id ? 'bg-violet-300/10 text-violet-100' : 'text-white/45 hover:bg-white/5 hover:text-white/80'}`}>{tab.label}</button>)}</nav>
          {detailSection === 'summary' && <>
          <div className="grid gap-3 border-b border-white/5 p-5 sm:grid-cols-3 sm:p-6"><Info label="Ловушка" value={trapNames.get(selected.trapId) ?? selected.trapId}/><Info label="Источник" value={selected.sourceIp ?? 'Не определён'} mono/><Info label="Время" value={dateTime(selected.first)}/></div>
          {selectedVulnerabilities.length > 0 && <div className="mx-5 mt-5 rounded-lg border border-violet-300/15 bg-violet-300/[0.04] p-4 sm:mx-6"><div className="flex items-center justify-between gap-3"><div><h4 className="text-sm font-medium text-violet-100">Сценарии уязвимостей</h4><p className="mt-1 text-xs text-white/40">Попытки из сетевого обработчика и команд виртуального терминала.</p></div><span className="rounded-full bg-violet-300/10 px-2.5 py-1 text-xs text-violet-100">{selectedVulnerabilities.length}</span></div><div className="mt-3 space-y-2">{selectedVulnerabilities.map(({ item, profileId }) => <div key={`${item.event.event_id}:${profileId}`} className="rounded-md border border-white/5 bg-black/10 px-3 py-2.5"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-sm text-white/80">{vulnerabilityNames[profileId] ?? profileId}</span><span className="text-[11px] text-white/45">{vulnerabilityStatus(item)}</span></div>{eventDetail(item) && <p className="mt-1 truncate font-mono text-[10px] text-white/35">{eventDetail(item)}</p>}</div>)}</div><p className="mt-3 text-[11px] leading-5 text-white/35">Ответ «принято» описывает виртуальную модель. Для проверки публичного порта запускайте клиент снаружи SSH-оболочки.</p></div>}
          {selected.match && <div className="mx-5 mt-5 rounded-lg border border-violet-300/15 bg-violet-300/[0.04] p-4 sm:mx-6"><div className="flex items-center justify-between gap-3"><div><p className="text-sm font-medium">Совпадение со сценарием</p><p className="mt-1 text-xs text-white/40">{selected.match.technique_key} · покрытие узлов сценария</p></div><span className="text-2xl font-semibold text-violet-200">{Math.round(selected.match.similarity * 100)}<span className="text-sm">%</span></span></div><div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-gradient-to-r from-violet-400 to-orange-300" style={{ width: `${Math.max(0, Math.min(100, selected.match.similarity * 100))}%` }}/></div></div>}
          </>}
          {detailSection === 'scenario' && <>
          {selected.match && <details open key={`${selected.key}:${selected.match.scenario_id}`} className="mx-5 mt-4 rounded-lg border border-violet-300/15 bg-black/10 sm:mx-6"><summary className="cursor-pointer px-4 py-3 text-sm font-medium text-violet-100">Разбор сценария · {selected.match.nodes.length} узлов, {selected.match.edges.length} переходов</summary><div className="space-y-3 border-t border-white/5 p-4"><p className="text-xs text-white/45">{matchStatus(selected.match).label} · совпало {selected.match.nodes.filter((node) => node.status === 'matched').length} из {selected.match.nodes.length} узлов ({Math.round(selected.match.coverage * 100)}%). Это покрытие графа, не вероятность атаки. Выберите узел, чтобы увидеть событие.</p>{selected.match.nodes.map((node, index) => { const incoming = selected.match!.edges.filter((edge) => edge.to_node === node.node_id); const present = node.matched_event_ids.filter((id) => selected.events.some((item) => item.event.event_id === id)); return <div key={node.node_id} className={`rounded-lg border p-3 ${node.status === 'matched' ? 'border-emerald-400/25 bg-emerald-400/[0.04]' : node.status === 'outcome_mismatch' || node.status === 'observed_unlinked' ? 'border-orange-300/25 bg-orange-300/[0.04]' : node.status === 'legacy_unattributed' ? 'border-amber-300/20 bg-amber-300/[0.04]' : 'border-white/10 bg-white/[0.02]'}`}><button type="button" disabled={!node.matched_event_ids.length} onClick={() => void showEvidence(node.matched_event_ids)} className="w-full text-left disabled:cursor-default"><span className="text-sm font-medium text-white/85">{index + 1}. {node.node_key.replaceAll('_', ' ')}</span><span className="ml-2 text-xs text-white/45">{node.status === 'matched' ? 'Действие наблюдалось' : node.status === 'outcome_mismatch' ? 'Действие обнаружено, нужный исход не подтверждён' : node.status === 'observed_unlinked' ? 'Действие обнаружено, переход не подтверждён' : node.status === 'legacy_unattributed' ? 'Историческое совпадение без привязки' : 'Нет подтверждения'}</span><span className="mt-1 block text-xs text-white/45">{node.action_kind} · {node.resource_class} · исход: {node.observed_outcome ?? 'не наблюдался'} / требуется: {node.expected_outcome === '*' ? 'любой' : node.expected_outcome}</span>{node.matched_event_ids.length > 0 && <span className="mt-1 block text-xs text-violet-200/75">Событие {node.matched_event_ids.map((id) => `#${selected.events.findIndex((item) => item.event.event_id === id) + 1 || id.slice(0, 8)}`).join(', ')}{!present.length ? ' · загрузить и показать' : ' · показать в таймлайне'}</span>}</button>{incoming.map((edge) => <p key={`${edge.from_node}:${edge.to_node}`} className={`mt-2 border-l-2 pl-2 text-xs ${edge.status === 'matched' ? 'border-emerald-400/50 text-emerald-200/70' : 'border-white/10 text-white/35'}`}>Переход {selected.match!.nodes.find((item) => item.node_id === edge.from_node)?.node_key ?? 'узел'} → {node.node_key}: {edge.status === 'matched' ? 'выполнен' : edge.status === 'legacy_unattributed' ? 'исторические данные без привязки' : 'не подтверждён'}{edge.time_delta_ms !== null ? ` · ${Math.round(edge.time_delta_ms / 1000)} с` : ''}</p>)}</div> })}</div></details>}
          {!selected.match && <p className="p-5 text-sm text-white/45">Для этой сессии нет совпавшего сценария.</p>}
          </>}
          {detailSection === 'timeline' && <>
          {evidenceError && <p role="alert" className="mx-5 mt-3 text-xs text-red-300 sm:mx-6">{evidenceError}</p>}
          <div className="flex h-[580px] flex-col p-5 sm:h-[680px] sm:p-6"><div className="mb-5 flex shrink-0 items-center justify-between"><div><h4 className="font-semibold">Ход событий</h4><p className="mt-1 text-xs text-white/40">Фактическая последовательность, зафиксированная ловушкой</p></div><span className="text-xs text-white/35">{selected.events.length} узлов</span></div>
            <div ref={timelineRef} className="relative min-h-0 flex-1 space-y-0 overflow-y-auto pr-2">{visibleEvents.map((item, pageIndex) => {
              const index = eventPage * eventsPerPage + pageIndex
              const detail = eventDetail(item)
              const isLast = index === selected.events.length - 1
              return <div key={item.event.event_id} data-highlighted={highlightedEventIds.includes(item.event.event_id)} className="relative flex gap-4 pb-5 last:pb-0"><div className="flex w-8 shrink-0 flex-col items-center"><span className={`z-10 flex h-8 w-8 items-center justify-center rounded-full border ${isLast ? 'border-orange-300/40 bg-orange-300/10 text-orange-200' : 'border-white/10 bg-[#100a09] text-white/45'}`}><span className="text-[10px] font-semibold">{index + 1}</span></span>{!isLast && <span className="absolute top-8 bottom-0 w-px bg-gradient-to-b from-orange-300/30 to-white/5"/>}</div><article className={`min-w-0 flex-1 rounded-lg border px-4 py-3 ${highlightedEventIds.includes(item.event.event_id) ? 'border-violet-300/60 bg-violet-300/10 ring-1 ring-violet-300/30' : 'border-white/5 bg-black/10'}`}><div className="flex flex-wrap items-center justify-between gap-2"><h5 className="text-sm font-medium text-white/85">{eventLabel(item.event.event_type)}</h5><time className="text-[11px] text-white/35">{dateTime(item.event.occurred_at)}</time></div>{detail && <code className="mt-2 block break-all rounded bg-black/25 px-2.5 py-2 font-mono text-xs text-orange-100/75">{detail}</code>}<p className="mt-2 text-[11px] text-white/35">{item.event.protocol.toUpperCase()} · {item.event.service_type}{item.event.destination_port ? ` · порт ${item.event.destination_port}` : ''}</p></article></div>
            })}</div>
            <div className="mt-4 flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-4">
              <span className="text-xs text-white/35">Показано {selected.events.length ? eventPage * eventsPerPage + 1 : 0}–{Math.min((eventPage + 1) * eventsPerPage, selected.events.length)} из {selected.events.length}</span>
              <div className="flex items-center gap-2">
                <button type="button" onClick={() => setEventPage((page) => Math.max(0, page - 1))} disabled={eventPage === 0} className="rounded-md border border-white/10 px-3 py-1.5 text-xs text-white/70 transition hover:border-orange-300/30 disabled:cursor-not-allowed disabled:opacity-35">Назад</button>
                <span className="min-w-20 text-center text-xs text-white/45">Страница {eventPage + 1} из {eventPageCount}</span>
                <button type="button" onClick={() => setEventPage((page) => Math.min(eventPageCount - 1, page + 1))} disabled={eventPage + 1 >= eventPageCount} className="rounded-md border border-white/10 px-3 py-1.5 text-xs text-white/70 transition hover:border-orange-300/30 disabled:cursor-not-allowed disabled:opacity-35">Вперёд</button>
              </div>
            </div>
          </div>
          </>}
          {detailSection === 'comparison' && (comparison ? <div className="border-t border-white/5 p-5 sm:p-6"><div className="flex flex-wrap items-end justify-between gap-3"><div><h4 className="font-semibold">Похожая сессия</h4><p className="mt-1 text-xs text-white/40">Жаккар {Math.round(comparison.jaccard * 100)}% для отбора; порядок и исходы учитываются при сравнении. Разница интервалов: {comparison.timing === null ? 'недостаточно событий' : Math.round(comparison.timing * 100) + '%' }.</p></div><span className="text-xl font-semibold text-sky-200">{Math.round(comparison.score * 100)}%</span></div><div className="mt-4 grid gap-3 md:grid-cols-2"><CompareSequence label="Выбранная сессия" attack={selected} trapName={trapNames.get(selected.trapId) ?? 'Ловушка'}/><CompareSequence label="Ближайшая сессия" attack={comparison.attack} trapName={trapNames.get(comparison.attack.trapId) ?? 'Ловушка'}/></div></div> : <p className="p-5 text-sm text-white/45">Для сравнения нужна ещё одна сессия.</p>)}
          {detailSection === 'logs' && <div className="space-y-4 p-5 sm:p-6">
            <div><h4 className="font-semibold">Все логи ловушки</h4><p className="mt-1 text-xs text-white/40">{trapNames.get(selected.trapId) ?? selected.trapId} · поиск по типу, адресу и содержимому события</p></div>
            <label className="relative block"><span className="sr-only">Поиск по всем логам</span><Icon name="search" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/30"/><input value={logQuery} onChange={(event) => setLogQuery(event.target.value)} placeholder="Поиск по всем логам…" className="w-full rounded-lg border border-white/10 bg-black/20 py-2.5 pl-9 pr-3 text-sm outline-none focus:border-violet-300/40"/></label>
            {logsError && <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/5 px-3 py-2 text-xs text-red-300">{logsError}</p>}
            <div className="max-h-[620px] space-y-2 overflow-y-auto pr-1">
              {logsLoading ? <p className="py-8 text-center text-sm text-white/40">Загружаю страницу логов…</p> : logEvents.map((item) => <details key={item.event.event_id} className="rounded-lg border border-white/10 bg-black/10"><summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-3 py-3"><span className="min-w-0"><span className="block truncate text-sm text-white/80">{eventLabel(item.event.event_type)}</span><span className="mt-1 block text-[11px] text-white/40">{item.event.source_ip ?? 'IP неизвестен'} · {item.event.service_type} · {item.event.protocol.toUpperCase()}</span></span><time className="text-[11px] text-white/35">{dateTime(item.event.occurred_at)}</time></summary><div className="space-y-2 border-t border-white/5 px-3 py-3"><p className="break-all font-mono text-[10px] text-white/35">event {item.event.event_id}{item.event.session_id ? ' · session ' + item.event.session_id : ''}</p><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-black/25 p-3 font-mono text-[11px] leading-5 text-white/65">{JSON.stringify({ payload: item.event.payload, metadata: item.event.metadata }, null, 2)}</pre></div></details>)}
              {!logsLoading && logEvents.length === 0 && <p className="py-8 text-center text-sm text-white/40">{appliedLogQuery ? 'По запросу ничего не найдено' : 'Логов пока нет'}</p>}
            </div>
            <div className="flex items-center justify-between border-t border-white/5 pt-4"><button type="button" onClick={() => setLogPage((page) => Math.max(0, page - 1))} disabled={logPage === 0 || logsLoading} className="rounded-md border border-white/10 px-3 py-2 text-xs text-white/70 disabled:cursor-not-allowed disabled:opacity-35">Назад</button><span className="text-xs text-white/40">Страница {logPage + 1}</span><button type="button" onClick={() => { if (!logNextCursor) return; setLogCursors((cursors) => [...cursors.slice(0, logPage + 1), logNextCursor]); setLogPage((page) => page + 1) }} disabled={!logNextCursor || logsLoading} className="rounded-md border border-white/10 px-3 py-2 text-xs text-white/70 disabled:cursor-not-allowed disabled:opacity-35">Вперёд</button></div>
          </div>}
        </>}
      </section>
    </div>
    <p className="text-[11px] leading-5 text-white/30">Процент показывает покрытие узлов известного сценария графом, а не вероятность взлома. Подтверждённый инцидент отображается только при наличии соответствующих подтверждающих событий.</p>
  </section>
}

function Metric({ icon, label, value, detail, color }: { icon: 'activity' | 'alert' | 'shield'; label: string; value: number; detail: string; color: string }) {
  return <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 shadow-lg shadow-black/10"><div className="flex items-center justify-between"><span className="text-xs text-white/45">{label}</span><span className={`flex h-8 w-8 items-center justify-center rounded-lg bg-white/[0.04] ${color}`}><Icon name={icon} className="h-4 w-4"/></span></div><p className="mt-3 text-3xl font-semibold tracking-tight">{value}</p><p className="mt-1 text-[11px] text-white/30">{detail}</p></section>
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0"><p className="text-[11px] uppercase tracking-wider text-white/30">{label}</p><p className={`mt-1 truncate text-sm text-white/75 ${mono ? 'font-mono' : ''}`} title={value}>{value}</p></div>
}

function CompareSequence({ label, attack, trapName }: { label: string; attack: Attack; trapName: string }) {
  const actions = sequence(attack)
  return <div className="rounded-lg border border-white/5 bg-black/10 p-3"><p className="text-xs text-white/40">{label} · {trapName}</p><div className="mt-3 flex flex-wrap items-center gap-1.5">{actions.map((action, index) => <span key={index} className="inline-flex items-center gap-1.5"><span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-white/70">{action.kind} ({action.result})</span>{index < actions.length - 1 && <span className="text-orange-300/50">→</span>}</span>)}</div></div>
}
