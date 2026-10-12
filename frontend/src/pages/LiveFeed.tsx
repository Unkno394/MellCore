import { useEffect, useMemo, useState } from 'react'
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

function Icon({ name, className = 'h-5 w-5' }: { name: 'activity' | 'alert' | 'search' | 'refresh' | 'chevron' | 'shield' | 'network' | 'clock' | 'close'; className?: string }) {
  const common = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }
  const paths = {
    activity: <><path d="M3 12h4l3-8 4 16 3-8h4" /></>,
    alert: <><path d="m12 3 9 16H3L12 3Z" /><path d="M12 9v4m0 3h.01" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
    network: <><rect x="9" y="3" width="6" height="6" rx="1" /><rect x="3" y="15" width="6" height="6" rx="1" /><rect x="15" y="15" width="6" height="6" rx="1" /><path d="M12 9v3m-6 3v-3h12v3" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    close: <><path d="m18 6-12 12M6 6l12 12" /></>,
  }
  return <svg aria-hidden="true" viewBox="0 0 24 24" className={className} {...common}>{paths[name]}</svg>
}

function matchStatus(match: AttackGraphMatch | null) {
  if (!match) return { label: 'События', tone: 'border-white/10 bg-white/5 text-white/55' }
  if (match.status === 'confirmed') return { label: 'Подтверждённый инцидент', tone: 'border-red-400/25 bg-red-400/10 text-red-300' }
  if (match.status === 'attempt') return { label: 'Активное подозрение', tone: 'border-amber-300/25 bg-amber-300/10 text-amber-200' }
  return { label: 'Кандидат сценария', tone: 'border-sky-300/25 bg-sky-300/10 text-sky-200' }
}

function eventDetail(item: AttackEvent) {
  const payload = item.event.payload && typeof item.event.payload === 'object' ? item.event.payload as Record<string, unknown> : {}
  const command = typeof payload.command === 'string' ? payload.command : typeof payload.input === 'string' ? payload.input : null
  const path = typeof payload.path === 'string' ? payload.path : null
  const resource = typeof payload.resource === 'string' ? payload.resource : null
  return command || path || resource || null
}

function actionClass(item: AttackEvent) {
  const type = item.event.event_type
  const detail = eventDetail(item)?.toLowerCase() ?? ''
  if (type.startsWith('auth.')) return 'SSH-аутентификация'
  if (type === 'connection.opened' || type === 'connection') return 'SSH-подключение'
  if (type === 'session.started') return 'Запуск сессии'
  if (type === 'session.ended') return 'Завершение сессии'
  if (type === 'filesystem.accessed') return detail.includes('read') || detail.includes('cat') ? 'Чтение файлов' : 'Обзор файлов'
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

export default function LiveFeed({ api, events, traps, initialTrapId = null, loading, error, onRefresh }: Props) {
  const [search, setSearch] = useState('')
  const [service, setService] = useState('Все сервисы')
  const [trapFilter, setTrapFilter] = useState(initialTrapId ?? 'all')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [matches, setMatches] = useState<AttackGraphMatch[]>([])
  const [matchesLoading, setMatchesLoading] = useState(false)
  const [matchesUnavailable, setMatchesUnavailable] = useState(false)
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
    for (const item of events) {
      const sessionId = item.event.session_id
      const key = sessionId ? `${item.event.trap_id}:session:${sessionId}` : `${item.event.trap_id}:event:${item.event.event_id}`
      grouped.set(key, [...(grouped.get(key) ?? []), item])
    }
    return [...grouped.entries()].map(([key, items]): Attack => {
      const sorted = [...items].sort((a, b) => a.event.occurred_at.localeCompare(b.event.occurred_at))
      const eventIds = new Set(sorted.map((item) => item.event.event_id))
      const match = matches.filter((candidate) => candidate.evidence_event_ids.some((id) => eventIds.has(id)))
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
  }, [events, matches])

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
  const comparison = selected ? attacks.filter((attack) => attack.key !== selected.key)
    .map((attack) => ({ attack, score: jaccard(selected, attack) }))
    .sort((a, b) => b.score - a.score)[0] ?? null : null
  const matched = attacks.filter((attack) => attack.match)
  const confirmedCount = matched.filter((attack) => attack.match?.status === 'confirmed').length
  const suspicionCount = matched.filter((attack) => attack.match?.status === 'attempt' || attack.match?.status === 'candidate').length
  const scenarios = useMemo(() => {
    const counts = new Map<string, number>()
    for (const attack of matched) if (attack.match) counts.set(attack.match.technique_name, (counts.get(attack.match.technique_name) ?? 0) + 1)
    return [...counts].sort((a, b) => b[1] - a[1]).slice(0, 3)
  }, [matched])

  return <section className="space-y-6 p-5 sm:p-7">
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[0.2em] text-orange-300/70">Центр наблюдения</p><h2 className="mt-2 text-3xl font-semibold tracking-tight">Атаки</h2><p className="mt-2 max-w-2xl text-sm text-white/45">Сессии атак, совпадения со сценариями и последовательность действий в ловушках.</p></div>
      <button type="button" disabled={loading} onClick={() => void onRefresh()} className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm text-white/75 transition hover:border-orange-400/30 hover:text-orange-200 disabled:opacity-50"><Icon name="refresh" className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />{loading ? 'Обновление…' : 'Обновить'}</button>
    </header>
    {error && <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/5 px-4 py-3 text-sm text-red-300">{error}</p>}

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Metric icon="activity" label="Атакующие сессии" value={attacks.length} detail="Сгруппировано по сеансам" color="text-orange-300" />
      <Metric icon="alert" label="Подтверждённые инциденты" value={confirmedCount} detail="Есть подтверждающие события" color="text-red-300" />
      <Metric icon="shield" label="Активные подозрения" value={suspicionCount} detail="Кандидаты и попытки по графу" color="text-amber-200" />
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
          <div className="grid gap-3 border-b border-white/5 p-5 sm:grid-cols-3 sm:p-6"><Info label="Ловушка" value={trapNames.get(selected.trapId) ?? selected.trapId}/><Info label="Источник" value={selected.sourceIp ?? 'Не определён'} mono/><Info label="Время" value={dateTime(selected.first)}/></div>
          {selected.match && <div className="mx-5 mt-5 rounded-lg border border-violet-300/15 bg-violet-300/[0.04] p-4 sm:mx-6"><div className="flex items-center justify-between gap-3"><div><p className="text-sm font-medium">Совпадение со сценарием</p><p className="mt-1 text-xs text-white/40">{selected.match.technique_key} · покрытие узлов сценария</p></div><span className="text-2xl font-semibold text-violet-200">{Math.round(selected.match.similarity * 100)}<span className="text-sm">%</span></span></div><div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-gradient-to-r from-violet-400 to-orange-300" style={{ width: `${Math.max(0, Math.min(100, selected.match.similarity * 100))}%` }}/></div></div>}
          <div className="p-5 sm:p-6"><div className="mb-5 flex items-center justify-between"><div><h4 className="font-semibold">Ход событий</h4><p className="mt-1 text-xs text-white/40">Фактическая последовательность, зафиксированная ловушкой</p></div><span className="text-xs text-white/35">{selected.events.length} узлов</span></div>
            <div className="relative space-y-0">{selected.events.map((item, index) => {
              const detail = eventDetail(item)
              const isLast = index === selected.events.length - 1
              return <div key={item.event.event_id} className="relative flex gap-4 pb-5 last:pb-0"><div className="flex w-8 shrink-0 flex-col items-center"><span className={`z-10 flex h-8 w-8 items-center justify-center rounded-full border ${isLast ? 'border-orange-300/40 bg-orange-300/10 text-orange-200' : 'border-white/10 bg-[#100a09] text-white/45'}`}><span className="text-[10px] font-semibold">{index + 1}</span></span>{!isLast && <span className="absolute top-8 bottom-0 w-px bg-gradient-to-b from-orange-300/30 to-white/5"/>}</div><article className="min-w-0 flex-1 rounded-lg border border-white/5 bg-black/10 px-4 py-3"><div className="flex flex-wrap items-center justify-between gap-2"><h5 className="text-sm font-medium text-white/85">{eventLabel(item.event.event_type)}</h5><time className="text-[11px] text-white/35">{dateTime(item.event.occurred_at)}</time></div>{detail && <code className="mt-2 block break-all rounded bg-black/25 px-2.5 py-2 font-mono text-xs text-orange-100/75">{detail}</code>}<p className="mt-2 text-[11px] text-white/35">{item.event.protocol.toUpperCase()} · {item.event.service_type}{item.event.destination_port ? ` · порт ${item.event.destination_port}` : ''}</p></article></div>
            })}</div>
          </div>
          {comparison && <div className="border-t border-white/5 p-5 sm:p-6"><div className="flex flex-wrap items-end justify-between gap-3"><div><h4 className="font-semibold">Сравнение сценариев</h4><p className="mt-1 text-xs text-white/40">Сходство множеств нормализованных действий — коэффициент Жаккара</p></div><span className="text-xl font-semibold text-sky-200">{Math.round(comparison.score * 100)}%</span></div><div className="mt-4 grid gap-3 md:grid-cols-2"><CompareSequence label="Выбранная сессия" attack={selected} trapName={trapNames.get(selected.trapId) ?? 'Ловушка'}/><CompareSequence label="Ближайшая сессия" attack={comparison.attack} trapName={trapNames.get(comparison.attack.trapId) ?? 'Ловушка'}/></div></div>}
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
  const actions = [...new Set(attack.events.map(actionClass))]
  return <div className="rounded-lg border border-white/5 bg-black/10 p-3"><p className="text-xs text-white/40">{label} · {trapName}</p><div className="mt-3 flex flex-wrap items-center gap-1.5">{actions.map((action, index) => <span key={action} className="inline-flex items-center gap-1.5"><span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-white/70">{action}</span>{index < actions.length - 1 && <span className="text-orange-300/50">→</span>}</span>)}</div></div>
}
