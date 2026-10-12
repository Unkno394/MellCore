import { useEffect, useMemo, useState } from 'react'
import { dateTime, eventLabel, statusLabel } from '../i18n/labels'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { AttackEvent, Server, Trap, TrapAction } from '../api/types'

type Props = {
  api: MellCoreApi
  traps: Trap[]
  servers: Server[]
  events: AttackEvent[]
  readOnly: boolean
  onChanged: () => Promise<void>
  onShowAttacks: (trapId: string) => void
}

const stateTone: Record<Trap['actual_state'], string> = {
  running: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-200',
  installing: 'border-orange-300/20 bg-orange-300/10 text-orange-200',
  failed: 'border-red-400/20 bg-red-400/10 text-red-300',
  unknown: 'border-white/10 bg-white/5 text-white/45',
  stopped: 'border-white/10 bg-white/5 text-white/55',
  removed: 'border-white/10 bg-white/5 text-white/35',
}

const actionText: Record<TrapAction, string> = { start: 'Запустить', stop: 'Остановить', restart: 'Перезапустить', remove: 'Удалить' }
const resourceLabels: Record<string, string> = { cpu: 'CPU', memory: 'Память', pids: 'Процессы' }

function serverTitle(server: Server | undefined) {
  return server ? `${server.name} · ${server.host}` : 'Сервер не найден'
}

export default function Honeypots({ api, traps, servers, events, readOnly, onChanged, onShowAttacks }: Props) {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [serverFilter, setServerFilter] = useState('all')
  const [stateFilter, setStateFilter] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(traps[0]?.trap_id ?? null)
  const [busyAction, setBusyAction] = useState<TrapAction | null>(null)
  const [pending, setPending] = useState<{ trapId: string; actionId: string; action: TrapAction } | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const serverNames = useMemo(() => new Map(servers.map((server) => [server.server_id, server])), [servers])
  const types = useMemo(() => [...new Set(traps.map((trap) => trap.profile_snapshot.honeypot_type))].sort(), [traps])
  const filtered = useMemo(() => traps.filter((trap) => {
    const server = serverNames.get(trap.server_id)
    const query = `${trap.name} ${trap.profile_snapshot.honeypot_type} ${server?.name ?? ''} ${server?.host ?? ''}`.toLowerCase()
    return query.includes(search.toLowerCase())
      && (typeFilter === 'all' || trap.profile_snapshot.honeypot_type === typeFilter)
      && (serverFilter === 'all' || trap.server_id === serverFilter)
      && (stateFilter === 'all' || trap.actual_state === stateFilter)
  }), [traps, search, typeFilter, serverFilter, stateFilter, serverNames])
  const selected = filtered.find((trap) => trap.trap_id === selectedId) ?? filtered[0] ?? null
  const selectedEvents = useMemo(() => selected
    ? events.filter((item) => item.event.trap_id === selected.trap_id)
      .sort((a, b) => b.event.occurred_at.localeCompare(a.event.occurred_at)).slice(0, 12)
    : [], [events, selected])
  const actionsDisabled = Boolean(busyAction) || readOnly || selected?.actual_state === 'installing'

  useEffect(() => {
    if (!pending) return
    let cancelled = false
    let timer = 0
    async function poll() {
      try {
        const result = await api.traps.actionStatus(pending!.trapId, pending!.actionId)
        if (cancelled) return
        if (result.status === 'queued') {
          timer = window.setTimeout(() => { void poll() }, 2000)
          return
        }
        const action = pending!.action
        setPending(null)
        setBusyAction(null)
        if (result.status === 'succeeded') {
          setError('')
          setMessage(action === 'remove' ? 'Ловушка удалена с сервера и из панели.' : `Команда «${actionText[action].toLowerCase()}» выполнена.`)
          if (action === 'remove') setSelectedId(null)
          await onChanged()
        } else {
          setError(result.detail || `Не удалось выполнить команду «${actionText[action].toLowerCase()}».`)
        }
      } catch (requestError) {
        if (cancelled) return
        setError(apiErrorMessage(requestError))
        timer = window.setTimeout(() => { void poll() }, 3000)
      }
    }
    void poll()
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [api, onChanged, pending])

  async function runAction(action: TrapAction) {
    if (!selected || readOnly || busyAction) return
    if (action === 'remove' && !window.confirm(`Остановить и удалить ловушку «${selected.name}» с сервера?`)) return
    setError('')
    setMessage('')
    setBusyAction(action)
    try {
      const result = await api.traps.action(selected.trap_id, action)
      setPending({ trapId: selected.trap_id, actionId: result.action_id, action })
      setMessage(`Команда «${actionText[action].toLowerCase()}» отправлена агенту.`)
    } catch (requestError) {
      setBusyAction(null)
      setError(apiErrorMessage(requestError))
    }
  }

  return <section className="space-y-5 p-4 sm:p-6">
    <header><p className="text-xs uppercase tracking-[0.18em] text-orange-300/65">Управление инфраструктурой</p><h2 className="mt-2 text-2xl font-semibold">Ловушки</h2><p className="mt-1 text-sm text-white/40">Фильтруйте экземпляры и управляйте их состоянием на подключённых серверах.</p></header>

    <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 shadow-lg shadow-black/10">
      <div className="grid gap-3 md:grid-cols-[minmax(220px,1.5fr)_repeat(3,minmax(140px,1fr))]">
        <label className="relative"><span className="sr-only">Поиск ловушек</span><svg aria-hidden="true" viewBox="0 0 24 24" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Название, сервер или IP" className="w-full rounded-lg border border-white/10 bg-black/20 py-2.5 pl-9 pr-3 text-sm outline-none focus:border-orange-400/40"/></label>
        <select aria-label="Фильтр по типу" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white/70"><option value="all">Все типы</option>{types.map((type) => <option key={type} value={type}>{type}</option>)}</select>
        <select aria-label="Фильтр по серверу" value={serverFilter} onChange={(event) => setServerFilter(event.target.value)} className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white/70"><option value="all">Все серверы</option>{servers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name}</option>)}</select>
        <select aria-label="Фильтр по состоянию" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)} className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white/70"><option value="all">Все состояния</option>{(['running', 'installing', 'stopped', 'failed', 'unknown', 'removed'] as const).map((value) => <option key={value} value={value}>{statusLabel(value)}</option>)}</select>
      </div>
      <p className="mt-3 text-xs text-white/35">Найдено: {filtered.length}</p>
    </section>

    <div className="grid items-start gap-4 2xl:grid-cols-[minmax(0,1.55fr)_minmax(340px,0.85fr)]">
      <section className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/75 shadow-lg shadow-black/10">
        <div className="overflow-x-auto"><table className="w-full min-w-[820px] text-left text-sm"><thead className="border-b border-white/10 bg-white/[0.02] text-[11px] uppercase tracking-wider text-white/35"><tr><th className="px-4 py-3">Ловушка</th><th className="px-4 py-3">Профиль</th><th className="px-4 py-3">Сервер</th><th className="px-4 py-3">IP / порт</th><th className="px-4 py-3">Состояние</th></tr></thead><tbody>{filtered.map((trap) => {
          const server = serverNames.get(trap.server_id)
          const active = selected?.trap_id === trap.trap_id
          return <tr key={trap.trap_id} onClick={() => { setSelectedId(trap.trap_id); setError(''); setMessage('') }} className={`cursor-pointer border-b border-white/5 transition ${active ? 'bg-orange-400/[0.06]' : 'hover:bg-white/[0.025]'}`}><td className="px-4 py-3.5"><span className="block font-medium text-white/90">{trap.name}</span><span className="mt-1 block font-mono text-[10px] text-white/30">{trap.trap_id.slice(0, 8)}</span></td><td className="px-4 py-3.5"><span className="block text-white/75">{trap.profile_snapshot.name}</span><span className="mt-1 block text-xs text-white/35">{trap.profile_snapshot.honeypot_type} · {statusLabel(trap.profile_snapshot.level)}</span></td><td className="max-w-40 truncate px-4 py-3.5 text-white/65" title={serverTitle(server)}>{server?.name ?? '—'}</td><td className="px-4 py-3.5 font-mono text-xs text-white/55">{server?.host ?? '—'}{trap.ports.map((port) => <span key={`${port.transport}-${port.host_port}`} className="ml-1 text-orange-200/75">:{port.host_port}/{port.transport}</span>)}</td><td className="px-4 py-3.5"><span className={`rounded-full border px-2.5 py-1 text-[11px] ${stateTone[trap.actual_state]}`}>{statusLabel(trap.actual_state)}</span></td></tr>
        })}</tbody></table></div>
        {filtered.length === 0 && <div className="px-6 py-14 text-center"><p className="text-sm text-white/55">Подходящих ловушек нет</p><p className="mt-1 text-xs text-white/30">Измените фильтры или создайте ловушку.</p></div>}
      </section>

      <aside className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/75 shadow-lg shadow-black/10">
        {selected ? <>
          <div className="border-b border-white/5 p-5"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-[11px] uppercase tracking-[0.18em] text-orange-200/65">Выбранная ловушка</p><h3 className="mt-2 truncate text-xl font-semibold">{selected.name}</h3><p className="mt-1 truncate text-xs text-white/35">{serverTitle(serverNames.get(selected.server_id))}</p></div><span className={`shrink-0 rounded-full border px-2.5 py-1 text-[11px] ${stateTone[selected.actual_state]}`}>{statusLabel(selected.actual_state)}</span></div></div>
          <div className="space-y-5 p-5">
            <section><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Конфигурация</h4><div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3"><Info label="Тип" value={selected.profile_snapshot.honeypot_type}/><Info label="Служба" value={selected.profile_snapshot.service_type}/><Info label="Уровень" value={statusLabel(selected.profile_snapshot.level)}/><Info label="Версия профиля" value={String(selected.profile_version)}/><Info label="Внешние порты" value={selected.ports.map((port) => `${port.host_port}/${port.transport}`).join(', ') || 'Не заданы'}/><Info label="Создана" value={new Date(selected.created_at).toLocaleDateString('ru-RU')}/></div><p className="mt-3 text-xs leading-5 text-white/40">{selected.profile_snapshot.description || 'У профиля нет описания.'}</p></section>
            <section className="border-t border-white/5 pt-4"><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Лимиты контейнера · применённая конфигурация</h4><div className="mt-3 grid grid-cols-3 gap-2">{Object.entries({ cpu: `${selected.resources.cpu_cores} CPU`, memory: `${selected.resources.memory_mb} МБ RAM`, pids: `${selected.resources.pids} процессов` }).map(([key, value]) => <div key={key} className="rounded-lg border border-white/5 bg-black/10 p-2.5"><p className="text-[10px] text-white/35">{resourceLabels[key]}</p><p className="mt-1 text-xs font-medium text-white/75">{value}</p></div>)}</div><p className="mt-2 text-[10px] text-white/30">Это заданные Docker-лимиты, а не текущее потребление. GPU не настраивается.</p></section>
            <section className="border-t border-white/5 pt-4"><div className="flex items-center justify-between gap-2"><div><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Журнал ловушки</h4><p className="mt-1 text-[10px] text-white/30">События, полученные от агента</p></div><span className="text-[10px] text-white/30">{selectedEvents.length} последних</span></div>{selected.actual_state === 'failed' && <p className="mt-3 rounded-lg border border-red-400/20 bg-red-400/[0.06] px-3 py-2 text-xs text-red-300">Ловушка в состоянии ошибки. Подробный вывод Docker пока не предоставляется API.</p>}<div className="mt-3 max-h-64 space-y-2 overflow-auto">{selectedEvents.map((item) => <article key={`${item.event.event_id}`} className="rounded-lg border border-white/5 bg-black/10 px-3 py-2"><div className="flex items-start justify-between gap-3"><span className="text-xs text-white/75">{eventLabel(item.event.event_type)}</span><time className="shrink-0 text-[10px] text-white/30">{dateTime(item.event.occurred_at)}</time></div><p className="mt-1 text-[10px] text-white/35">{item.event.service_type}{item.event.source_ip ? ` · ${item.event.source_ip}` : ''}</p><EventPayload payload={item.event.payload}/></article>)}{selectedEvents.length === 0 && <p className="rounded-lg border border-white/5 bg-black/10 px-3 py-4 text-center text-xs text-white/35">Событий от агента пока нет.</p>}</div></section>
            <details className="border-t border-white/5 pt-4"><summary className="cursor-pointer text-xs font-semibold uppercase tracking-wider text-white/40 hover:text-white/65">Параметры конфигурации</summary><pre className="mt-3 max-h-48 overflow-auto rounded-lg border border-white/5 bg-black/20 p-3 text-[10px] leading-5 text-white/55">{JSON.stringify(selected.effective_config, null, 2)}</pre></details>
            <section className="border-t border-white/5 pt-4"><div className="flex items-center justify-between"><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Управление</h4><button type="button" onClick={() => onShowAttacks(selected.trap_id)} className="text-xs text-orange-200/75 transition hover:text-orange-100">Атаки этой ловушки →</button></div><div className="mt-3 grid grid-cols-2 gap-2">{selected.actual_state !== 'running' && <ActionButton label="Запустить" disabled={actionsDisabled || selected.actual_state === 'removed'} onClick={() => void runAction('start')} tone="green"/>}{selected.actual_state === 'running' && <ActionButton label="Остановить" disabled={actionsDisabled} onClick={() => void runAction('stop')}/>}{selected.actual_state === 'running' && <ActionButton label="Перезапустить" disabled={actionsDisabled} onClick={() => void runAction('restart')}/>}<ActionButton label="Удалить" disabled={actionsDisabled} onClick={() => void runAction('remove')} tone="red"/></div>{busyAction && <p role="status" className="mt-3 text-xs text-orange-200/70">{pending ? `Ожидаю подтверждение: ${actionText[busyAction].toLowerCase()}…` : 'Отправляю команду агенту…'}</p>}{error && <p role="alert" className="mt-3 text-xs text-red-300">{error}</p>}{message && !error && <p role="status" className="mt-3 text-xs text-emerald-200/75">{message}</p>}{readOnly && <p className="mt-3 text-xs text-white/35">У вас доступ только для просмотра.</p>}</section>
          </div>
        </> : <div className="flex min-h-64 flex-col items-center justify-center p-8 text-center"><div className="text-sm text-white/50">Выберите ловушку в таблице</div><p className="mt-2 text-xs text-white/30">Здесь появятся конфигурация, лимиты и команды управления.</p></div>}
      </aside>
    </div>
  </section>
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><p className="text-[10px] uppercase tracking-wider text-white/30">{label}</p><p className="mt-1 truncate text-xs text-white/75" title={value}>{value}</p></div>
}

function EventPayload({ payload }: { payload: unknown }) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null
  const summary = Object.entries(payload as Record<string, unknown>)
    .filter(([, value]) => typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join(' · ')
  return summary ? <p className="mt-1 break-words font-mono text-[10px] text-orange-100/50">{summary}</p> : null
}

function ActionButton({ label, disabled, onClick, tone = 'neutral' }: { label: string; disabled: boolean; onClick: () => void; tone?: 'green' | 'red' | 'neutral' }) {
  const tones = { green: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200 hover:bg-emerald-400/15', red: 'border-red-400/20 bg-red-400/[0.05] text-red-300 hover:bg-red-400/10', neutral: 'border-white/10 bg-white/[0.03] text-white/70 hover:bg-white/[0.07]' }
  return <button type="button" disabled={disabled} onClick={onClick} className={`rounded-lg border px-3 py-2.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}>{label}</button>
}
