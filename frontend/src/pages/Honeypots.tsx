import { useEffect, useMemo, useState } from 'react'
import { profileNameLabel, statusLabel } from '../i18n/labels'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Server, Trap, TrapAction } from '../api/types'

type Props = {
  api: MellCoreApi
  traps: Trap[]
  servers: Server[]
  readOnly: boolean
  onChanged: () => Promise<void>
  onShowAttacks: (trapId: string) => void
  initialServerFilter?: string
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

export default function Honeypots({ api, traps, servers, readOnly, onChanged, onShowAttacks, initialServerFilter = 'all' }: Props) {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [serverFilter, setServerFilter] = useState(initialServerFilter)
  const [stateFilter, setStateFilter] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(traps[0]?.trap_id ?? null)
  const [busyAction, setBusyAction] = useState<TrapAction | null>(null)
  const [deletingRegistration, setDeletingRegistration] = useState(false)
  const [pending, setPending] = useState<{ trapId: string; actionId: string; action: TrapAction } | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const serverNames = useMemo(() => new Map(servers.map((server) => [server.server_id, server])), [servers])
  const types = useMemo(() => [...new Set(traps.map((trap) => trap.profile_snapshot.level))].sort(), [traps])
  const filtered = useMemo(() => traps.filter((trap) => {
    const server = serverNames.get(trap.server_id)
    const query = `${trap.name} ${statusLabel(trap.profile_snapshot.level)} ${trap.profile_snapshot.service_type} ${server?.name ?? ''} ${server?.host ?? ''}`.toLowerCase()
    return query.includes(search.toLowerCase())
      && (typeFilter === 'all' || trap.profile_snapshot.level === typeFilter)
      && (serverFilter === 'all' || trap.server_id === serverFilter)
      && (stateFilter === 'all' || trap.actual_state === stateFilter)
  }), [traps, search, typeFilter, serverFilter, stateFilter, serverNames])
  const selected = filtered.find((trap) => trap.trap_id === selectedId) ?? filtered[0] ?? null
  const actionsDisabled = Boolean(busyAction) || deletingRegistration || readOnly || selected?.actual_state === 'installing'

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
          setMessage(action === 'remove' ? 'Агент подтвердил удаление ловушки.' : `Команда «${actionText[action].toLowerCase()}» выполнена.`)
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
      setMessage(`Команда «${actionText[action].toLowerCase()}» поставлена в очередь Центра. Жду подтверждение агента.`)
    } catch (requestError) {
      setBusyAction(null)
      setError(apiErrorMessage(requestError))
    }
  }

  async function deleteUnusedRegistration() {
    if (!selected || !['unknown', 'removed'].includes(selected.actual_state) || readOnly || deletingRegistration) return
    const warning = selected.actual_state === 'unknown'
      ? `Удалить запись «${selected.name}»? Делайте это только если ловушка не запущена на сервере.`
      : `Убрать запись удалённой ловушки «${selected.name}» из панели?`
    if (!window.confirm(warning)) return
    setError('')
    setMessage('')
    setDeletingRegistration(true)
    try {
      await api.traps.delete(selected.trap_id)
      setSelectedId(null)
      setMessage('Запись ловушки убрана из панели.')
      await onChanged()
    } catch (requestError) {
      setError(apiErrorMessage(requestError))
    } finally {
      setDeletingRegistration(false)
    }
  }

  return <section className="space-y-5 p-4 sm:p-6">
    <header><p className="text-xs uppercase tracking-[0.18em] text-orange-300/65">Управление инфраструктурой</p><h2 className="mt-2 text-2xl font-semibold">Ловушки</h2><p className="mt-1 text-sm text-white/40">Фильтруйте экземпляры и управляйте их состоянием на подключённых серверах.</p></header>

    <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 shadow-lg shadow-black/10">
      <div className="grid gap-3 md:grid-cols-[minmax(220px,1.5fr)_repeat(3,minmax(140px,1fr))]">
        <label className="relative"><span className="sr-only">Поиск ловушек</span><svg aria-hidden="true" viewBox="0 0 24 24" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Название, сервер или IP" className="w-full rounded-lg border border-white/10 bg-black/20 py-2.5 pl-9 pr-3 text-sm outline-none focus:border-orange-400/40"/></label>
        <select aria-label="Фильтр по уровню" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white/70"><option value="all">Все уровни</option>{types.map((type) => <option key={type} value={type}>{statusLabel(type)}</option>)}</select>
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
          return <tr key={trap.trap_id} onClick={() => { setSelectedId(trap.trap_id); setError(''); setMessage('') }} className={`cursor-pointer border-b border-white/5 transition ${active ? 'bg-orange-400/[0.06]' : 'hover:bg-white/[0.025]'}`}><td className="px-4 py-3.5"><span className="block font-medium text-white/90">{trap.name}</span><span className="mt-1 block font-mono text-[10px] text-white/30">{trap.trap_id.slice(0, 8)}</span></td><td className="px-4 py-3.5"><span className="block text-white/75">{profileNameLabel(trap.profile_snapshot.name, trap.profile_snapshot.level)}</span><span className="mt-1 block text-xs text-white/35">{statusLabel(trap.profile_snapshot.level)} · {trap.profile_snapshot.service_type.toUpperCase()}</span></td><td className="max-w-40 truncate px-4 py-3.5 text-white/65" title={serverTitle(server)}>{server?.name ?? '—'}</td><td className="px-4 py-3.5 font-mono text-xs text-white/55">{server?.host ?? '—'}{trap.ports.map((port) => <span key={`${port.transport}-${port.host_port}`} className="ml-1 text-orange-200/75">:{port.host_port}/{port.transport}</span>)}</td><td className="px-4 py-3.5"><span className={`rounded-full border px-2.5 py-1 text-[11px] ${stateTone[trap.actual_state]}`}>{statusLabel(trap.actual_state)}</span></td></tr>
        })}</tbody></table></div>
        {filtered.length === 0 && <div className="px-6 py-14 text-center"><p className="text-sm text-white/55">Подходящих ловушек нет</p><p className="mt-1 text-xs text-white/30">Измените фильтры или создайте ловушку.</p></div>}
      </section>

      <aside className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/75 shadow-lg shadow-black/10">
        {selected ? <>
          <div className="border-b border-white/5 p-5"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-[11px] uppercase tracking-[0.18em] text-orange-200/65">Выбранная ловушка</p><h3 className="mt-2 truncate text-xl font-semibold">{selected.name}</h3><p className="mt-1 truncate text-xs text-white/35">{serverTitle(serverNames.get(selected.server_id))}</p></div><span className={`shrink-0 rounded-full border px-2.5 py-1 text-[11px] ${stateTone[selected.actual_state]}`}>{statusLabel(selected.actual_state)}</span></div></div>
          <div className="space-y-5 p-5">
            <section><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Конфигурация</h4><div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3"><Info label="Уровень" value={statusLabel(selected.profile_snapshot.level)}/><Info label="Служба" value={selected.profile_snapshot.service_type.toUpperCase()}/><Info label="Профиль" value={profileNameLabel(selected.profile_snapshot.name, selected.profile_snapshot.level)}/><Info label="Версия профиля" value={String(selected.profile_version)}/><Info label="Публичные порты" value={selected.ports.map((port) => `${port.host_port}/${port.transport}`).join(', ') || 'Не заданы'}/><Info label="Создана" value={new Date(selected.created_at).toLocaleDateString('ru-RU')}/></div>{selected.ports.some((port) => port.route_mode === 'dispatcher_backend') && <p className="mt-3 text-xs leading-5 text-white/45">Публичный порт слушает Dispatcher. Docker показывает внутренние адреса 127.0.0.1:{selected.ports.filter((port) => port.route_mode === 'dispatcher_backend').map((port) => port.target_port).join(', 127.0.0.1:')}.</p>}<p className="mt-3 text-xs leading-5 text-white/40">{selected.profile_snapshot.description || 'У профиля нет описания.'}</p></section>
            <section className="border-t border-white/5 pt-4"><h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Лимиты контейнера · применённая конфигурация</h4><div className="mt-3 grid grid-cols-3 gap-2">{Object.entries({ cpu: `${selected.resources.cpu_cores} CPU`, memory: `${selected.resources.memory_mb} МБ RAM`, pids: `${selected.resources.pids} процессов` }).map(([key, value]) => <div key={key} className="rounded-lg border border-white/5 bg-black/10 p-2.5"><p className="text-[10px] text-white/35">{resourceLabels[key]}</p><p className="mt-1 text-xs font-medium text-white/75">{value}</p></div>)}</div><p className="mt-2 text-[10px] text-white/30">Это заданные Docker-лимиты, а не текущее потребление. GPU не настраивается.</p></section>
            <details className="border-t border-white/5 pt-4"><summary className="cursor-pointer text-xs font-semibold uppercase tracking-wider text-white/40 hover:text-white/65">Параметры конфигурации</summary><pre className="mt-3 max-h-48 overflow-auto rounded-lg border border-white/5 bg-black/20 p-3 text-[10px] leading-5 text-white/55">{JSON.stringify(selected.effective_config, null, 2)}</pre></details>
            <section className="border-t border-white/5 pt-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-white/40">Управление</h4>
                <button type="button" onClick={() => onShowAttacks(selected.trap_id)} className="text-xs text-orange-200/75 transition hover:text-orange-100">События этой ловушки →</button>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2">
                {selected.actual_state === 'removed' ? (
                  <ActionButton label={deletingRegistration ? 'Убираю запись…' : 'Убрать запись'} disabled={actionsDisabled} onClick={() => void deleteUnusedRegistration()} tone="red"/>
                ) : <>
                  {selected.actual_state !== 'running' && <ActionButton label="Запустить" disabled={actionsDisabled} onClick={() => void runAction('start')} tone="green"/>}
                  {selected.actual_state === 'running' && <ActionButton label="Остановить" disabled={actionsDisabled} onClick={() => void runAction('stop')}/>}
                  {selected.actual_state === 'running' && <ActionButton label="Перезапустить" disabled={actionsDisabled} onClick={() => void runAction('restart')}/>}
                  {selected.actual_state === 'unknown'
                    ? <ActionButton label={deletingRegistration ? 'Убираю запись…' : 'Убрать запись'} disabled={actionsDisabled} onClick={() => void deleteUnusedRegistration()} tone="red"/>
                    : <ActionButton label="Удалить" disabled={actionsDisabled} onClick={() => void runAction('remove')} tone="red"/>}
                </>}
              </div>
              {busyAction && <p role="status" className="mt-3 text-xs text-orange-200/70">{pending ? `Ожидаю подтверждение: ${actionText[busyAction].toLowerCase()}…` : 'Отправляю команду агенту…'}</p>}
              {error && <p role="alert" className="mt-3 text-xs text-red-300">{error}</p>}
              {message && !error && <p role="status" className="mt-3 text-xs text-emerald-200/75">{message}</p>}
              {readOnly && <p className="mt-3 text-xs text-white/35">У вас доступ только для просмотра.</p>}
            </section>
          </div>
        </> : <div className="flex min-h-64 flex-col items-center justify-center p-8 text-center"><div className="text-sm text-white/50">Выберите ловушку в таблице</div><p className="mt-2 text-xs text-white/30">Здесь появятся конфигурация, лимиты и команды управления.</p></div>}
      </aside>
    </div>
    {selected && <SharedPortControl api={api} traps={traps} selected={selected} readOnly={readOnly} onChanged={onChanged}/>}
  </section>
}

function isDispatcherShareable(trap: Trap) {
  const { level, honeypot_type: type, service_type: service } = trap.profile_snapshot
  const isSupportedKind = service === 'ssh'
    && ((type === 'kozyavka' && level === 'low') || (type === 'pritvoryashka' && level === 'medium'))
  return isSupportedKind
    && trap.ports.some((port) => port.transport === 'tcp' && (port.target_port === 2222 || port.route_mode === 'dispatcher_backend'))
}

function SharedPortControl({ api, traps, selected, readOnly, onChanged }: {
  api: MellCoreApi
  traps: Trap[]
  selected: Trap
  readOnly: boolean
  onChanged: () => Promise<void>
}) {
  const [listenerPort, setListenerPort] = useState('')
  const [selectedWeight, setSelectedWeight] = useState(50)
  const [busy, setBusy] = useState(false)
  const [canShare, setCanShare] = useState<boolean | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const possiblePorts = useMemo(() => [...new Set(traps
    .filter((trap) => trap.server_id === selected.server_id && trap.actual_state === 'running' && isDispatcherShareable(trap))
    .flatMap((trap) => trap.ports.filter((port) => port.transport === 'tcp' && (port.target_port === 2222 || port.route_mode === 'dispatcher_backend')).map((port) => port.host_port)))].sort((a, b) => a - b), [traps, selected.server_id])
  const chosenPort = listenerPort === '' ? null : Number(listenerPort)
  const currentMembers = chosenPort === null ? [] : traps.filter((trap) => trap.trap_id !== selected.trap_id
    && trap.server_id === selected.server_id && trap.actual_state === 'running' && isDispatcherShareable(trap)
    && trap.ports.some((port) => port.transport === 'tcp' && port.host_port === chosenPort))
  const maxWeight = Math.max(0, 100 - currentMembers.length)

  useEffect(() => {
    let active = true
    setCanShare(null)
    setListenerPort('')
    setSelectedWeight(50)
    setError('')
    setMessage('')
    void api.servers.presence(selected.server_id).then((presence) => {
      if (active) setCanShare(presence.connected && presence.can_share_tcp_ports)
    }).catch(() => { if (active) setCanShare(false) })
    return () => { active = false }
  }, [api, selected.server_id, selected.trap_id])

  async function joinPort() {
    if (chosenPort === null || !currentMembers.length || busy || readOnly) return
    if (selectedWeight < 1 || selectedWeight > maxWeight || !Number.isInteger(selectedWeight)) {
      setError('Укажите долю от 1 до 100%, оставив не менее 1% каждому участнику.')
      return
    }
    setBusy(true)
    setError('')
    setMessage('Перенастраиваю контейнеры на внутренние порты и запускаю Dispatcher…')
    try {
      const others = currentMembers.map((trap) => ({
        trap_id: trap.trap_id,
        weight: trap.ports.find((port) => port.host_port === chosenPort)?.weight ?? 1,
      }))
      const remainingWeight = 100 - selectedWeight
      const total = others.reduce((sum, member) => sum + Math.max(1, member.weight), 0)
      const weights = others.map((member) => Math.max(1, Math.floor(remainingWeight * Math.max(1, member.weight) / total)))
      let remainder = remainingWeight - weights.reduce((sum, weight) => sum + weight, 0)
      for (let index = 0; remainder > 0; index = (index + 1) % weights.length) { weights[index] += 1; remainder -= 1 }
      for (let index = weights.length - 1; remainder < 0; index = (index - 1 + weights.length) % weights.length) {
        if (weights[index] > 1) { weights[index] -= 1; remainder += 1 }
      }
      const queued = await api.traps.sharePort(selected.trap_id, chosenPort, [
        ...others.map((member, index) => ({ trap_id: member.trap_id, weight: weights[index] })),
        { trap_id: selected.trap_id, weight: selectedWeight },
      ])
      let progress = queued
      const deadline = Date.now() + 120_000
      while (progress.status === 'queued' && Date.now() < deadline) {
        await new Promise<void>((resolve) => window.setTimeout(resolve, 2000))
        progress = await api.traps.actionStatus(selected.trap_id, queued.action_id)
      }
      if (progress.status === 'failed') throw new Error(progress.detail || 'Агент отклонил настройку общего порта.')
      if (progress.status === 'queued') throw new Error('Агент пока не подтвердил настройку. Проверьте журнал hf-agent на сервере.')
      setMessage(`SSH-ловушки теперь распределяются через общий порт ${chosenPort}.`)
      await onChanged()
    } catch (cause) {
      setError(apiErrorMessage(cause))
      setMessage('')
    } finally { setBusy(false) }
  }

  if (!isDispatcherShareable(selected) || selected.actual_state !== 'running') return null
  return <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-5 shadow-lg shadow-black/10">
    <h3 className="font-semibold">Общий SSH-порт</h3>
    <p className="mt-1 max-w-3xl text-xs leading-5 text-white/45">Можно объединить эту запущенную ловушку с Low/Middle SSH на том же сервере. После применения контейнеры будут доступны только через loopback, а публичный порт будет слушать Dispatcher.</p>
    {canShare === false && <p role="alert" className="mt-3 text-xs text-amber-200/80">Агент не подтвердил поддержку Dispatcher или сейчас не подключён. Обновите hf-agent и hf-dispatcher на сервере ловушек.</p>}
    {canShare === null && <p className="mt-3 text-xs text-white/45">Проверяю поддержку Dispatcher на агенте…</p>}
    {canShare && <div className="mt-4 grid gap-3 sm:grid-cols-[minmax(180px,1fr)_minmax(150px,0.6fr)_auto] sm:items-end">
      <label className="text-xs text-white/60">Порт запущенной SSH-ловушки<select value={listenerPort} onChange={(event) => setListenerPort(event.target.value)} disabled={busy || readOnly} className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white"><option value="">Выберите порт</option>{possiblePorts.map((port) => <option key={port} value={port}>{port}</option>)}</select></label>
      <label className="text-xs text-white/60">Доля этой ловушки, %<input type="number" min="1" max={maxWeight || 100} step="1" value={selectedWeight} onChange={(event) => setSelectedWeight(Number(event.target.value))} disabled={busy || readOnly} className="mt-1.5 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2.5 text-sm text-white"/></label>
      <button type="button" onClick={() => void joinPort()} disabled={busy || readOnly || !chosenPort || !currentMembers.length || selectedWeight < 1 || selectedWeight > maxWeight} className="rounded-lg border border-orange-400/25 bg-orange-400/10 px-4 py-2.5 text-sm font-medium text-orange-100 disabled:opacity-40">{busy ? 'Применяю…' : 'Объединить ловушки'}</button>
    </div>}
    {chosenPort !== null && <p className="mt-3 text-xs text-white/40">Участников на порту {chosenPort}: {currentMembers.length}. Их веса будут пересчитаны так, чтобы сумма оставалась 100%.</p>}
    {error && <p role="alert" className="mt-3 text-xs text-red-300">{error}</p>}
    {message && !error && <p role="status" className="mt-3 text-xs text-emerald-200/75">{message}</p>}
  </section>
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><p className="text-[10px] uppercase tracking-wider text-white/30">{label}</p><p className="mt-1 truncate text-xs text-white/75" title={value}>{value}</p></div>
}

function ActionButton({ label, disabled, onClick, tone = 'neutral' }: { label: string; disabled: boolean; onClick: () => void; tone?: 'green' | 'red' | 'neutral' }) {
  const tones = { green: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200 hover:bg-emerald-400/15', red: 'border-red-400/20 bg-red-400/[0.05] text-red-300 hover:bg-red-400/10', neutral: 'border-white/10 bg-white/[0.03] text-white/70 hover:bg-white/[0.07]' }
  return <button type="button" disabled={disabled} onClick={onClick} className={`rounded-lg border px-3 py-2.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}>{label}</button>
}
