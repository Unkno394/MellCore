import { useEffect, useMemo, useState } from 'react'
import { ApiError, apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Profile, Server, Trap, ServerActionProgress, ServerPresence } from '../api/types'
import type { ToastNotify } from '../components/ToastNotifications'
import ConnectServer from './ConnectServer'
import CreateHoneypot from './CreateHoneypot'
import Honeypots from './Honeypots'

type Props = {
  api: MellCoreApi
  profiles: Profile[]
  servers: Server[]
  traps: Trap[]
  permissions: string[]
  onChanged: () => Promise<void>
  onShowAttacks: (trapId: string) => void
  notify: ToastNotify
  dismissToast: (id: number) => void
}

type Tab = 'servers' | 'traps'
type Subview = 'list' | 'add-server' | 'add-trap'
type PendingAction = { serverId: string; actionId: string } | null

export default function Infrastructure(props: Props) {
  const can = (permission: string) => props.permissions.includes(permission)
  const [tab, setTab] = useState<Tab>('servers')
  const [subview, setSubview] = useState<Subview>('list')
  const [selectedServer, setSelectedServer] = useState('all')
  const [pending, setPending] = useState<PendingAction>(null)
  const [busy, setBusy] = useState(false)
  const [presence, setPresence] = useState<Record<string, ServerPresence | null>>({})
  const trapCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const trap of props.traps) {
      if (trap.actual_state === 'removed') continue
      counts.set(trap.server_id, (counts.get(trap.server_id) ?? 0) + 1)
    }
    return counts
  }, [props.traps])
  const failedServers = props.servers.filter((server) =>
    (server.status === 'error' || (server.status === 'unknown' && Date.now() - new Date(server.created_at).getTime() > 15 * 60_000))
    && presence[server.server_id]?.connected === false && (trapCounts.get(server.server_id) ?? 0) === 0)

  useEffect(() => {
    let cancelled = false
    let timer = 0
    async function refreshPresence() {
      const results = await Promise.all(props.servers.map(async (server) => {
        try {
          const result = await props.api.servers.presence(server.server_id)
          return [server.server_id, result] as const
        } catch {
          return [server.server_id, null] as const
        }
      }))
      if (cancelled) return
      setPresence(Object.fromEntries(results))
      timer = window.setTimeout(() => { void refreshPresence() }, 20_000)
    }
    void refreshPresence()
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [props.api, props.servers])

  useEffect(() => {
    if (!pending) return
    let cancelled = false
    let timer = 0
    async function poll() {
      try {
        const result: ServerActionProgress = await props.api.servers.actionStatus(pending!.serverId, pending!.actionId)
        if (cancelled) return
        if (result.status === 'queued') {
          timer = window.setTimeout(() => { void poll() }, 2000)
          return
        }
        setPending(null)
        if (result.status === 'succeeded') {
          props.notify('success', 'Сервер перезагружается', 'Команда выполнена. Агент подключится к Центру после загрузки сервера.')
          await props.onChanged()
        } else {
          props.notify('error', 'Не удалось перезагрузить сервер', result.detail || 'Агент не выполнил команду перезагрузки.')
        }
      } catch (error) {
        if (cancelled) return
        if (error instanceof ApiError && error.status === 404) {
          setPending(null)
          props.notify('error', 'Задание перезагрузки не найдено', 'Центр потерял задание. Обновите состояние сервера и попробуйте снова.')
          return
        }
        timer = window.setTimeout(() => { void poll() }, 3000)
      }
    }
    void poll()
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [pending, props.api, props.onChanged])

  async function reboot(server: Server) {
    if (!window.confirm(`Перезагрузить сервер «${server.name}» (${server.host})?`)) return
    setBusy(true)
    props.notify('info', 'Перезагрузка сервера', `Отправляю команду агенту «${server.name}».`)
    try {
      const action = await props.api.servers.action(server.server_id, 'reboot')
      setPending({ serverId: server.server_id, actionId: action.action_id })
    } catch (error) {
      props.notify('error', 'Не удалось отправить команду', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  function showAgentUpdateInstructions(server: Server) {
    const sshTarget = `${server.ssh_user}@${server.host}`
    const port = server.ssh_port
    props.notify(
      'info',
      'Обновите hf-agent по SSH',
      `Панель пока не обновляет бинарник автоматически. На машине со свежей сборкой выполните: scp -P ${port} target/release/hf-agent ${sshTarget}:/tmp/hf-agent && ssh -p ${port} ${sshTarget} 'sudo install -m 0755 /tmp/hf-agent /usr/local/bin/hf-agent && sudo systemctl restart hf-agent'.`,
    )
  }

  async function remove(server: Server) {
    const count = trapCounts.get(server.server_id) ?? 0
    if (count > 0) {
      props.notify('error', 'Сначала удалите ловушки', 'Сначала удалите ловушки этого сервера во вкладке «Ловушки».')
      setTab('traps')
      setSelectedServer(server.server_id)
      return
    }
    const serverPresence = presence[server.server_id]
    const canUninstall = serverPresence?.can_uninstall === true
    const heartbeatAge = serverPresence?.last_heartbeat_age_ms
    const uninstallLikely = canUninstall && heartbeatAge != null && heartbeatAge < 20_000
    const warning = uninstallLikely
      ? 'Агент на связи получит команду самоудаления.'
      : 'Доступ агента будет отозван; локальные файлы на сервере могут остаться.'
    if (!window.confirm(`Удалить «${server.name}» из MellCore? ${warning}`)) return
    setBusy(true)
    props.notify('info', 'Удаление сервера', 'Отправляю команду самоудаления агенту и отзываю его доступ…')
    try {
      const result = await props.api.servers.delete(server.server_id)
      if (result.remote_cleanup === 'scheduled') {
        props.notify('success', 'Сервер удалён', 'Агент принял команду самоудаления. Доступ отозван, локальная очистка запланирована примерно через 45 секунд.')
      } else if (result.remote_cleanup === 'unreachable') {
        props.notify('info', 'Запись удалена, агент недоступен', 'Доступ отозван. Агент не был на связи: его файлы на сервере нужно удалить вручную.')
      } else if (result.remote_cleanup === 'unsupported') {
        props.notify('info', 'Запись удалена', 'Доступ отозван. На сервере старая версия агента: его файлы нужно удалить вручную.')
      } else if (result.remote_cleanup === 'unconfirmed') {
        props.notify('info', 'Запись удалена, очистка не подтверждена', 'Доступ агента отозван и запись удалена. Агент не подтвердил самоудаление; при необходимости удалите локальные файлы агента вручную.')
      } else {
        props.notify('success', 'Сервер удалён', 'Запись удалена. Зарегистрированного агента у этого сервера не было.')
      }
      await props.onChanged()
    } catch (error) {
      props.notify('error', 'Не удалось удалить сервер', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  async function removeFailed() {
    if (failedServers.length === 0 || !window.confirm(`Удалить ${failedServers.length} записей о неудачном подключении без ловушек? Доступы агентов в Центре будут отозваны.`)) return
    setBusy(true)
    props.notify('info', 'Удаление записей', `Удаляю неудачные подключения: ${failedServers.length}.`)
    let removed = 0
    let cleanupWarnings = 0
    let failure: string | null = null
    for (const server of failedServers) {
      try {
        const result = await props.api.servers.delete(server.server_id)
        if (['unreachable', 'unsupported', 'unconfirmed'].includes(result.remote_cleanup)) cleanupWarnings += 1
        removed += 1
      } catch (error) {
        failure = `Удалено ${removed} из ${failedServers.length}. «${server.name}»: ${apiErrorMessage(error)}`
        break
      }
    }
    if (failure) {
      props.notify('error', 'Не все записи удалены', failure)
    } else if (cleanupWarnings > 0) {
      props.notify('info', 'Записи удалены, очистка не подтверждена', `Удалено записей: ${removed}. Для ${cleanupWarnings} агентов проверьте локальные файлы и при необходимости удалите их вручную.`)
    } else {
      props.notify('success', 'Записи удалены', `Удалено записей: ${removed} из ${failedServers.length}.`)
    }
    try {
      await props.onChanged()
    } finally {
      setBusy(false)
    }
  }

  return <section className="space-y-5 p-4 sm:p-6">
    <header>
      <p className="text-xs uppercase tracking-[0.18em] text-orange-300/65">Управление ресурсами</p>
      <h2 className="mt-2 text-2xl font-semibold">Инфраструктура</h2>
      <p className="mt-1 text-sm text-white/40">Серверы, установленные агенты и размещённые на них ловушки.</p>
    </header>

    <div className="flex w-fit rounded-lg border border-white/10 bg-black/20 p-1" role="tablist" aria-label="Раздел инфраструктуры">
      {(['servers', 'traps'] as const).map((value) => <button key={value} type="button" role="tab" aria-selected={tab === value} onClick={() => { setTab(value); setSubview('list') }} className={`rounded-md px-5 py-2 text-sm transition ${tab === value ? 'bg-orange-500/15 text-orange-100' : 'text-white/50 hover:text-white/80'}`}>
        {value === 'servers' ? `Серверы · ${props.servers.length}` : `Ловушки · ${props.traps.length}`}
      </button>)}
    </div>

    {subview !== 'list' && <button type="button" onClick={() => setSubview('list')} className="text-sm text-white/50 hover:text-orange-100">← К инфраструктуре</button>}

    {subview === 'list' && <div className="flex flex-wrap items-center gap-2">
      <button type="button" onClick={() => setSubview('add-server')} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-4 py-2 text-sm text-orange-100"><span className="mr-2 inline-block whitespace-nowrap font-mono">＋</span>Добавить сервер</button>
      <button type="button" onClick={() => setSubview('add-trap')} className="rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2 text-sm text-white/75 hover:border-orange-500/30"><span className="mr-2 inline-block whitespace-nowrap font-mono">＋</span>Добавить ловушку</button>
      {tab === 'servers' && failedServers.length > 0 && <button type="button" disabled={!can('servers.disconnect') || busy || Boolean(pending)} onClick={() => void removeFailed()} className="rounded-lg border border-red-400/20 px-4 py-2 text-sm text-red-200/80 hover:bg-red-400/5 disabled:opacity-40">Удалить неподключённые · {failedServers.length}</button>}
    </div>}

    {subview === 'add-server' && <ConnectServer api={props.api} readOnly={false} onChanged={props.onChanged} notify={props.notify}/>}
    {subview === 'add-trap' && <CreateHoneypot api={props.api} profiles={props.profiles} servers={props.servers.filter((server) => presence[server.server_id]?.connected === true)} traps={props.traps} readOnly={false} onCreated={props.onChanged} notify={props.notify} dismissToast={props.dismissToast}/>}
    {subview === 'list' && tab === 'traps' && <Honeypots api={props.api} traps={props.traps} servers={props.servers} permissions={props.permissions} onChanged={props.onChanged} onShowAttacks={props.onShowAttacks} initialServerFilter={selectedServer}/>}
    {subview === 'list' && tab === 'servers' && <section className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/75">
      {props.servers.length === 0 ? <div className="p-8 text-center text-sm text-white/45">Подключённых серверов пока нет. Добавьте сервер, чтобы установить агент.</div> : <div className="divide-y divide-white/5">
        {props.servers.map((server) => {
          const count = trapCounts.get(server.server_id) ?? 0
          const inProgress = pending?.serverId === server.server_id
          const connected = presence[server.server_id]?.connected
          const canReboot = presence[server.server_id]?.can_reboot === true
          return <article key={server.server_id} className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:p-5">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2"><h3 className="truncate font-medium text-white/90">{server.name}</h3><span className={`rounded-full border px-2 py-0.5 text-[11px] ${connected === true ? 'border-emerald-400/20 bg-emerald-400/5 text-emerald-200' : 'border-white/10 bg-white/5 text-white/55'}`}>{connected === true ? 'Агент на связи' : connected === false ? (server.status === 'error' ? 'Подключение не удалось' : 'Агент не на связи') : 'Проверяю связь…'}</span>{connected && !canReboot && <span className="text-[11px] text-amber-200/70">Нужно обновить агент</span>}</div>
              <p className="mt-1 font-mono text-xs text-white/45">{server.host}:{server.ssh_port} · {server.ssh_user}</p>
              <button type="button" onClick={() => { setSelectedServer(server.server_id); setTab('traps') }} className="mt-2 text-xs text-orange-200/75 hover:text-orange-100">Ловушки на сервере: {count} →</button>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              {connected && !canReboot && <button type="button" disabled={!can('servers.manage') || busy || Boolean(pending)} onClick={() => showAgentUpdateInstructions(server)} className="rounded-lg border border-amber-400/20 px-3 py-2 text-xs text-amber-100/80 hover:bg-amber-400/5 disabled:opacity-40">Как обновить агента</button>}
              <button type="button" title={connected && !canReboot ? 'Обновите hf-agent на этом сервере для перезагрузки из панели' : undefined} disabled={!can('servers.manage') || busy || Boolean(pending) || !canReboot} onClick={() => void reboot(server)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-white/70 hover:border-orange-400/30 hover:text-orange-100 disabled:opacity-40">{inProgress ? 'Перезагрузка…' : 'Перезагрузить'}</button>
              <button type="button" disabled={!can('servers.disconnect') || busy || Boolean(pending)} onClick={() => void remove(server)} className="rounded-lg border border-red-400/20 px-3 py-2 text-xs text-red-200/80 hover:bg-red-400/5 disabled:opacity-40">{server.status === 'error' || server.status === 'unknown' ? 'Удалить запись' : 'Удалить сервер'}</button>
            </div>
          </article>
        })}
      </div>}
    </section>}
  </section>
}
