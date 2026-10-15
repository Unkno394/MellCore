import { useEffect, useMemo, useState } from 'react'
import { ApiError, apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { BaitEngagement, BaitFile, BaitFileConfig, BaitKind, Trap, TrapActionProgress, TrapInput, VirtualProcess } from '../api/types'
import { dateTime, statusLabel } from '../i18n/labels'
import BaitEditor, { baitCategories, draftFromFile, draftFromProcess, newBaitDraft, type BaitDraft } from './BaitEditor'

type Props = {
  api: MellCoreApi
  traps: Trap[]
  readOnly: boolean
  onChanged: () => Promise<void>
  onShowEvents: (trapId: string) => void
}

const labels = new Map(baitCategories.map((category) => [category.id, category.label]))
const linuxRoots = ['/home/admin/', '/root/', '/tmp/', '/opt/', '/srv/', '/var/backups/', '/var/log/', '/etc/']
const windowsRoots = ['/C/Users/', '/C/Windows/', '/C/Program Files/', '/C/ProgramData/']

function normalizedCategory(value: unknown): BaitKind {
  return typeof value === 'string' && labels.has(value as BaitKind) ? value as BaitKind : 'file'
}

function trapBaits(trap: Trap | undefined): BaitFile[] {
  const value = trap?.effective_config.baits
  if (!Array.isArray(value)) return []
  return value.filter((item): item is BaitFile =>
    !!item && typeof item === 'object' && typeof item.id === 'string'
    && typeof item.name === 'string' && (typeof item.path === 'string' || item.path === null || item.path === undefined)
    && typeof item.content === 'string')
    .map((item) => ({
      ...item,
      path: item.path ?? null,
      category: normalizedCategory(item.category ?? item.kind) as Exclude<BaitKind, 'process'>,
      implementation: item.implementation ?? (item.category === 'account' || item.kind === 'account' ? 'virtual_account' : 'virtual_file'),
      config: item.config ?? {},
    }))
}

function trapProcesses(trap: Trap | undefined): VirtualProcess[] {
  const value = trap?.effective_config.virtual_processes
  if (!Array.isArray(value)) return []
  return value.filter((item): item is VirtualProcess =>
    !!item && typeof item === 'object' && typeof item.id === 'string'
    && typeof item.name === 'string' && typeof item.user === 'string'
    && typeof item.command === 'string' && typeof item.running === 'boolean')
    .map((item) => ({
      ...item,
      title: item.title || item.name,
      category: normalizedCategory(item.category ?? item.kind) as Extract<BaitKind, 'process' | 'database' | 'network_service' | 'web_interface'>,
      implementation: 'virtual_process',
      config: item.config ?? { protocol: 'tcp' },
    }))
}

async function awaitAction(api: MellCoreApi, trapId: string, action: TrapActionProgress): Promise<TrapActionProgress> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const progress = await api.traps.actionStatus(trapId, action.action_id)
    if (progress.status !== 'queued') return progress
    await new Promise((resolve) => window.setTimeout(resolve, 2000))
  }
  return action
}

function validGuestPath(path: string, roots: string[]) {
  return path.length <= 256 && roots.some((root) => path.startsWith(root))
    && !path.endsWith('/') && !path.includes('//')
    && !path.split('/').some((part) => part === '.' || part === '..')
    && !/[\u0000-\u001f\u007f]/.test(path)
}

function fileConfig(draft: BaitDraft): BaitFileConfig {
  switch (draft.category) {
    case 'credential': return { credential_format: draft.credentialFormat }
    case 'cloud_infrastructure': return { cloud_provider: draft.cloudProvider }
    case 'windows': return { windows_artifact: draft.windowsArtifact }
    case 'database': return { database_format: draft.databaseFormat }
    case 'backup': return { backup_format: draft.backupFormat }
    case 'canary': return { canary_marker: draft.canaryMarker }
    case 'system_config': return { system_config_format: draft.systemConfigFormat }
    case 'history': return { history_format: draft.historyFormat }
    default: return {}
  }
}

export default function Baits({ api, traps, readOnly, onChanged, onShowEvents }: Props) {
  const middle = useMemo(() => traps.filter((trap) => trap.profile_snapshot.honeypot_type === 'pritvoryashka'), [traps])
  const [os, setOs] = useState<'linux' | 'windows'>('linux')
  const osTraps = useMemo(
    () => middle.filter((trap) => (trap.effective_config.distribution === 'windows' ? 'windows' : 'linux') === os),
    [middle, os],
  )
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeGroup, setActiveGroup] = useState<'all' | 'access' | 'data' | 'infrastructure' | 'activity'>('all')
  const [editor, setEditor] = useState<BaitDraft | null>(null)
  const [engagement, setEngagement] = useState<BaitEngagement[]>([])
  const [statsError, setStatsError] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!osTraps.some((trap) => trap.trap_id === selectedId)) {
      setSelectedId(osTraps[0]?.trap_id ?? null)
      setEditor(null)
    }
  }, [osTraps, selectedId])

  useEffect(() => {
    if (!selectedId) { setEngagement([]); return }
    let active = true
    const load = async () => {
      try {
        const rows = await api.traps.baitEngagement(selectedId)
        if (active) { setEngagement(rows); setStatsError('') }
      } catch (loadError) {
        if (active) setStatsError(apiErrorMessage(loadError))
      }
    }
    void load()
    const timer = window.setInterval(() => void load(), 15000)
    return () => { active = false; window.clearInterval(timer) }
  }, [api, selectedId])

  const selected = osTraps.find((trap) => trap.trap_id === selectedId)
  const windows = os === 'windows'
  const baits = trapBaits(selected)
  const processes = trapProcesses(selected)
  const counts = new Map(engagement.map((item) => [item.bait_id, item]))

  function resetEditor() { setEditor(null); setError('') }
  function chooseTrap(id: string) { setSelectedId(id); resetEditor(); setMessage('') }
  function beginNew() { setError(''); setMessage(''); const draft = newBaitDraft(); setEditor(windows ? { ...draft, path: '/C/Users/Public/Documents/internal-report.txt' } : draft) }

  async function persist(nextBaits: BaitFile[], nextProcesses: VirtualProcess[], successText: string) {
    if (!selected) return
    const config = { ...selected.config, baits: nextBaits, virtual_processes: nextProcesses }
    if (new TextEncoder().encode(JSON.stringify(config)).length > 65536) return setError('Конфигурация приманок не должна превышать 64 КиБ.')
    setBusy(true); setError(''); setMessage('')
    let saved = false
    try {
      const input: TrapInput = {
        name: selected.name,
        profile_id: selected.profile_id,
        config,
        resources: selected.resources,
        desired_state: selected.desired_state,
        ports: selected.ports,
      }
      await api.traps.update(selected, input)
      saved = true
      await onChanged()
      if (selected.desired_state === 'running') {
        setMessage('Настройки сохранены. Перезапускаю ловушку и применяю виртуальные объекты…')
        const action = await api.traps.action(selected.trap_id, 'restart')
        const result = await awaitAction(api, selected.trap_id, action)
        if (result.status === 'failed') throw new Error(result.detail || 'Агент не смог применить конфигурацию ловушки.')
        setMessage(result.status === 'succeeded' ? successText : 'Настройки сохранены; агент ещё их применяет. Проверь состояние ловушки.')
        await onChanged()
      } else {
        setMessage(`${successText} Применится при следующем запуске ловушки.`)
      }
      resetEditor()
    } catch (saveError) {
      const detail = saveError instanceof Error && !(saveError instanceof ApiError) ? saveError.message : apiErrorMessage(saveError)
      setError(`${saved ? 'Конфигурация сохранена, но применение не завершилось: ' : ''}${detail}`)
    } finally { setBusy(false) }
  }

  async function saveDraft(draft: BaitDraft) {
    if (!selected) return
    const title = draft.title.trim()
    if (!title || new TextEncoder().encode(title).length > 80) return setError('Название приманки должно содержать от 1 до 80 байт.')

    if (draft.implementation === 'virtual_account') {
      const login = draft.login.trim()
      const uid = Number(draft.uid)
      const home = draft.homeDirectory.trim()
      if (!/^[A-Za-z0-9_.-]{1,32}$/.test(login)) return setError('Логин должен содержать латинские буквы, цифры, точку, дефис или подчёркивание; максимум 32 символа.')
      if (!windows && (!Number.isInteger(uid) || uid < 1001 || uid > 65535)) return setError('UID должен быть целым числом от 1001 до 65535.')
      if (!validGuestPath(home, windows ? ['/C/Users/'] : ['/home/'])) return setError(windows ? 'Домашний каталог должен быть внутри /C/Users/.' : 'Домашний каталог должен быть внутри /home/.')
      if (baits.some((bait) => bait.config?.account?.login.toLowerCase() === login.toLowerCase() && bait.id !== draft.id)) return setError('Учётная запись с таким логином уже есть.')
      const account: BaitFile = {
        id: draft.id ?? crypto.randomUUID(),
        name: title,
        path: draft.source === 'file' ? draft.path || null : null,
        content: draft.source === 'file' ? draft.content : '',
        category: 'account',
        implementation: 'virtual_account',
        config: { account: windows ? { login, home_directory: home } : { login, uid, home_directory: home, shell: draft.shell } },
      }
      const nextBaits = [...baits.filter((item) => item.id !== account.id), account]
      await persist(nextBaits, processes.filter((item) => item.id !== account.id), draft.id ? 'Учётная запись обновлена и применена.' : 'Виртуальная учётная запись создана и применена.')
      return
    }

    if (draft.implementation === 'virtual_file') {
      const path = draft.path.trim()
      if (!validGuestPath(path, windows ? windowsRoots : linuxRoots)) return setError(windows ? 'Для Windows-файла укажи путь /C/Users/..., /C/Windows/..., /C/Program Files/... или /C/ProgramData/...' : 'Укажи нормальный абсолютный путь внутри виртуальных каталогов Linux.')
      if (new TextEncoder().encode(draft.content).length > 4096) return setError('Содержимое не должно превышать 4096 байт.')
      if (draft.category === 'canary' && (!draft.canaryMarker.trim() || !draft.content.includes(draft.canaryMarker.trim()))) return setError('Маркер Canary должен быть непустым и присутствовать в содержимом файла.')
      if (baits.some((bait) => bait.path === path && bait.id !== draft.id)) return setError('Приманка с таким путём уже добавлена.')
      if (!draft.id && baits.length >= 32) return setError('В одной ловушке допускается до 32 файловых приманок.')
      const category = draft.category as Exclude<BaitKind, 'process'>
      const bait: BaitFile = {
        id: draft.id ?? crypto.randomUUID(),
        name: title,
        path,
        content: draft.content,
        category,
        implementation: 'virtual_file',
        config: fileConfig(draft),
      }
      const nextBaits = [...baits.filter((item) => item.id !== bait.id), bait]
      if (new TextEncoder().encode(JSON.stringify(nextBaits)).length > 48 * 1024) return setError('Файловые приманки не должны занимать больше 48 КиБ конфигурации.')
      await persist(nextBaits, processes.filter((item) => item.id !== bait.id), draft.id ? 'Приманка обновлена и применена.' : 'Приманка создана и применена.')
      return
    }

    const name = draft.processName.trim()
    const user = draft.user.trim()
    const command = draft.command.trim()
    const portText = draft.listenPort.trim()
    const port = portText ? Number(portText) : null
    if (!/^[A-Za-z0-9_.@-]{1,48}$/.test(name)) return setError('Имя процесса должно содержать латинские буквы, цифры, точку, дефис, @ или подчёркивание; максимум 48 символов.')
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(user)) return setError('Укажи виртуального пользователя латинскими буквами, цифрами, дефисом или подчёркиванием.')
    if (!command || new TextEncoder().encode(command).length > 256 || /[\u0000-\u001f\u007f]/.test(command)) return setError('Команда должна содержать от 1 до 256 печатных байт.')
    if (portText && (!Number.isInteger(port) || port! < 1 || port! > 65535)) return setError('Порт должен быть от 1 до 65535 или пустым.')
    if (['network_service', 'web_interface'].includes(draft.category) && port === null) return setError('Для виртуальной службы укажи порт отображения.')
    if (processes.some((process) => process.name.toLowerCase() === name.toLowerCase() && process.id !== draft.id)) return setError('Виртуальный процесс с таким именем уже есть.')
    if (port !== null && processes.some((process) => process.listen_port === port && process.config?.protocol === draft.protocol && process.id !== draft.id)) return setError('Этот порт и протокол уже назначены другому виртуальному процессу.')
    if (!draft.id && processes.length >= 24) return setError('В одной ловушке допускается до 24 виртуальных процессов.')
    const process: VirtualProcess = {
      id: draft.id ?? crypto.randomUUID(),
      title,
      category: draft.category as Extract<BaitKind, 'process' | 'database' | 'network_service' | 'web_interface'>,
      implementation: 'virtual_process',
      name,
      user,
      command,
      running: draft.running,
      listen_port: port,
      config: { protocol: draft.protocol },
    }
    const nextProcesses = [...processes.filter((item) => item.id !== process.id), process]
    if (new TextEncoder().encode(JSON.stringify(nextProcesses)).length > 12 * 1024) return setError('Список виртуальных процессов превышает 12 КиБ.')
    await persist(baits.filter((item) => item.id !== process.id), nextProcesses, draft.id ? 'Виртуальный объект обновлён.' : 'Виртуальный объект добавлен.')
  }

  async function removeArtifact(bait: BaitFile) {
    if (!window.confirm(`Удалить «${bait.name}» из виртуальной ловушки?`)) return
    await persist(baits.filter((item) => item.id !== bait.id), processes, 'Приманка удалена из ловушки.')
  }

  async function removeProcess(process: VirtualProcess) {
    if (!window.confirm(`Удалить виртуальный процесс «${process.title || process.name}»?`)) return
    await persist(baits, processes.filter((item) => item.id !== process.id), 'Виртуальный процесс удалён.')
  }

  const filteredCategories = baitCategories.filter((category) => activeGroup === 'all' || category.group === activeGroup)
  const linuxCount = middle.filter((trap) => trap.effective_config.distribution !== 'windows').length
  const windowsCount = middle.length - linuxCount

  return <section className="space-y-6 p-5 sm:p-6">
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[0.25em] text-orange-400/70">Middle · {windows ? 'виртуальная Windows-система' : 'виртуальная Linux-система'}</p><h2 className="mt-2 text-2xl font-semibold">Приманки</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-white/45">Создавай виртуальные файлы и объекты выбранной системы. Каждая форма показывает, что Middle действительно моделирует и какое действие попадёт в события.</p></div>
    </div>
    <div className="inline-flex rounded-xl border border-white/10 bg-[#160e0c]/75 p-1" role="group" aria-label="Операционная система приманок">{([{ id: 'linux', label: 'Linux', count: linuxCount }, { id: 'windows', label: 'Windows', count: windowsCount }] as const).map((item) => <button type="button" aria-pressed={os === item.id} key={item.id} onClick={() => { setOs(item.id); setEditor(null); setError(''); setMessage('') }} className={`rounded-lg px-4 py-2 text-sm transition ${os === item.id ? 'bg-orange-500 text-[#1a0d08]' : 'text-white/55 hover:text-white'}`}>{item.label}<span className={`ml-2 text-xs ${os === item.id ? 'text-[#1a0d08]/65' : 'text-white/35'}`}>{item.count}</span></button>)}</div>
    <div className="rounded-lg border border-sky-300/15 bg-sky-300/[0.04] px-4 py-3 text-xs leading-5 text-sky-100/65">Все объекты существуют только внутри виртуальной {windows ? 'Windows' : 'Linux'}-модели Middle. Файлы и процессы не создаются на хостовой ОС; виртуальные процессы не запускаются как реальные программы.</div>

    {middle.length === 0 ? <div className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-8 text-sm text-white/45">Сначала создай Middle-ловушку в «Инфраструктуре».</div> : osTraps.length === 0 ? <div className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-8 text-sm text-white/45">Ловушек Middle с профилем {windows ? 'Windows' : 'Linux'} пока нет. Создай такую ловушку в «Инфраструктуре».</div> : <div className="grid items-start gap-5 xl:grid-cols-[0.8fr_1.5fr]">
      <aside className="space-y-3 rounded-xl border border-white/10 bg-[#160e0c]/75 p-4"><div className="flex items-center justify-between"><h3 className="font-semibold">Middle · {windows ? 'Windows' : 'Linux'}</h3><span className="text-xs text-white/35">{osTraps.length}</span></div>{osTraps.map((trap) => <button type="button" key={trap.trap_id} onClick={() => chooseTrap(trap.trap_id)} className={`w-full rounded-lg border p-4 text-left transition ${selectedId === trap.trap_id ? 'border-orange-400/40 bg-orange-500/[0.08]' : 'border-white/[0.07] bg-black/10 hover:border-white/20'}`}><span className="block font-medium">{trap.name}</span><span className="mt-1 block text-xs text-white/40">{statusLabel(trap.actual_state)} · {trapBaits(trap).length + trapProcesses(trap).length} объектов</span></button>)}</aside>
      <div className="space-y-5">
        <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 sm:p-5">
          <div className="flex flex-wrap items-end justify-between gap-3"><div><h3 className="font-semibold">Объекты в {selected?.name}</h3><p className="mt-1 text-xs text-white/40">Группировка по назначению приманки.</p></div><div className="flex gap-2"><button type="button" onClick={() => selected && onShowEvents(selected.trap_id)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-200">События ловушки →</button>{!readOnly && <button type="button" onClick={beginNew} className="rounded-lg bg-orange-500 px-3 py-2 text-xs font-semibold text-[#1a0d08]">Создать приманку</button>}</div></div>
          {statsError && <p className="mt-3 text-xs text-amber-200">Статистика взаимодействий недоступна: {statsError}</p>}
          <div className="mt-4 flex flex-wrap gap-2">{[{ id: 'all', title: 'Все категории' }, { id: 'access', title: 'Доступ и учётные данные' }, { id: 'data', title: 'Данные и проекты' }, { id: 'infrastructure', title: 'Службы и инфраструктура' }, { id: 'activity', title: 'Следы активности' }].map((item) => <button type="button" key={item.id} onClick={() => setActiveGroup(item.id as typeof activeGroup)} className={`rounded-full border px-3 py-1.5 text-xs ${activeGroup === item.id ? 'border-orange-300/35 bg-orange-300/10 text-orange-100' : 'border-white/10 text-white/45 hover:text-white/80'}`}>{item.title}</button>)}</div>
          <div className="mt-4 space-y-4">{filteredCategories.map((category) => {
            const categoryBaits = baits.filter((bait) => (bait.category ?? bait.kind ?? 'file') === category.id)
            const categoryProcesses = processes.filter((process) => (process.category ?? process.kind ?? 'process') === category.id)
            if (!categoryBaits.length && !categoryProcesses.length) return null
            return <section key={category.id} className="rounded-lg border border-white/[0.07] bg-black/10 p-3 sm:p-4"><div className="flex items-center justify-between gap-2"><h4 className="text-sm font-semibold text-white/80">{category.label}</h4><span className="text-[11px] text-white/35">{categoryBaits.length + categoryProcesses.length}</span></div>
              <div className="mt-3 space-y-2">{categoryBaits.map((bait) => { const count = counts.get(bait.id); const account = bait.config?.account; return <div key={bait.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-white/[0.06] bg-black/20 p-3"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="truncate text-sm font-medium">{bait.name}</p><span className="rounded-full border border-violet-300/15 px-2 py-0.5 text-[10px] text-violet-200/75">{bait.implementation === 'virtual_account' ? 'виртуальный пользователь' : 'виртуальный файл'}</span></div><p className="mt-1 truncate font-mono text-xs text-white/40" title={bait.path ?? undefined}>{account ? windows ? `login ${account.login} · ${account.home_directory ?? `/C/Users/${account.login}`}` : `login ${account.login} · UID ${account.uid ?? 'авто'} · ${account.home_directory ?? `/home/${account.login}`}` : bait.path}</p><p className="mt-2 text-[11px] text-white/45">Взаимодействий: <span className="text-orange-200">{count?.opens ?? 0}</span> · сеансов: {count?.sessions ?? 0}{count && ` · последнее: ${dateTime(count.last_opened_at)}`}</p></div><button type="button" disabled={busy || readOnly} onClick={() => setEditor(draftFromFile(bait))} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-white/70 disabled:opacity-40">Изменить</button><button type="button" disabled={busy || readOnly} onClick={() => void removeArtifact(bait)} className="rounded-lg border border-red-400/20 px-3 py-2 text-xs text-red-300 disabled:opacity-40">Удалить</button></div> })}
                {categoryProcesses.map((process) => { const count = counts.get(process.id); return <div key={process.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-white/[0.06] bg-black/20 p-3"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="truncate text-sm font-medium">{process.title || process.name}</p><span className="rounded-full border border-violet-300/15 px-2 py-0.5 text-[10px] text-violet-200/75">{labels.get(process.category ?? process.kind ?? 'process')}</span><span className={`rounded-full px-2 py-0.5 text-[10px] ${process.running ? 'bg-emerald-300/10 text-emerald-200' : 'bg-white/5 text-white/45'}`}>{process.running ? 'running' : 'stopped'}</span></div><p className="mt-1 truncate font-mono text-xs text-white/45">{process.user}$ {process.command}{process.listen_port ? ` · виртуальный ${process.config?.protocol ?? 'tcp'} :${process.listen_port}` : ''}</p><p className="mt-2 text-[11px] text-white/45">Просмотров: <span className="text-orange-200">{count?.opens ?? 0}</span> · сеансов: {count?.sessions ?? 0}</p></div><button type="button" disabled={busy || readOnly} onClick={() => setEditor(draftFromProcess(process))} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-white/70 disabled:opacity-40">Изменить</button><button type="button" disabled={busy || readOnly} onClick={() => void removeProcess(process)} className="rounded-lg border border-red-400/20 px-3 py-2 text-xs text-red-300 disabled:opacity-40">Удалить</button></div> })}</div>
            </section>
          })}
          {!baits.length && !processes.length && <p className="py-8 text-center text-sm text-white/40">Пользовательских объектов пока нет. Middle сохранит стандартные процессы, службы и файлы.</p>}</div>
        </section>
        {message && <p role="status" className="rounded-lg border border-emerald-400/20 bg-emerald-500/5 p-3 text-sm text-emerald-300">{message}</p>}
        {editor && !readOnly && <BaitEditor draft={editor} windows={windows} busy={busy} error={error} onChange={setEditor} onSave={() => void saveDraft(editor)} onCancel={resetEditor} />}
      </div>
    </div>}
  </section>
}
