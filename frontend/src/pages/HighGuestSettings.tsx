import { useEffect, useState } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { BaitFile, Trap, TrapInput } from '../api/types'

type Props = { api: MellCoreApi; traps: Trap[]; readOnly: boolean; onChanged: () => Promise<void>; mode: 'baits' | 'vulnerabilities' }
const profiles = [
  { id: 'ssh_weak_credentials', label: 'Слабый SSH-пароль' },
  { id: 'ssh_root_login_enabled', label: 'SSH-вход root' },
  { id: 'sudo_nopasswd', label: 'sudo без пароля' },
]

export default function HighGuestSettings({ api, traps, readOnly, onChanged, mode }: Props) {
  const high = traps.filter((trap) => trap.profile_snapshot.honeypot_type === 'high_vm'
    && trap.effective_config.os_profile !== 'windows_rdp')
  const [selectedId, setSelectedId] = useState('')
  const selected = high.find((trap) => trap.trap_id === selectedId) ?? high[0]
  const [draft, setDraft] = useState<BaitFile[]>([])
  const [enabled, setEnabled] = useState<string[]>([])
  const [name, setName] = useState('')
  const [path, setPath] = useState('')
  const [content, setContent] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    setDraft(Array.isArray(selected?.effective_config.baits) ? selected.effective_config.baits as BaitFile[] : [])
    setEnabled(Array.isArray(selected?.effective_config.vulnerability_profiles) ? selected.effective_config.vulnerability_profiles as string[] : [])
    setMessage('')
    setError('')
    setEditingId(null)
    setName(''); setPath(''); setContent('')
  }, [selected?.trap_id, selected?.version])

  async function save(config: Record<string, unknown>) {
    if (!selected) return
    setBusy(true); setError(''); setMessage('')
    let saved = false
    try {
      const input: TrapInput = {
        name: selected.name, profile_id: selected.profile_id,
        config: { ...selected.config, ...config }, resources: selected.resources,
        desired_state: selected.desired_state, ports: selected.ports,
      }
      await api.traps.update(selected, input)
      saved = true
      await onChanged()
      if (selected.desired_state === 'running') {
        setMessage('Сохранено. Применяю настройки в гостевой VM…')
        const action = await api.traps.action(selected.trap_id, 'restart')
        let progress = action
        for (let attempt = 0; progress.status === 'queued' && attempt < 30; attempt += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 2000))
          progress = await api.traps.actionStatus(selected.trap_id, action.action_id)
        }
        if (progress.status === 'failed') throw new Error(progress.detail || 'Не удалось применить настройки High.')
        setMessage(progress.status === 'succeeded' ? 'Настройки применены.' : 'Настройки сохранены; проверь состояние ловушки.')
        await onChanged()
      } else setMessage('Настройки сохранены и применятся при запуске.')
    } catch (cause) {
      setError(`${saved ? 'Сохранено, но применение не завершилось: ' : ''}${apiErrorMessage(cause)}`)
    } finally { setBusy(false) }
  }

  function addBait() {
    const trimmedPath = path.trim()
    const username = selected?.effective_config.username
    const roots = ['/srv/', '/opt/', '/var/backups/', ...(typeof username === 'string' ? [`/home/${username}/`] : [])]
    if (!roots.some((root) => trimmedPath.startsWith(root)) || trimmedPath.includes('//')
      || trimmedPath.split('/').some((part) => part === '.' || part === '..') || trimmedPath.endsWith('/')) {
      setError('Путь должен находиться в /srv, /opt, /var/backups или домашнем каталоге SSH-пользователя.')
      return
    }
    if (!name.trim() || new TextEncoder().encode(name.trim()).length > 80 || !content
      || new TextEncoder().encode(content).length > 4096 || (!editingId && draft.length >= 32)
      || draft.some((bait) => bait.path === trimmedPath && bait.id !== editingId)) {
      setError('Укажи уникальный путь, название и содержимое до 4096 байт; максимум 32 файла.')
      return
    }
    setDraft([...draft.filter((bait) => bait.id !== editingId), { id: editingId ?? crypto.randomUUID(), name: name.trim(), path: trimmedPath,
      content, category: 'file', implementation: 'virtual_file', config: {} }])
    setEditingId(null); setName(''); setPath(''); setContent(''); setError('')
  }

  return <section className="space-y-4 rounded-xl border border-orange-300/20 bg-orange-300/[0.035] p-4 sm:p-5">
    <h3 className="font-semibold">High · {mode === 'baits' ? 'файлы-приманки' : 'уязвимости Linux'}</h3>
    <p className="text-xs leading-5 text-white/50">Настройки создаются внутри Linux VM. Работающая ловушка перезапустится после сохранения.</p>
    <label className="block max-w-lg text-sm">Ловушка
      <select value={selected?.trap_id ?? ''} disabled={busy || !high.length} onChange={(event) => setSelectedId(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5">
        {!high.length && <option value="">Нет Linux High-ловушек</option>}
        {high.map((trap) => <option key={trap.trap_id} value={trap.trap_id}>{trap.name}</option>)}
      </select>
    </label>
    {selected && mode === 'vulnerabilities' && <div className="space-y-2">{profiles.map((profile) => <label key={profile.id} className="flex gap-3 text-sm">
      <input type="checkbox" disabled={readOnly || busy} checked={enabled.includes(profile.id)} onChange={(event) => setEnabled((current) => event.target.checked ? [...current, profile.id] : current.filter((id) => id !== profile.id))}/>{profile.label}
    </label>)}</div>}
    {selected && mode === 'baits' && <div className="space-y-3">
      {draft.map((bait) => <div key={bait.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 p-3 text-sm"><span>{bait.name} · {bait.path}</span><span className="flex gap-3"><button disabled={readOnly || busy} type="button" onClick={() => { setEditingId(bait.id); setName(bait.name); setPath(bait.path ?? ''); setContent(bait.content) }}>Изменить</button><button disabled={readOnly || busy} type="button" onClick={() => setDraft((current) => current.filter((item) => item.id !== bait.id))}>Удалить</button></span></div>)}
      {!readOnly && <div className="grid gap-2"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Название" className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2"/><input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/opt/backup/.env" className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2"/><textarea value={content} onChange={(event) => setContent(event.target.value)} placeholder="Содержимое файла" className="rounded-lg border border-white/10 bg-[#100a09] px-3 py-2"/><button type="button" onClick={addBait} disabled={busy} className="justify-self-start text-orange-200">{editingId ? 'Обновить файл' : 'Добавить файл'}</button></div>}
    </div>}
    {selected && !readOnly && <button type="button" disabled={busy} onClick={() => void save(mode === 'baits' ? { baits: draft } : { vulnerability_profiles: enabled })} className="rounded-lg bg-orange-400 px-4 py-2 text-sm font-medium text-black disabled:opacity-40">{busy ? 'Сохраняем…' : 'Сохранить High'}</button>}
    {error && <p role="alert" className="text-sm text-red-200">{error}</p>}
    {message && <p role="status" className="text-sm text-emerald-200">{message}</p>}
  </section>
}
