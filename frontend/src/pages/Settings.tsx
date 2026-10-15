import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { AuditEntry, EffectiveAccess, Invitation, PermissionInfo, RoleInput, RoleView, User } from '../api/types'
import type { ToastKind } from '../components/ToastNotifications'

type SettingsProps = { api: MellCoreApi; user: User; permissions: string[]; notify: (kind: ToastKind, title: string, message: string) => void; onPasswordChanged: () => Promise<void> }
const categoryLabels: Record<string, string> = { traps: 'Ловушки', servers: 'Серверы и агенты', attacks: 'Атаки', telemetry: 'Логи и телеметрия', graph: 'Граф атак', profiles: 'Профили и приманки', users: 'Пользователи', roles: 'Роли', audit: 'Аудит', settings: 'Настройки платформы' }

export default function Settings(props: SettingsProps) {
  const [tab, setTab] = useState<'account' | 'access' | 'invitations' | 'audit'>('account')
  const canAccess = props.permissions.includes('roles.view') || props.permissions.includes('users.view')
  const canInvite = props.permissions.includes('users.manage') && props.permissions.includes('users.assign_roles')
  const canAudit = props.permissions.includes('audit.view')
  return <section className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6"><div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs uppercase tracking-[0.18em] text-orange-300/70">Платформа</p><h2 className="mt-2 text-2xl font-semibold">Настройки</h2></div><div className="flex flex-wrap rounded-lg border border-white/10 bg-black/20 p-1"><Tab active={tab === 'account'} onClick={() => setTab('account')}>Аккаунт</Tab>{canAccess && <Tab active={tab === 'access'} onClick={() => setTab('access')}>Роли и права</Tab>}{canInvite && <Tab active={tab === 'invitations'} onClick={() => setTab('invitations')}>Приглашения</Tab>}{canAudit && <Tab active={tab === 'audit'} onClick={() => setTab('audit')}>Аудит</Tab>}</div></div>{tab === 'access' && canAccess ? <AccessSettings {...props}/> : tab === 'invitations' && canInvite ? <InvitationSettings {...props}/> : tab === 'audit' && canAudit ? <AuditSettings {...props}/> : <AccountSettings {...props}/>}</section>
}
function Tab({ active, onClick, children }: { active: boolean; onClick: () => void; children: string }) { return <button type="button" onClick={onClick} className={`rounded-md px-4 py-2 text-sm transition ${active ? 'bg-orange-500/15 text-orange-200' : 'text-white/45 hover:text-white/75'}`}>{children}</button> }

function AccountSettings({ api, user, notify, onPasswordChanged }: SettingsProps) {
  const [email, setEmail] = useState(''); const [emailPassword, setEmailPassword] = useState(''); const [currentPassword, setCurrentPassword] = useState(''); const [newPassword, setNewPassword] = useState(''); const [confirmPassword, setConfirmPassword] = useState(''); const [busy, setBusy] = useState(false)
  async function changeEmail(event: FormEvent<HTMLFormElement>) { event.preventDefault(); setBusy(true); try { const response = await api.auth.changeEmail(emailPassword, email); setEmail(''); setEmailPassword(''); notify('success', 'Запрос принят', response.message) } catch (error) { notify('error', 'Не удалось сменить почту', apiErrorMessage(error)) } finally { setBusy(false) } }
  async function changePassword(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (newPassword !== confirmPassword) { notify('error', 'Пароли не совпадают', 'Повторите новый пароль без ошибок.'); return } setBusy(true); try { await api.auth.changePassword(currentPassword, newPassword); notify('success', 'Пароль изменён', 'Войдите снова с новым паролем.'); await onPasswordChanged() } catch (error) { notify('error', 'Не удалось сменить пароль', apiErrorMessage(error)) } finally { setBusy(false) } }
  const inputClass = 'mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50'
  return <div className="grid gap-6 lg:grid-cols-2"><form onSubmit={changeEmail} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6"><div><h3 className="text-lg font-semibold">Сменить почту</h3><p className="mt-1 text-sm text-white/45">Текущий адрес: {user.email || 'не указан'}</p></div><label className="block text-sm text-white/65">Новый адрес<input required type="email" disabled={busy} value={email} onChange={(e) => setEmail(e.target.value)} className={inputClass}/></label><label className="block text-sm text-white/65">Текущий пароль<input required type="password" disabled={busy} value={emailPassword} onChange={(e) => setEmailPassword(e.target.value)} className={inputClass}/></label><button disabled={busy} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">Отправить подтверждение</button></form><form onSubmit={changePassword} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6"><div><h3 className="text-lg font-semibold">Сменить пароль</h3><p className="mt-1 text-sm text-white/45">Все текущие сеансы будут отозваны.</p></div><label className="block text-sm text-white/65">Текущий пароль<input required type="password" disabled={busy} value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} className={inputClass}/></label><label className="block text-sm text-white/65">Новый пароль<input required type="password" minLength={12} maxLength={256} disabled={busy} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className={inputClass}/></label><label className="block text-sm text-white/65">Повторите пароль<input required type="password" minLength={12} maxLength={256} disabled={busy} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className={inputClass}/></label><button disabled={busy} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">Изменить пароль</button></form></div>
}

function AccessSettings({ api, user: currentUser, permissions: ownPermissions, notify }: SettingsProps) {
  const [roles, setRoles] = useState<RoleView[]>([]); const [catalog, setCatalog] = useState<PermissionInfo[]>([]); const [users, setUsers] = useState<User[]>([]); const [selected, setSelected] = useState<RoleView | null>(null); const [editor, setEditor] = useState<RoleInput>({ name: '', description: '', permissions: [] }); const [access, setAccess] = useState<EffectiveAccess | null>(null); const [target, setTarget] = useState(''); const [assigned, setAssigned] = useState<string[]>([]); const [busy, setBusy] = useState(false)
  const can = useCallback((key: string) => ownPermissions.includes(key), [ownPermissions])
  const reload = useCallback(async () => { setBusy(true); try { const [nextRoles, nextCatalog, nextUsers] = await Promise.all([api.roles.list(), api.roles.permissions(), can('users.view') ? api.users.list() : Promise.resolve([])]); setRoles(nextRoles); setCatalog(nextCatalog); setUsers(nextUsers) } catch (error) { notify('error', 'Не удалось загрузить права', apiErrorMessage(error)) } finally { setBusy(false) } }, [api, can, notify])
  useEffect(() => { void Promise.resolve().then(reload) }, [reload])
  const groups = useMemo(() => Object.entries(catalog.reduce<Record<string, PermissionInfo[]>>((result, item) => { (result[item.category] ||= []).push(item); return result }, {})), [catalog])
  function edit(role?: RoleView) { setSelected(role ?? null); setEditor(role ? { name: role.name, description: role.description, permissions: [...role.permissions] } : { name: '', description: '', permissions: [] }) }
  function toggle(key: string) { setEditor((value) => ({ ...value, permissions: value.permissions.includes(key) ? value.permissions.filter((item) => item !== key) : [...value.permissions, key] })) }
  async function save(event: FormEvent) { event.preventDefault(); setBusy(true); try { if (selected) await api.roles.update(selected.id, editor); else await api.roles.create(editor); notify('success', 'Роль сохранена', 'Новые права действуют со следующего API-запроса.'); edit(); await reload() } catch (error) { notify('error', 'Не удалось сохранить роль', apiErrorMessage(error)) } finally { setBusy(false) } }
  async function copy(role: RoleView) { const name = window.prompt('Название копии роли', `${role.name} — копия`); if (!name) return; try { await api.roles.copy(role.id, name); await reload() } catch (error) { notify('error', 'Не удалось скопировать роль', apiErrorMessage(error)) } }
  async function remove(role: RoleView) { if (!window.confirm(`Удалить роль «${role.name}»?`)) return; try { await api.roles.delete(role.id); await reload() } catch (error) { notify('error', 'Не удалось удалить роль', apiErrorMessage(error)) } }
  async function chooseUser(id: string) { setTarget(id); if (!id) { setAccess(null); setAssigned([]); return } try { const value = await api.users.access(id); setAccess(value); setAssigned(value.roles.map((role) => role.id)) } catch (error) { notify('error', 'Не удалось получить эффективные права', apiErrorMessage(error)) } }
  async function saveAssignment() { if (!target || !assigned.length || !window.confirm('Применить новый набор ролей пользователя?')) return; try { const value = await api.users.assignRoles(target, assigned); setAccess(value); notify('success', 'Роли назначены', 'Эффективные права обновлены без повторного входа.'); await reload() } catch (error) { notify('error', 'Не удалось назначить роли', apiErrorMessage(error)) } }
  return <div className="space-y-6"><div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{roles.map((role) => <article key={role.id} className={`rounded-xl border p-5 ${role.is_system ? 'border-orange-400/15 bg-orange-400/[0.03]' : 'border-white/10 bg-[#160e0c]/80'}`}><div className="flex items-start justify-between gap-3"><div><h3 className="font-semibold">{role.name}</h3><p className="mt-1 text-xs text-white/40">{role.system_key ? 'Системная роль' : 'Пользовательская роль'} · {role.user_count} польз.</p></div><span className="rounded bg-white/5 px-2 py-1 text-xs text-white/45">{role.permissions.length}</span></div><p className="mt-3 min-h-10 text-sm text-white/50">{role.description || 'Без описания'}</p><div className="mt-4 flex flex-wrap gap-3">{!role.is_system && can('roles.edit') && <button onClick={() => edit(role)} className="text-xs text-orange-200">Изменить</button>}{can('roles.create') && <button onClick={() => void copy(role)} className="text-xs text-white/55">Копировать</button>}{!role.is_system && can('roles.delete') && <button onClick={() => void remove(role)} className="text-xs text-red-300">Удалить</button>}</div></article>)}</div>
    {(can('roles.create') || (selected && can('roles.edit'))) && <form onSubmit={save} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 sm:p-6"><div className="flex items-center justify-between"><div><h3 className="text-lg font-semibold">{selected ? `Редактирование: ${selected.name}` : 'Новая роль'}</h3><p className="mt-1 text-sm text-white/40">Выдать можно только разрешения, которыми вы обладаете.</p></div>{selected && <button type="button" onClick={() => edit()} className="text-xs text-white/50">Отмена</button>}</div><div className="mt-5 grid gap-4 sm:grid-cols-2"><input required maxLength={80} value={editor.name} onChange={(e) => setEditor({ ...editor, name: e.target.value })} placeholder="Название роли" className="rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none"/><input maxLength={2048} value={editor.description} onChange={(e) => setEditor({ ...editor, description: e.target.value })} placeholder="Описание" className="rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none"/></div><div className="mt-5 grid gap-4 lg:grid-cols-2">{groups.map(([category, items]) => { const available = items.filter((item) => can(item.key)); const all = available.length > 0 && available.every((item) => editor.permissions.includes(item.key)); return <fieldset key={category} className="rounded-lg border border-white/10 p-4"><div className="mb-3 flex items-center justify-between"><legend className="font-medium">{categoryLabels[category] ?? category}</legend><button type="button" disabled={!available.length} onClick={() => setEditor((value) => ({ ...value, permissions: all ? value.permissions.filter((key) => !available.some((item) => item.key === key)) : [...new Set([...value.permissions, ...available.map((item) => item.key)])] }))} className="text-xs text-orange-200 disabled:text-white/20">{all ? 'Снять все' : 'Выбрать все'}</button></div>{items.map((item) => <label key={item.key} title={!can(item.key) ? 'У вас нет этого разрешения' : item.description} className={`flex items-center gap-3 py-1.5 text-sm ${can(item.key) ? 'text-white/65' : 'text-white/20'}`}><input type="checkbox" checked={editor.permissions.includes(item.key)} disabled={!can(item.key)} onChange={() => toggle(item.key)} className="accent-orange-500"/><span>{item.key.split('.')[1]}</span></label>)}</fieldset> })}</div><button disabled={busy} className="mt-5 rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">Сохранить роль</button></form>}
    {can('users.assign_roles') && <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 sm:p-6"><h3 className="text-lg font-semibold">Назначение ролей</h3><p className="mt-1 text-sm text-white/40">Собственные назначения менять нельзя; права нескольких ролей объединяются. В списке есть все участники команды, включая администраторов.</p><select value={target} onChange={(e) => void chooseUser(e.target.value)} className="mt-5 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3 text-sm"><option value="">Выберите пользователя</option>{users.filter((item) => item.id !== currentUser.id).map((item) => <option key={item.id} value={item.id}>{item.name} · {item.email ?? item.username}{item.role === 'admin' ? ' · администратор' : ''}</option>)}</select>{target && <div className="mt-5 grid gap-5 lg:grid-cols-2"><div className="space-y-2">{roles.map((role) => <label key={role.id} className="flex items-center justify-between rounded-lg border border-white/5 px-3 py-2 text-sm"><span>{role.name}</span><input type="checkbox" checked={assigned.includes(role.id)} onChange={() => setAssigned((value) => value.includes(role.id) ? value.filter((id) => id !== role.id) : [...value, role.id])} className="accent-orange-500"/></label>)}</div><div className="rounded-lg border border-orange-400/10 bg-orange-400/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-orange-200/60">Текущие роли</p><div className="mt-3 flex flex-wrap gap-2">{access?.roles.map((role) => <span key={role.id} className="rounded border border-orange-400/20 bg-orange-400/5 px-2 py-1 text-xs text-orange-100/80">{role.name}</span>)}</div><p className="mt-5 text-xs uppercase tracking-wider text-orange-200/60">Эффективные права</p><div className="mt-3 flex flex-wrap gap-2">{access?.permissions.map((permission) => <span key={permission} className="rounded border border-white/10 px-2 py-1 text-[11px] text-white/50">{permission}</span>)}{!access?.permissions.length && <span className="text-sm text-white/35">Нет разрешений</span>}</div></div></div>}<button disabled={!target || !assigned.length} onClick={() => void saveAssignment()} className="mt-5 rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-30">Применить роли</button></section>}
  </div>
}

function InvitationSettings({ api, permissions, notify }: SettingsProps) {
  const [roles, setRoles] = useState<RoleView[]>([])
  const [invitations, setInvitations] = useState<Invitation[]>([])
  const [email, setEmail] = useState('')
  const [roleIds, setRoleIds] = useState<string[]>([])
  const [hours, setHours] = useState(72)
  const [createdUrl, setCreatedUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => {
    try {
      const [nextRoles, nextInvitations] = await Promise.all([api.roles.list(), api.invitations.list()])
      setRoles(nextRoles)
      setInvitations(nextInvitations)
    } catch (error) {
      notify('error', 'Не удалось загрузить приглашения', apiErrorMessage(error))
    }
  }, [api, notify])
  useEffect(() => { void Promise.resolve().then(load) }, [load])
  const grantableRoles = roles.filter((role) => role.permissions.every((permission) => permissions.includes(permission)))

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!roleIds.length) return
    setBusy(true)
    try {
      const result = await api.invitations.create(email, roleIds, hours)
      setCreatedUrl(result.invite_url)
      setEmail('')
      setRoleIds([])
      notify('success', 'Приглашение создано', 'Ссылка показывается только сейчас — скопируйте и передайте её адресату.')
      await load()
    } catch (error) {
      notify('error', 'Не удалось создать приглашение', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(createdUrl)
      notify('success', 'Ссылка скопирована', 'Теперь её можно безопасно отправить приглашённому пользователю.')
    } catch {
      notify('error', 'Не удалось скопировать', 'Выделите ссылку и скопируйте её вручную.')
    }
  }

  async function revoke(invitation: Invitation) {
    if (!window.confirm(`Отозвать приглашение для ${invitation.email}? Ссылка сразу перестанет работать.`)) return
    try {
      await api.invitations.revoke(invitation.id)
      await load()
    } catch (error) {
      notify('error', 'Не удалось отозвать приглашение', apiErrorMessage(error))
    }
  }

  const statusLabels: Record<Invitation['status'], string> = { pending: 'Ожидает', accepted: 'Принято', revoked: 'Отозвано', expired: 'Истекло' }
  return <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]"><form onSubmit={create} className="h-fit space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 sm:p-6"><div><h3 className="text-lg font-semibold">Пригласить участника</h3><p className="mt-1 text-sm text-white/40">Одноразовая ссылка действует ограниченное время. Пользователь сразу получит выбранные роли.</p></div><label className="block text-sm text-white/65">Электронная почта<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50"/></label><fieldset><legend className="text-sm text-white/65">Роли</legend><div className="mt-2 space-y-2">{grantableRoles.map((role) => <label key={role.id} className="flex items-center justify-between rounded-lg border border-white/5 px-3 py-2 text-sm"><span><span className="text-white/80">{role.name}</span><span className="ml-2 text-xs text-white/35">{role.permissions.length} прав</span></span><input type="checkbox" checked={roleIds.includes(role.id)} onChange={() => setRoleIds((current) => current.includes(role.id) ? current.filter((id) => id !== role.id) : [...current, role.id])} className="accent-orange-500"/></label>)}</div></fieldset><label className="block text-sm text-white/65">Срок действия<select value={hours} onChange={(event) => setHours(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value={24}>24 часа</option><option value={72}>3 дня</option><option value={168}>7 дней</option></select></label><button disabled={busy || !roleIds.length} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-40">{busy ? 'Создаём…' : 'Создать приглашение'}</button>{createdUrl && <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/5 p-4"><p className="text-xs uppercase tracking-wider text-emerald-200/70">Одноразовая ссылка</p><input readOnly value={createdUrl} onFocus={(event) => event.currentTarget.select()} className="mt-3 w-full rounded border border-white/10 bg-black/25 px-3 py-2 text-xs text-white/60"/><button type="button" onClick={() => void copyLink()} className="mt-3 text-sm text-emerald-200">Скопировать ссылку</button></div>}</form><section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 sm:p-6"><div><h3 className="text-lg font-semibold">История приглашений</h3><p className="mt-1 text-sm text-white/40">Сами токены здесь не хранятся и повторно не показываются.</p></div><div className="mt-5 space-y-3">{invitations.map((invitation) => <article key={invitation.id} className="rounded-lg border border-white/5 bg-black/10 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-sm font-medium text-white/85">{invitation.email}</p><p className="mt-1 text-xs text-white/35">Создал: {invitation.creator_name} · до {new Date(invitation.expires_at).toLocaleString('ru-RU')}</p></div><span className={`rounded border px-2 py-1 text-xs ${invitation.status === 'pending' ? 'border-amber-400/20 text-amber-200' : invitation.status === 'accepted' ? 'border-emerald-400/20 text-emerald-200' : 'border-white/10 text-white/35'}`}>{statusLabels[invitation.status]}</span></div><div className="mt-3 flex flex-wrap gap-2">{invitation.roles.map((role) => <span key={role.id} className="rounded bg-white/5 px-2 py-1 text-xs text-white/50">{role.name}</span>)}</div>{invitation.status === 'pending' && <button type="button" onClick={() => void revoke(invitation)} className="mt-3 text-xs text-red-300">Отозвать</button>}</article>)}{!invitations.length && <p className="py-8 text-center text-sm text-white/35">Приглашений пока нет.</p>}</div></section></div>
}

function AuditSettings({ api, notify }: SettingsProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [roles, setRoles] = useState<RoleView[]>([])
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => {
    setBusy(true)
    try {
      const [nextEntries, nextRoles] = await Promise.all([api.audit.roles(100), api.roles.list()])
      setEntries(nextEntries)
      setRoles(nextRoles)
    } catch (error) {
      notify('error', 'Не удалось загрузить аудит', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }, [api, notify])
  useEffect(() => { void Promise.resolve().then(load) }, [load])
  const roleNames = useMemo(() => new Map(roles.map((role) => [role.id, role.name])), [roles])
  const actionLabels: Record<string, string> = { 'role.create': 'Создал роль', 'role.update': 'Изменил роль', 'role.delete': 'Удалил роль', 'user.roles_assigned': 'Изменил роли пользователя', 'invitation.create': 'Создал приглашение', 'invitation.revoke': 'Отозвал приглашение', 'invitation.accept': 'Принял приглашение' }
  function describe(entry: AuditEntry) {
    const details = entry.details
    if (typeof details.name === 'string') return details.name
    if (typeof details.email === 'string') return details.email
    if (Array.isArray(details.role_ids)) return details.role_ids.map((id) => typeof id === 'string' ? roleNames.get(id) ?? id : '').filter(Boolean).join(', ')
    return `Объект ${entry.object_id}`
  }
  return <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 sm:p-6"><div className="flex items-start justify-between gap-4"><div><h3 className="text-lg font-semibold">Аудит доступа</h3><p className="mt-1 text-sm text-white/40">Создание, изменение и удаление ролей, назначения и приглашения.</p></div><button type="button" disabled={busy} onClick={() => void load()} className="text-sm text-orange-200 disabled:opacity-40">Обновить</button></div><div className="mt-5 overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="border-b border-white/10 text-xs uppercase tracking-wider text-white/35"><tr><th className="px-3 py-3 font-medium">Время</th><th className="px-3 py-3 font-medium">Кто</th><th className="px-3 py-3 font-medium">Действие</th><th className="px-3 py-3 font-medium">Детали</th><th className="px-3 py-3 font-medium">Request ID</th></tr></thead><tbody>{entries.map((entry) => <tr key={entry.id} className="border-b border-white/5"><td className="whitespace-nowrap px-3 py-4 text-white/45">{new Date(entry.created_at).toLocaleString('ru-RU')}</td><td className="px-3 py-4"><span className="block text-white/80">{entry.actor_name ?? 'Удалённый пользователь'}</span><span className="text-xs text-white/35">{entry.actor_email ?? entry.actor_id ?? 'system'}</span></td><td className="px-3 py-4 text-orange-100/80">{actionLabels[entry.action] ?? entry.action}</td><td className="max-w-xs break-words px-3 py-4 text-white/55">{describe(entry)}</td><td className="px-3 py-4 font-mono text-[10px] text-white/25">{entry.request_id}</td></tr>)}</tbody></table>{!entries.length && !busy && <p className="py-10 text-center text-sm text-white/35">Событий изменения доступа пока нет.</p>}</div></section>
}
