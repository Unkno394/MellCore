import { useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { User } from '../api/types'
import type { ToastKind } from '../components/ToastNotifications'

type SettingsProps = {
  api: MellCoreApi
  user: User
  notify: (kind: ToastKind, title: string, message: string) => void
  onPasswordChanged: () => Promise<void>
}

export default function Settings({ api, user, notify, onPasswordChanged }: SettingsProps) {
  const [email, setEmail] = useState('')
  const [emailPassword, setEmailPassword] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [busy, setBusy] = useState(false)

  async function changeEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    try {
      const response = await api.auth.changeEmail(emailPassword, email)
      setEmail('')
      setEmailPassword('')
      notify('success', 'Запрос принят', response.message)
    } catch (error) {
      notify('error', 'Не удалось сменить почту', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (newPassword !== confirmPassword) {
      notify('error', 'Пароли не совпадают', 'Повторите новый пароль без ошибок.')
      return
    }
    setBusy(true)
    try {
      await api.auth.changePassword(currentPassword, newPassword)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      notify('success', 'Пароль изменён', 'Войдите снова с новым паролем.')
      await onPasswordChanged()
    } catch (error) {
      notify('error', 'Не удалось сменить пароль', apiErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  return <section className="mx-auto max-w-3xl space-y-6 p-6">
    <div><p className="text-xs uppercase tracking-[0.18em] text-orange-300/70">Аккаунт</p><h2 className="mt-2 text-2xl font-semibold">Настройки</h2></div>

    <form onSubmit={changeEmail} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6">
      <div><h3 className="text-lg font-semibold">Сменить почту</h3><p className="mt-1 text-sm text-white/45">Текущий адрес: {user.email || 'не указан'}</p></div>
      <label className="block text-sm text-white/65">Новый адрес почты
        <input required type="email" autoComplete="email" disabled={busy} value={email} onChange={(event) => setEmail(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50" />
      </label>
      <label className="block text-sm text-white/65">Текущий пароль
        <input required type="password" autoComplete="current-password" disabled={busy} value={emailPassword} onChange={(event) => setEmailPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50" />
      </label>
      <button disabled={busy} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">Отправить подтверждение</button>
    </form>

    <form onSubmit={changePassword} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6">
      <div><h3 className="text-lg font-semibold">Сменить пароль</h3><p className="mt-1 text-sm text-white/45">После смены пароля потребуется войти снова.</p></div>
      <label className="block text-sm text-white/65">Текущий пароль
        <input required type="password" autoComplete="current-password" disabled={busy} value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50" />
      </label>
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm text-white/65">Новый пароль
          <input required type="password" autoComplete="new-password" minLength={12} maxLength={256} disabled={busy} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50" />
        </label>
        <label className="block text-sm text-white/65">Повторите новый пароль
          <input required type="password" autoComplete="new-password" minLength={12} maxLength={256} disabled={busy} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/25 px-4 py-3 outline-none focus:border-orange-500/50" />
        </label>
      </div>
      <button disabled={busy} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">Изменить пароль</button>
    </form>
  </section>
}
