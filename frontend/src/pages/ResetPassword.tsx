import { useState, type FormEvent, type ReactNode } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'

export default function ResetPassword({ api }: { api: MellCoreApi }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [complete, setComplete] = useState(false)
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? ''

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    if (!token) return setError('The reset link does not contain a token.')
    if (password.length < 12) return setError('Password must contain at least 12 characters.')
    if (password !== confirm) return setError('Passwords do not match.')
    try {
      await api.auth.resetPassword(token, password)
      window.history.replaceState(null, '', '/reset-password')
      setComplete(true)
    } catch (requestError) {
      setError(apiErrorMessage(requestError))
    }
  }

  return (
    <AuthShell title="Reset password">
      {complete ? <p className="text-sm text-emerald-300">Password changed. All previous sessions were revoked.</p> : <form onSubmit={submit} className="space-y-4"><PasswordInput label="New password" value={password} onChange={setPassword} /><PasswordInput label="Confirm password" value={confirm} onChange={setConfirm} />{error && <p role="alert" className="text-sm text-red-400">{error}</p>}<button className="w-full rounded-lg bg-orange-600 px-4 py-3 text-sm font-semibold">Change password →</button></form>}
      <HomeLink />
    </AuthShell>
  )
}

function PasswordInput({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <label className="block text-sm text-white/65">{label}<input required type="password" minLength={12} maxLength={256} value={value} onChange={(event) => onChange(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label>
}

export function AuthShell({ title, children }: { title: string; children: ReactNode }) {
  return <section className="flex min-h-screen items-center justify-center p-5"><div className="w-full max-w-md rounded-2xl border border-orange-500/20 bg-[#160e0c]/90 p-8 shadow-2xl backdrop-blur-xl"><div className="mb-7 text-center"><div className="text-2xl font-bold tracking-[0.18em] text-[#f1a36b]">MellCore</div><h1 className="mt-4 text-xl font-semibold">{title}</h1></div>{children}</div></section>
}

function HomeLink() {
  return <button type="button" onClick={() => { window.history.replaceState(null, '', '/'); window.location.reload() }} className="mt-6 w-full text-center text-sm text-orange-300 hover:text-orange-200">Return to sign in</button>
}
