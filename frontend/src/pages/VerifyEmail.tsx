import { useEffect, useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import { AuthShell } from './ResetPassword'

export default function VerifyEmail({ api }: { api: MellCoreApi }) {
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? ''
  const [status, setStatus] = useState(token ? 'Verifying your email…' : 'The verification link does not contain a token.')
  const [error, setError] = useState('')
  const [email, setEmail] = useState('')

  useEffect(() => {
    if (!token) return
    void api.auth.verifyEmail(token).then(() => {
      window.history.replaceState(null, '', '/verify-email')
      setStatus('Email verified. Sign in again to continue.')
    }).catch((requestError: unknown) => setStatus(apiErrorMessage(requestError)))
  }, [api, token])

  async function resend(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const response = await api.auth.resendVerification(email)
      setStatus(response.message)
    } catch (requestError) {
      setError(apiErrorMessage(requestError))
    }
  }

  return <AuthShell title="Verify email"><p role="status" className="text-sm text-white/65">{status}</p><form onSubmit={resend} className="mt-6 space-y-3 border-t border-white/10 pt-6"><label className="block text-sm text-white/60">Need a new link?<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label>{error && <p role="alert" className="text-sm text-red-400">{error}</p>}<button className="w-full rounded-lg border border-orange-500/30 px-4 py-3 text-sm text-orange-300">Resend verification</button></form><button type="button" onClick={() => { window.history.replaceState(null, '', '/'); window.location.reload() }} className="mt-6 w-full text-sm text-orange-300">Return to sign in</button></AuthShell>
}
