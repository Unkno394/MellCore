import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ApiClient, ApiError, apiErrorMessage } from './api/client'
import { createApi } from './api/services'
import type { AttackEvent, AttackGraphMatch, Profile, Server, Trap, User } from './api/types'
import { clearSession, createSession, loadSession, saveSession, type AuthSession } from './auth/session'
import Auth from './pages/Auth'
import Infrastructure from './pages/Infrastructure'
import LiveFeed from './pages/LiveFeed'
import Baits from './pages/Baits'
import Vulnerabilities from './pages/Vulnerabilities'
import ResetPassword from './pages/ResetPassword'
import Settings from './pages/Settings'
import VerifyEmail from './pages/VerifyEmail'
import CRTWarp from './components/CRTWarp'
import ToastNotifications, { type ToastItem, type ToastNotify } from './components/ToastNotifications'
import Sidebar, { type PageName } from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'

const unauthorizedEvent = 'mellcore:unauthorized'
const apiClient = new ApiClient({
  getToken: () => loadSession()?.token ?? null,
  onUnauthorized: () => {
    window.dispatchEvent(new Event(unauthorizedEvent))
  },
})
const api = createApi(apiClient)
let refreshInFlight: Promise<AuthSession> | null = null
let authEpoch = 0

function renewSession(): Promise<AuthSession> {
  if (!refreshInFlight) {
    const epoch = authEpoch
    refreshInFlight = api.auth.refresh().then((response) => {
      if (epoch !== authEpoch) throw new Error('Сеанс изменился во время обновления')
      const next = createSession(response)
      saveSession(next)
      return next
    }).finally(() => { refreshInFlight = null })
  }
  return refreshInFlight
}

function App() {
  const [session, setSession] = useState<AuthSession | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [authChecking, setAuthChecking] = useState(true)
  const [authNotice, setAuthNotice] = useState('')
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [servers, setServers] = useState<Server[]>([])
  const [traps, setTraps] = useState<Trap[]>([])
  const [events, setEvents] = useState<AttackEvent[]>([])
  const [graphMatches, setGraphMatches] = useState<Array<AttackGraphMatch & { trap_id: string }>>([])
  const [resourceError, setResourceError] = useState('')
  const [eventError, setEventError] = useState('')
  const [loading, setLoading] = useState(false)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [currentPage, setCurrentPage] = useState<PageName>('Dashboard')
  const [attackTrapId, setAttackTrapId] = useState<string | null>(null)
  const isLightTheme = false
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const toastIdRef = useRef(Date.now())

  const notify = useCallback<ToastNotify>((kind, title, message, options) => {
    const toastId = Math.max(Date.now(), toastIdRef.current + 1)
    toastIdRef.current = toastId
    setToasts((current) => [...current, { id: toastId, kind, title, message, persistent: options?.persistent }])
    return toastId
  }, [])
  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const refreshEvents = useCallback(async (sourceTraps: Trap[], silent = false) => {
    if (!silent) setEventsLoading(true)
    setEventError('')
    try {
      const results = await Promise.allSettled(sourceTraps.map((trap) => api.traps.events(trap.trap_id)))
      const successful = results.flatMap((result) => result.status === 'fulfilled' ? result.value.items : [])
      setEvents(successful.sort((a, b) => b.event.occurred_at.localeCompare(a.event.occurred_at)))
      const failed = results.filter((result) => result.status === 'rejected')
      if (failed.length) setEventError(`Телеметрия загружена частично: не удалось получить события для ${failed.length} из ${sourceTraps.length} ловушек. ${apiErrorMessage(failed[0].reason)}`)
    } finally {
      if (!silent) setEventsLoading(false)
    }
  }, [])

  const refreshInventory = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setResourceError('')
    try {
      const [nextProfiles, nextServers, nextTraps] = await Promise.all([
        api.profiles.list(), api.servers.list(), api.traps.list(),
      ])
      setProfiles(nextProfiles)
      setServers(nextServers)
      setTraps(nextTraps)
      const matchResults = await Promise.allSettled(nextTraps.map((trap) => api.traps.attackMatches(trap.trap_id)))
      setGraphMatches(matchResults.flatMap((result, index) => result.status === 'fulfilled'
        ? result.value.map((match) => ({ ...match, trap_id: nextTraps[index].trap_id }))
        : []))
      await refreshEvents(nextTraps, silent)
    } catch (error) {
      setResourceError(apiErrorMessage(error))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [refreshEvents])

  // Keep the overview and attack feed in sync with incoming agent telemetry.
  // Refresh on page entry and periodically while signed in; users should not
  // need to reload the whole app to see newly ingested events/incidents.
  useEffect(() => {
    if (!session) return
    void refreshInventory(true)
    const timer = window.setInterval(() => { void refreshInventory(true) }, 20_000)
    return () => window.clearInterval(timer)
  }, [session, currentPage, refreshInventory])

  useEffect(() => {
    let active = true
    void renewSession().then((next) => {
      if (!active) return
      setSession(next)
      setUser(next.user)
    }).catch((error: unknown) => {
      if (!active) return
      const stored = loadSession()
      if (stored) {
        setSession(stored)
        setUser(stored.user)
      } else if (!(error instanceof ApiError && error.status === 401)) {
        setAuthNotice(apiErrorMessage(error))
      }
    }).finally(() => { if (active) setAuthChecking(false) })
    return () => { active = false }
  }, [])

  useEffect(() => {
    let retryTimer: number | undefined
    const expire = () => {
      authEpoch += 1
      clearSession()
      setSession(null)
      setUser(null)
      setProfiles([])
      setServers([])
      setTraps([])
      setEvents([])
      setAuthNotice('Сеанс отозван или истёк. Войдите снова.')
      setAuthChecking(false)
    }
    const recover = () => {
      if (retryTimer) window.clearTimeout(retryTimer)
      retryTimer = undefined
      void renewSession().then((next) => {
        setSession(next)
        setUser(next.user)
        setAuthNotice('')
      }).catch((error: unknown) => {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
          expire()
        } else {
          retryTimer = window.setTimeout(recover, 15_000)
        }
      })
    }
    window.addEventListener(unauthorizedEvent, recover)
    return () => {
      window.removeEventListener(unauthorizedEvent, recover)
      if (retryTimer) window.clearTimeout(retryTimer)
    }
  }, [])

  useEffect(() => {
    if (!session) return
    const remaining = Math.max(0, Math.min(session.expiresAt - Date.now() - 60_000, 2_147_483_647))
    const timer = window.setTimeout(() => window.dispatchEvent(new Event(unauthorizedEvent)), remaining)
    return () => window.clearTimeout(timer)
  }, [session])

  useEffect(() => {
    if (!session) return
    let active = true
    void api.auth.me().then(async ({ user: currentUser }) => {
      if (!active) return
      setUser(currentUser)
      saveSession({ ...session, user: currentUser })
      await refreshInventory()
    }).catch((error: unknown) => {
      if (!active) return
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        window.dispatchEvent(new Event(unauthorizedEvent))
      } else {
        setAuthNotice(apiErrorMessage(error))
      }
    }).finally(() => { if (active) setAuthChecking(false) })
    return () => { active = false }
  }, [session, refreshInventory])

  async function logout() {
    authEpoch += 1
    if (refreshInFlight) await refreshInFlight.catch(() => undefined)
    try { await api.auth.logout() } catch { /* Local logout still ends the browser session. */ }
    clearSession()
    setSession(null)
    setUser(null)
    setProfiles([]); setServers([]); setTraps([]); setEvents([]); setGraphMatches([])
    setAuthNotice('Вы вышли из аккаунта.')
  }

  const path = window.location.pathname.replace(/\/$/, '') || '/'
  const trapNames = useMemo(() => new Map(traps.map((trap) => [trap.trap_id, trap.name])), [traps])
  const incidentRows = useMemo(() => graphMatches.map((match) => {
    const evidence = events.filter((item) => item.event.trap_id === match.trap_id && match.evidence_event_ids.includes(item.event.event_id))
      .sort((a, b) => b.event.occurred_at.localeCompare(a.event.occurred_at))
    return { match, event: evidence[0] ?? null }
  }).sort((a, b) => b.match.updated_at.localeCompare(a.match.updated_at)), [events, graphMatches])
  const activeIncidents = incidentRows.filter(({ match }) => match.status !== 'confirmed' && Date.now() - new Date(match.updated_at).getTime() < 24 * 60 * 60 * 1000).slice(0, 5)
  const latestIncidents = incidentRows.slice(0, 5)
  const infrastructureIssues = [
    ...servers.filter((server) => server.status === 'error' || server.status === 'offline')
      .map((server) => ({ key: `server:${server.server_id}`, title: server.name, detail: `Сервер ${server.status === 'offline' ? 'не в сети' : 'сообщил об ошибке'}` })),
    ...traps.filter((trap) => trap.actual_state === 'failed' || (trap.actual_state === 'installing' && Date.now() - new Date(trap.updated_at).getTime() > 5 * 60 * 1000))
      .map((trap) => ({ key: `trap:${trap.trap_id}`, title: trap.name, detail: trap.actual_state === 'failed' ? 'Ошибка запуска ловушки' : 'Установка длится дольше пяти минут' })),
    ...(resourceError ? [{ key: 'api:management', title: 'API управления', detail: resourceError }] : []),
    ...(eventError ? [{ key: 'api:telemetry', title: 'Загрузка телеметрии', detail: eventError }] : []),
  ]
  const stats = [
    { label: 'Зарегистрировано ловушек', value: String(traps.length).padStart(2, '0'), detail: 'В реестре управления' },
    { label: 'Работают', value: String(traps.filter((trap) => trap.actual_state === 'running').length).padStart(2, '0'), detail: 'По данным API управления' },
    { label: 'Загружено событий', value: String(events.length), detail: 'События атакующих' },
  ]
  const readOnly = user?.role === 'viewer'

  return <main className={`app-root relative min-h-screen overflow-hidden ${isLightTheme ? 'light-theme' : 'dark-theme'} bg-[#100a09] text-[#e8dfda]`}>
    <div className="pointer-events-none fixed inset-0 z-0"><CRTWarp color="#d4810a" backgroundColor="#100a09" speed={0.5} curvature={0.25} scanlineStrength={0.25} scanlineFrequency={200} waveAmplitude={0.3} waveFrequency={2.5} bloom={0.9} bloomRadius={1} noise={0.1} vignette={0} brightness={0.85} pixelation={1} rgbShift={0.015} mouseReact mouseStrength={0.5} dpr={1} fps={30} paused={false}/></div>
    <div className="relative z-10">
      {path === '/reset-password' ? <ResetPassword api={api}/> : path === '/verify-email' ? <VerifyEmail api={api}/> : authChecking ? <div className="flex min-h-screen items-center justify-center text-sm text-white/50">Проверяем сеанс MellCore…</div> : session && user ? <div className="flex min-h-screen"><Sidebar activePage={currentPage} onNavigate={(page) => { setCurrentPage(page); if (page !== 'LiveFeed') setAttackTrapId(null) }}/><div className="min-w-0 flex-1"><Topbar currentPage={currentPage} user={user} onLogout={() => void logout()}/>
        {loading && <div className="mx-6 mt-5 rounded-lg border border-white/10 bg-white/5 p-3 text-sm text-white/45">Обновляем данные управления…</div>}
        {resourceError && <div role="alert" className="mx-6 mt-5 rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-300">Ошибка API управления: {resourceError}</div>}
        {currentPage === 'Dashboard' ? <section className="space-y-6 p-6"><div><p className="text-sm text-white/45">С возвращением, {user.name}</p><h2 className="mt-1 text-2xl font-semibold">Обзор безопасности</h2><p className="mt-2 text-sm text-white/45">Состояние ловушек и загруженная выборка событий.</p></div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">{stats.map((stat) => <article key={stat.label} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl transition hover:border-orange-500/30"><p className="text-sm text-white/50">{stat.label}</p><p className="mt-4 text-3xl font-semibold tracking-tight">{stat.value}</p><p className="mt-2 text-xs text-white/40">{stat.detail}</p></article>)}</div>
          <section className="mt-4 rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><div className="flex items-center justify-between gap-3"><div><h3 className="font-semibold">Ошибки инфраструктуры</h3><p className="mt-1 text-xs text-white/40">Состояние подключённых серверов, установки и загрузки телеметрии</p></div><span className={`rounded-md border px-2 py-1 text-xs ${infrastructureIssues.length ? 'border-red-400/20 bg-red-400/5 text-red-200' : 'border-emerald-400/20 bg-emerald-400/5 text-emerald-200'}`}>{infrastructureIssues.length}</span></div><div className="mt-4 space-y-2">{infrastructureIssues.map((issue) => <div key={issue.key} className="flex items-start gap-3 rounded-lg border border-red-400/10 bg-red-400/[0.025] px-3 py-2.5"><span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-red-300"/><div className="min-w-0"><p className="text-xs font-medium text-white/80">{issue.title}</p><p className="mt-1 break-words text-xs text-red-200/65">{issue.detail}</p></div></div>)}{infrastructureIssues.length === 0 && <p className="py-3 text-sm text-white/40">Ошибок инфраструктуры нет.</p>}</div></section>
          <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_0.85fr]"><section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><div className="flex items-start justify-between gap-3"><div><h3 className="font-semibold">Активные инциденты</h3><p className="mt-1 text-xs text-white/40">Незавершённые совпадения графа за последние 24 часа</p></div><span className="rounded-md border border-orange-400/20 bg-orange-400/5 px-2 py-1 text-xs text-orange-200">{activeIncidents.length}</span></div><div className="mt-5 space-y-3">{activeIncidents.map(({ match, event }) => <button type="button" key={`${match.trap_id}:${match.session_key}:${match.technique_key}`} onClick={() => { setAttackTrapId(match.trap_id); setCurrentPage('LiveFeed') }} className="flex w-full items-center gap-3 rounded-lg border border-white/5 bg-black/10 p-3 text-left transition hover:border-orange-400/20 hover:bg-white/[0.03]"><span className="h-2 w-2 shrink-0 rounded-full bg-amber-300 shadow-[0_0_10px_rgba(252,211,77,0.35)]"/><span className="min-w-0 flex-1"><span className="block truncate text-sm text-white/85">{match.technique_name}</span><span className="mt-1 block truncate text-xs text-white/40">{trapNames.get(match.trap_id) ?? 'Ловушка'} · {event?.event.source_ip ?? 'источник неизвестен'}</span></span><span className="shrink-0 text-xs text-violet-200">{Math.round(match.similarity * 100)}%</span></button>)}{activeIncidents.length === 0 && <p className="py-8 text-center text-sm text-white/40">Активных подозрений нет.</p>}</div></section>
            <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><div className="flex items-start justify-between gap-3"><div><h3 className="font-semibold">Последние инциденты</h3><p className="mt-1 text-xs text-white/40">Совпадения с известными сценариями</p></div><button type="button" onClick={() => setCurrentPage('LiveFeed')} className="text-xs text-orange-200/70 transition hover:text-orange-100">Все события →</button></div><div className="mt-5 space-y-4">{latestIncidents.map(({ match, event }) => <button type="button" key={`${match.trap_id}:${match.session_key}:${match.technique_key}`} onClick={() => { setAttackTrapId(match.trap_id); setCurrentPage('LiveFeed') }} className="flex w-full items-start gap-3 text-left"><span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${match.status === 'confirmed' ? 'bg-red-400' : 'bg-violet-300'}`}/><span className="min-w-0 flex-1"><span className="block truncate text-sm">{match.technique_name}</span><span className="mt-1 block truncate text-xs text-white/40">{trapNames.get(match.trap_id) ?? 'Ловушка'} · {event?.event.source_ip ?? 'источник неизвестен'}</span></span><span className="shrink-0 text-[10px] text-white/35">{new Date(match.updated_at).toLocaleTimeString('ru-RU')}</span></button>)}{latestIncidents.length === 0 && <p className="py-8 text-center text-sm text-white/40">Совпадений с известными сценариями пока нет.</p>}</div></section></div>
        </section> : currentPage === 'Infrastructure' ? <Infrastructure api={api} profiles={profiles} servers={servers} traps={traps} readOnly={readOnly} onChanged={refreshInventory} onShowAttacks={(trapId) => { setAttackTrapId(trapId); setCurrentPage('LiveFeed') }} notify={notify} dismissToast={dismissToast}/> : currentPage === 'Baits' ? <Baits api={api} traps={traps} readOnly={readOnly} onChanged={refreshInventory} onShowEvents={(trapId) => { setAttackTrapId(trapId); setCurrentPage('LiveFeed') }}/> : currentPage === 'Vulnerabilities' ? <Vulnerabilities api={api} traps={traps} readOnly={readOnly} onChanged={refreshInventory}/> : currentPage === 'LiveFeed' ? <LiveFeed api={api} events={events} traps={traps} initialTrapId={attackTrapId} loading={eventsLoading} error={eventError} onRefresh={() => refreshEvents(traps)}/> : <Settings api={api} user={user} notify={notify} onPasswordChanged={logout}/>}</div></div> : (
        <Auth api={api} notice={authNotice} onAuthenticated={(nextSession) => { authEpoch += 1; setAuthNotice(''); setAuthChecking(true); setSession(nextSession); setUser(nextSession.user) }}/>
      )}
    </div>
    <ToastNotifications toasts={toasts} onDismiss={dismissToast}/>
  </main>
}

export default App
