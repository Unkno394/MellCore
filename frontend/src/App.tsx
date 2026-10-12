import { useCallback, useEffect, useMemo, useState } from 'react'
import { ApiClient, apiErrorMessage } from './api/client'
import { createApi } from './api/services'
import type { AttackEvent, Profile, Server, Trap, User } from './api/types'
import { clearSession, loadSession, saveSession, type AuthSession } from './auth/session'
import Auth from './pages/Auth'
import ConnectServer from './pages/ConnectServer'
import CreateHoneypot from './pages/CreateHoneypot'
import Honeypots from './pages/Honeypots'
import LiveFeed from './pages/LiveFeed'
import Profiles from './pages/Profiles'
import ResetPassword from './pages/ResetPassword'
import Sessions from './pages/Sessions'
import Settings from './pages/Settings'
import VerifyEmail from './pages/VerifyEmail'
import CRTWarp from './components/CRTWarp'
import Sidebar, { type PageName } from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'

const unauthorizedEvent = 'mellcore:unauthorized'
const apiClient = new ApiClient({
  getToken: () => loadSession()?.token ?? null,
  onUnauthorized: () => {
    clearSession()
    window.dispatchEvent(new Event(unauthorizedEvent))
  },
})
const api = createApi(apiClient)

function App() {
  const [session, setSession] = useState<AuthSession | null>(() => loadSession())
  const [user, setUser] = useState<User | null>(() => loadSession()?.user ?? null)
  const [authChecking, setAuthChecking] = useState(() => Boolean(loadSession()))
  const [authNotice, setAuthNotice] = useState('')
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [servers, setServers] = useState<Server[]>([])
  const [traps, setTraps] = useState<Trap[]>([])
  const [events, setEvents] = useState<AttackEvent[]>([])
  const [resourceError, setResourceError] = useState('')
  const [eventError, setEventError] = useState('')
  const [loading, setLoading] = useState(false)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [activityCutoff] = useState(() => Date.now() - 24 * 60 * 60 * 1000)
  const [currentPage, setCurrentPage] = useState<PageName>('Dashboard')
  const [isLightTheme, setIsLightTheme] = useState(false)

  const refreshEvents = useCallback(async (sourceTraps: Trap[]) => {
    setEventsLoading(true)
    setEventError('')
    try {
      const results = await Promise.allSettled(sourceTraps.map((trap) => api.traps.events(trap.trap_id)))
      const successful = results.flatMap((result) => result.status === 'fulfilled' ? result.value.items : [])
      setEvents(successful.sort((a, b) => b.event.occurred_at.localeCompare(a.event.occurred_at)))
      const failed = results.filter((result) => result.status === 'rejected')
      if (failed.length) setEventError(`Telemetry is partial: ${failed.length} of ${sourceTraps.length} trap event requests failed. ${apiErrorMessage(failed[0].reason)}`)
    } finally {
      setEventsLoading(false)
    }
  }, [])

  const refreshInventory = useCallback(async () => {
    setLoading(true)
    setResourceError('')
    try {
      const [nextProfiles, nextServers, nextTraps] = await Promise.all([
        api.profiles.list(), api.servers.list(), api.traps.list(),
      ])
      setProfiles(nextProfiles)
      setServers(nextServers)
      setTraps(nextTraps)
      await refreshEvents(nextTraps)
    } catch (error) {
      setResourceError(apiErrorMessage(error))
    } finally {
      setLoading(false)
    }
  }, [refreshEvents])

  useEffect(() => {
    const expire = () => {
      clearSession()
      setSession(null)
      setUser(null)
      setProfiles([])
      setServers([])
      setTraps([])
      setEvents([])
      setAuthNotice('Your session expired. MellCore does not provide refresh tokens; please sign in again.')
      setAuthChecking(false)
    }
    window.addEventListener(unauthorizedEvent, expire)
    return () => window.removeEventListener(unauthorizedEvent, expire)
  }, [])

  useEffect(() => {
    if (!session) return
    const remaining = Math.max(0, Math.min(session.expiresAt - Date.now(), 2_147_483_647))
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
      clearSession()
      setSession(null)
      setUser(null)
      setAuthNotice(apiErrorMessage(error))
    }).finally(() => { if (active) setAuthChecking(false) })
    return () => { active = false }
  }, [session, refreshInventory])

  async function logout() {
    try { await api.auth.logout() } catch { /* Local logout still ends the browser session. */ }
    clearSession()
    setSession(null)
    setUser(null)
    setProfiles([]); setServers([]); setTraps([]); setEvents([])
    setAuthNotice('Signed out. The local JWT has been removed.')
  }

  const path = window.location.pathname.replace(/\/$/, '') || '/'
  const activityByHour = useMemo(() => {
    return Array.from({ length: 24 }, (_, hour) => ({ hour, count: events.filter(({ event }) => new Date(event.occurred_at).getTime() >= activityCutoff && new Date(event.occurred_at).getHours() === hour).length }))
  }, [activityCutoff, events])
  const maxActivity = Math.max(1, ...activityByHour.map((item) => item.count))
  const trapNames = useMemo(() => new Map(traps.map((trap) => [trap.trap_id, trap.name])), [traps])
  const stats = [
    { label: 'Configured Honeypots', value: String(traps.length).padStart(2, '0'), detail: 'Registered in management API' },
    { label: 'Actually Running', value: String(traps.filter((trap) => trap.actual_state === 'running').length).padStart(2, '0'), detail: 'Reported backend actual_state' },
    { label: 'Loaded Events', value: String(events.length), detail: 'Current per-trap snapshot' },
    { label: 'Session Status', value: 'N/A', detail: 'No sessions status endpoint' },
  ]
  const readOnly = user?.role === 'viewer'

  return <main className={`app-root relative min-h-screen overflow-hidden ${isLightTheme ? 'light-theme' : 'dark-theme'} bg-[#100a09] text-[#e8dfda]`}>
    <div className="pointer-events-none fixed inset-0 z-0"><CRTWarp color="#d4810a" backgroundColor="#100a09" speed={0.5} curvature={0.25} scanlineStrength={0.25} scanlineFrequency={200} waveAmplitude={0.3} waveFrequency={2.5} bloom={0.9} bloomRadius={1} noise={0.1} vignette={0} brightness={0.85} pixelation={1} rgbShift={0.015} mouseReact mouseStrength={0.5} dpr={1} fps={30} paused={false}/></div>
    <div className="relative z-10">
      {path === '/reset-password' ? <ResetPassword api={api}/> : path === '/verify-email' ? <VerifyEmail api={api}/> : authChecking ? <div className="flex min-h-screen items-center justify-center text-sm text-white/50">Validating session with MellCore…</div> : session && user ? <div className="flex min-h-screen"><Sidebar activePage={currentPage} onNavigate={setCurrentPage}/><div className="min-w-0 flex-1"><Topbar currentPage={currentPage} user={user} onLogout={() => void logout()}/>
        {loading && <div className="mx-6 mt-5 rounded-lg border border-white/10 bg-white/5 p-3 text-sm text-white/45">Refreshing management data…</div>}
        {resourceError && <div role="alert" className="mx-6 mt-5 rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-300">Management API error: {resourceError}</div>}
        {currentPage === 'Dashboard' ? <section className="space-y-6 p-6"><div><p className="text-sm text-white/45">Welcome back, {user.name}</p><h2 className="mt-1 text-2xl font-semibold">Security overview</h2><p className="mt-2 text-sm text-white/45">Real management state and the currently loaded telemetry snapshot.</p></div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">{stats.map((stat) => <article key={stat.label} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl transition hover:border-orange-500/30"><p className="text-sm text-white/50">{stat.label}</p><p className="mt-4 text-3xl font-semibold tracking-tight">{stat.value}</p><p className="mt-2 text-xs text-white/40">{stat.detail}</p></article>)}</div>
          <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-100">Dashboard event counts are a client-side snapshot (up to 100 events per trap), not backend-wide aggregates. Severity and session liveness are unavailable.</div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.5fr_1fr]"><section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><div className="flex justify-between gap-3"><div><h3 className="font-semibold">Activity overview</h3><p className="mt-1 text-xs text-white/40">Loaded events occurring in the last 24 hours</p></div><span className="rounded-md border border-white/10 px-2 py-1 text-xs text-white/50">Snapshot</span></div><div className="mt-6 flex h-40 items-end gap-1">{activityByHour.map((item) => <div key={item.hour} title={`${String(item.hour).padStart(2, '0')}:00 — ${item.count} events`} className="group relative flex h-full flex-1 items-end"><div className="w-full rounded-t-sm bg-gradient-to-t from-red-950 to-orange-500/80 opacity-80" style={{ height: `${item.count === 0 ? 2 : Math.max(8, item.count / maxActivity * 100)}%` }}/></div>)}</div><div className="mt-3 flex justify-between text-[10px] text-white/35"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span></div></section>
            <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><h3 className="font-semibold">Recent events</h3><p className="mt-1 text-xs text-white/40">Newest persisted events in this snapshot</p>{eventError && <p className="mt-3 text-xs text-red-300">{eventError}</p>}<div className="mt-5 space-y-4">{events.slice(0, 4).map(({ event }) => <div key={event.event_id} className="flex items-center gap-3"><span className="h-2 w-2 rounded-full bg-orange-400"/><div className="min-w-0 flex-1"><p className="truncate text-sm">{event.event_type}</p><p className="mt-1 truncate text-xs text-white/40">{trapNames.get(event.trap_id) ?? event.trap_id}</p></div><span className="text-[10px] text-white/35">{new Date(event.occurred_at).toLocaleTimeString()}</span></div>)}{!eventsLoading && events.length === 0 && <p className="text-sm text-white/40">No events returned.</p>}</div></section></div>
        </section> : currentPage === 'Honeypots' ? <Honeypots api={api} traps={traps} readOnly={readOnly} onChanged={refreshInventory}/> : currentPage === 'ConnectServer' ? <ConnectServer api={api} servers={servers} readOnly={readOnly} onChanged={refreshInventory}/> : currentPage === 'CreateHoneypot' ? <CreateHoneypot api={api} profiles={profiles} servers={servers} readOnly={readOnly} onCreated={refreshInventory}/> : currentPage === 'LiveFeed' ? <LiveFeed events={events} traps={traps} loading={eventsLoading} error={eventError} onRefresh={() => refreshEvents(traps)}/> : currentPage === 'Sessions' ? <Sessions events={events} traps={traps} loading={eventsLoading} error={eventError}/> : currentPage === 'Settings' ? <Settings isLightTheme={isLightTheme} onThemeChange={setIsLightTheme}/> : <Profiles api={api} profiles={profiles} isAdmin={user.role === 'admin'} onChanged={refreshInventory}/>}</div></div> : (
        <Auth api={api} notice={authNotice} onAuthenticated={(nextSession) => { setAuthNotice(''); setAuthChecking(true); setSession(nextSession); setUser(nextSession.user) }}/>
      )}
    </div>
  </main>
}

export default App
