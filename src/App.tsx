import { sessions } from './data/sessions'
import { events } from './data/events'
import { useState } from 'react'
import { initialHoneypots, type Honeypot } from './data/honeypots'
import ConnectServer from './pages/ConnectServer'
import CreateHoneypot from './pages/CreateHoneypot'
import Auth from './pages/Auth'
import Honeypots from './pages/Honeypots'
import Profiles from './pages/Profiles'
import LiveFeed from './pages/LiveFeed'
import Sessions from './pages/Sessions'
import Settings from './pages/Settings'
import CRTWarp from './components/CRTWarp'
import Sidebar from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLightTheme, setIsLightTheme] = useState(false)

  const [honeypots, setHoneypots] = useState<Honeypot[]>(
    initialHoneypots
  )
  const activeHoneypots = honeypots.filter(
    (honeypot) => honeypot.status === 'Active'
  ).length
  
  const totalHoneypots = honeypots.length
  
  
const totalSessions = sessions.filter(
  (session) => session.status === 'Active'
).length

  
const activityByHour = Array.from({ length: 24 }, (_, hour) => ({
  hour,
  count: events.filter(
    (event) => Number(event.time.split(':')[0]) === hour
  ).length,
}))

const maxActivity = Math.max(
  1,
  ...activityByHour.map((item) => item.count)
)

  const threatAlerts = honeypots.filter(
    (honeypot) => honeypot.status === 'Warning'
  ).length
  
  const stats = [
    {
      label: 'Active Honeypots',
      value: String(activeHoneypots).padStart(2, '0'),
      detail: `${totalHoneypots} sensors configured`,
    },
    {
      label: 'Active Sessions',
      value: String(totalSessions),
      detail: 'Across all honeypots',
    },
    {
      label: 'Total Events',
      value: String(events.length),
      detail: 'Events recorded in demo sessions',
    },
    {
      label: 'Threat Alerts',
      value: String(threatAlerts).padStart(2, '0'),
      detail: 'Honeypots in warning status',
    },
  ]

  const [currentPage, setCurrentPage] = useState<
    | 'Dashboard'
    | 'Honeypots'
    | 'Profiles'
    | 'ConnectServer'
    | 'CreateHoneypot'
    | 'LiveFeed'
    | 'Sessions'
    | 'Settings'
  >('Dashboard')

  return (
    <main
  className={`app-root relative min-h-screen overflow-hidden ${
    isLightTheme ? 'light-theme' : 'dark-theme'
  } bg-[#100a09] text-[#e8dfda]`}
>
      <div className="pointer-events-none fixed inset-0 z-0">
        <CRTWarp
          color="#d4810a"
          backgroundColor="#100a09"
          speed={0.5}
          curvature={0.25}
          scanlineStrength={0.25}
          scanlineFrequency={200}
          waveAmplitude={0.3}
          waveFrequency={2.5}
          bloom={0.9}
          bloomRadius={1}
          noise={0.1}
          vignette={0}
          brightness={0.85}
          pixelation={1}
          rgbShift={0.015}
          mouseReact
          mouseStrength={0.5}
          dpr={1}
          fps={30}
          paused={false}
        />
      </div>

      {isAuthenticated ? (
        <div className="relative z-10 flex min-h-screen">
          <Sidebar
            activePage={currentPage}
            onNavigate={setCurrentPage}
          />

          <div className="min-w-0 flex-1">
            <Topbar />

            {currentPage === 'Dashboard' ? (
              <section className="space-y-6 p-6">
                <div>
                  <p className="text-sm text-white/45">
                    Welcome back, Operator
                  </p>

                  <h2 className="mt-1 text-2xl font-semibold">
                    Security overview
                  </h2>

                  <p className="mt-2 text-sm text-white/45">
                    Monitor your honeypots, sessions and incoming activity.
                  </p>
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  {stats.map((stat) => (
                    <article
                      key={stat.label}
                      className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl transition hover:border-orange-500/30"
                    >
                      <p className="text-sm text-white/50">
                        {stat.label}
                      </p>

                      <p className="mt-4 text-3xl font-semibold tracking-tight">
                        {stat.value}
                      </p>

                      <p className="mt-2 text-xs text-white/40">
                        {stat.detail}
                      </p>
                    </article>
                  ))}
                </div>

                <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.5fr_1fr]">
                  <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <h3 className="font-semibold">
                          Activity overview
                        </h3>

                        <p className="mt-1 text-xs text-white/40">
                          Incoming events over time
                        </p>
                      </div>

                      <span className="rounded-md border border-white/10 px-2 py-1 text-xs text-white/50">
                        Last 24 hours
                      </span>
                    </div>

                    
<div className="mt-6 flex h-40 items-end gap-1">
  {activityByHour.map((item) => (
    <div
      key={item.hour}
      className="group relative flex h-full flex-1 items-end"
      title={`${String(item.hour).padStart(2, '0')}:00 — ${item.count} events`}
    >
      <div
        className="w-full rounded-t-sm bg-gradient-to-t from-red-950 to-orange-500/80 opacity-80 transition hover:opacity-100"
        style={{
          height: `${item.count === 0 ? 2 : Math.max(8, (item.count / maxActivity) * 100)}%`,
        }}
      />
    </div>
  ))}
</div>


                    <div className="mt-3 flex justify-between text-[10px] text-white/35">
                      <span>00:00</span>
                      <span>06:00</span>
                      <span>12:00</span>
                      <span>18:00</span>
                      <span>Now</span>
                    </div>
                  </section>

                  <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
                    <h3 className="font-semibold">
                      Recent events
                    </h3>

                    <p className="mt-1 text-xs text-white/40">
                      Latest detected activity
                    </p>

                    <div className="mt-5 space-y-4">
                    {[...events]
  .sort((a, b) => b.time.localeCompare(a.time))
  .slice(0, 4)
  .map((event) => (
    <div
      key={event.id}
      className="flex items-center gap-3"
    >
      <span
        className={`h-2 w-2 shrink-0 rounded-full ${
          event.level === 'High'
            ? 'bg-red-500'
            : event.level === 'Medium'
              ? 'bg-orange-400'
              : 'bg-emerald-400'
        }`}
      />

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm">
          {event.type}
        </p>

        <p className="mt-1 truncate text-xs text-white/40">
          {event.honeypot}
        </p>
      </div>

      <span className="shrink-0 text-[10px] text-white/35">
        {event.time}
      </span>
    </div>
  ))}
                    </div>
                  </section>
                </div>
              </section>
            ) : currentPage === 'Honeypots' ? (
              <Honeypots honeypots={honeypots} />
            ) : currentPage === 'ConnectServer' ? (
              <ConnectServer />
            ) : currentPage === 'CreateHoneypot' ? (
              <CreateHoneypot
                onCreateHoneypot={(newHoneypot) => {
                  setHoneypots((current) => [
                    newHoneypot,
                    ...current,
                  ])
                }}
              />
            ) : currentPage === 'LiveFeed' ? (
  <LiveFeed />
) : currentPage === 'Sessions' ? (
  <Sessions />
) : currentPage === 'Settings' ? (
  <Settings
  isLightTheme={isLightTheme}
  onThemeChange={setIsLightTheme}
/>
) : (
  
<Profiles
  honeypots={honeypots}
  onUpdateHoneypot={(honeypotId, profileName) => {
    setHoneypots((current) =>
      current.map((honeypot) =>
        honeypot.id === honeypotId
          ? { ...honeypot, profile: profileName }
          : honeypot
      )
    )
  }}
/>

)}
          </div>
        </div>
      ) : (
        <div className="relative z-10">
          <Auth
            onAuthenticated={() => setIsAuthenticated(true)}
          />
        </div>
      )}
    </main>
  )
}

export default App
