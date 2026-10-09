
import CRTWarp from './components/CRTWarp'
import Sidebar from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'

const stats = [
  { label: 'Active Honeypots', value: '08', detail: 'Sensors deployed' },
  { label: 'Active Sessions', value: '24', detail: '+6 in the last hour' },
  { label: 'Events Today', value: '1,284', detail: 'Across all sensors' },
  { label: 'Threat Alerts', value: '07', detail: 'Requires investigation' },
]

function App() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#100a09] text-[#e8dfda]">
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

      <div className="relative z-10 flex min-h-screen">
        <Sidebar />

        <div className="min-w-0 flex-1">
          <Topbar />

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
                  <p className="text-sm text-white/50">{stat.label}</p>
                  <p className="mt-4 text-3xl font-semibold tracking-tight">
                    {stat.value}
                  </p>
                  <p className="mt-2 text-xs text-white/40">{stat.detail}</p>
                </article>
              ))}
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.5fr_1fr]">
              <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h3 className="font-semibold">Activity overview</h3>
                    <p className="mt-1 text-xs text-white/40">
                      Incoming events over time
                    </p>
                  </div>
                  <span className="rounded-md border border-white/10 px-2 py-1 text-xs text-white/50">
                    Last 24 hours
                  </span>
                </div>

                <div className="mt-6 flex h-40 items-end gap-2">
                  {[35, 52, 42, 68, 46, 80, 58, 72, 48, 90, 64, 76, 55, 85, 45, 68, 95, 61, 78, 50, 70, 42, 63, 82].map((height, index) => (
                    <div
                      key={index}
                      className="flex-1 rounded-t-sm bg-gradient-to-t from-red-950 to-orange-500/80 opacity-80 transition hover:opacity-100"
                      style={{ height: `${height}%` }}
                    />
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
                <h3 className="font-semibold">Recent events</h3>
                <p className="mt-1 text-xs text-white/40">
                  Latest detected activity
                </p>

                <div className="mt-5 space-y-4">
                  {[
                    { type: 'SSH login attempt', sensor: 'SSH Honeypot 01', time: '2m ago', level: 'High' },
                    { type: 'Port scan detected', sensor: 'Network Sensor 03', time: '8m ago', level: 'Medium' },
                    { type: 'New session opened', sensor: 'Web Honeypot 02', time: '14m ago', level: 'Low' },
                    { type: 'Authentication failed', sensor: 'SSH Honeypot 01', time: '21m ago', level: 'High' },
                  ].map((event) => (
                    <div key={`${event.type}-${event.time}`} className="flex items-center gap-3">
                      <span className={`h-2 w-2 shrink-0 rounded-full ${
                        event.level === 'High'
                          ? 'bg-red-500'
                          : event.level === 'Medium'
                            ? 'bg-orange-400'
                            : 'bg-emerald-400'
                      }`} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm">{event.type}</p>
                        <p className="mt-1 truncate text-xs text-white/40">{event.sensor}</p>
                      </div>
                      <span className="shrink-0 text-[10px] text-white/35">{event.time}</span>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          </section>
        </div>
      </div>
    </main>
  )
}

export default App