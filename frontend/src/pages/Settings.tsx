type SettingsProps = {
  isLightTheme: boolean
  onThemeChange: (isLight: boolean) => void
}
import { useState } from 'react'

type SettingsData = {
  theme: string
  language: string
  timeFormat: string
  eventsPerPage: string
  defaultThreatLevel: string
  showSourceIP: boolean
  showTimestamps: boolean
  soundAlerts: boolean
  desktopNotifications: boolean
  autoRefresh: boolean
  refreshInterval: string
}

const defaultSettings: SettingsData = {
  theme: 'Dark',
  language: 'English',
  timeFormat: '24h',
  eventsPerPage: '25',
  defaultThreatLevel: 'All',
  showSourceIP: true,
  showTimestamps: true,
  soundAlerts: false,
  desktopNotifications: false,
  autoRefresh: false,
  refreshInterval: '5',
}


function loadSettings(): SettingsData {
  try {
    const saved = localStorage.getItem('mellcore-settings')

    if (saved) {
      return {
        ...defaultSettings,
        ...JSON.parse(saved),
      }
    }
  } catch (error) {
    console.error('Failed to load settings:', error)
  }

  return { ...defaultSettings }
}


type SelectFieldProps = {
  label: string
  description: string
  value: string
  options: string[]
  onChange: (value: string) => void
}

function SelectField({
  label,
  description,
  value,
  options,
  onChange,
}: SelectFieldProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/5 py-4 last:border-0">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="mt-1 text-xs text-white/40">
          {description}
        </p>
      </div>

      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="min-w-36 rounded-lg border border-white/10 bg-[#160e0c] px-4 py-2 text-sm text-white outline-none focus:border-orange-500/50"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </div>
  )
}

type ToggleFieldProps = {
  label: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}

function ToggleField({
  label,
  description,
  checked,
  onChange,
}: ToggleFieldProps) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/5 py-4 last:border-0">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="mt-1 text-xs text-white/40">
          {description}
        </p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative h-7 w-12 shrink-0 rounded-full transition ${
          checked ? 'bg-orange-500' : 'bg-white/15'
        }`}
      >
        <span
          className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all ${
            checked ? 'left-6' : 'left-1'
          }`}
        />
      </button>
    </div>
  )
}

export default function Settings({
  isLightTheme,
  onThemeChange,
}: SettingsProps) {
  const [settings, setSettings] = useState<SettingsData>(
    loadSettings
  )
  const themeName = isLightTheme ? 'Light' : 'Dark'

  const [saved, setSaved] = useState(false)

  function updateSetting<K extends keyof SettingsData>(
    key: K,
    value: SettingsData[K]
  ) {
    setSettings((current) => ({
      ...current,
      [key]: value,
    }))

    setSaved(false)
  }

  function saveSettings() {
    try {
      localStorage.setItem(
        'mellcore-settings',
        JSON.stringify({ ...settings, theme: themeName })
      )
      setSaved(true)
    } catch {
      setSaved(false)
      window.alert('Unable to save settings in this browser.')
    }
  }

  function resetSettings() {
    setSettings({ ...defaultSettings })
    onThemeChange(false)
    setSaved(false)
  }

  return (
    <section className="space-y-6 p-6">
      <div>
        <p className="text-sm text-white/45">
          SYSTEM / CONFIGURATION
        </p>

        <h2 className="mt-1 text-2xl font-semibold">
          Settings
        </h2>

        <p className="mt-2 text-sm text-white/45">
          Configure your monitoring workspace and preferences.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
          <div className="mb-4">
            <h3 className="text-lg font-semibold">
              Interface preferences
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Customize your dashboard appearance
            </p>
          </div>

          <ToggleField
  label="Light theme"
  description="Switch between dark and light appearance"
  checked={isLightTheme}
  onChange={(value) => {
    onThemeChange(value)
    updateSetting('theme', value ? 'Light' : 'Dark')
  }}
/>

          <SelectField
            label="Language"
            description="Interface language"
            value={settings.language}
            options={['English']}
            onChange={(value) => updateSetting('language', value)}
          />

          <SelectField
            label="Time format"
            description="How timestamps are displayed"
            value={settings.timeFormat}
            options={['24h', '12h']}
            onChange={(value) => updateSetting('timeFormat', value)}
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
          <div className="mb-4">
            <h3 className="text-lg font-semibold">
              Event display
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Configure event visibility and filtering
            </p>
          </div>

          <SelectField
            label="Events per page"
            description="Maximum number of events displayed"
            value={settings.eventsPerPage}
            options={['10', '25', '50', '100']}
            onChange={(value) =>
              updateSetting('eventsPerPage', value)
            }
          />

          <SelectField
            label="Default threat level"
            description="UI-only preference; backend telemetry has no severity field"
            value={settings.defaultThreatLevel}
            options={['All', 'High', 'Medium', 'Low']}
            onChange={(value) =>
              updateSetting('defaultThreatLevel', value)
            }
          />

          <ToggleField
            label="Show source IP"
            description="Display source IP addresses in event records"
            checked={settings.showSourceIP}
            onChange={(value) =>
              updateSetting('showSourceIP', value)
            }
          />

          <ToggleField
            label="Show timestamps"
            description="Display event occurrence times"
            checked={settings.showTimestamps}
            onChange={(value) =>
              updateSetting('showTimestamps', value)
            }
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
          <div className="mb-4">
            <h3 className="text-lg font-semibold">
              Notifications
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Manage security alert preferences
            </p>
          </div>

          <ToggleField
            label="Sound alerts"
            description="Enable sound notification preference"
            checked={settings.soundAlerts}
            onChange={(value) =>
              updateSetting('soundAlerts', value)
            }
          />

          <ToggleField
            label="Desktop notifications"
            description="Enable browser notification preference"
            checked={settings.desktopNotifications}
            onChange={(value) =>
              updateSetting('desktopNotifications', value)
            }
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
          <div className="mb-4">
            <h3 className="text-lg font-semibold">
              Monitoring preferences
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Configure automatic event updates
            </p>
          </div>

          <ToggleField
            label="Auto refresh"
            description="Enable automatic refresh preference"
            checked={settings.autoRefresh}
            onChange={(value) =>
              updateSetting('autoRefresh', value)
            }
          />

          <SelectField
            label="Refresh interval"
            description="Preferred update interval in seconds"
            value={settings.refreshInterval}
            options={['5', '10', '30', '60']}
            onChange={(value) =>
              updateSetting('refreshInterval', value)
            }
          />
        </section>
      </div>

      <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-semibold">
              Save configuration
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Preferences are stored locally in this browser.
              MellCore does not expose a settings API.
            </p>

            {saved && (
              <p className="mt-2 text-xs text-emerald-400">
                Settings saved successfully
              </p>
            )}
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={resetSettings}
              className="rounded-lg border border-white/10 px-5 py-3 text-sm text-white/60 transition hover:bg-white/5"
            >
              Reset defaults
            </button>

            <button
              type="button"
              onClick={saveSettings}
              className="rounded-lg border border-orange-500/40 bg-gradient-to-r from-orange-700 to-orange-600 px-6 py-3 text-sm font-medium text-white transition hover:brightness-110"
            >
              Save changes
            </button>
          </div>
        </div>
      </div>

      <div className="text-xs text-white/35">
        MellCore · Local interface preferences
      </div>
    </section>
  )
}
