import { Plus, Trash2 } from 'lucide-react'
import type { MiddleSshAuthMode, SshCredential } from '../api/types'

const preparedCredentials: SshCredential[] = [
  { username: 'root', password: 'admin123' },
  { username: 'admin', password: 'password123' },
  { username: 'test', password: 'test' },
  { username: 'ubuntu', password: 'ubuntu' },
  { username: 'user', password: 'user123' },
  { username: 'deploy', password: 'deploy' },
  { username: 'postgres', password: 'postgres' },
  { username: 'support', password: 'support123' },
  { username: 'guest', password: 'guest' },
]

export function chooseDefaultSshCredentials(primaryUsername = 'admin'): SshCredential[] {
  const primary = preparedCredentials.find((credential) => credential.username === primaryUsername)
    ?? { username: primaryUsername, password: 'password123' }
  const shuffled = preparedCredentials.filter((credential) => credential.username !== primaryUsername)
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(Math.random() * (index + 1))
    ;[shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]]
  }
  return [primary, ...shuffled.slice(0, 2)]
}

export function withFixedSshUsername(credentials: SshCredential[], fixedUsername?: string): SshCredential[] {
  if (fixedUsername === undefined || credentials.length === 0) return credentials
  return credentials.map((credential, index) => index === 0 ? { ...credential, username: fixedUsername } : credential)
}

export function orderFixedSshUsernameFirst(credentials: SshCredential[], fixedUsername?: string): SshCredential[] {
  if (fixedUsername === undefined || credentials.length < 2) return withFixedSshUsername(credentials, fixedUsername)
  const primaryIndex = credentials.findIndex((credential) => credential.username.toLowerCase() === fixedUsername.toLowerCase())
  if (primaryIndex < 0) return withFixedSshUsername(credentials, fixedUsername)
  return [credentials[primaryIndex], ...credentials.filter((_, index) => index !== primaryIndex)]
}

export function validateSshCredentials(credentials: SshCredential[], fixedUsername?: string): string | null {
  if (!credentials.length) return 'Добавьте хотя бы одну пару SSH.'
  if (credentials.length > 32) return 'Можно указать не больше 32 пар SSH.'

  const usernames = new Set<string>()
  for (const [index, credential] of credentials.entries()) {
    const rawUsername = index === 0 && fixedUsername !== undefined ? fixedUsername : credential.username
    const username = rawUsername.trim()
    if (rawUsername !== username || !/^[a-z_][a-z0-9_-]{0,31}$/.test(username)) {
      return 'Логин должен быть в формате Unix: строчные латинские буквы, цифры, _ или -.'
    }
    if (usernames.has(username.toLowerCase())) {
      return `Логин «${username}» указан несколько раз. Для каждого логина можно задать только один пароль.`
    }
    usernames.add(username.toLowerCase())
    if (!credential.password.trim() || credential.password.length > 128 || /[\u0000-\u001f\u007f]/.test(credential.password)) {
      return 'У каждой пары SSH должен быть пароль длиной от 1 до 128 символов.'
    }
  }
  return null
}

export const fallbackSshCredentials: SshCredential[] = [
  { username: 'root', password: 'admin123' },
  { username: 'admin', password: 'password123' },
  { username: 'test', password: 'test' },
]

type Props = {
  mode: MiddleSshAuthMode
  credentials: SshCredential[]
  title?: string
  radioName?: string
  fixedUsername?: string
  disabled?: boolean
  allowAdaptive?: boolean
  maxCredentials?: number
  onModeChange: (mode: MiddleSshAuthMode) => void
  onCredentialsChange: (credentials: SshCredential[]) => void
}

export default function SshAuthSettings({ mode, credentials, title = 'Авторизация SSH Middle', radioName = 'middle-ssh-auth-mode', fixedUsername, disabled = false, allowAdaptive = true, maxCredentials = 32, onModeChange, onCredentialsChange }: Props) {
  function updateCredential(index: number, key: keyof SshCredential, value: string) {
    onCredentialsChange(credentials.map((credential, row) => row === index ? { ...credential, [key]: value } : credential))
  }

  return <section className="rounded-xl border border-white/10 bg-black/10 p-4">
    <div>
      <h3 className="text-sm font-medium text-white/80">{title}</h3>
      <p className="mt-1 text-xs leading-5 text-white/45">Выбери, как ловушка будет отвечать на попытки SSH-входа.</p>
    </div>
    <div className={`mt-4 grid gap-3 ${allowAdaptive ? 'sm:grid-cols-2' : ''}`}>
      <label className={`rounded-lg border p-3 ${mode === 'realistic' ? 'border-orange-400/35 bg-orange-400/[0.06]' : 'border-white/10 bg-black/10'}`}>
        <span className="flex items-center gap-2 text-sm text-white/80"><input type="radio" name={radioName} value="realistic" checked={mode === 'realistic'} disabled={disabled} onChange={() => onModeChange('realistic')} className="accent-orange-400"/>Реалистичная авторизация</span>
        <span className="mt-2 block text-xs leading-5 text-white/45">Работают только указанные слабые пары. Один и тот же набор действует для всех IP этой ловушки.</span>
      </label>
      {allowAdaptive && <label className={`rounded-lg border p-3 ${mode === 'adaptive' ? 'border-orange-400/35 bg-orange-400/[0.06]' : 'border-white/10 bg-black/10'}`}>
        <span className="flex items-center gap-2 text-sm text-white/80"><input type="radio" name={radioName} value="adaptive" checked={mode === 'adaptive'} disabled={disabled} onChange={() => onModeChange('adaptive')} className="accent-orange-400"/>Адаптивная авторизация</span>
        <span className="mt-2 block text-xs leading-5 text-white/45">Для каждого IP после 2–5 отказов принимается следующая пара логин/пароль. Она закрепляется за этим IP и ловушкой: с того же IP другие пары отклоняются, а разные IP могут закрепить разные пароли за одним виртуальным пользователем.</span>
      </label>}
    </div>
    {mode === 'realistic' ? <div className="mt-4 space-y-2">
      <div className="flex items-center justify-between gap-2"><p className="text-xs text-white/50">Слабые учётные данные</p>{maxCredentials > 1 && <button type="button" disabled={disabled || credentials.length >= maxCredentials} onClick={() => onCredentialsChange([...credentials, { username: '', password: '' }])} className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2.5 py-1.5 text-xs text-orange-100/80 disabled:opacity-40"><Plus size={14}/>Добавить пару</button>}</div>
      {credentials.map((credential, index) => <div key={index} className="grid grid-cols-[1fr_1fr_auto] gap-2">
        <label className="sr-only" htmlFor={`ssh-user-${index}`}>Логин</label><input id={`ssh-user-${index}`} required disabled={disabled || (index === 0 && fixedUsername !== undefined)} readOnly={index === 0 && fixedUsername !== undefined} maxLength={32} pattern="[a-z_][a-z0-9_-]*" autoComplete="off" value={index === 0 && fixedUsername !== undefined ? fixedUsername : credential.username} onChange={(event) => updateCredential(index, 'username', event.target.value)} placeholder="Логин" className="min-w-0 rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-orange-500/50 disabled:opacity-60"/>
        <label className="sr-only" htmlFor={`ssh-password-${index}`}>Пароль</label><input id={`ssh-password-${index}`} required disabled={disabled} maxLength={128} autoComplete="new-password" value={credential.password} onChange={(event) => updateCredential(index, 'password', event.target.value)} placeholder="Пароль" className="min-w-0 rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-orange-500/50"/>
        <button type="button" aria-label="Удалить пару" title="Удалить пару" disabled={disabled || credentials.length <= 1 || (index === 0 && fixedUsername !== undefined)} onClick={() => onCredentialsChange(credentials.filter((_, row) => row !== index))} className="rounded-lg border border-white/10 px-2 text-white/50 hover:text-red-200 disabled:opacity-30"><Trash2 size={15}/></button>
      </div>)}
      <p className="text-[11px] leading-5 text-white/35">{maxCredentials === 1 ? 'Эта пара создаёт настоящего пользователя внутри изолированной High VM.' : 'У каждого логина может быть только один пароль. Первый логин связан с пользователем SSH и shell; дополнительные пары должны использовать другие логины.'}</p>
    </div> : <p className="mt-4 rounded-lg border border-white/10 bg-black/15 p-3 text-xs leading-5 text-white/45">Заданные слабые пары не используются в этом режиме. Пароль не сохраняется в открытом виде: HoneyForge хранит имя пользователя и хеш принятого пароля, связанный с IP-адресом.</p>}
  </section>
}
