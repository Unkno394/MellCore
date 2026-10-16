import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  Check,
  Clipboard,
  Container,
  Cpu,
  HardDrive,
  Network,
  Terminal,
  X,
} from 'lucide-react'

type LocalCliPanelProps = {
  open: boolean
  onClose: () => void
}

const installCommands = `cargo install hf-cli --version 0.1.0 --root "$HOME/.local"
sudo install -m 0755 "$HOME/.local/bin/hf" /usr/local/bin/hf
sudo install -m 0755 "$HOME/.local/bin/hf-local-dispatcher" /usr/local/bin/hf-local-dispatcher
hf --help`

const deployCommands = `sudo hf deploy low --port 2222
sudo hf deploy low --port 2225 --shared --auth-mode configured --username admin --password-file /root/low-password
sudo hf deploy medium --port 2225 --shared --os debian --hostname srv-app-01 --username admin --ssh-auth-mode realistic --password-file /root/middle-password
sudo hf deploy high --os ubuntu --port 2224 --hostname web-01 --username admin --shell bash --password-file /root/high-password
sudo hf deploy high --os debian --port 2227 --shared --hostname high-debian-1 --username admin --shell bash --password-file /root/high-password
sudo hf deploy high --os debian --port 2227 --shared --weight 50 --hostname high-debian-2 --username admin --shell bash --password-file /root/high-password
sudo hf deploy high --os windows --port 3389
sudo hf deploy high --os debian --iso /srv/iso/debian.iso --port 2226

sudo hf list
sudo hf logs high-1 --lines 50
sudo hf stop high-1
sudo hf remove high-1`

const loadImagesCommands = `sudo docker load --input low.tar
sudo docker load --input middle.tar`

function CodeSnippet({
  label,
  value,
}: {
  label: string
  value: string
}) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-[#090605]">
      <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-2.5">
        <span className="text-[11px] font-medium uppercase tracking-[0.15em] text-white/40">
          {label}
        </span>
        <button
          type="button"
          onClick={() => void copy()}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-white/45 transition hover:bg-white/[0.06] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-400"
          aria-label={copied ? 'Команды скопированы' : 'Скопировать команды'}
        >
          {copied ? (
            <Check aria-hidden="true" className="h-3.5 w-3.5 text-emerald-400" />
          ) : (
            <Clipboard aria-hidden="true" className="h-3.5 w-3.5" />
          )}
          {copied ? 'Скопировано' : 'Копировать'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-[12px] leading-6 text-[#f1c49e]">
        <code>{value}</code>
      </pre>
    </div>
  )
}

export default function LocalCliPanel({ open, onClose }: LocalCliPanelProps) {
  useEffect(() => {
    if (!open) return

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex justify-end bg-black/65 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="local-cli-title"
        className="flex h-full w-full max-w-xl flex-col border-l border-white/10 bg-[#130c0a] shadow-2xl shadow-black/60"
      >
        <header className="flex shrink-0 items-start justify-between gap-5 border-b border-white/[0.08] px-6 py-5 sm:px-8">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-orange-400/20 bg-orange-400/[0.08] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.17em] text-orange-300">
              <Terminal aria-hidden="true" className="h-3.5 w-3.5" />
              Локальное развёртывание
            </div>
            <h2 id="local-cli-title" className="text-xl font-semibold text-white sm:text-2xl">
              Попробуйте HoneyForge CLI
            </h2>
            <p className="mt-2 max-w-md text-sm leading-relaxed text-white/50">
              Запускайте и обслуживайте ловушки на своём Linux-сервере одной командой.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-white/45 transition hover:bg-white/[0.07] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-400"
            aria-label="Закрыть панель"
          >
            <X aria-hidden="true" className="h-5 w-5" />
          </button>
        </header>

        <div className="min-h-0 flex-1 space-y-7 overflow-y-auto px-6 py-6 sm:px-8">
          <div className="rounded-xl border border-orange-400/15 bg-orange-400/[0.05] p-4 text-sm leading-relaxed text-white/65">
            Это отдельная команда hf из пакета hf-cli для локальных операций. Она не устанавливает hf-agent, не
            подключается к Центру, не использует протоколы управления, SSH-туннели или веб-панель.
            Список ловушек хранится локально на сервере.
          </div>

          <section aria-labelledby="local-cli-install-title">
            <div className="mb-3 flex items-center gap-3">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/[0.06] text-orange-300">
                <Terminal aria-hidden="true" className="h-4 w-4" />
              </span>
              <div>
                <h3 id="local-cli-install-title" className="text-sm font-semibold text-white">
                  Установка команды
                </h3>
                <p className="mt-0.5 text-xs text-white/40">
                  На Linux-сервере с Rust/Cargo установите hf-cli из crates.io. Пакет содержит hf и hf-local-dispatcher.
                </p>
              </div>
            </div>
            <CodeSnippet label="Установка на Linux-сервере" value={installCommands} />
          </section>

          <section aria-labelledby="local-cli-requirements-title">
            <h3 id="local-cli-requirements-title" className="mb-3 text-sm font-semibold text-white">
              Что понадобится
            </h3>
            <div className="space-y-2">
              <div className="flex gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3.5">
                <Container aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-orange-300" />
                <p className="text-xs leading-relaxed text-white/55">
                  <span className="font-medium text-white/80">Low и Medium:</span> Docker с Compose и
                  загруженные образы <code className="text-orange-200/80">honeyforge-low:local</code> и{' '}
                  <code className="text-orange-200/80">honeyforge-pritvoryashka:local</code>.
                </p>
              </div>
              <div className="flex gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3.5">
                <Cpu aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-orange-300" />
                <p className="text-xs leading-relaxed text-white/55">
                  <span className="font-medium text-white/80">High:</span> доступный{' '}
                  <code className="text-orange-200/80">/dev/kvm</code>, libvirt/QEMU и утилиты{' '}
                  <code className="text-orange-200/80">qemu-img</code>,{' '}
                  <code className="text-orange-200/80">virsh</code>,{' '}
                  <code className="text-orange-200/80">virt-install</code> и{' '}
                  <code className="text-orange-200/80">setfacl</code>. Для Ubuntu, Debian и Arch CLI
                  загружает и подготавливает базовый образ; серверу нужен доступ к зеркалам пакетов.
                  Для Windows заранее нужен подготовленный QCOW2 с файлом контрольной суммы либо
                  установленный <code>hf-image-builder</code> с утверждённым каталогом источников.
                  Можно установить ОС из ISO: положите ISO на этот сервер и укажите{' '}
                  <code>--iso</code>. CLI проверяет образ и готовность гостевой службы до публикации порта.
                </p>
              </div>
            </div>
            <div className="mb-2 mt-4 flex items-center gap-2 text-[11px] text-white/45">
              <HardDrive aria-hidden="true" className="h-3.5 w-3.5" />
              Образы Low и Medium из комплекта сборки
            </div>
            <CodeSnippet label="Загрузка образов" value={loadImagesCommands} />
          </section>

          <section aria-labelledby="local-cli-commands-title">
            <div className="mb-3 flex items-center gap-3">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/[0.06] text-orange-300">
                <Network aria-hidden="true" className="h-4 w-4" />
              </span>
              <div>
                <h3 id="local-cli-commands-title" className="text-sm font-semibold text-white">
                  Развёртывание и управление
                </h3>
                <p className="mt-0.5 text-xs text-white/40">
                  Low, Middle и Linux High могут делить SSH-порт через локальный Dispatcher. Windows High
                  публикует RDP отдельно.
                </p>
              </div>
            </div>
            <CodeSnippet label="Примеры команд" value={deployCommands} />
            <p className="mt-2 text-xs leading-5 text-white/45">
              Перед запуском создайте файлы паролей на целевом сервере и задайте им права{' '}
              <code>0600</code>. CLI читает пароль из файла и не принимает его аргументом команды.
              Команда <code>hf logs ID --lines 50</code> показывает локальные журналы ловушки;
              логи не отправляются в Центр.
            </p>
          </section>

          <div className="flex gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-4">
            <Network aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300/80" />
            <p className="text-xs leading-relaxed text-white/45">
              High работает в изолированной виртуальной сети. CLI публикует SSH для Linux или RDP
              для Windows и ограничивает исходящий сетевой трафик VM.
            </p>
          </div>
        </div>
      </section>
    </div>,
    document.body,
  )
}
