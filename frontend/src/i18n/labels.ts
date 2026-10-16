// API values remain unchanged; only their presentation is localized.
import type { HighTrapProgressState } from '../api/types'

export function highProgressLabel(value: HighTrapProgressState): string {
  const labels: Record<HighTrapProgressState, string> = {
    DOWNLOADING: 'Скачивание и проверка ISO',
    VM_CREATED: 'Создание виртуальной машины',
    INSTALLING: 'Установка операционной системы',
    REBOOTING: 'Перезагрузка виртуальной машины',
    CONFIGURING: 'Настройка и проверка доступа',
    READY: 'Готово',
    FAILED: 'Ошибка установки',
  }
  return labels[value]
}

export function highProgressDescription(value: HighTrapProgressState): string {
  const descriptions: Record<HighTrapProgressState, string> = {
    DOWNLOADING: 'Агент скачивает ISO и сверяет его SHA-256. Размер файла и скорость соединения влияют на длительность этапа.',
    VM_CREATED: 'ISO проверен. Агент создаёт и запускает виртуальную машину.',
    INSTALLING: 'Гостевая операционная система устанавливается внутри виртуальной машины.',
    REBOOTING: 'Виртуальная машина перезагружается после установки системы.',
    CONFIGURING: 'Агент настраивает гостевую систему и проверяет подключение к её службе.',
    READY: 'Виртуальная машина настроена и отвечает на проверку агента.',
    FAILED: 'Агент не смог завершить установку.',
  }
  return descriptions[value]
}

export function statusLabel(value: string): string {
  const labels: Record<string, string> = {
    running: 'Работает', installing: 'Устанавливается', failed: 'Ошибка',
    stopped: 'Остановлена', removed: 'Удалена', unknown: 'Неизвестно',
    low: 'Нижний', medium: 'Средний', high: 'Высокий',
    admin: 'Администратор', viewer: 'Наблюдатель', user: 'Пользователь',
    active: 'Активен', inactive: 'Неактивен', pending: 'Ожидает',
    online: 'В сети', offline: 'Не в сети', error: 'Ошибка',
  }
  return labels[value] ?? value
}

const internalProfileNames = new Set(['kozyavka', 'pritvoryashka', 'high_ubuntu_ssh'])

export function profileNameLabel(name: string, level: string): string {
  return internalProfileNames.has(name.trim().toLowerCase()) ? statusLabel(level) : name
}

export function eventLabel(value: string): string {
  const labels: Record<string, string> = {
    connection: 'Подключение', 'connection.opened': 'Подключение открыто',
    'connection.closed': 'Подключение закрыто',
    'auth.attempted': 'Попытка входа', 'auth.failed': 'Ошибка входа',
    'auth.succeeded': 'Вход выполнен', 'session.started': 'Сеанс начат',
    'session.ended': 'Сеанс завершён', 'command.executed': 'Выполнена команда',
    'filesystem.accessed': 'Доступ к файлу',
    'bait.opened': 'Открыта приманка',
    'vulnerability.exploit_attempt': 'Попытка взаимодействия с уязвимостью',
  }
  return labels[value] ?? value
}

export function dateTime(value: string): string {
  return new Date(value).toLocaleString('ru-RU')
}
