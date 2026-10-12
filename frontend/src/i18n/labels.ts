// API values remain unchanged; only their presentation is localized.
export function statusLabel(value: string): string {
  const labels: Record<string, string> = {
    running: 'Работает', installing: 'Устанавливается', failed: 'Ошибка',
    stopped: 'Остановлена', removed: 'Удалена', unknown: 'Неизвестно',
    low: 'Низкий', medium: 'Средний', high: 'Высокий',
    admin: 'Администратор', viewer: 'Наблюдатель', user: 'Пользователь',
    active: 'Активен', inactive: 'Неактивен', pending: 'Ожидает',
    online: 'В сети', offline: 'Не в сети', error: 'Ошибка',
  }
  return labels[value] ?? value
}

export function eventLabel(value: string): string {
  const labels: Record<string, string> = {
    connection: 'Подключение', 'connection.opened': 'Подключение открыто',
    'connection.closed': 'Подключение закрыто',
    'auth.attempted': 'Попытка входа', 'auth.failed': 'Ошибка входа',
    'auth.succeeded': 'Вход выполнен', 'session.started': 'Сеанс начат',
    'session.ended': 'Сеанс завершён', 'command.executed': 'Выполнена команда',
    'filesystem.accessed': 'Доступ к файлу',
  }
  return labels[value] ?? value
}

export function dateTime(value: string): string {
  return new Date(value).toLocaleString('ru-RU')
}
