export type ScenarioEndpoint = {
  targetPort: number
  defaultPublicPort: number
  service: string
}

export type ScenarioOption = {
  id: string
  name: string
  protocol: string
  description: string
}

export const scenarioEndpoints: Record<string, ScenarioEndpoint[]> = {
  redis_unauthenticated_access: [{ targetPort: 6379, defaultPublicPort: 6379, service: 'Redis' }],
  docker_api_exposed: [{ targetPort: 2375, defaultPublicPort: 2375, service: 'Docker API' }],
  http_admin_panel_exposure: [{ targetPort: 8080, defaultPublicPort: 8080, service: 'HTTP' }],
  web_path_traversal: [{ targetPort: 8080, defaultPublicPort: 8080, service: 'HTTP' }],
  web_command_injection: [{ targetPort: 8080, defaultPublicPort: 8080, service: 'HTTP' }],
  sql_database_weak_credentials: [
    { targetPort: 13306, defaultPublicPort: 3306, service: 'MySQL' },
    { targetPort: 15432, defaultPublicPort: 5432, service: 'PostgreSQL' },
  ],
  ftp_anonymous_login: [
    { targetPort: 2121, defaultPublicPort: 21, service: 'FTP control' },
    { targetPort: 2021, defaultPublicPort: 2121, service: 'FTP data' },
  ],
}

export const linuxScenarioOptions: ScenarioOption[] = [
  { id: 'ssh_weak_credentials', name: 'SSH Weak Credentials', protocol: 'SSH', description: 'Принимает слабые виртуальные учётные данные и открывает оболочку Middle.' },
  { id: 'ssh_root_login_enabled', name: 'SSH Root Login Enabled', protocol: 'SSH', description: 'Разрешает виртуальный вход root в пределах SSH-сценария.' },
  { id: 'redis_unauthenticated_access', name: 'Redis Unauthenticated Access', protocol: 'Redis', description: 'Поднимает отдельный RESP endpoint с фиктивным хранилищем.' },
  { id: 'docker_api_exposed', name: 'Docker API Exposed', protocol: 'Docker API', description: 'Поднимает отдельный HTTP endpoint Docker API с фиктивными контейнерами.' },
  { id: 'http_admin_panel_exposure', name: 'HTTP Admin Panel Exposure', protocol: 'HTTP', description: 'Добавляет виртуальную панель входа на общий HTTP endpoint.' },
  { id: 'sql_database_weak_credentials', name: 'SQL Database Weak Credentials', protocol: 'MySQL + PostgreSQL', description: 'Поднимает отдельные MySQL и PostgreSQL endpoints с виртуальными базами.' },
  { id: 'ftp_anonymous_login', name: 'FTP Anonymous Login', protocol: 'FTP', description: 'Поднимает FTP control и passive data endpoints.' },
  { id: 'web_path_traversal', name: 'Web Path Traversal', protocol: 'HTTP', description: 'Добавляет traversal-поведение на общий HTTP endpoint.' },
  { id: 'web_command_injection', name: 'Web Command Injection', protocol: 'HTTP', description: 'Имитирует ответ на попытку внедрения команды; команды ОС не запускаются.' },
]

export const windowsScenarioOptions: ScenarioOption[] = [
  { id: 'ssh_weak_credentials', name: 'SSH Weak Credentials', protocol: 'SSH', description: 'Принимает заданные слабые виртуальные учётные данные и фиксирует попытки входа в Windows Middle.' },
  { id: 'win_autologon_credentials', name: 'Секрет AutoAdminLogon', protocol: 'Реестр', description: 'Фиктивный пароль в Winlogon; чтение фиксируется.' },
  { id: 'win_always_install_elevated', name: 'AlwaysInstallElevated', protocol: 'PowerShell', description: 'Виртуальные ключи Installer и ответ msiexec. Код хоста не запускается.' },
  { id: 'win_writable_service_binary', name: 'Изменяемый файл службы', protocol: 'Служба', description: 'OpsBackup видна в службах и реестре; файл расположен в ProgramData.' },
  { id: 'win_guest_share', name: 'Открытый виртуальный ресурс', protocol: 'PowerShell', description: 'PublicShare виден в net share и Get-SmbShare; SMB listener нет.' },
]

export function endpointsForScenarios(profileIds: string[]): ScenarioEndpoint[] {
  const byTarget = new Map<number, ScenarioEndpoint>()
  for (const id of profileIds) {
    for (const endpoint of scenarioEndpoints[id] ?? []) byTarget.set(endpoint.targetPort, endpoint)
  }
  return [...byTarget.values()].sort((a, b) => a.targetPort - b.targetPort)
}
