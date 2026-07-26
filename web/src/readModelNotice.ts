export type DeviceRevisionState = {
  timezone: string
  activeTimezone: string
  timezoneRevision: number
  activeTimezoneRevision: number
}

export type RevisionDiagnostics = {
  activeRevision: number
  activeRevisionTimezone?: string
  revisionAligned: boolean
  revisionReason?: string
}

export function readModelNotice(
  device: DeviceRevisionState,
  diagnostics?: RevisionDiagnostics | null,
): string | null {
  const activeTimezone = diagnostics?.activeRevisionTimezone ||
    device.activeTimezone || device.timezone
  if (diagnostics?.activeRevision === 0 || diagnostics?.revisionReason === 'initial_build') {
    return 'Инициализация оборудования: создаётся первый согласованный read model для Syslog, CDR, RADIUS и AntiFraud. Приём данных продолжается, таблицы появятся после атомарной активации.'
  }
  if (diagnostics?.revisionReason === 'timezone_change' ||
      device.timezone !== activeTimezone) {
    return `Часовой пояс меняется с ${activeTimezone} на ${device.timezone}: новый read model пересобирается в фоне. До атомарного переключения данные показаны в ${activeTimezone}.`
  }
  if (device.timezoneRevision !== device.activeTimezoneRevision ||
      diagnostics?.revisionAligned === false) {
    return `Техническая синхронизация read model для ${activeTimezone}: ревизии данных догоняют текущую конфигурацию. Приём данных продолжается.`
  }
  return null
}
