export type Role = 'admin' | 'analyst' | 'viewer'

export type FirmwareScheme = '3.23.2' | '3.410'

export type RetentionPolicyClass =
  'syslog' | 'cdr' | 'softswitch_cdr' | 'raw_cdr_archive'

export function retentionLabel(value: RetentionPolicyClass): string {
  return {
    syslog: 'Syslog и события',
    cdr: 'CDR оборудования',
    softswitch_cdr: 'CDR софтсвитчей',
    raw_cdr_archive: 'Raw CDR архив всех источников',
  }[value]
}

export function retentionDescription(value: RetentionPolicyClass): string {
  return {
    syslog: 'Исходные Syslog datagram в syslog_messages.',
    cdr: 'Нормализованные CDR оборудования и timezone interpretations.',
    softswitch_cdr: 'Нормализованные CDR софтсвитчей и timezone interpretations.',
    raw_cdr_archive: 'Неизменённые исходные CDR-файлы всех источников в объектном хранилище.',
  }[value]
}

export function normalizeFirmwareScheme(value?: string): FirmwareScheme {
  const trimmed = (value || '').trim()
  if (trimmed === '3.410' || trimmed.startsWith('3.410')) return '3.410'
  return '3.23.2'
}

export function canManageUsers(role: Role | string): boolean {
  return role === 'admin'
}

export function purgeConfirmationReady(deviceName: string, typedName: string, busy: boolean): boolean {
  return !busy && typedName === deviceName && deviceName.length > 0
}

export function purgeRetryLabel(purgeState?: string): string {
  return purgeState === 'purge_failed' ? 'Повторить полное удаление' : 'Удалить все данные и источник'
}
