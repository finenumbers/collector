export type Role = 'admin' | 'analyst' | 'viewer'

export type FirmwareScheme = '3.23.2' | '3.410'

export function normalizeFirmwareScheme(value?: string): FirmwareScheme {
  const trimmed = (value || '').trim()
  if (trimmed === '3.410' || trimmed.startsWith('3.410')) return '3.410'
  return '3.23.2'
}

export function canManageUsers(role: Role | string): boolean {
  return role === 'admin'
}

export function canOpenSystemSettings(role: Role | string): boolean {
  return role === 'admin' || role === 'analyst' || role === 'viewer'
}

export function purgeConfirmationReady(deviceName: string, typedName: string, busy: boolean): boolean {
  return !busy && typedName === deviceName && deviceName.length > 0
}

export function purgeRetryLabel(purgeState?: string): string {
  return purgeState === 'purge_failed' ? 'Повторить полное удаление' : 'Удалить все данные и источник'
}
