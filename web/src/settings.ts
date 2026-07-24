export type Role = 'admin' | 'analyst' | 'viewer'

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
  return purgeState === 'purge_failed' ? 'Повторить полное удаление' : 'Удалить все данные и SMG'
}
