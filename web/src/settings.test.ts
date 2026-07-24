import { describe, expect, it } from 'vitest'
import {
  canManageUsers, canOpenSystemSettings, purgeConfirmationReady, purgeRetryLabel,
} from './settings'

describe('system settings RBAC', () => {
  it('allows every authenticated role to open settings', () => {
    expect(canOpenSystemSettings('viewer')).toBe(true)
    expect(canOpenSystemSettings('analyst')).toBe(true)
    expect(canOpenSystemSettings('admin')).toBe(true)
  })

  it('restricts user management to administrators', () => {
    expect(canManageUsers('admin')).toBe(true)
    expect(canManageUsers('analyst')).toBe(false)
    expect(canManageUsers('viewer')).toBe(false)
  })
})

describe('destructive SMG purge confirmation', () => {
  it('requires an exact device name match while idle', () => {
    expect(purgeConfirmationReady('SMG-A', 'SMG-A', false)).toBe(true)
    expect(purgeConfirmationReady('SMG-A', 'smg-a', false)).toBe(false)
    expect(purgeConfirmationReady('SMG-A', 'SMG-A', true)).toBe(false)
    expect(purgeConfirmationReady('SMG-A', '', false)).toBe(false)
  })

  it('labels retry after a failed purge', () => {
    expect(purgeRetryLabel('purge_failed')).toBe('Повторить полное удаление')
    expect(purgeRetryLabel('active')).toBe('Удалить все данные и SMG')
  })
})
