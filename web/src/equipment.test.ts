import { describe, expect, it } from 'vitest'
import {
  fallbackTemplates, normalizeTemplate, sourceCapabilities, sourceCategory, templatesFor,
} from './equipment'

describe('equipment templates', () => {
  it('keeps exact Eltex labels in the equipment category', () => {
    expect(templatesFor(fallbackTemplates, 'equipment').map((item) => item.displayName)).toEqual([
      'Eltex SMG-1016M (3.23.2)',
      'Eltex SMG-1016M (3.410)',
    ])
  })

  it('isolates raw-only softswitch capabilities', () => {
    const template = fallbackTemplates.find((item) => item.key === 'softswitch-cdr-raw-v1')!
    expect(template.category).toBe('softswitch')
    expect(template.capabilities).toEqual({
      syslog: false,
      typedCdr: false,
      rawCdr: true,
      antifraud: false,
      radius: false,
    })
    expect(sourceCategory({ templateKey: template.key })).toBe('softswitch')
    expect(sourceCapabilities({ templateKey: template.key }).typedCdr).toBe(false)
  })

  it('normalizes template API aliases', () => {
    expect(normalizeTemplate({ id: 'eltex-smg-1016m-3.410' }).displayName)
      .toBe('Eltex SMG-1016M (3.410)')
  })
})
