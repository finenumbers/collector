import { describe, expect, it } from 'vitest'
import main from './main.tsx?raw'
import {
  defaultSourceDataset, fallbackTemplates, normalizeTemplate, sourceCapabilities, sourceCategory,
  sourceDatasets, templatesFor,
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

  it('defines Satel RTU as typed and raw CDR softswitch', () => {
    const template = fallbackTemplates.find((item) => item.key === 'satel-rtu-cdr-v1')!
    expect(template.displayName).toBe('Satel RTU')
    expect(template.category).toBe('softswitch')
    expect(template.capabilities).toEqual({
      syslog: false,
      typedCdr: true,
      rawCdr: true,
      antifraud: false,
      radius: false,
    })
    expect(sourceDatasets(template)).toEqual(['calls', 'ingest_files'])
    expect(defaultSourceDataset(template)).toBe('calls')
  })

  it('keeps raw-only softswitch navigation file-only', () => {
    const template = fallbackTemplates.find((item) => item.key === 'softswitch-cdr-raw-v1')!
    expect(sourceDatasets(template)).toEqual(['ingest_files'])
    expect(defaultSourceDataset(template)).toBe('ingest_files')
  })

  it('normalizes template API aliases', () => {
    expect(normalizeTemplate({ id: 'eltex-smg-1016m-3.410' }).displayName)
      .toBe('Eltex SMG-1016M (3.410)')
  })

  it('uses exact softswitch labels and category-specific dashboard sections', () => {
    expect(main).not.toContain('Шаблон приёма')
    expect(main.match(/'Софтсвитч'/g)?.length).toBeGreaterThanOrEqual(2)
    expect(main).toContain('<h4>Оборудование</h4><span>Eltex')
    expect(main).toContain('<h4>Софтсвитчи</h4><span>Типизированные')
    expect(main).toContain('equipmentRows.map')
    expect(main).toContain('softswitchRows.map')
    expect(main).not.toContain('(snapshot?.devices || []).map((row) => <tr')
  })

  it('selects the specialized Satel CDR table by template key', () => {
    expect(main).toContain("device.templateKey === 'satel-rtu-cdr-v1'")
    expect(main).toContain('<SatelCallsTable')
    expect(main).toContain('<SatelCallDrawer')
  })
})
