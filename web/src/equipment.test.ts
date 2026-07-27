import { describe, expect, it } from 'vitest'
import main from './main.tsx?raw'
import {
  defaultSourceDataset, deviceSurfaces, fallbackTemplates, normalizeTemplate, sourceDatasets, templatesFor,
} from './equipment'

describe('equipment templates', () => {
  it('keeps exact Eltex labels in the equipment category', () => {
    expect(templatesFor(fallbackTemplates, 'equipment').map((item) => item.displayName)).toEqual([
      'Eltex SMG-1016M (3.23.2)',
      'Eltex SMG-1016M (3.410)',
    ])
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
    expect(sourceDatasets(template)).toEqual(['calls'])
    expect(defaultSourceDataset(template)).toBe('calls')
  })

  it('shows exactly three enabled and two disabled Eltex surfaces', () => {
    const template = fallbackTemplates[0]
    expect(deviceSurfaces({ ...template, antifraudEnabled: true }))
      .toEqual(['calls', 'syslog', 'antifraud'])
    expect(deviceSurfaces({ ...template, antifraudEnabled: false }))
      .toEqual(['calls', 'syslog'])
  })

  it('does not expose legacy Syslog category surfaces', () => {
    expect(main).not.toContain("id: 'alarms'")
    expect(main).not.toContain("id: 'radius'")
    expect(main).not.toContain('category=${')
    expect(main).toContain("label: 'Сообщения Syslog'")
  })

  it('exposes Satel RTU as the only softswitch template', () => {
    expect(templatesFor(fallbackTemplates, 'softswitch').map((item) => item.key))
      .toEqual(['satel-rtu-cdr-v1'])
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
    expect(main).not.toContain('Метрики Eltex за выбранный интервал')
    expect(main).not.toContain('(snapshot?.devices || []).map((row) => <tr')
    // Dashboard order: services → softswitches → equipment.
    const servicesAt = main.indexOf('<h4>Сервисы</h4>')
    const softAt = main.indexOf('<h4>Софтсвитчи</h4><span>Типизированные')
    const equipAt = main.indexOf('<h4>Оборудование</h4><span>Eltex')
    expect(servicesAt).toBeGreaterThan(-1)
    expect(softAt).toBeGreaterThan(servicesAt)
    expect(equipAt).toBeGreaterThan(softAt)
  })

  it('selects the specialized Satel CDR table by template key', () => {
    expect(main).toContain("device.templateKey === 'satel-rtu-cdr-v1'")
    expect(main).toContain('<SatelCallsTable')
    expect(main).toContain('<SatelCallDrawer')
  })

  it('surfaces durable Satel replay progress without raw-format detection', () => {
    expect(main).toContain('Satel RTU: обработано')
    expect(main).toContain('device.replay?.pending')
    expect(main).toContain('device.replay?.processing')
    expect(main).not.toContain('softswitch-cdr-raw-v1')
    expect(main).not.toContain('SoftswitchPendingView')
    expect(main).not.toContain('Satel RTU активирован')
  })

  it('removes the softswitch file page but keeps ingest-files for CDR admin banner', () => {
    expect(main).not.toContain('function CdrFilesPage')
    expect(main).not.toContain('rawCdrNavigation')
    expect(main).toContain('/ingest-files?limit=20')
    expect(main).toContain('CdrIngestBannerLoader')
  })

  it('opens Dashboard from the logo without a separate sidebar item', () => {
    expect(main).toContain('title="Открыть Dashboard" aria-label="Открыть Dashboard"')
    expect(main).toContain("onClick={() => setActiveView('dashboard')}")
    expect(main).not.toContain('dashboard-nav')
    expect(main).not.toContain('LayoutDashboard')
  })

  it('keeps the footer fixed and navigation inside its source category', () => {
    expect(main).toContain('<div className="sidebar-scroll">')
    expect(main.indexOf('<div className="sidebar-scroll">'))
      .toBeLessThan(main.indexOf('<div className="sidebar-footer">'))
    expect(main).toContain("activeView === 'device' && sourceCategory(selected) === category")
  })
})
