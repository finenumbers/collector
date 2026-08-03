import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import main from './main.tsx?raw'
import {
  defaultSourceDataset, deviceSurfaces, fallbackTemplates, normalizeTemplate, sourceDatasets, templatesFor,
} from './equipment'

const styles = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'styles.css'), 'utf8')

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
    // Softswitch KPI strip: enrichment counts instead of ASR / average talk.
    expect(main).toContain('label="VoIPmonitor"')
    expect(main).toContain('label="Неразобранное"')
    expect(main).toContain('softswitchUnresolved')
    expect(main).toContain('label="Операторы"')
    expect(main).toContain('label="GeoIP"')
    expect(main).toContain('softswitchTotals.pstnEnrichedCalls')
    expect(main).toContain('softswitchTotals.geoipEnrichedCalls')
    expect(main).toContain('все поля PSTN')
    expect(main).toContain('все поля GeoIP')
    expect(main).toContain('label="Объем данных"')
    expect(main).toContain('formatStorageMB')
    expect(styles).toContain('flex-wrap: nowrap')
    expect(main).toContain('title="Последнее значение АнтиФрода"')
    expect(main).not.toContain('formatVoipmonitorDetail')
    expect(main).not.toContain('label="Софтсвитчи"')
    expect(main).not.toContain('label="Оборудование"')
    expect(main).toContain('fleet-panel')
    expect(main).toContain('className="table-fit"')
    // Compact cols shrink-wrap; flex/pair take remaining width without overflowing.
    expect(styles).toMatch(/\.table-fit[\s\S]*?table-layout:\s*auto/)
    expect(styles).not.toMatch(/\.table-fit[\s\S]*?table-layout:\s*fixed/)
    expect(styles).toMatch(/\.col-flex-pair[^{]*\{[^}]*width:\s*50%/s)
    expect(styles).toMatch(/\.col-flex-3[^{]*\{[^}]*width:\s*33\.333%/s)
    expect(styles).toMatch(/\.col-flex-4[^{]*\{[^}]*width:\s*25%/s)
    expect(styles).toMatch(/\.col-flex-pair[^{,]*,[\s\S]*?max-width:\s*0/)
    expect(styles).toMatch(/td\.col-flex\s*\{[^}]*max-width:\s*0/s)
    expect(main).toContain('satelPresetFlexShare')
    expect(main).toContain('eltexPresetFlexShare')
    expect(styles).toContain('.outcome-row.pstn-absent')
    expect(styles).toContain('.outcome-row.pstn-ineligible')
    expect(main).toContain('pstn-absent')
    expect(main).toContain('Не существует')
    expect(main).toContain('SummaryColumnHeaderFilter')
    expect(main).toContain('column-values')
    expect(main).toContain('createPortal')
    expect(main).toContain('Нет значений за день')
    expect(main).toContain('1 выбрано')
    expect(main).toContain('Очистить «')
    expect(main).toContain('Сбросить фильтры')
    expect(main.indexOf('Сбросить фильтры')).toBeLessThan(main.indexOf('aria-label="Пресет колонок"'))
    expect(main).toContain('satelColumnFiltersActive')
    expect(main).toContain('eltexColumnFiltersActive')
    expect(main).toContain('antifraudFiltersActive')
    expect(main).toContain('ELTEX_FILTER_COLUMNS')
    expect(main).toContain('ANTIFRAUD_FILTER_COLUMNS')
    expect(main).toContain('outgoingRedirectingNumber')
    expect(main).toContain('antifraud-calls/column-values')
    expect(main).toContain('radius_outcome')
    expect(main).toContain('SATEL_FILTER_KEYS_BY_PRESET')
    expect(main).toContain('billAniOperator')
    expect(main).toContain('remoteSrcGeoipIso')
    expect(main).toContain('outOrigDnis')
    expect(main).toContain('cursorGenerationRef')
    expect(main).toContain("matched: 'Связан'")
    expect(main).toMatch(/operators:\s*new Set/)
    expect(main).toMatch(/geoip:\s*new Set/)
    expect(main).toMatch(/all:\s*new Set/)
    // Column-filter surfaces hide toolbar search; syslog find jumps within full day feed.
    expect(main).toContain('dataset === \'syslog\' ? <div className="search syslog-find">')
    expect(main).toContain('Найти за сутки…')
    expect(main).toContain('Скрывать поток')
    expect(main).toContain('syslogHideStream')
    expect(main).toContain('/syslog-messages/find?')
    expect(main).toContain('jumpSyslogToHit')
    expect(styles).toMatch(/\.search\.syslog-find\s*\{[^}]*width:\s*min\(300px/)
    expect(styles).toMatch(/\.toolbar-actions\s*>\s*\.view-toggle[\s\S]*?flex-shrink:\s*0/)
    expect(styles).toMatch(/\.syslog-hide-stream\s*\{/)
    expect(styles).toMatch(/\.syslog-find-hit\s*\{[^}]*background:\s*#4ade80/s)
    expect(styles).toMatch(/\.syslog-find-row-active\s*\{[^}]*background:\s*#fef08a/s)
    expect(main).toContain('!columnFiltersActive && <div className="search">')
    expect(main).toContain('Поиск по данным…')
    expect(main).toContain('menuRef.current?.contains(target)')
    expect(styles).toContain('.col-filter-trigger')
    expect(styles).toMatch(/\.col-filter-trigger\s*\{[^}]*background:\s*transparent/s)
    expect(styles).toContain('.col-filter-menu')
    expect(styles).toContain('position: fixed')
    expect(styles).toContain('.col-filter-count')
    expect(main).toContain('title="Последний CDR"')
    expect(main.indexOf('title="Последний CDR"')).toBeLessThan(
      main.lastIndexOf('title="Последний приём Syslog"'),
    )
    expect(main.lastIndexOf('title="Последний приём Syslog"')).toBeLessThan(
      main.indexOf('title="Последнее значение АнтиФрода"'),
    )
    expect(main).toContain('latestCdrAt, row.activeTimezone || row.timezone || \'UTC\')')
    expect(main).toContain('latestAntifraudAt, row.activeTimezone || row.timezone || \'UTC\')')
    // Timezone label under all three equipment freshness columns.
    expect(main.match(/formatTime\(row\.freshness\.latestCdrAt[\s\S]*?<small>\{row\.activeTimezone/)).toBeTruthy()
    expect(main.match(/formatTime\(row\.freshness\.latestAntifraudAt[\s\S]*?<small>\{row\.activeTimezone/)).toBeTruthy()
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

  it('highlights the active device in the sidebar with green only when device view is open', () => {
    expect(main).toContain(
      "className={`device-button ${activeView === 'device' && device.id === activeDevice ? 'active' : ''}`}",
    )
    expect(styles).toContain('.device-button.active')
    expect(styles).toContain('#d8f5e4')
    expect(styles).toContain('grid-template-columns: 192px')
  })

  it('clamps dataset when a saved device loses the current surface', () => {
    expect(main).toContain('!deviceSurfaces(device).includes(dataset as DeviceSurface)')
    expect(main).toContain('setDataset(defaultSourceDataset(device))')
  })

  it('skips setDevices when the poll fingerprint is unchanged', () => {
    expect(main).toContain('devicesPollFingerprint(current) === devicesPollFingerprint(next)')
    expect(main).toContain('function devicesPollFingerprint(devices: Device[])')
  })

	it('clears open drawers when the table date or dataset reloads', () => {
    expect(main).toContain('setSelectedAntifraud(null)')
    expect(main).toContain('setSelectedCall(null)')
    expect(main).toContain('setSelectedSatelCall(null)')
    expect(main).toContain('setSelectedEvent(null)')
  })

  it('explains matched CDR coverage when AntiFraud detail is missing', () => {
    expect(main).toContain("coverage?.state === 'matched'")
    expect(main).toContain('Связанная цепочка AntiFraud временно недоступна')
    expect(main).toContain('antifraud_detail_unavailable')
    expect(main).toContain('body.detail')
  })

  it('formats softswitch dashboard freshness in the device timezone', () => {
    const softswitchBlock = main.slice(
      main.indexOf('title="Последний CDR"'),
      main.indexOf('Софтсвитчи ещё не добавлены'),
    )
    expect(softswitchBlock).toContain('row.fileMetrics?.latestAt || row.freshness.latestCdrAt')
    expect(softswitchBlock).toContain("row.activeTimezone || row.timezone || 'UTC'")
    expect(softswitchBlock).not.toContain(", 'UTC')")
  })
})
