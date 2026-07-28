import { describe, expect, it } from 'vitest'
import main from './main.tsx?raw'
import { readModelNotice } from './readModelNotice'

const aligned = {
  timezone: 'Asia/Novosibirsk',
  activeTimezone: 'Asia/Novosibirsk',
  timezoneRevision: 2,
  activeTimezoneRevision: 2,
}

describe('dashboard and read-model timezone messaging', () => {
  it('renders raw receive freshness in the active timezone and labels both', () => {
    expect(main).toContain('title="Последний приём Syslog"')
    expect(main).toContain('Последний приём Syslog')
    expect(main).toContain(
      "formatTime(row.freshness.latestSyslogAt, row.activeTimezone || row.timezone || 'UTC')",
    )
    expect(main).toContain("Активный: {row.activeTimezone || row.timezone || 'UTC'}")
    expect(main).toContain("<small>{row.activeTimezone || row.timezone || 'UTC'}</small>")
  })

  it('uses timezone rebuild wording only for an actual timezone change', () => {
    expect(readModelNotice({
      ...aligned,
      timezone: 'Europe/Moscow',
      timezoneRevision: 3,
    })).toContain('Часовой пояс меняется с Asia/Novosibirsk на Europe/Moscow')

    const technical = readModelNotice({
      ...aligned,
      timezoneRevision: 3,
    })
    expect(technical).toContain('Техническая синхронизация read model')
    expect(technical).not.toContain('Часовой пояс меняется')
  })

  it('keeps initial build distinct from revision catch-up', () => {
    expect(readModelNotice(aligned, {
      activeRevision: 0,
      revisionAligned: false,
    })).toContain('создаётся первый согласованный read model для Syslog, CDR и Custom AntiFraud')
    expect(readModelNotice(aligned, {
      activeRevision: 2,
      revisionAligned: false,
    })).toContain('Техническая синхронизация read model')
    expect(readModelNotice(aligned, {
      activeRevision: 2,
      revisionAligned: true,
    })).toBeNull()
  })

  it('keeps timezone wording throughout atomic cutover', () => {
    expect(readModelNotice({
      timezone: 'Europe/Moscow',
      activeTimezone: 'Europe/Moscow',
      timezoneRevision: 3,
      activeTimezoneRevision: 3,
    }, {
      activeRevision: 2,
      activeRevisionTimezone: 'Asia/Novosibirsk',
      revisionAligned: false,
      revisionReason: 'timezone_change',
    })).toContain('Часовой пояс меняется с Asia/Novosibirsk на Europe/Moscow')
  })
})
