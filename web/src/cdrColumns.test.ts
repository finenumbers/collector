import { describe, expect, it } from 'vitest'
import {
  CDR_PRESETS,
  ELTEX_CDR_COLUMNS,
  SATEL_CDR_COLUMNS,
  defaultCdrPresetId,
  resolvePresetColumns,
} from './cdrColumns'

describe('CDR column presets', () => {
  it('ships «Все данные» as the default preset', () => {
    expect(CDR_PRESETS).toEqual([{ id: 'all', label: 'Все данные' }])
    expect(defaultCdrPresetId()).toBe('all')
  })

  it('resolves eltex all-columns without rawFields or ingest keys', () => {
    const columns = resolvePresetColumns('eltex', 'all')
    const keys = columns.map((column) => column.key)
    expect(keys).toEqual(ELTEX_CDR_COLUMNS.map((column) => column.key))
    expect(keys).not.toContain('rawFields')
    expect(keys).not.toContain('deviceId')
    expect(keys).not.toContain('fileId')
    expect(keys).not.toContain('rowNumber')
    expect(keys).not.toContain('ingestedAt')
    expect(keys).toContain('setupTime')
    expect(keys).toContain('incomingSipCallId')
    expect(keys).toContain('radiusSessionId')
  })

  it('resolves satel all-columns without rawFields', () => {
    const columns = resolvePresetColumns('satel', 'all')
    const keys = columns.map((column) => column.key)
    expect(keys).toEqual(SATEL_CDR_COLUMNS.map((column) => column.key))
    expect(keys).not.toContain('rawFields')
    expect(keys).toContain('inAni')
    expect(keys).toContain('srcMediaPacketsLost')
    expect(keys).toContain('signalNodeName')
  })

  it('falls back to all columns for unknown preset ids', () => {
    expect(resolvePresetColumns('eltex', 'unknown').length).toBe(ELTEX_CDR_COLUMNS.length)
    expect(resolvePresetColumns('satel', 'unknown').length).toBe(SATEL_CDR_COLUMNS.length)
  })
})
