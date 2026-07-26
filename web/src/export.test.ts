import { describe, expect, it } from 'vitest'
import { exportTarget, exportURL, type ExportNavigationDataset } from './export'

describe('export navigation mapping', () => {
  it.each([
    ['calls', { dataset: 'calls' }],
    ['antifraud', { dataset: 'antifraud' }],
    ['syslog_all', { dataset: 'events', category: 'all' }],
    ['alarms', { dataset: 'events', category: 'alarms' }],
    ['call_trace', { dataset: 'events', category: 'call_trace' }],
    ['sip', { dataset: 'events', category: 'sip' }],
    ['isup', { dataset: 'events', category: 'isup' }],
    ['q931', { dataset: 'events', category: 'q931' }],
    ['h323', { dataset: 'events', category: 'h323' }],
    ['rtp', { dataset: 'events', category: 'rtp' }],
    ['hardware', { dataset: 'events', category: 'hardware' }],
    ['ivr', { dataset: 'events', category: 'ivr' }],
    ['ip_network', { dataset: 'events', category: 'ip_network' }],
    ['ip_connections', { dataset: 'events', category: 'ip_connections' }],
    ['ip_modules', { dataset: 'events', category: 'ip_modules' }],
    ['radius', { dataset: 'events', category: 'radius' }],
    ['config_history', { dataset: 'events', category: 'config_history' }],
    ['auth_log', { dataset: 'events', category: 'auth_log' }],
    ['system_journal', { dataset: 'events', category: 'system_journal' }],
    ['unknown', { dataset: 'events', category: 'unknown' }],
  ] as const)('maps %s to its backend export target', (dataset, expected) => {
    expect(exportTarget(dataset)).toEqual(expected)
  })

  it('omits category for calls and safely encodes search values', () => {
    const url = exportURL('device-id', 'calls' satisfies ExportNavigationDataset, '+7 999&x')
    expect(url).toBe('/api/devices/device-id/export.xlsx?dataset=calls&q=%2B7+999%26x')
    expect(url).not.toContain('category=')
  })
})
