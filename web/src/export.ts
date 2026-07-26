export type ExportNavigationDataset =
  'calls' | 'syslog_all' | 'antifraud' | 'alarms' | 'call_trace' | 'sip' | 'isup' |
  'q931' | 'h323' | 'rtp' | 'hardware' | 'ivr' | 'ip_network' | 'ip_connections' |
  'ip_modules' | 'radius' | 'config_history' | 'auth_log' | 'system_journal' | 'unknown'

export type ExportTarget = {
  dataset: 'calls' | 'antifraud' | 'events'
  category?: string
}

export function exportTarget(dataset: ExportNavigationDataset): ExportTarget {
  if (dataset === 'calls' || dataset === 'antifraud') return { dataset }
  return {
    dataset: 'events',
    category: dataset === 'syslog_all' ? 'all' : dataset,
  }
}

export function exportURL(
  deviceID: string,
  navigationDataset: ExportNavigationDataset,
  query: string,
): string {
  const target = exportTarget(navigationDataset)
  const parameters = new URLSearchParams({ dataset: target.dataset, q: query })
  if (target.category) parameters.set('category', target.category)
  return `/api/devices/${deviceID}/export.xlsx?${parameters.toString()}`
}
