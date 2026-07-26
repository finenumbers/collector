export type SourceCategory = 'equipment' | 'softswitch'
export type SourceDataset = 'calls'

export type SourceCapabilities = {
  syslog: boolean
  typedCdr: boolean
  rawCdr: boolean
  antifraud: boolean
  radius: boolean
}

export type EquipmentTemplate = {
  key: string
  category: SourceCategory
  displayName: string
  capabilities: SourceCapabilities
}

export const fallbackTemplates: EquipmentTemplate[] = [
  {
    key: 'eltex-smg-1016m-3.23.2',
    category: 'equipment',
    displayName: 'Eltex SMG-1016M (3.23.2)',
    capabilities: { syslog: true, typedCdr: true, rawCdr: true, antifraud: true, radius: true },
  },
  {
    key: 'eltex-smg-1016m-3.410',
    category: 'equipment',
    displayName: 'Eltex SMG-1016M (3.410)',
    capabilities: { syslog: true, typedCdr: true, rawCdr: true, antifraud: true, radius: true },
  },
  {
    key: 'satel-rtu-cdr-v1',
    category: 'softswitch',
    displayName: 'Satel RTU',
    capabilities: { syslog: false, typedCdr: true, rawCdr: true, antifraud: false, radius: false },
  },
]

export function normalizeTemplate(value: Partial<EquipmentTemplate> & {
  id?: string
  templateKey?: string
  sourceCategory?: SourceCategory
}): EquipmentTemplate {
  const key = value.key || value.templateKey || value.id || ''
  const fallback = fallbackTemplates.find((item) => item.key === key)
  return {
    key,
    category: value.category || value.sourceCategory || fallback?.category || 'equipment',
    displayName: value.displayName || fallback?.displayName || key,
    capabilities: { ...fallback?.capabilities, ...value.capabilities } as SourceCapabilities,
  }
}

export function sourceCategory(value: {
  sourceCategory?: SourceCategory
  templateKey?: string
}): SourceCategory {
  if (value.sourceCategory) return value.sourceCategory
  return fallbackTemplates.find((item) => item.key === value.templateKey)?.category || 'equipment'
}

export function sourceCapabilities(value: {
  capabilities?: SourceCapabilities
  templateKey?: string
}): SourceCapabilities {
  const fallback = fallbackTemplates.find((item) => item.key === value.templateKey)
    || fallbackTemplates[0]
  return { ...fallback.capabilities, ...value.capabilities }
}

export function templatesFor(items: EquipmentTemplate[], category: SourceCategory) {
  return items.filter((item) => item.category === category)
}

export function sourceDatasets(value: {
  capabilities?: SourceCapabilities
  templateKey?: string
}): SourceDataset[] {
  const capabilities = sourceCapabilities(value)
  return capabilities.typedCdr ? ['calls'] : []
}

export function defaultSourceDataset(value: {
  capabilities?: SourceCapabilities
  templateKey?: string
}): SourceDataset {
  return sourceDatasets(value)[0] || 'calls'
}
