export type CallOutcome = 'success' | 'failure' | 'warning' | 'neutral'

export function cdrOutcome(releaseCause?: number): CallOutcome {
  if (releaseCause == null) return 'neutral'
  return releaseCause === 16 ? 'success' : 'failure'
}

export function antifraudOutcome(row: {
  q850Cause?: number
  decision?: string
  completeness?: string
}): CallOutcome {
  if (row.q850Cause != null) return cdrOutcome(row.q850Cause)
  if (row.decision === 'reject') return 'failure'
  if (row.decision === 'accept' && row.completeness === 'complete') return 'success'
  if (row.decision === 'timeout_fail_open') return 'warning'
  return 'neutral'
}

export function outcomeLabel(outcome: CallOutcome): string {
  switch (outcome) {
    case 'success': return 'Успешно'
    case 'failure': return 'Неуспешно'
    case 'warning': return 'Требует внимания'
    default: return 'Нет результата'
  }
}
