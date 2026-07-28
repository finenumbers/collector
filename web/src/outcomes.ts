export type CallOutcome = 'success' | 'failure' | 'warning' | 'neutral'

export function cdrOutcome(releaseCause?: number): CallOutcome {
  if (releaseCause == null) return 'neutral'
  return releaseCause === 16 ? 'success' : 'failure'
}

export function outcomeLabel(outcome: CallOutcome): string {
  switch (outcome) {
    case 'success': return 'Успешно'
    case 'failure': return 'Неуспешно'
    case 'warning': return 'Требует внимания'
    default: return 'Нет результата'
  }
}
