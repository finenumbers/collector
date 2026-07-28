import { describe, expect, it } from 'vitest'
import { cdrOutcome, outcomeLabel } from './outcomes'

describe('call outcome semantics', () => {
  it('classifies CDR by Q.850 normal clearing', () => {
    expect(cdrOutcome(16)).toBe('success')
    expect(cdrOutcome(21)).toBe('failure')
    expect(cdrOutcome()).toBe('neutral')
  })

  it('labels outcomes for table badges', () => {
    expect(outcomeLabel('success')).toBe('Успешно')
    expect(outcomeLabel('failure')).toBe('Неуспешно')
    expect(outcomeLabel('warning')).toBe('Требует внимания')
    expect(outcomeLabel('neutral')).toBe('Нет результата')
  })
})
