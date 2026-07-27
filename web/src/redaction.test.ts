import { describe, expect, it } from 'vitest'
import { redactDisplayText, redactDisplayValue } from './redaction'

describe('frontend defense-in-depth redaction', () => {
  it('redacts payload assignments and authorization values', () => {
    const value = redactDisplayText('User-Password=hunter2 Authorization: Bearer abc.def')
    expect(value).not.toContain('hunter2')
    expect(value).not.toContain('abc.def')
  })

  it('redacts nested secret-like object keys', () => {
    expect(redactDisplayValue({ apiKey: 'secret', safe: 'visible' })).toEqual({
      apiKey: '[REDACTED]', safe: 'visible',
    })
  })
})
