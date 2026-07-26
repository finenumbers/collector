import { describe, expect, it } from 'vitest'
import html from '../index.html?raw'
import main from './main.tsx?raw'

describe('product shell', () => {
  it('publishes the requested browser identity and assets', () => {
    expect(html).toContain('<title>Logs Collector</title>')
    expect(html).toContain('href="/favicon.png"')
    expect(main).toContain('src="/fine-numbers-logo.png"')
  })

  it('has no manual CDR profile UI', () => {
    expect(main).not.toContain('Профиль колонок CDR')
    expect(main).not.toContain('cdrColumns')
  })
})
