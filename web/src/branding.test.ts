import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { inflateSync } from 'node:zlib'
import html from '../index.html?raw'
import main from './main.tsx?raw'

function pngAlphaValues(path: URL) {
  const png = readFileSync(path)
  const width = png.readUInt32BE(16)
  const height = png.readUInt32BE(20)
  expect(png[24]).toBe(8)
  expect(png[25]).toBe(6)
  const idat: Buffer[] = []
  for (let offset = 8; offset < png.length;) {
    const length = png.readUInt32BE(offset)
    const type = png.toString('ascii', offset + 4, offset + 8)
    if (type === 'IDAT') idat.push(png.subarray(offset + 8, offset + 8 + length))
    offset += 12 + length
  }
  const packed = inflateSync(Buffer.concat(idat))
  const stride = width * 4
  const previous = Buffer.alloc(stride)
  const alpha: number[] = []
  let sourceOffset = 0
  for (let y = 0; y < height; y++) {
    const filter = packed[sourceOffset++]
    const row = Buffer.alloc(stride)
    for (let x = 0; x < stride; x++) {
      const raw = packed[sourceOffset++]
      const left = x >= 4 ? row[x - 4] : 0
      const up = previous[x]
      const upperLeft = x >= 4 ? previous[x - 4] : 0
      if (filter === 0) row[x] = raw
      else if (filter === 1) row[x] = raw + left
      else if (filter === 2) row[x] = raw + up
      else if (filter === 3) row[x] = raw + Math.floor((left + up) / 2)
      else if (filter === 4) {
        const p = left + up - upperLeft
        const pa = Math.abs(p - left), pb = Math.abs(p - up), pc = Math.abs(p - upperLeft)
        row[x] = raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upperLeft)
      } else throw new Error(`unsupported PNG filter ${filter}`)
    }
    for (let x = 3; x < stride; x += 4) alpha.push(row[x])
    row.copy(previous)
  }
  return alpha
}

describe('product shell', () => {
  it('publishes the requested browser identity and assets', () => {
    expect(html).toContain('<title>Logs Collector</title>')
    expect(html.match(/<title>[^<]*<\/title>/g)).toEqual(['<title>Logs Collector</title>'])
    expect(html).toContain('href="/favicon.png"')
    expect(main).toContain("import fineNumbersLogoUrl from './assets/fine-numbers-logo-transparent-v2.png'")
    expect(main.match(/src=\{fineNumbersLogoUrl\}/g)).toHaveLength(2)
    expect(main).not.toContain('src="/fine-numbers-logo.png"')
    expect(main).not.toContain('/fine-numbers-logo.png')
  })

  it('ships a genuinely transparent RGBA logo', () => {
    const alpha = pngAlphaValues(new URL('./assets/fine-numbers-logo-transparent-v2.png', import.meta.url))
    expect(alpha).toContain(0)
    expect(alpha).toContain(255)
  })

  it('has no manual CDR profile UI', () => {
    expect(main).not.toContain('Профиль колонок CDR')
    expect(main).not.toContain('cdrColumns')
  })
})
