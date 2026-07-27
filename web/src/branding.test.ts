import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { inflateSync } from 'node:zlib'
import html from '../index.html?raw'
import main from './main.tsx?raw'

type DecodedPng = {
  width: number
  height: number
  rgba: Buffer
}

function decodePng(path: URL): DecodedPng {
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
  const rgba = Buffer.alloc(stride * height)
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
    row.copy(rgba, y * stride)
    row.copy(previous)
  }
  return { width, height, rgba }
}

function pixel(png: DecodedPng, x: number, y: number) {
  const offset = (y * png.width + x) * 4
  return [...png.rgba.subarray(offset, offset + 4)]
}

describe('product shell', () => {
  it('publishes the requested browser identity and assets', () => {
    expect(html).toContain('<title>Logs Collector</title>')
    expect(html.match(/<title>[^<]*<\/title>/g)).toEqual(['<title>Logs Collector</title>'])
    expect(html).toContain('href="/favicon.png"')
    expect(main).toContain("import fineNumbersLogoUrl from './assets/fine-numbers-logo-transparent-v3.png'")
    expect(main.match(/src=\{fineNumbersLogoUrl\}/g)).toHaveLength(2)
    expect(main).not.toContain('fine-numbers-logo-transparent-v2.png')
    expect(main).not.toContain('src="/fine-numbers-logo.png"')
    expect(main).not.toContain('/fine-numbers-logo.png')
    expect(existsSync(new URL('./assets/fine-numbers-logo-transparent-v2.png', import.meta.url))).toBe(false)
    expect(existsSync(new URL('../public/fine-numbers-logo.png', import.meta.url))).toBe(false)
  })

  it('ships a clean transparent RGBA logo without enclosed black matte', () => {
    const png = decodePng(new URL('./assets/fine-numbers-logo-transparent-v3.png', import.meta.url))
    expect([png.width, png.height]).toEqual([1024, 273])

    // Corners, open canvas, and enclosed counters that flood-fill missed.
    for (const [x, y] of [[0, 0], [1023, 0], [300, 100], [590, 80], [740, 200]]) {
      expect(pixel(png, x, y), `expected transparent pixel at ${x},${y}`).toEqual([0, 0, 0, 0])
    }

    expect(pixel(png, 20, 20)).toEqual([35, 31, 32, 255])
    expect(pixel(png, 360, 80)).toEqual([35, 31, 32, 255])
    expect(pixel(png, 100, 100)).toEqual([255, 255, 255, 255])
    expect(pixel(png, 130, 75)).toEqual([255, 235, 0, 255])

    const alpha = [...png.rgba].filter((_, index) => index % 4 === 3)
    expect(alpha).toContain(0)
    expect(alpha).toContain(255)
    expect(alpha.some((value) => value > 0 && value < 255)).toBe(true)
  })

  it('has no manual CDR profile editor UI', () => {
    expect(main).not.toContain('Профиль колонок CDR')
  })
})
