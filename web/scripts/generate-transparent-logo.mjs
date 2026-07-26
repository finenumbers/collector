#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import jpeg from 'jpeg-js'
import { PNG } from 'pngjs'

const sourcePath = process.argv[2]
const outputPath = process.argv[3] ?? 'src/assets/fine-numbers-logo-transparent-v3.png'

if (!sourcePath) {
  console.error('Usage: node scripts/generate-transparent-logo.mjs <source-jpeg> [output-png]')
  process.exit(1)
}

const source = jpeg.decode(readFileSync(resolve(sourcePath)), {
  formatAsRGBA: true,
  useTArray: true,
})
const output = new PNG({ width: source.width, height: source.height })

const darkBrand = [35, 31, 32]
const blackNoiseFloor = 2
const iconRightEdge = Math.round(source.height)

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value))
}

function darkMatteFit(red, green, blue) {
  // Solve source = alpha * brandColor over a black matte. Subtracting the
  // measured JPEG noise floor makes near-black ringing fully transparent.
  const clean = [
    Math.max(0, red - blackNoiseFloor),
    Math.max(0, green - blackNoiseFloor),
    Math.max(0, blue - blackNoiseFloor),
  ]
  const numerator = clean.reduce((sum, channel, index) => sum + channel * darkBrand[index], 0)
  const denominator = darkBrand.reduce((sum, channel) => sum + channel * channel, 0)
  const rawAlpha = clamp(numerator / denominator, 0, 1)
  const colorDistance = Math.sqrt(
    clean.reduce((sum, channel, index) => {
      const difference = channel - rawAlpha * darkBrand[index]
      return sum + difference * difference
    }, 0),
  )
  const colorConfidence = 1 - clamp((colorDistance - 3) / 12, 0, 1)
  const separatedAlpha = rawAlpha >= 0.85 ? 1 : clamp((rawAlpha - 0.12) / 0.73, 0, 1)
  return { rawAlpha, alpha: separatedAlpha * colorConfidence }
}

for (let y = 0; y < source.height; y += 1) {
  for (let x = 0; x < source.width; x += 1) {
    const offset = (y * source.width + x) * 4
    const red = source.data[offset]
    const green = source.data[offset + 1]
    const blue = source.data[offset + 2]
    const matte = darkMatteFit(red, green, blue)
    const alpha = matte.alpha
    const isInsideIconCore = x >= 3
      && x < iconRightEdge - 2
      && y >= 3
      && y < source.height - 3
    const isInsideOpaqueIcon = x < iconRightEdge
      && (isInsideIconCore || matte.rawAlpha >= 0.85)

    if (!isInsideOpaqueIcon && alpha < 0.01) {
      output.data[offset] = 0
      output.data[offset + 1] = 0
      output.data[offset + 2] = 0
      output.data[offset + 3] = 0
      continue
    }

    if (isInsideOpaqueIcon) {
      // The white/yellow glyph was already composited onto the opaque square.
      // Keep its antialiasing, while normalizing solid brand-color interiors.
      const isYellow = red > 160 && green > 120 && blue < 80
      const isWhite = red > 220 && green > 220 && blue > 220
      const isDark = red < 55 && green < 55 && blue < 55
      const color = isYellow
        ? [255, 235, 0]
        : isWhite
          ? [255, 255, 255]
          : isDark
            ? darkBrand
            : [red, green, blue]
      output.data[offset] = color[0]
      output.data[offset + 1] = color[1]
      output.data[offset + 2] = color[2]
      output.data[offset + 3] = 255
      continue
    }

    // Store unassociated brand RGB with reconstructed alpha. This removes the
    // black component from antialiased edges and prevents dark matte halos.
    output.data[offset] = darkBrand[0]
    output.data[offset + 1] = darkBrand[1]
    output.data[offset + 2] = darkBrand[2]
    output.data[offset + 3] = Math.round(alpha * 255)
  }
}

writeFileSync(
  resolve(outputPath),
  PNG.sync.write(output, {
    colorType: 6,
    inputColorType: 6,
    bitDepth: 8,
    deflateLevel: 9,
    deflateStrategy: 3,
  }),
)
