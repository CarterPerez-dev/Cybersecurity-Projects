// ===================
// © AngelaMos | 2026
// census.ts
// ===================

import { CENSUS_MARKS, type CensusMark, CODEPOINT_CLASSES } from '@/config'

export interface Census {
  glyphs: number
  bytes: number
  nonAscii: number
  tag: number
  bidi: number
  zeroWidth: number
}

export interface Segment {
  start: number
  text: string
  mark: CensusMark | null
}

interface Range {
  LOW: number
  HIGH: number
}

const encoder = new TextEncoder()

function inRange(code: number, range: Range): boolean {
  return code >= range.LOW && code <= range.HIGH
}

function inAnyRange(code: number, ranges: readonly Range[]): boolean {
  return ranges.some((range) => inRange(code, range))
}

export function markOf(code: number): CensusMark | null {
  if (inRange(code, CODEPOINT_CLASSES.TAG)) {
    return CENSUS_MARKS.TAG
  }
  if (inAnyRange(code, CODEPOINT_CLASSES.BIDI)) {
    return CENSUS_MARKS.BIDI
  }
  if (inAnyRange(code, CODEPOINT_CLASSES.ZERO_WIDTH)) {
    return CENSUS_MARKS.ZERO_WIDTH
  }
  return null
}

export function census(text: string): Census {
  const counts: Census = {
    glyphs: 0,
    bytes: encoder.encode(text).length,
    nonAscii: 0,
    tag: 0,
    bidi: 0,
    zeroWidth: 0,
  }

  for (const character of text) {
    const code = character.codePointAt(0) ?? 0
    counts.glyphs += 1

    if (code > CODEPOINT_CLASSES.ASCII_HIGH) {
      counts.nonAscii += 1
    }

    const mark = markOf(code)
    if (mark === CENSUS_MARKS.TAG) {
      counts.tag += 1
    } else if (mark === CENSUS_MARKS.BIDI) {
      counts.bidi += 1
    } else if (mark === CENSUS_MARKS.ZERO_WIDTH) {
      counts.zeroWidth += 1
    }
  }

  return counts
}

export function hiddenTotal(counts: Census): number {
  return counts.tag + counts.bidi + counts.zeroWidth
}

export function segments(text: string): Segment[] {
  const output: Segment[] = []
  let offset = 0

  for (const character of text) {
    const mark = markOf(character.codePointAt(0) ?? 0)
    const previous = output.at(-1)

    if (previous !== undefined && previous.mark === null && mark === null) {
      previous.text += character
    } else {
      output.push({ start: offset, text: character, mark })
    }

    offset += character.length
  }

  return output
}
