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

export interface CodepointSets {
  tag: readonly number[]
  bidi: readonly number[]
  zero_width: readonly number[]
}

const encoder = new TextEncoder()

export const FALLBACK_CODEPOINTS: CodepointSets = {
  tag: [CODEPOINT_CLASSES.TAG.LOW, CODEPOINT_CLASSES.TAG.HIGH],
  bidi: CODEPOINT_CLASSES.BIDI,
  zero_width: CODEPOINT_CLASSES.ZERO_WIDTH,
}

export function markOf(
  code: number,
  sets: CodepointSets = FALLBACK_CODEPOINTS
): CensusMark | null {
  const [low, high] = sets.tag
  if (low !== undefined && high !== undefined && code >= low && code <= high) {
    return CENSUS_MARKS.TAG
  }
  if (sets.bidi.includes(code)) {
    return CENSUS_MARKS.BIDI
  }
  if (sets.zero_width.includes(code)) {
    return CENSUS_MARKS.ZERO_WIDTH
  }
  return null
}

export function census(
  text: string,
  sets: CodepointSets = FALLBACK_CODEPOINTS
): Census {
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

    const mark = markOf(code, sets)
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

export function segments(
  text: string,
  sets: CodepointSets = FALLBACK_CODEPOINTS
): Segment[] {
  const output: Segment[] = []
  let offset = 0

  for (const character of text) {
    const mark = markOf(character.codePointAt(0) ?? 0, sets)
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
