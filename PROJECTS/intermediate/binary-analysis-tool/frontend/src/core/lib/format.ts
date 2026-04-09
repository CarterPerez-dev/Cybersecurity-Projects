// ===================
// © AngelaMos | 2026
// format.ts
//
// Display formatting utilities for binary analysis
// values
//
// formatBytes converts raw byte counts to human-readable
// strings (B/KB/MB/GB) using 1024-based units with two
// decimal places above bytes. formatHex renders numbers
// as zero-padded uppercase hex strings (default 8 chars).
// truncateHash shortens SHA-256 digests to a display
// length (default 16 chars) with an ellipsis. copyTo
// Clipboard wraps the Clipboard API with a boolean
// success/failure return
//
// Connects to:
//   pages/analysis  - hex formatting, hash display
//   pages/landing   - byte size display
// ===================

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB'] as const
const BYTES_PER_UNIT = 1024
const DEFAULT_HEX_PAD = 8
const DEFAULT_HASH_DISPLAY_LENGTH = 16

export function formatBytes(bytes: number): string {
  let unitIndex = 0
  let value = bytes
  while (value >= BYTES_PER_UNIT && unitIndex < BYTE_UNITS.length - 1) {
    value /= BYTES_PER_UNIT
    unitIndex++
  }
  const decimals = unitIndex === 0 ? 0 : 2
  return `${value.toFixed(decimals)} ${BYTE_UNITS[unitIndex]}`
}

export function formatHex(value: number, pad: number = DEFAULT_HEX_PAD): string {
  return `0x${value.toString(16).toUpperCase().padStart(pad, '0')}`
}

export function truncateHash(
  hash: string,
  length: number = DEFAULT_HASH_DISPLAY_LENGTH
): string {
  if (hash.length <= length) return hash
  return `${hash.slice(0, length)}\u2026`
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
