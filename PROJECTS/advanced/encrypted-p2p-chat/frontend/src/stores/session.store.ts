/**
 * Session tokens store with persistence
 * Stores authentication tokens in localStorage
 */

import { persistentMap, persistentAtom } from "@nanostores/persistent"

interface SessionTokens {
  accessToken: string
  refreshToken: string
  expiresAt: number
}

const DEFAULT_TOKENS: SessionTokens = {
  accessToken: "",
  refreshToken: "",
  expiresAt: 0,
}

export const $sessionTokens = persistentMap<SessionTokens>(
  "chat:session:",
  DEFAULT_TOKENS,
  {
    encode: JSON.stringify,
    decode: JSON.parse,
  }
)

export const $lastActivity = persistentAtom<string>(
  "chat:last_activity",
  "",
  {
    encode: String,
    decode: String,
  }
)

export function setSessionTokens(
  accessToken: string,
  refreshToken: string,
  expiresInSeconds: number
): void {
  const expiresAt = Date.now() + expiresInSeconds * 1000
  $sessionTokens.set({
    accessToken,
    refreshToken,
    expiresAt,
  })
  updateLastActivity()
}

export function clearSessionTokens(): void {
  $sessionTokens.set(DEFAULT_TOKENS)
}

export function isSessionValid(): boolean {
  const tokens = $sessionTokens.get()
  if (tokens.accessToken === "") {
    return false
  }
  return tokens.expiresAt > Date.now()
}

export function getAccessToken(): string | null {
  if (!isSessionValid()) {
    return null
  }
  return $sessionTokens.get().accessToken
}

export function getRefreshToken(): string | null {
  const tokens = $sessionTokens.get()
  return tokens.refreshToken !== "" ? tokens.refreshToken : null
}

export function updateLastActivity(): void {
  $lastActivity.set(new Date().toISOString())
}

export function getLastActivity(): Date | null {
  const activity = $lastActivity.get()
  return activity !== "" ? new Date(activity) : null
}
