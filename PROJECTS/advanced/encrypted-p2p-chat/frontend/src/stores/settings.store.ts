/**
 * User settings store with persistence
 * Stores user preferences in localStorage
 */

import { persistentMap } from "@nanostores/persistent"
import { computed } from "nanostores"

type Theme = "dark" | "light"
type FontSize = "small" | "medium" | "large"
type NotificationSound = "retro" | "subtle" | "none"

interface UserSettings {
  theme: Theme
  fontSize: FontSize
  soundEnabled: boolean
  notificationSound: NotificationSound
  desktopNotifications: boolean
  showTypingIndicators: boolean
  showReadReceipts: boolean
  showOnlineStatus: boolean
  enterToSend: boolean
  compactMode: boolean
}

const DEFAULT_SETTINGS: UserSettings = {
  theme: "dark",
  fontSize: "medium",
  soundEnabled: true,
  notificationSound: "retro",
  desktopNotifications: true,
  showTypingIndicators: true,
  showReadReceipts: true,
  showOnlineStatus: true,
  enterToSend: true,
  compactMode: false,
}

export const $settings = persistentMap<UserSettings>(
  "chat:settings:",
  DEFAULT_SETTINGS,
  {
    encode: JSON.stringify,
    decode: JSON.parse,
  }
)

export const $theme = computed($settings, (settings) => settings.theme)

export const $fontSize = computed($settings, (settings) => settings.fontSize)

export function setTheme(theme: Theme): void {
  $settings.setKey("theme", theme)
}

export function setFontSize(fontSize: FontSize): void {
  $settings.setKey("fontSize", fontSize)
}

export function setSoundEnabled(enabled: boolean): void {
  $settings.setKey("soundEnabled", enabled)
}

export function setNotificationSound(sound: NotificationSound): void {
  $settings.setKey("notificationSound", sound)
}

export function setDesktopNotifications(enabled: boolean): void {
  $settings.setKey("desktopNotifications", enabled)
}

export function setShowTypingIndicators(show: boolean): void {
  $settings.setKey("showTypingIndicators", show)
}

export function setShowReadReceipts(show: boolean): void {
  $settings.setKey("showReadReceipts", show)
}

export function setShowOnlineStatus(show: boolean): void {
  $settings.setKey("showOnlineStatus", show)
}

export function setEnterToSend(enabled: boolean): void {
  $settings.setKey("enterToSend", enabled)
}

export function setCompactMode(enabled: boolean): void {
  $settings.setKey("compactMode", enabled)
}

export function resetSettings(): void {
  $settings.set(DEFAULT_SETTINGS)
}

export function getSettings(): UserSettings {
  return $settings.get()
}

export type { Theme, FontSize, NotificationSound, UserSettings }
