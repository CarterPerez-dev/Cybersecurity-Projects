// ===================
// © AngelaMos | 2025
// EncryptionBadge.tsx
// ===================
import { Show } from "solid-js"
import type { JSX } from "solid-js"

interface EncryptionBadgeProps {
  isEncrypted: boolean
  showLabel?: boolean
  size?: "sm" | "md"
  class?: string
}

export function EncryptionBadge(props: EncryptionBadgeProps): JSX.Element {
  const iconSize = (): string => props.size === "sm" ? "w-3 h-3" : "w-4 h-4"
  const textSize = (): string => props.size === "sm" ? "text-[6px]" : "text-[8px]"

  return (
    <Show when={props.isEncrypted}>
      <div
        class={`flex items-center gap-1 ${props.class ?? ""}`}
        title="END-TO-END ENCRYPTED"
      >
        <LockIcon class={`${iconSize()} text-success`} />
        <Show when={props.showLabel}>
          <span class={`font-pixel ${textSize()} text-success`}>
            E2E
          </span>
        </Show>
      </div>
    </Show>
  )
}

interface LockIconProps {
  class?: string
}

function LockIcon(props: LockIconProps): JSX.Element {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="currentColor"
      class={props.class}
      aria-hidden="true"
    >
      <rect x="5" y="3" width="6" height="1" />
      <rect x="4" y="4" width="1" height="4" />
      <rect x="11" y="4" width="1" height="4" />
      <rect x="3" y="8" width="10" height="1" />
      <rect x="3" y="9" width="10" height="5" />
      <rect x="7" y="11" width="2" height="2" fill="currentColor" class="text-black" />
    </svg>
  )
}

interface UnencryptedBadgeProps {
  showLabel?: boolean
  size?: "sm" | "md"
  class?: string
}

export function UnencryptedBadge(props: UnencryptedBadgeProps): JSX.Element {
  const iconSize = (): string => props.size === "sm" ? "w-3 h-3" : "w-4 h-4"
  const textSize = (): string => props.size === "sm" ? "text-[6px]" : "text-[8px]"

  return (
    <div
      class={`flex items-center gap-1 ${props.class ?? ""}`}
      title="NOT ENCRYPTED"
    >
      <UnlockIcon class={`${iconSize()} text-gray`} />
      <Show when={props.showLabel}>
        <span class={`font-pixel ${textSize()} text-gray`}>
          UNENCRYPTED
        </span>
      </Show>
    </div>
  )
}

function UnlockIcon(props: LockIconProps): JSX.Element {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="currentColor"
      class={props.class}
      aria-hidden="true"
    >
      <rect x="5" y="1" width="6" height="1" />
      <rect x="4" y="2" width="1" height="6" />
      <rect x="11" y="2" width="1" height="2" />
      <rect x="3" y="8" width="10" height="1" />
      <rect x="3" y="9" width="10" height="5" />
      <rect x="7" y="11" width="2" height="2" fill="currentColor" class="text-black" />
    </svg>
  )
}
