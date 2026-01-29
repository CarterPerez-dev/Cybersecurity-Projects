// ===================
// © AngelaMos | 2025
// TypingIndicator.tsx
// ===================
import { Show, For } from "solid-js"
import type { JSX } from "solid-js"
import { useStore } from "@nanostores/solid"
import { $activeRoomTypingUsernames } from "../../stores"

interface TypingIndicatorProps {
  class?: string
}

export function TypingIndicator(props: TypingIndicatorProps): JSX.Element {
  const typingUsernames = useStore($activeRoomTypingUsernames)

  const typingText = (): string => {
    const users = typingUsernames()
    if (users.length === 0) return ""
    if (users.length === 1) return `${users[0]} IS TYPING`
    if (users.length === 2) return `${users[0]} AND ${users[1]} ARE TYPING`
    return `${users[0]} AND ${users.length - 1} OTHERS ARE TYPING`
  }

  return (
    <Show when={typingUsernames().length > 0}>
      <div class={`flex items-center gap-2 ${props.class ?? ""}`}>
        <TypingDots />
        <span class="font-pixel text-[8px] text-gray">
          {typingText()}
        </span>
      </div>
    </Show>
  )
}

function TypingDots(): JSX.Element {
  return (
    <div class="flex items-center gap-1">
      <For each={[0, 1, 2]}>
        {(index) => (
          <div
            class="w-1 h-1 bg-orange animate-bounce-pixel"
            style={{ "animation-delay": `${index * 150}ms` }}
          />
        )}
      </For>
    </div>
  )
}

interface TypingIndicatorInlineProps {
  usernames: string[]
  class?: string
}

export function TypingIndicatorInline(props: TypingIndicatorInlineProps): JSX.Element {
  const typingText = (): string => {
    const users = props.usernames
    if (users.length === 0) return ""
    if (users.length === 1) return `${users[0]} IS TYPING`
    if (users.length === 2) return `${users[0]} AND ${users[1]} ARE TYPING`
    return `${users[0]} AND ${users.length - 1} OTHERS ARE TYPING`
  }

  return (
    <Show when={props.usernames.length > 0}>
      <div class={`flex items-center gap-2 ${props.class ?? ""}`}>
        <TypingDots />
        <span class="font-pixel text-[8px] text-gray">
          {typingText()}
        </span>
      </div>
    </Show>
  )
}
