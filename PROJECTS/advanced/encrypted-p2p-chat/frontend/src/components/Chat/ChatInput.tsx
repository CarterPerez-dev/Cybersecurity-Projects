// ===================
// © AngelaMos | 2025
// ChatInput.tsx
// ===================
import { createSignal, Show, onCleanup } from "solid-js"
import type { JSX } from "solid-js"
import { Button } from "../UI/Button"
import { wsManager } from "../../websocket"
import { MESSAGE_MAX_LENGTH } from "../../types"

interface ChatInputProps {
  roomId: string
  recipientId: string
  disabled?: boolean
  onSend?: (content: string) => void
  class?: string
}

export function ChatInput(props: ChatInputProps): JSX.Element {
  const [message, setMessage] = createSignal("")
  const [isTyping, setIsTyping] = createSignal(false)
  let typingTimeout: ReturnType<typeof setTimeout> | undefined
  let inputRef: HTMLInputElement | undefined

  const charCount = (): number => message().length
  const isOverLimit = (): boolean => charCount() > MESSAGE_MAX_LENGTH
  const canSend = (): boolean => message().trim().length > 0 && !isOverLimit() && (props.disabled !== true)

  const handleInput = (e: Event): void => {
    const target = e.target as HTMLInputElement
    setMessage(target.value)

    if (!isTyping()) {
      setIsTyping(true)
      wsManager.sendTypingIndicator(props.roomId, true)
    }

    if (typingTimeout !== undefined) {
      clearTimeout(typingTimeout)
    }

    typingTimeout = setTimeout(() => {
      setIsTyping(false)
      wsManager.sendTypingIndicator(props.roomId, false)
    }, 2000)
  }

  const handleSend = (): void => {
    if (!canSend()) return

    const content = message().trim()
    props.onSend?.(content)
    setMessage("")

    if (isTyping()) {
      setIsTyping(false)
      wsManager.sendTypingIndicator(props.roomId, false)
    }

    inputRef?.focus()
  }

  const handleKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  onCleanup(() => {
    if (typingTimeout !== undefined) {
      clearTimeout(typingTimeout)
    }
    if (isTyping()) {
      wsManager.sendTypingIndicator(props.roomId, false)
    }
  })

  return (
    <div class={`flex-shrink-0 p-4 border-t-2 border-orange ${props.class ?? ""}`}>
      <div class="flex gap-2">
        <div class="flex-1 flex items-center bg-black border-2 border-orange">
          <span class="font-pixel text-[10px] text-orange px-2">&gt;&gt;&gt;</span>
          <input
            ref={inputRef}
            type="text"
            value={message()}
            onInput={handleInput}
            onKeyDown={handleKeyDown}
            placeholder="TYPE YOUR MESSAGE..."
            disabled={props.disabled}
            maxLength={MESSAGE_MAX_LENGTH + 100}
            class="flex-1 bg-transparent font-pixel text-[10px] text-white py-2 pr-3 focus:outline-none placeholder:text-gray disabled:opacity-50"
          />
        </div>
        <Button
          variant="primary"
          size="md"
          onClick={handleSend}
          disabled={!canSend()}
          leftIcon={<SendIcon />}
        >
          SEND
        </Button>
      </div>

      <div class="flex items-center justify-between mt-2">
        <Show when={isOverLimit()}>
          <span class="font-pixel text-[8px] text-error">
            MESSAGE TOO LONG
          </span>
        </Show>
        <span class={`font-pixel text-[8px] ml-auto ${isOverLimit() ? "text-error" : "text-gray"}`}>
          {charCount()}/{MESSAGE_MAX_LENGTH}
        </span>
      </div>
    </div>
  )
}

function SendIcon(): JSX.Element {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
      <rect x="0" y="5" width="8" height="2" />
      <rect x="6" y="3" width="2" height="2" />
      <rect x="6" y="7" width="2" height="2" />
      <rect x="8" y="1" width="2" height="4" />
      <rect x="8" y="7" width="2" height="4" />
      <rect x="10" y="3" width="2" height="6" />
    </svg>
  )
}
