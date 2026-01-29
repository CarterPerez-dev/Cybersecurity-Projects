/**
 * 8-bit styled tooltip component
 */

import { Show, createSignal, onCleanup } from "solid-js"
import type { JSX } from "solid-js"
import type { TooltipProps } from "../../types"

type TooltipPosition = "top" | "bottom" | "left" | "right"

const POSITION_CLASSES: Record<TooltipPosition, string> = {
  top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
  bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
  left: "right-full top-1/2 -translate-y-1/2 mr-2",
  right: "left-full top-1/2 -translate-y-1/2 ml-2",
}

const ARROW_CLASSES: Record<TooltipPosition, string> = {
  top: "top-full left-1/2 -translate-x-1/2 border-t-orange border-x-transparent border-b-transparent",
  bottom: "bottom-full left-1/2 -translate-x-1/2 border-b-orange border-x-transparent border-t-transparent",
  left: "left-full top-1/2 -translate-y-1/2 border-l-orange border-y-transparent border-r-transparent",
  right: "right-full top-1/2 -translate-y-1/2 border-r-orange border-y-transparent border-l-transparent",
}

const DEFAULT_DELAY_MS = 300

export function Tooltip(props: TooltipProps): JSX.Element {
  const [visible, setVisible] = createSignal(false)
  let timeoutId: ReturnType<typeof setTimeout> | undefined

  const position = (): TooltipPosition => props.position ?? "top"
  const delay = (): number => props.delay ?? DEFAULT_DELAY_MS

  const showTooltip = (): void => {
    timeoutId = setTimeout(() => {
      setVisible(true)
    }, delay())
  }

  const hideTooltip = (): void => {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId)
    }
    setVisible(false)
  }

  onCleanup(() => {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId)
    }
  })

  return (
    <div
      class="relative inline-block"
      role="presentation"
      onMouseEnter={showTooltip}
      onMouseLeave={hideTooltip}
      onFocus={showTooltip}
      onBlur={hideTooltip}
    >
      {props.children}

      <Show when={visible()}>
        <div
          class={`
            absolute z-50 pointer-events-none
            ${POSITION_CLASSES[position()]}
          `}
          role="tooltip"
        >
          <div
            class={`
              relative
              px-2 py-1
              bg-black border-2 border-orange
              font-pixel text-[8px] text-white
              whitespace-nowrap
              shadow-[2px_2px_0_var(--color-orange)]
              animate-fade-in
            `}
          >
            {props.content}
            <span
              class={`
                absolute w-0 h-0
                border-4
                ${ARROW_CLASSES[position()]}
              `}
            />
          </div>
        </div>
      </Show>
    </div>
  )
}
