/**
 * 8-bit styled dropdown menu component
 */

import { Show, For, createSignal, onCleanup, createEffect } from "solid-js"
import type { JSX } from "solid-js"
import type { DropdownProps, DropdownItem } from "../../types"

type DropdownAlign = "left" | "right"

export function Dropdown(props: DropdownProps): JSX.Element {
  const [isOpen, setIsOpen] = createSignal(false)
  let containerRef: HTMLDivElement | undefined

  const align = (): DropdownAlign => props.align ?? "left"

  const getItemClasses = (item: DropdownItem): string => {
    if (item.disabled === true) {
      return "text-gray cursor-not-allowed"
    }
    if (item.danger === true) {
      return "text-error hover:bg-error hover:text-white"
    }
    return "text-white hover:bg-orange hover:text-black"
  }

  const getItemActiveClass = (item: DropdownItem): string => {
    return item.disabled === true ? "" : "active:translate-x-[1px] active:translate-y-[1px]"
  }

  const handleToggle = (): void => {
    setIsOpen(!isOpen())
  }

  const handleSelect = (item: DropdownItem): void => {
    if (item.disabled === true) return
    props.onSelect(item.value)
    setIsOpen(false)
  }

  const handleClickOutside = (e: MouseEvent): void => {
    if (containerRef !== undefined && !containerRef.contains(e.target as Node)) {
      setIsOpen(false)
    }
  }

  const handleKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      setIsOpen(false)
    }
  }

  createEffect(() => {
    if (isOpen()) {
      document.addEventListener("click", handleClickOutside)
      document.addEventListener("keydown", handleKeyDown)
    }

    onCleanup(() => {
      document.removeEventListener("click", handleClickOutside)
      document.removeEventListener("keydown", handleKeyDown)
    })
  })

  return (
    <div
      ref={containerRef}
      class={`relative inline-block ${props.class ?? ""}`}
    >
      <div
        role="button"
        tabIndex={0}
        onClick={handleToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault()
            handleToggle()
          }
        }}
      >
        {props.trigger}
      </div>

      <Show when={isOpen()}>
        <div
          class={`
            absolute z-40 mt-1 min-w-[160px]
            bg-black border-2 border-orange
            shadow-[4px_4px_0_var(--color-orange)]
            animate-scale-in origin-top
            ${align() === "right" ? "right-0" : "left-0"}
          `}
          role="menu"
        >
          <For each={props.items}>
            {(item) => (
              <button
                type="button"
                role="menuitem"
                disabled={item.disabled}
                onClick={() => handleSelect(item)}
                class={`
                  w-full flex items-center gap-2 px-3 py-2
                  font-pixel text-[10px] text-left
                  transition-colors duration-100
                  ${getItemClasses(item)}
                  ${getItemActiveClass(item)}
                `}
              >
                <Show when={item.icon}>
                  <span class="flex-shrink-0">{item.icon}</span>
                </Show>
                <span class="flex-1">{item.label}</span>
              </button>
            )}
          </For>
        </div>
      </Show>
    </div>
  )
}
