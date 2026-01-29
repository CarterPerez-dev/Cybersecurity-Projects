/**
 * 8-bit styled modal component
 */

import { Show, createEffect, onCleanup } from "solid-js"
import type { JSX } from "solid-js"
import type { ModalProps, Size } from "../../types"
import { IconButton } from "./IconButton"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "max-w-xs",
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-xl",
}

export function Modal(props: ModalProps): JSX.Element {
  const size = (): Size => props.size ?? "md"
  const closeOnOverlayClick = (): boolean => props.closeOnOverlayClick ?? true
  const showCloseButton = (): boolean => props.showCloseButton ?? true

  const handleOverlayClick = (e: MouseEvent): void => {
    if (e.target === e.currentTarget && closeOnOverlayClick()) {
      props.onClose()
    }
  }

  const handleKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      props.onClose()
    }
  }

  createEffect(() => {
    if (props.isOpen) {
      document.addEventListener("keydown", handleKeyDown)
      document.body.style.overflow = "hidden"
    }

    onCleanup(() => {
      document.removeEventListener("keydown", handleKeyDown)
      document.body.style.overflow = ""
    })
  })

  const handleOverlayKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault()
      if (closeOnOverlayClick()) {
        props.onClose()
      }
    }
  }

  return (
    <Show when={props.isOpen}>
      <div
        class="fixed inset-0 z-50 flex items-center justify-center p-4"
        role="button"
        tabIndex={0}
        onClick={handleOverlayClick}
        onKeyDown={handleOverlayKeyDown}
        aria-label="Close modal overlay"
      >
        <div class="absolute inset-0 bg-black/80 animate-fade-in" />

        <div
          class={`
            relative z-10 w-full
            bg-black border-4 border-orange
            shadow-[8px_8px_0_var(--color-orange)]
            animate-scale-in
            ${SIZE_CLASSES[size()]}
          `}
          role="dialog"
          aria-modal="true"
          aria-labelledby={props.title ? "modal-title" : undefined}
        >
          <Show when={(props.title !== undefined && props.title !== "") || showCloseButton()}>
            <div class="flex items-start justify-between p-4 border-b-2 border-orange">
              <div class="flex-1">
                <Show when={props.title}>
                  <h2
                    id="modal-title"
                    class="font-pixel text-sm text-orange uppercase"
                  >
                    {props.title}
                  </h2>
                </Show>
                <Show when={props.description}>
                  <p class="font-pixel text-[10px] text-gray mt-1">
                    {props.description}
                  </p>
                </Show>
              </div>

              <Show when={showCloseButton()}>
                <IconButton
                  icon={<CloseIcon />}
                  ariaLabel="Close modal"
                  onClick={props.onClose}
                  size="sm"
                  variant="ghost"
                />
              </Show>
            </div>
          </Show>

          <div class="p-4">
            {props.children}
          </div>
        </div>
      </div>
    </Show>
  )
}

function CloseIcon(): JSX.Element {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M2 2L14 14M14 2L2 14"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="square"
      />
    </svg>
  )
}
