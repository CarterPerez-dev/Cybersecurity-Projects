/**
 * 8-bit styled toast notification component
 */

import { For, Show } from "solid-js"
import type { JSX } from "solid-js"
import type { ToastProps } from "../../types"
import { $toasts, dismissToast } from "../../stores"
import { useStore } from "@nanostores/solid"
import { IconButton } from "./IconButton"

type ToastVariant = "info" | "success" | "warning" | "error"

const VARIANT_CLASSES: Record<ToastVariant, string> = {
  info: "border-info text-info",
  success: "border-success text-success",
  warning: "border-orange text-orange",
  error: "border-error text-error",
}

const VARIANT_ICONS: Record<ToastVariant, () => JSX.Element> = {
  info: InfoIcon,
  success: CheckIcon,
  warning: WarningIcon,
  error: ErrorIcon,
}

export function Toast(props: ToastProps): JSX.Element {
  const handleDismiss = (): void => {
    dismissToast(props.id)
  }

  return (
    <div
      class={`
        flex items-start gap-3 p-4
        bg-black border-2
        shadow-[4px_4px_0_currentColor]
        animate-slide-in-right
        ${VARIANT_CLASSES[props.variant]}
      `}
      role="alert"
    >
      <span class="flex-shrink-0 mt-0.5">
        {VARIANT_ICONS[props.variant]()}
      </span>

      <div class="flex-1 min-w-0">
        <p class="font-pixel text-[10px] text-white uppercase">
          {props.title}
        </p>
        <Show when={props.description}>
          <p class="font-pixel text-[8px] text-gray mt-1">
            {props.description}
          </p>
        </Show>
        <Show when={props.action} keyed>
          {(action) => (
            <button
              onClick={() => action.onClick()}
              class="font-pixel text-[8px] text-orange hover:underline mt-2"
            >
              {action.label}
            </button>
          )}
        </Show>
      </div>

      <IconButton
        icon={<CloseIcon />}
        ariaLabel="Dismiss"
        onClick={handleDismiss}
        size="xs"
        variant="ghost"
      />
    </div>
  )
}

export function ToastContainer(): JSX.Element {
  const toasts = useStore($toasts)

  return (
    <div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      <For each={toasts()}>
        {(toast) => <Toast {...toast} />}
      </For>
    </div>
  )
}

function InfoIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="3" width="2" height="2" />
      <rect x="7" y="7" width="2" height="6" />
    </svg>
  )
}

function CheckIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="3" y="8" width="2" height="2" />
      <rect x="5" y="10" width="2" height="2" />
      <rect x="7" y="8" width="2" height="2" />
      <rect x="9" y="6" width="2" height="2" />
      <rect x="11" y="4" width="2" height="2" />
    </svg>
  )
}

function WarningIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="2" width="2" height="8" />
      <rect x="7" y="12" width="2" height="2" />
    </svg>
  )
}

function ErrorIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="3" y="3" width="2" height="2" />
      <rect x="5" y="5" width="2" height="2" />
      <rect x="7" y="7" width="2" height="2" />
      <rect x="9" y="9" width="2" height="2" />
      <rect x="11" y="11" width="2" height="2" />
      <rect x="11" y="3" width="2" height="2" />
      <rect x="9" y="5" width="2" height="2" />
      <rect x="5" y="9" width="2" height="2" />
      <rect x="3" y="11" width="2" height="2" />
    </svg>
  )
}

function CloseIcon(): JSX.Element {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
      <rect x="2" y="2" width="2" height="2" />
      <rect x="4" y="4" width="2" height="2" />
      <rect x="6" y="4" width="2" height="2" />
      <rect x="8" y="2" width="2" height="2" />
      <rect x="2" y="8" width="2" height="2" />
      <rect x="4" y="6" width="2" height="2" />
      <rect x="6" y="6" width="2" height="2" />
      <rect x="8" y="8" width="2" height="2" />
    </svg>
  )
}
