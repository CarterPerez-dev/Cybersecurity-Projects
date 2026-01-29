/**
 * 8-bit styled button component
 */

import { Show, splitProps } from "solid-js"
import type { JSX } from "solid-js"
import type { ButtonProps, Size, ButtonVariant } from "../../types"
import { Spinner } from "./Spinner"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "px-2 py-1 text-[8px]",
  sm: "px-3 py-1.5 text-[10px]",
  md: "px-4 py-2 text-xs",
  lg: "px-6 py-3 text-sm",
  xl: "px-8 py-4 text-base",
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: `
    bg-black text-white border-2 border-orange
    hover:bg-orange hover:text-black
    active:translate-x-[2px] active:translate-y-[2px]
    shadow-pixel hover:shadow-none active:shadow-none
  `,
  secondary: `
    bg-black text-orange border-2 border-dark-gray
    hover:border-orange hover:text-white
    active:translate-x-[2px] active:translate-y-[2px]
  `,
  ghost: `
    bg-transparent text-orange border-2 border-transparent
    hover:border-orange hover:bg-black/50
    active:translate-x-[2px] active:translate-y-[2px]
  `,
  danger: `
    bg-black text-white border-2 border-error
    hover:bg-error hover:text-white
    active:translate-x-[2px] active:translate-y-[2px]
    shadow-[4px_4px_0_var(--color-error)] hover:shadow-none active:shadow-none
  `,
}

const DISABLED_CLASSES = `
  opacity-50 cursor-not-allowed
  hover:bg-black hover:text-white
  active:translate-x-0 active:translate-y-0
  shadow-none
`

export function Button(props: ButtonProps): JSX.Element {
  const [local, rest] = splitProps(props, [
    "variant",
    "size",
    "fullWidth",
    "disabled",
    "loading",
    "leftIcon",
    "rightIcon",
    "type",
    "onClick",
    "class",
    "children",
  ])

  const variant = (): ButtonVariant => local.variant ?? "primary"
  const size = (): Size => local.size ?? "md"
  const isDisabled = (): boolean => local.disabled ?? false
  const isLoading = (): boolean => local.loading ?? false

  const handleClick = (): void => {
    if (!isDisabled() && !isLoading() && local.onClick !== undefined) {
      local.onClick()
    }
  }

  return (
    <button
      type={local.type ?? "button"}
      disabled={isDisabled() || isLoading()}
      onClick={handleClick}
      class={`
        font-pixel inline-flex items-center justify-center gap-2
        transition-all duration-100 select-none
        focus:outline-none focus:ring-2 focus:ring-orange focus:ring-offset-2 focus:ring-offset-black
        ${SIZE_CLASSES[size()]}
        ${VARIANT_CLASSES[variant()]}
        ${(isDisabled() || isLoading()) ? DISABLED_CLASSES : ""}
        ${local.fullWidth === true ? "w-full" : ""}
        ${local.class ?? ""}
      `}
      {...rest}
    >
      <Show when={isLoading()}>
        <Spinner size="xs" />
      </Show>
      <Show when={!isLoading() && local.leftIcon}>
        {local.leftIcon}
      </Show>
      <span>{local.children}</span>
      <Show when={!isLoading() && local.rightIcon}>
        {local.rightIcon}
      </Show>
    </button>
  )
}
