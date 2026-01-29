/**
 * 8-bit styled input component
 */

import { Show, splitProps, createSignal } from "solid-js"
import type { JSX } from "solid-js"
import type { InputProps } from "../../types"

export function Input(props: InputProps): JSX.Element {
  const [local, rest] = splitProps(props, [
    "type",
    "name",
    "placeholder",
    "value",
    "onInput",
    "onChange",
    "onFocus",
    "onBlur",
    "disabled",
    "error",
    "label",
    "hint",
    "leftIcon",
    "rightIcon",
    "fullWidth",
    "maxLength",
    "minLength",
    "required",
    "autofocus",
    "class",
  ])

  const [focused, setFocused] = createSignal(false)

  const handleInput: JSX.EventHandler<HTMLInputElement, InputEvent> = (e) => {
    if (local.onInput !== undefined) {
      local.onInput(e.currentTarget.value)
    }
  }

  const handleChange: JSX.EventHandler<HTMLInputElement, Event> = (e) => {
    if (local.onChange !== undefined) {
      local.onChange(e.currentTarget.value)
    }
  }

  const hasError = (): boolean => Boolean(local.error)
  const isDisabled = (): boolean => local.disabled ?? false

  return (
    <div class={`flex flex-col gap-1 ${local.fullWidth === true ? "w-full" : ""}`}>
      <Show when={local.label}>
        <label
          class="font-pixel text-[10px] text-orange uppercase tracking-wider"
          for={local.name}
        >
          {local.label}
          <Show when={local.required}>
            <span class="text-error ml-1">*</span>
          </Show>
        </label>
      </Show>

      <div
        class={`
          relative flex items-center
          bg-black border-2
          transition-all duration-100
          ${focused() ? "border-orange shadow-[0_0_0_2px_var(--color-orange)]" : "border-dark-gray"}
          ${hasError() ? "border-error shadow-[0_0_0_2px_var(--color-error)]" : ""}
          ${isDisabled() ? "opacity-50 cursor-not-allowed" : ""}
        `}
      >
        <Show when={local.leftIcon}>
          <span class="pl-3 text-gray">{local.leftIcon}</span>
        </Show>

        <input
          type={local.type ?? "text"}
          name={local.name}
          id={local.name}
          placeholder={local.placeholder}
          value={local.value ?? ""}
          disabled={isDisabled()}
          maxLength={local.maxLength}
          minLength={local.minLength}
          required={local.required}
          autofocus={local.autofocus}
          onInput={handleInput}
          onChange={handleChange}
          onFocus={() => {
            setFocused(true)
            local.onFocus?.()
          }}
          onBlur={() => {
            setFocused(false)
            local.onBlur?.()
          }}
          class={`
            w-full bg-transparent font-pixel text-[16px] text-white
            px-3 py-2
            placeholder:font-placeholder placeholder:text-[16px] placeholder:text-gray
            focus:outline-none
            disabled:cursor-not-allowed
            ${local.leftIcon !== undefined ? "pl-1" : ""}
            ${local.rightIcon !== undefined ? "pr-1" : ""}
            ${local.class ?? ""}
          `}
          {...rest}
        />

        <Show when={local.rightIcon}>
          <span class="pr-3 text-gray">{local.rightIcon}</span>
        </Show>
      </div>

      <Show when={local.error}>
        <span class="font-pixel text-[8px] text-error">{local.error}</span>
      </Show>

      <Show when={local.hint && !local.error}>
        <span class="font-pixel text-[8px] text-gray">{local.hint}</span>
      </Show>
    </div>
  )
}
