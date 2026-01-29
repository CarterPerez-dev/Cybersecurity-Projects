// ===================
// © AngelaMos | 2025
// PasskeyButton.tsx
// ===================

import {
  Show,
  createSignal,
  onMount,
} from "solid-js"
import type { JSX } from "solid-js"
import { Button } from "../UI/Button"
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
} from "../../services"

interface PasskeyButtonProps {
  mode: "register" | "login"
  onClick: () => void | Promise<void>
  loading?: boolean
  disabled?: boolean
  class?: string
}

export function PasskeyButton(props: PasskeyButtonProps): JSX.Element {
  const [webAuthnSupported, setWebAuthnSupported] = createSignal(true)
  const [platformAvailable, setPlatformAvailable] = createSignal(false)

  onMount(() => {
    const supported = isWebAuthnSupported()
    setWebAuthnSupported(supported)

    if (supported) {
      void isPlatformAuthenticatorAvailable().then((available) => {
        setPlatformAvailable(available)
      })
    }
  })

  const buttonText = (): string => {
    if (!webAuthnSupported()) {
      return "WEBAUTHN NOT SUPPORTED"
    }
    return props.mode === "register" ? "REGISTER WITH PASSKEY" : "LOGIN WITH PASSKEY"
  }

  const isDisabled = (): boolean => {
    return !webAuthnSupported() || (props.disabled ?? false)
  }

  return (
    <div class={`flex flex-col gap-2 ${props.class ?? ""}`}>
      <Button
        variant="primary"
        size="lg"
        fullWidth
        loading={props.loading}
        disabled={isDisabled()}
        onClick={props.onClick}
        leftIcon={<PasskeyIcon />}
      >
        {buttonText()}
      </Button>

      <Show when={!webAuthnSupported()}>
        <p class="font-pixel text-[8px] text-error text-center">
          YOUR BROWSER DOES NOT SUPPORT PASSKEYS
        </p>
      </Show>

      <Show when={webAuthnSupported() && platformAvailable()}>
        <p class="font-pixel text-[8px] text-success text-center">
          BIOMETRIC AUTH AVAILABLE
        </p>
      </Show>
    </div>
  )
}

function PasskeyIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="2" y="6" width="2" height="6" />
      <rect x="4" y="4" width="2" height="2" />
      <rect x="6" y="2" width="4" height="2" />
      <rect x="10" y="4" width="2" height="2" />
      <rect x="12" y="6" width="2" height="2" />
      <rect x="6" y="8" width="4" height="2" />
      <rect x="4" y="10" width="2" height="2" />
      <rect x="10" y="10" width="2" height="2" />
      <rect x="6" y="12" width="4" height="2" />
    </svg>
  )
}
