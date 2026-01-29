// ===================
// © AngelaMos | 2025
// AuthForm.tsx
// ===================

import { createSignal, Show } from "solid-js"
import type { JSX } from "solid-js"
import { A } from "@solidjs/router"
import { Input } from "../UI/Input"
import { PasskeyButton } from "./PasskeyButton"
import { AuthCard } from "./AuthCard"
import {
  validateUsername,
  validateDisplayName,
} from "../../lib/validators"
import { authService } from "../../services"
import { showToast } from "../../stores"
import { ApiError } from "../../types"

type AuthMode = "login" | "register"

interface AuthFormProps {
  mode: AuthMode
}

export function AuthForm(props: AuthFormProps): JSX.Element {
  const [username, setUsername] = createSignal("")
  const [displayName, setDisplayName] = createSignal("")
  const [loading, setLoading] = createSignal(false)
  const [usernameError, setUsernameError] = createSignal<string | undefined>()
  const [displayNameError, setDisplayNameError] = createSignal<string | undefined>()

  const isRegister = (): boolean => props.mode === "register"

  const title = (): string => isRegister() ? "CREATE ACCOUNT" : "WELCOME BACK"

  const subtitle = (): string =>
    isRegister()
      ? "REGISTER WITH A PASSKEY FOR SECURE, PASSWORDLESS AUTHENTICATION"
      : "SIGN IN WITH YOUR PASSKEY TO CONTINUE"

  const validateForm = (): boolean => {
    let valid = true

    if (isRegister()) {
      const usernameResult = validateUsername(username())
      if (!usernameResult.valid) {
        setUsernameError(usernameResult.error)
        valid = false
      } else {
        setUsernameError(undefined)
      }

      const displayNameResult = validateDisplayName(displayName())
      if (!displayNameResult.valid) {
        setDisplayNameError(displayNameResult.error)
        valid = false
      } else {
        setDisplayNameError(undefined)
      }
    }

    return valid
  }

  const handleSubmit = async (): Promise<void> => {
    if (!validateForm()) {
      return
    }

    setLoading(true)

    try {
      if (isRegister()) {
        await authService.register(username(), displayName())
        showToast("success", "REGISTRATION COMPLETE", "YOUR PASSKEY HAS BEEN CREATED")
      } else {
        const trimmedUsername = username().trim()
        const usernameValue = trimmedUsername === "" ? undefined : trimmedUsername
        await authService.login(usernameValue)
        showToast("success", "LOGIN SUCCESSFUL", "WELCOME BACK")
      }
    } catch (error) {
      let message = "AN UNEXPECTED ERROR OCCURRED"

      if (error instanceof ApiError) {
        message = error.message.toUpperCase()
      } else if (error instanceof Error) {
        if (error.name === "NotAllowedError") {
          message = "PASSKEY OPERATION CANCELLED"
        } else if (error.name === "InvalidStateError") {
          message = "PASSKEY ALREADY REGISTERED"
        } else {
          message = error.message.toUpperCase()
        }
      }

      showToast("error", isRegister() ? "REGISTRATION FAILED" : "LOGIN FAILED", message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthCard title={title()} subtitle={subtitle()}>
      <div class="space-y-4">
        <Show when={isRegister()}>
          <Input
            name="username"
            label="USERNAME"
            placeholder="ENTER USERNAME"
            value={username()}
            onInput={setUsername}
            error={usernameError()}
            required
            disabled={loading()}
            fullWidth
          />

          <Input
            name="displayName"
            label="DISPLAY NAME"
            placeholder="ENTER DISPLAY NAME"
            value={displayName()}
            onInput={setDisplayName}
            error={displayNameError()}
            required
            disabled={loading()}
            fullWidth
          />
        </Show>

        <Show when={!isRegister()}>
          <Input
            name="username"
            label="USERNAME (OPTIONAL)"
            placeholder="LEAVE BLANK FOR DISCOVERABLE"
            value={username()}
            onInput={setUsername}
            hint="LEAVE BLANK TO USE DISCOVERABLE CREDENTIALS"
            disabled={loading()}
            fullWidth
          />
        </Show>

        <div class="pt-2">
          <PasskeyButton
            mode={props.mode}
            onClick={handleSubmit}
            loading={loading()}
          />
        </div>
      </div>

      <div class="mt-6 pt-4 border-t-2 border-dark-gray">
        <p class="font-pixel text-[10px] text-center text-gray">
          <Show
            when={isRegister()}
            fallback={
              <>
                DON'T HAVE AN ACCOUNT?{" "}
                <A href="/register" class="text-orange hover:underline">
                  REGISTER
                </A>
              </>
            }
          >
            ALREADY HAVE AN ACCOUNT?{" "}
            <A href="/login" class="text-orange hover:underline">
              SIGN IN
            </A>
          </Show>
        </p>
      </div>
    </AuthCard>
  )
}
