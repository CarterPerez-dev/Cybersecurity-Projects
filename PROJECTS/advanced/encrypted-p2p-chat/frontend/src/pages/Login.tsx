/**
 * Login page with WebAuthn passkey authentication
 */

import type { JSX } from "solid-js"
import { AuthForm } from "../components/Auth"
import { GuestRoute } from "../components/Layout"

export default function Login(): JSX.Element {
  return (
    <GuestRoute>
      <div class="min-h-screen flex items-center justify-center bg-black p-4">
        <AuthForm mode="login" />
      </div>
    </GuestRoute>
  )
}
