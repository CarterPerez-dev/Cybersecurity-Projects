/**
 * Home page - landing or redirect to chat
 */

import type { JSX } from "solid-js"
import { Show } from "solid-js"
import { A } from "@solidjs/router"
import { useStore } from "@nanostores/solid"
import { $isAuthenticated } from "../stores"
import { Button } from "../components/UI"

export default function Home(): JSX.Element {
  const isAuthenticated = useStore($isAuthenticated)

  return (
    <div class="min-h-screen flex flex-col items-center justify-center bg-black p-4">
      <div class="text-center max-w-lg">
        <div class="mb-8">
          <LockIcon />
        </div>

        <h1 class="font-pixel text-2xl text-orange mb-4">
          ENCRYPTED CHAT
        </h1>

        <p class="font-pixel text-[10px] text-gray mb-8 leading-relaxed">
          END-TO-END ENCRYPTED MESSAGING WITH DOUBLE RATCHET PROTOCOL.
          YOUR MESSAGES ARE SECURE AND PRIVATE.
        </p>

        <div class="flex flex-col gap-4 items-center">
          <Show
            when={isAuthenticated()}
            fallback={
              <>
                <A href="/register">
                  <Button variant="primary" size="lg">
                    GET STARTED
                  </Button>
                </A>
                <A href="/login">
                  <Button variant="secondary" size="md">
                    SIGN IN
                  </Button>
                </A>
              </>
            }
          >
            <A href="/chat">
              <Button variant="primary" size="lg">
                GO TO CHAT
              </Button>
            </A>
          </Show>
        </div>

        <div class="mt-12 grid grid-cols-3 gap-4">
          <FeatureItem icon={<EncryptIcon />} label="E2E ENCRYPTED" />
          <FeatureItem icon={<KeyIcon />} label="PASSKEY AUTH" />
          <FeatureItem icon={<ShieldIcon />} label="NO PASSWORDS" />
        </div>
      </div>
    </div>
  )
}

interface FeatureItemProps {
  icon: JSX.Element
  label: string
}

function FeatureItem(props: FeatureItemProps): JSX.Element {
  return (
    <div class="flex flex-col items-center gap-2">
      <div class="text-orange">{props.icon}</div>
      <span class="font-pixel text-[8px] text-gray">{props.label}</span>
    </div>
  )
}

function LockIcon(): JSX.Element {
  return (
    <svg width="64" height="64" viewBox="0 0 64 64" fill="none" class="mx-auto">
      <rect x="20" y="12" width="24" height="4" fill="currentColor" class="text-orange" />
      <rect x="16" y="16" width="4" height="16" fill="currentColor" class="text-orange" />
      <rect x="44" y="16" width="4" height="16" fill="currentColor" class="text-orange" />
      <rect x="12" y="32" width="40" height="4" fill="currentColor" class="text-orange" />
      <rect x="12" y="36" width="40" height="20" fill="currentColor" class="text-orange" />
      <rect x="30" y="42" width="4" height="8" fill="currentColor" class="text-black" />
    </svg>
  )
}

function EncryptIcon(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
      <rect x="10" y="2" width="4" height="4" />
      <rect x="6" y="6" width="4" height="4" />
      <rect x="14" y="6" width="4" height="4" />
      <rect x="2" y="10" width="4" height="4" />
      <rect x="18" y="10" width="4" height="4" />
      <rect x="6" y="14" width="4" height="4" />
      <rect x="14" y="14" width="4" height="4" />
      <rect x="10" y="18" width="4" height="4" />
    </svg>
  )
}

function KeyIcon(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
      <rect x="4" y="8" width="4" height="4" />
      <rect x="8" y="4" width="4" height="4" />
      <rect x="8" y="12" width="4" height="4" />
      <rect x="12" y="8" width="8" height="4" />
      <rect x="16" y="12" width="4" height="4" />
      <rect x="20" y="12" width="4" height="4" />
    </svg>
  )
}

function ShieldIcon(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
      <rect x="10" y="2" width="4" height="2" />
      <rect x="6" y="4" width="4" height="2" />
      <rect x="14" y="4" width="4" height="2" />
      <rect x="4" y="6" width="2" height="8" />
      <rect x="18" y="6" width="2" height="8" />
      <rect x="6" y="14" width="2" height="4" />
      <rect x="16" y="14" width="2" height="4" />
      <rect x="8" y="18" width="2" height="2" />
      <rect x="14" y="18" width="2" height="2" />
      <rect x="10" y="20" width="4" height="2" />
    </svg>
  )
}
