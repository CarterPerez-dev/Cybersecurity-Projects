/**
 * 8-bit styled auth card container
 */

import type { ParentProps, JSX } from "solid-js"
import { Show } from "solid-js"

interface AuthCardProps extends ParentProps {
  title: string
  subtitle?: string
}

export function AuthCard(props: AuthCardProps): JSX.Element {
  return (
    <div class="w-full max-w-md">
      <div
        class="
          bg-black border-4 border-orange
          shadow-[8px_8px_0_var(--color-orange)]
          p-6
        "
      >
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-4">
            <LockIcon />
            <h1 class="font-pixel text-lg text-orange uppercase">
              {props.title}
            </h1>
          </div>

          <Show when={props.subtitle}>
            <p class="font-pixel text-[10px] text-gray leading-relaxed">
              {props.subtitle}
            </p>
          </Show>
        </div>

        {props.children}
      </div>

      <div class="mt-4 flex justify-center">
        <span class="font-pixel text-[8px] text-gray">
          END-TO-END ENCRYPTED
        </span>
      </div>
    </div>
  )
}

function LockIcon(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <rect x="7" y="4" width="10" height="2" fill="currentColor" class="text-orange" />
      <rect x="5" y="6" width="2" height="5" fill="currentColor" class="text-orange" />
      <rect x="17" y="6" width="2" height="5" fill="currentColor" class="text-orange" />
      <rect x="4" y="11" width="16" height="2" fill="currentColor" class="text-orange" />
      <rect x="4" y="13" width="16" height="8" fill="currentColor" class="text-orange" />
      <rect x="11" y="15" width="2" height="4" fill="currentColor" class="text-black" />
    </svg>
  )
}
