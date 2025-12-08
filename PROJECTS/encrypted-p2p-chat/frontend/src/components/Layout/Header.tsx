/**
 * 8-bit styled header/navbar component
 */

import type { JSX } from "solid-js"
import { Show } from "solid-js"
import { A } from "@solidjs/router"
import { useStore } from "@nanostores/solid"
import {
  $isAuthenticated,
  $sidebarOpen,
  toggleSidebar,
  openModal,
} from "../../stores"
import { IconButton } from "../UI/IconButton"
import { Badge } from "../UI/Badge"

export function Header(): JSX.Element {
  const isAuthenticated = useStore($isAuthenticated)
  const sidebarOpen = useStore($sidebarOpen)

  return (
    <header class="flex-shrink-0 bg-black border-b-4 border-orange">
      <div class="flex items-center justify-between h-14 px-4">
        <div class="flex items-center gap-3">
          <Show when={isAuthenticated()}>
            <IconButton
              icon={sidebarOpen() ? <CloseMenuIcon /> : <MenuIcon />}
              ariaLabel={sidebarOpen() ? "Close menu" : "Open menu"}
              onClick={toggleSidebar}
              size="sm"
            />
          </Show>

          <A href="/" class="flex items-center gap-2 hover:no-underline">
            <LockIcon />
            <h1 class="font-pixel text-sm text-orange uppercase hidden sm:block">
              ENCRYPTED CHAT
            </h1>
            <h1 class="font-pixel text-sm text-orange uppercase sm:hidden">
              E-CHAT
            </h1>
          </A>

          <Badge variant="primary" size="xs">
            E2EE
          </Badge>
        </div>

        <nav class="flex items-center gap-2">
          <Show
            when={isAuthenticated()}
            fallback={
              <>
                <A
                  href="/login"
                  class="font-pixel text-[10px] text-white hover:text-orange px-3 py-2"
                >
                  LOGIN
                </A>
                <A
                  href="/register"
                  class="font-pixel text-[10px] bg-orange text-black px-3 py-2 hover:bg-white"
                >
                  REGISTER
                </A>
              </>
            }
          >
            <IconButton
              icon={<SearchIcon />}
              ariaLabel="Search"
              size="sm"
              onClick={() => openModal("new-conversation")}
            />
          </Show>
        </nav>
      </div>
    </header>
  )
}

function MenuIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="2" y="3" width="12" height="2" />
      <rect x="2" y="7" width="12" height="2" />
      <rect x="2" y="11" width="12" height="2" />
    </svg>
  )
}

function CloseMenuIcon(): JSX.Element {
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

function LockIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <rect x="6" y="3" width="8" height="2" fill="currentColor" class="text-orange" />
      <rect x="4" y="5" width="2" height="4" fill="currentColor" class="text-orange" />
      <rect x="14" y="5" width="2" height="4" fill="currentColor" class="text-orange" />
      <rect x="3" y="9" width="14" height="2" fill="currentColor" class="text-orange" />
      <rect x="3" y="11" width="14" height="6" fill="currentColor" class="text-orange" />
      <rect x="9" y="12" width="2" height="4" fill="currentColor" class="text-black" />
    </svg>
  )
}

function SearchIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="4" y="2" width="6" height="2" />
      <rect x="2" y="4" width="2" height="6" />
      <rect x="10" y="4" width="2" height="6" />
      <rect x="4" y="10" width="6" height="2" />
      <rect x="10" y="10" width="2" height="2" />
      <rect x="12" y="12" width="2" height="2" />
    </svg>
  )
}
