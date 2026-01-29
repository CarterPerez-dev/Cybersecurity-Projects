/**
 * Main application shell layout
 */

import type { ParentProps, JSX } from "solid-js"
import { Show } from "solid-js"
import { useStore } from "@nanostores/solid"
import { $sidebarOpen, $isMobile } from "../../stores"
import { Sidebar } from "./Sidebar"
import { Header } from "./Header"

interface AppShellProps extends ParentProps {
  showSidebar?: boolean
  showHeader?: boolean
}

export function AppShell(props: AppShellProps): JSX.Element {
  const sidebarOpen = useStore($sidebarOpen)
  const isMobile = useStore($isMobile)

  const showSidebar = (): boolean => props.showSidebar ?? true
  const showHeader = (): boolean => props.showHeader ?? true

  return (
    <div class="flex flex-col h-screen w-screen overflow-hidden bg-black">
      <Show when={showHeader()}>
        <Header />
      </Show>

      <div class="flex flex-1 overflow-hidden">
        <Show when={showSidebar() && sidebarOpen()}>
          <div class="w-72 h-full border-r-2 border-orange overflow-hidden flex-shrink-0">
            <Sidebar />
          </div>
        </Show>

        <main class="flex-1 overflow-hidden bg-black">
          {props.children}
        </main>
      </div>

      <Show when={isMobile() && sidebarOpen()}>
        <div
          class="fixed inset-0 z-30 bg-black/80"
          onClick={() => $sidebarOpen.set(false)}
        />
      </Show>
    </div>
  )
}
