/**
 * 404 Not Found page
 */

import type { JSX } from "solid-js"
import { A } from "@solidjs/router"
import { Button } from "../components/UI"

export default function NotFound(): JSX.Element {
  return (
    <div class="min-h-screen flex flex-col items-center justify-center bg-black p-4">
      <div class="text-center">
        <h1 class="font-pixel text-6xl text-orange mb-4">
          404
        </h1>

        <p class="font-pixel text-sm text-white mb-2">
          PAGE NOT FOUND
        </p>

        <p class="font-pixel text-[10px] text-gray mb-8">
          THE PAGE YOU ARE LOOKING FOR DOES NOT EXIST
        </p>

        <A href="/">
          <Button variant="primary" size="lg">
            GO HOME
          </Button>
        </A>
      </div>
    </div>
  )
}
