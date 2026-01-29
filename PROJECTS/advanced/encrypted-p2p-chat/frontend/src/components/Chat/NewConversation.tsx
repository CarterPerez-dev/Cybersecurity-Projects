// ===================
// © AngelaMos | 2025
// NewConversation.tsx
// ===================
import { createSignal, Show } from "solid-js"
import type { JSX } from "solid-js"
import { Modal } from "../UI/Modal"
import { Button } from "../UI/Button"
import { UserSearch } from "./UserSearch"
import type { User } from "../../types"
import { showToast } from "../../stores"

interface NewConversationProps {
  isOpen: boolean
  onClose: () => void
  onCreateRoom: (userId: string) => Promise<void>
}

export function NewConversation(props: NewConversationProps): JSX.Element {
  const [selectedUser, setSelectedUser] = createSignal<User | null>(null)
  const [loading, setLoading] = createSignal(false)

  const handleUserSelect = (user: User): void => {
    setSelectedUser(user)
  }

  const handleCreate = async (): Promise<void> => {
    const user = selectedUser()
    if (user === null) return

    setLoading(true)

    try {
      await props.onCreateRoom(user.id)
      showToast("success", "CHAT CREATED", `STARTED CONVERSATION WITH ${user.display_name.toUpperCase()}`)
      handleClose()
    } catch (_error: unknown) {
      showToast("error", "FAILED TO CREATE CHAT", "PLEASE TRY AGAIN")
    } finally {
      setLoading(false)
    }
  }

  const handleClose = (): void => {
    setSelectedUser(null)
    setLoading(false)
    props.onClose()
  }

  return (
    <Modal
      isOpen={props.isOpen}
      onClose={handleClose}
      title="NEW CONVERSATION"
      size="md"
    >
      <div class="space-y-4">
        <div>
          <label class="font-pixel text-[10px] text-gray block mb-2">
            SEARCH FOR A USER
          </label>
          <UserSearch
            onSelect={handleUserSelect}
            placeholder="ENTER USERNAME..."
          />
        </div>

        <Show when={selectedUser()} keyed>
          {(user) => (
            <div class="p-3 border-2 border-orange">
              <p class="font-pixel text-[8px] text-gray mb-2">SELECTED USER</p>
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 border-2 border-orange flex items-center justify-center">
                  <span class="font-pixel text-[10px] text-orange">
                    {user.display_name.slice(0, 2).toUpperCase()}
                  </span>
                </div>
                <div>
                  <div class="font-pixel text-[10px] text-white">
                    {user.display_name}
                  </div>
                  <div class="font-pixel text-[8px] text-gray">
                    @{user.username}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedUser(null)}
                  class="ml-auto w-6 h-6 flex items-center justify-center border-2 border-gray text-gray hover:border-error hover:text-error transition-colors"
                  aria-label="Remove selection"
                >
                  <CloseIcon />
                </button>
              </div>
            </div>
          )}
        </Show>

        <div class="flex items-center gap-3 pt-4 border-t-2 border-dark-gray">
          <Button
            variant="secondary"
            size="md"
            onClick={handleClose}
            fullWidth
          >
            CANCEL
          </Button>
          <Button
            variant="primary"
            size="md"
            onClick={() => void handleCreate()}
            disabled={selectedUser() === null || loading()}
            loading={loading()}
            fullWidth
          >
            START CHAT
          </Button>
        </div>
      </div>
    </Modal>
  )
}

function CloseIcon(): JSX.Element {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor">
      <rect x="1" y="2" width="2" height="2" />
      <rect x="2" y="3" width="2" height="2" />
      <rect x="3" y="4" width="2" height="2" />
      <rect x="4" y="3" width="2" height="2" />
      <rect x="5" y="2" width="2" height="2" />
      <rect x="6" y="3" width="2" height="2" />
      <rect x="7" y="2" width="2" height="2" />
      <rect x="4" y="5" width="2" height="2" />
      <rect x="3" y="6" width="2" height="2" />
      <rect x="2" y="7" width="2" height="2" />
      <rect x="5" y="6" width="2" height="2" />
      <rect x="6" y="7" width="2" height="2" />
    </svg>
  )
}
