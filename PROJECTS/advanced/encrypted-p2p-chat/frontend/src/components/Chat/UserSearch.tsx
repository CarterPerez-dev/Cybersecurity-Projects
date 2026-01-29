// ===================
// © AngelaMos | 2025
// UserSearch.tsx
// ===================
import { createSignal, Show, For, onCleanup } from "solid-js"
import type { JSX } from "solid-js"
import { Input } from "../UI/Input"
import { Spinner } from "../UI/Spinner"
import { api } from "../../lib/api-client"
import { USER_SEARCH_MIN_LENGTH, USER_SEARCH_DEFAULT_LIMIT } from "../../config"
import type { User } from "../../types"

interface UserSearchProps {
  onSelect: (user: User) => void
  excludeIds?: string[]
  placeholder?: string
  class?: string
}

interface SearchResult {
  users: User[]
  loading: boolean
  error: string | null
}

export function UserSearch(props: UserSearchProps): JSX.Element {
  const [query, setQuery] = createSignal("")
  const [result, setResult] = createSignal<SearchResult>({
    users: [],
    loading: false,
    error: null,
  })
  const [isFocused, setIsFocused] = createSignal(false)

  let searchTimeout: ReturnType<typeof setTimeout> | undefined

  const handleInput = (value: string): void => {
    setQuery(value)

    if (searchTimeout !== undefined) {
      clearTimeout(searchTimeout)
    }

    if (value.trim().length < USER_SEARCH_MIN_LENGTH) {
      setResult({ users: [], loading: false, error: null })
      return
    }

    setResult((prev) => ({ ...prev, loading: true }))

    searchTimeout = setTimeout(() => {
      void searchUsers(value.trim())
    }, 300)
  }

  const searchUsers = async (searchQuery: string): Promise<void> => {
    try {
      const response = await api.users.search({
        query: searchQuery,
        limit: USER_SEARCH_DEFAULT_LIMIT,
      })
      setResult({ users: response.users, loading: false, error: null })
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Search failed"
      setResult({ users: [], loading: false, error: errorMessage })
    }
  }

  const handleSelect = (user: User): void => {
    props.onSelect(user)
    setQuery("")
    setResult({ users: [], loading: false, error: null })
    setIsFocused(false)
  }

  const filteredUsers = (): User[] => {
    const excludeSet = new Set(props.excludeIds ?? [])
    return result().users.filter((u) => !excludeSet.has(u.id))
  }

  const showResults = (): boolean => {
    return isFocused() && (result().loading || filteredUsers().length > 0 || result().error !== null)
  }

  onCleanup(() => {
    if (searchTimeout !== undefined) {
      clearTimeout(searchTimeout)
    }
  })

  return (
    <div class={`relative ${props.class ?? ""}`}>
      <Input
        name="user-search"
        placeholder={props.placeholder ?? "SEARCH USERS..."}
        value={query()}
        onInput={handleInput}
        onFocus={() => setIsFocused(true)}
        onBlur={() => setTimeout(() => setIsFocused(false), 200)}
        fullWidth
        leftIcon={<SearchIcon />}
      />

      <Show when={showResults()}>
        <div class="absolute top-full left-0 right-0 mt-1 bg-black border-2 border-orange max-h-64 overflow-y-auto scrollbar-pixel z-50">
          <Show when={result().loading}>
            <div class="flex items-center justify-center py-4">
              <Spinner size="sm" />
            </div>
          </Show>

          <Show when={result().error}>
            <div class="p-3">
              <span class="font-pixel text-[10px] text-error">
                {result().error}
              </span>
            </div>
          </Show>

          <Show when={!result().loading && !result().error}>
            <For each={filteredUsers()}>
              {(user) => (
                <button
                  type="button"
                  class="w-full p-3 flex items-center gap-3 hover:bg-orange hover:text-black transition-colors"
                  onClick={() => handleSelect(user)}
                >
                  <div class="w-8 h-8 border-2 border-orange flex items-center justify-center flex-shrink-0">
                    <span class="font-pixel text-[8px] text-orange">
                      {user.display_name.slice(0, 2).toUpperCase()}
                    </span>
                  </div>
                  <div class="text-left min-w-0">
                    <div class="font-pixel text-[10px] truncate">
                      {user.display_name}
                    </div>
                    <div class="font-pixel text-[8px] text-gray truncate">
                      @{user.username}
                    </div>
                  </div>
                </button>
              )}
            </For>
          </Show>

          <Show when={!result().loading && !result().error && filteredUsers().length === 0 && query().length >= USER_SEARCH_MIN_LENGTH}>
            <div class="p-3">
              <span class="font-pixel text-[10px] text-gray">
                NO USERS FOUND
              </span>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  )
}

function SearchIcon(): JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor" class="text-gray">
      <rect x="4" y="1" width="4" height="1" />
      <rect x="2" y="2" width="2" height="1" />
      <rect x="8" y="2" width="2" height="1" />
      <rect x="1" y="3" width="1" height="2" />
      <rect x="10" y="3" width="1" height="2" />
      <rect x="1" y="5" width="1" height="2" />
      <rect x="10" y="5" width="1" height="2" />
      <rect x="2" y="7" width="2" height="1" />
      <rect x="8" y="7" width="2" height="1" />
      <rect x="4" y="8" width="4" height="1" />
      <rect x="9" y="9" width="2" height="2" />
      <rect x="11" y="11" width="2" height="2" />
    </svg>
  )
}
