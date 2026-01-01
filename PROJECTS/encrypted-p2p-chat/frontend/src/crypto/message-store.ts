// ===================
// © AngelaMos | 2025
// message-store.ts
// ===================
import type { Message } from "../types"

const DB_NAME = "encrypted-chat-messages"
const DB_VERSION = 1

const STORES = {
  MESSAGES: "decrypted_messages",
} as const

let db: IDBDatabase | null = null

async function openDatabase(): Promise<IDBDatabase> {
  if (db !== null) return db

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => {
      reject(new Error("Failed to open message database"))
    }

    request.onsuccess = () => {
      db = request.result
      resolve(db)
    }

    request.onupgradeneeded = (event) => {
      const database = (event.target as IDBOpenDBRequest).result

      if (!database.objectStoreNames.contains(STORES.MESSAGES)) {
        const messageStore = database.createObjectStore(STORES.MESSAGES, { keyPath: "id" })
        messageStore.createIndex("room_id", "room_id", { unique: false })
        messageStore.createIndex("created_at", "created_at", { unique: false })
        messageStore.createIndex("room_created", ["room_id", "created_at"], { unique: false })
      }
    }
  })
}

async function performTransaction<T>(
  storeName: string,
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, mode)
    const store = transaction.objectStore(storeName)
    const request = operation(store)

    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error(request.error?.message ?? "Database operation failed"))
  })
}

export async function saveDecryptedMessage(message: Message): Promise<void> {
  await performTransaction(
    STORES.MESSAGES,
    "readwrite",
    (store) => store.put(message)
  )
}

export async function saveDecryptedMessages(messages: Message[]): Promise<void> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.MESSAGES, "readwrite")
    const store = transaction.objectStore(STORES.MESSAGES)

    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new Error(transaction.error?.message ?? "Failed to save messages"))

    for (const message of messages) {
      store.put(message)
    }
  })
}

export async function getDecryptedMessage(messageId: string): Promise<Message | null> {
  const result = await performTransaction<Message | undefined>(
    STORES.MESSAGES,
    "readonly",
    (store) => store.get(messageId) as IDBRequest<Message | undefined>
  )

  return result ?? null
}

export async function getDecryptedMessages(roomId: string, limit?: number): Promise<Message[]> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.MESSAGES, "readonly")
    const store = transaction.objectStore(STORES.MESSAGES)
    const index = store.index("room_id")
    const request = index.getAll(roomId)

    request.onsuccess = () => {
      let results = request.result as Message[]
      results = results.sort(
        (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
      )

      if (limit !== undefined && limit > 0) {
        results = results.slice(-limit)
      }

      resolve(results)
    }

    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to get messages"))
  })
}

export async function getLatestMessageTimestamp(roomId: string): Promise<string | null> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.MESSAGES, "readonly")
    const store = transaction.objectStore(STORES.MESSAGES)
    const index = store.index("room_created")
    const range = IDBKeyRange.bound([roomId, ""], [roomId, "\uffff"])
    const request = index.openCursor(range, "prev")

    request.onsuccess = () => {
      const cursor = request.result
      if (cursor !== null) {
        const message = cursor.value as Message
        resolve(message.created_at)
      } else {
        resolve(null)
      }
    }

    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to get latest timestamp"))
  })
}

export async function deleteMessage(messageId: string): Promise<void> {
  await performTransaction(
    STORES.MESSAGES,
    "readwrite",
    (store) => store.delete(messageId)
  )
}

export async function updateMessageId(oldId: string, newId: string): Promise<void> {
  const message = await getDecryptedMessage(oldId)
  if (message) {
    await deleteMessage(oldId)
    message.id = newId
    await saveDecryptedMessage(message)
  }
}

export async function clearRoomMessages(roomId: string): Promise<void> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.MESSAGES, "readwrite")
    const store = transaction.objectStore(STORES.MESSAGES)
    const index = store.index("room_id")
    const request = index.openCursor(IDBKeyRange.only(roomId))

    request.onsuccess = () => {
      const cursor = request.result
      if (cursor !== null) {
        cursor.delete()
        cursor.continue()
      }
    }

    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new Error(transaction.error?.message ?? "Failed to clear room messages"))
  })
}

export async function clearAllMessages(): Promise<void> {
  await performTransaction(
    STORES.MESSAGES,
    "readwrite",
    (store) => store.clear()
  )
}

export async function getMessageCount(roomId: string): Promise<number> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.MESSAGES, "readonly")
    const store = transaction.objectStore(STORES.MESSAGES)
    const index = store.index("room_id")
    const request = index.count(IDBKeyRange.only(roomId))

    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to count messages"))
  })
}

export function closeDatabase(): void {
  if (db !== null) {
    db.close()
    db = null
  }
}
