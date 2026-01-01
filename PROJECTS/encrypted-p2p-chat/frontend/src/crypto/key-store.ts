// ===================
// © AngelaMos | 2025
// key-store.ts
// ===================
import type {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  SerializedRatchetState,
} from "../types"

const DB_NAME = "encrypted-chat-keys"
const DB_VERSION = 1

const STORES = {
  IDENTITY: "identity_keys",
  SIGNED_PREKEYS: "signed_prekeys",
  ONE_TIME_PREKEYS: "one_time_prekeys",
  RATCHET_STATES: "ratchet_states",
} as const

let db: IDBDatabase | null = null

async function openDatabase(): Promise<IDBDatabase> {
  if (db !== null) return db

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => {
      reject(new Error("Failed to open key database"))
    }

    request.onsuccess = () => {
      db = request.result
      resolve(db)
    }

    request.onupgradeneeded = (event) => {
      const database = (event.target as IDBOpenDBRequest).result

      if (!database.objectStoreNames.contains(STORES.IDENTITY)) {
        database.createObjectStore(STORES.IDENTITY, { keyPath: "userId" })
      }

      if (!database.objectStoreNames.contains(STORES.SIGNED_PREKEYS)) {
        const signedStore = database.createObjectStore(STORES.SIGNED_PREKEYS, { keyPath: "id" })
        signedStore.createIndex("userId", "userId", { unique: false })
      }

      if (!database.objectStoreNames.contains(STORES.ONE_TIME_PREKEYS)) {
        const otpStore = database.createObjectStore(STORES.ONE_TIME_PREKEYS, { keyPath: "id" })
        otpStore.createIndex("userId", "userId", { unique: false })
        otpStore.createIndex("isUsed", "is_used", { unique: false })
      }

      if (!database.objectStoreNames.contains(STORES.RATCHET_STATES)) {
        database.createObjectStore(STORES.RATCHET_STATES, { keyPath: "peer_id" })
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

export interface StoredIdentityKey extends IdentityKeyPair {
  userId: string
}

export async function saveIdentityKey(
  userId: string,
  keyPair: IdentityKeyPair
): Promise<void> {
  const stored: StoredIdentityKey = {
    userId,
    ...keyPair,
  }

  await performTransaction(
    STORES.IDENTITY,
    "readwrite",
    (store) => store.put(stored)
  )
}

export async function getIdentityKey(userId: string): Promise<IdentityKeyPair | null> {
  const result = await performTransaction<StoredIdentityKey | undefined>(
    STORES.IDENTITY,
    "readonly",
    (store) => store.get(userId) as IDBRequest<StoredIdentityKey | undefined>
  )

  if (result === undefined) return null

  return {
    x25519_private: result.x25519_private,
    x25519_public: result.x25519_public,
    ed25519_private: result.ed25519_private,
    ed25519_public: result.ed25519_public,
  }
}

export async function deleteIdentityKey(userId: string): Promise<void> {
  await performTransaction(
    STORES.IDENTITY,
    "readwrite",
    (store) => store.delete(userId)
  )
}

export interface StoredSignedPreKey extends SignedPreKey {
  userId: string
}

export async function saveSignedPreKey(
  userId: string,
  preKey: SignedPreKey
): Promise<void> {
  const stored: StoredSignedPreKey = {
    userId,
    ...preKey,
  }

  await performTransaction(
    STORES.SIGNED_PREKEYS,
    "readwrite",
    (store) => store.put(stored)
  )
}

export async function getSignedPreKey(id: string): Promise<SignedPreKey | null> {
  const result = await performTransaction<StoredSignedPreKey | undefined>(
    STORES.SIGNED_PREKEYS,
    "readonly",
    (store) => store.get(id) as IDBRequest<StoredSignedPreKey | undefined>
  )

  if (result === undefined) return null

  return {
    id: result.id,
    private_key: result.private_key,
    public_key: result.public_key,
    signature: result.signature,
    created_at: result.created_at,
    expires_at: result.expires_at,
  }
}

export async function getLatestSignedPreKey(userId: string): Promise<SignedPreKey | null> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.SIGNED_PREKEYS, "readonly")
    const store = transaction.objectStore(STORES.SIGNED_PREKEYS)
    const index = store.index("userId")
    const request = index.getAll(userId)

    request.onsuccess = () => {
      const results = request.result as StoredSignedPreKey[]
      if (results.length === 0) {
        resolve(null)
        return
      }

      const sorted = results.sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      )

      const latest = sorted[0]
      resolve({
        id: latest.id,
        private_key: latest.private_key,
        public_key: latest.public_key,
        signature: latest.signature,
        created_at: latest.created_at,
        expires_at: latest.expires_at,
      })
    }

    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to get signed prekey"))
  })
}

export async function deleteSignedPreKey(id: string): Promise<void> {
  await performTransaction(
    STORES.SIGNED_PREKEYS,
    "readwrite",
    (store) => store.delete(id)
  )
}

export interface StoredOneTimePreKey extends OneTimePreKey {
  userId: string
}

export async function saveOneTimePreKey(
  userId: string,
  preKey: OneTimePreKey
): Promise<void> {
  const stored: StoredOneTimePreKey = {
    userId,
    ...preKey,
  }

  await performTransaction(
    STORES.ONE_TIME_PREKEYS,
    "readwrite",
    (store) => store.put(stored)
  )
}

export async function saveOneTimePreKeys(
  userId: string,
  preKeys: OneTimePreKey[]
): Promise<void> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.ONE_TIME_PREKEYS, "readwrite")
    const store = transaction.objectStore(STORES.ONE_TIME_PREKEYS)

    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new Error(transaction.error?.message ?? "Failed to save one-time prekeys"))

    for (const preKey of preKeys) {
      const stored: StoredOneTimePreKey = {
        userId,
        ...preKey,
      }
      store.put(stored)
    }
  })
}

export async function getOneTimePreKey(id: string): Promise<OneTimePreKey | null> {
  const result = await performTransaction<StoredOneTimePreKey | undefined>(
    STORES.ONE_TIME_PREKEYS,
    "readonly",
    (store) => store.get(id) as IDBRequest<StoredOneTimePreKey | undefined>
  )

  if (result === undefined) return null

  return {
    id: result.id,
    private_key: result.private_key,
    public_key: result.public_key,
    is_used: result.is_used,
    created_at: result.created_at,
  }
}

export async function getOneTimePreKeyByPublicKey(publicKey: string): Promise<OneTimePreKey | null> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.ONE_TIME_PREKEYS, "readonly")
    const store = transaction.objectStore(STORES.ONE_TIME_PREKEYS)
    const request = store.getAll()

    request.onsuccess = () => {
      const results = request.result as StoredOneTimePreKey[]
      const match = results.find((r) => r.public_key === publicKey)

      if (!match) {
        resolve(null)
        return
      }

      resolve({
        id: match.id,
        private_key: match.private_key,
        public_key: match.public_key,
        is_used: match.is_used,
        created_at: match.created_at,
      })
    }

    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to find one-time prekey"))
  })
}

export async function getUnusedOneTimePreKeys(userId: string): Promise<OneTimePreKey[]> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.ONE_TIME_PREKEYS, "readonly")
    const store = transaction.objectStore(STORES.ONE_TIME_PREKEYS)
    const index = store.index("userId")
    const request = index.getAll(userId)

    request.onsuccess = () => {
      const results = request.result as StoredOneTimePreKey[]
      const unused = results
        .filter((r) => !r.is_used)
        .map((r) => ({
          id: r.id,
          private_key: r.private_key,
          public_key: r.public_key,
          is_used: r.is_used,
          created_at: r.created_at,
        }))

      resolve(unused)
    }

    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to get unused one-time prekeys"))
  })
}

export async function markOneTimePreKeyUsed(id: string): Promise<void> {
  const preKey = await performTransaction<StoredOneTimePreKey | undefined>(
    STORES.ONE_TIME_PREKEYS,
    "readonly",
    (store) => store.get(id) as IDBRequest<StoredOneTimePreKey | undefined>
  )

  if (preKey === undefined) return

  preKey.is_used = true

  await performTransaction(
    STORES.ONE_TIME_PREKEYS,
    "readwrite",
    (store) => store.put(preKey)
  )
}

export async function deleteOneTimePreKey(id: string): Promise<void> {
  await performTransaction(
    STORES.ONE_TIME_PREKEYS,
    "readwrite",
    (store) => store.delete(id)
  )
}

export async function saveRatchetState(state: SerializedRatchetState): Promise<void> {
  await performTransaction(
    STORES.RATCHET_STATES,
    "readwrite",
    (store) => store.put(state)
  )
}

export async function getRatchetState(peerId: string): Promise<SerializedRatchetState | null> {
  const result = await performTransaction<SerializedRatchetState | undefined>(
    STORES.RATCHET_STATES,
    "readonly",
    (store) => store.get(peerId) as IDBRequest<SerializedRatchetState | undefined>
  )

  return result ?? null
}

export async function deleteRatchetState(peerId: string): Promise<void> {
  await performTransaction(
    STORES.RATCHET_STATES,
    "readwrite",
    (store) => store.delete(peerId)
  )
}

export async function getAllRatchetStates(): Promise<SerializedRatchetState[]> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORES.RATCHET_STATES, "readonly")
    const store = transaction.objectStore(STORES.RATCHET_STATES)
    const request = store.getAll()

    request.onsuccess = () => resolve(request.result as SerializedRatchetState[])
    request.onerror = () => reject(new Error(request.error?.message ?? "Failed to get all ratchet states"))
  })
}

export async function clearAllKeys(): Promise<void> {
  const database = await openDatabase()

  return new Promise((resolve, reject) => {
    const storeNames = [
      STORES.IDENTITY,
      STORES.SIGNED_PREKEYS,
      STORES.ONE_TIME_PREKEYS,
      STORES.RATCHET_STATES,
    ]

    const transaction = database.transaction(storeNames, "readwrite")

    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new Error(transaction.error?.message ?? "Failed to clear all keys"))

    for (const storeName of storeNames) {
      transaction.objectStore(storeName).clear()
    }
  })
}

export function closeDatabase(): void {
  if (db !== null) {
    db.close()
    db = null
  }
}
