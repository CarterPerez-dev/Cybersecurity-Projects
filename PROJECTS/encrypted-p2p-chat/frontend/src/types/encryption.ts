// ===================
// © AngelaMos | 2025
// encryption.ts
// ===================
export interface PreKeyBundle {
  identity_key: string
  identity_key_ed25519: string
  signed_prekey: string
  signed_prekey_signature: string
  one_time_prekey: string | null
}

export interface X3DHResult {
  shared_key: Uint8Array
  associated_data: Uint8Array
  ephemeral_public_key: string
  used_one_time_prekey: boolean
}

export interface X3DHHeader {
  identity_key: string
  ephemeral_key: string
  one_time_prekey_id: string | null
}

export interface DoubleRatchetState {
  peer_id: string
  root_key: Uint8Array
  sending_chain_key: Uint8Array
  receiving_chain_key: Uint8Array | null
  dh_private_key: CryptoKeyPair | null
  dh_public_key: Uint8Array | null
  dh_peer_public_key: Uint8Array | null
  sending_message_number: number
  receiving_message_number: number
  previous_sending_chain_length: number
  skipped_message_keys: Map<string, Uint8Array>
}

export interface SerializedRatchetState {
  peer_id: string
  root_key: string
  sending_chain_key: string
  receiving_chain_key: string | null
  dh_private_key: string | null
  dh_public_key: string | null
  dh_peer_public_key: string | null
  sending_message_number: number
  receiving_message_number: number
  previous_sending_chain_length: number
  skipped_message_keys: Record<string, string>
}

export interface EncryptedMessage {
  ciphertext: Uint8Array
  nonce: Uint8Array
  header: MessageHeader
}

export interface MessageHeader {
  dh_public_key: string
  message_number: number
  previous_chain_length: number
}

export interface FullMessageHeader {
  ratchet: MessageHeader
  x3dh?: X3DHHeader
}

export interface IdentityKeyPair {
  x25519_private: string
  x25519_public: string
  ed25519_private: string
  ed25519_public: string
}

export interface SignedPreKey {
  id: string
  private_key: string
  public_key: string
  signature: string
  created_at: string
  expires_at: string
}

export interface OneTimePreKey {
  id: string
  private_key: string
  public_key: string
  is_used: boolean
  created_at: string
}

export interface StoredKeys {
  identity: IdentityKeyPair | null
  signed_prekey: SignedPreKey | null
  one_time_prekeys: OneTimePreKey[]
}

export const X25519_KEY_SIZE = 32
export const ED25519_KEY_SIZE = 32
export const ED25519_SIGNATURE_SIZE = 64
export const AES_GCM_KEY_SIZE = 32
export const AES_GCM_NONCE_SIZE = 12
export const HKDF_OUTPUT_SIZE = 32
export const MAX_SKIP_MESSAGE_KEYS = 1000
export const MAX_CACHED_MESSAGE_KEYS = 2000
export const DEFAULT_ONE_TIME_PREKEY_COUNT = 100
export const SIGNED_PREKEY_ROTATION_HOURS = 48
