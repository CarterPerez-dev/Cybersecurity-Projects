// ===================
// © AngelaMos | 2025
// double-ratchet.ts
// ===================
import type {
  DoubleRatchetState,
  SerializedRatchetState,
  EncryptedMessage,
  MessageHeader,
} from "../types"
import { MAX_SKIP_MESSAGE_KEYS } from "../types"
import {
  generateX25519KeyPair,
  x25519DeriveSharedSecret,
  importX25519PublicKey,
  importX25519PrivateKey,
  exportPublicKey,
  exportPrivateKey,
  hkdfDerive,
  aesGcmEncrypt,
  aesGcmDecrypt,
  hmacSha256,
  concatBytes,
  bytesToBase64,
  base64ToBytes,
} from "./primitives"

const RATCHET_INFO = new TextEncoder().encode("DoubleRatchet")
const MESSAGE_KEY_INFO = new TextEncoder().encode("MessageKey")
const CHAIN_KEY_INFO = new TextEncoder().encode("ChainKey")

function createSkippedKeyId(dhPublicKey: Uint8Array, messageNumber: number): string {
  return `${bytesToBase64(dhPublicKey)}:${messageNumber}`
}

export async function initializeRatchetSender(
  peerId: string,
  sharedKey: Uint8Array,
  peerPublicKey: Uint8Array
): Promise<DoubleRatchetState> {
  const dhKeyPair = await generateX25519KeyPair()
  const dhPublicKey = await exportPublicKey(dhKeyPair.publicKey)

  const peerKey = await importX25519PublicKey(peerPublicKey)
  const dhOutput = await x25519DeriveSharedSecret(dhKeyPair.privateKey, peerKey)

  const rootChainInput = concatBytes(sharedKey, dhOutput)
  const derivedKeys = await hkdfDerive(rootChainInput, new Uint8Array(32), RATCHET_INFO, 64)

  const rootKey = derivedKeys.slice(0, 32)
  const sendingChainKey = derivedKeys.slice(32, 64)

  return {
    peer_id: peerId,
    root_key: rootKey,
    sending_chain_key: sendingChainKey,
    receiving_chain_key: null,
    dh_private_key: dhKeyPair,
    dh_public_key: dhPublicKey,
    dh_peer_public_key: peerPublicKey,
    sending_message_number: 0,
    receiving_message_number: 0,
    previous_sending_chain_length: 0,
    skipped_message_keys: new Map(),
  }
}

export async function initializeRatchetReceiver(
  peerId: string,
  sharedKey: Uint8Array,
  dhKeyPair: CryptoKeyPair
): Promise<DoubleRatchetState> {
  const dhPublicKey = await exportPublicKey(dhKeyPair.publicKey)

  return {
    peer_id: peerId,
    root_key: sharedKey,
    sending_chain_key: new Uint8Array(0),
    receiving_chain_key: null,
    dh_private_key: dhKeyPair,
    dh_public_key: dhPublicKey,
    dh_peer_public_key: null,
    sending_message_number: 0,
    receiving_message_number: 0,
    previous_sending_chain_length: 0,
    skipped_message_keys: new Map(),
  }
}

async function deriveMessageKey(chainKey: Uint8Array): Promise<{
  messageKey: Uint8Array
  nextChainKey: Uint8Array
}> {
  const messageKey = await hmacSha256(chainKey, MESSAGE_KEY_INFO)
  const nextChainKey = await hmacSha256(chainKey, CHAIN_KEY_INFO)

  return {
    messageKey: messageKey.slice(0, 32),
    nextChainKey,
  }
}

async function performDHRatchet(
  state: DoubleRatchetState,
  peerPublicKey: Uint8Array
): Promise<void> {
  if (state.dh_private_key === null) {
    throw new Error("DH private key not initialized")
  }

  state.previous_sending_chain_length = state.sending_message_number
  state.sending_message_number = 0
  state.receiving_message_number = 0
  state.dh_peer_public_key = peerPublicKey

  const peerKey = await importX25519PublicKey(peerPublicKey)
  const dhOutput = await x25519DeriveSharedSecret(state.dh_private_key.privateKey, peerKey)

  const rootChainInput = concatBytes(state.root_key, dhOutput)
  const derivedKeys = await hkdfDerive(rootChainInput, new Uint8Array(32), RATCHET_INFO, 64)

  state.root_key = derivedKeys.slice(0, 32)
  state.receiving_chain_key = derivedKeys.slice(32, 64)

  const newDHKeyPair = await generateX25519KeyPair()
  state.dh_private_key = newDHKeyPair
  state.dh_public_key = await exportPublicKey(newDHKeyPair.publicKey)

  const newDHOutput = await x25519DeriveSharedSecret(newDHKeyPair.privateKey, peerKey)
  const newRootChainInput = concatBytes(state.root_key, newDHOutput)
  const newDerivedKeys = await hkdfDerive(newRootChainInput, new Uint8Array(32), RATCHET_INFO, 64)

  state.root_key = newDerivedKeys.slice(0, 32)
  state.sending_chain_key = newDerivedKeys.slice(32, 64)
}

async function skipMessageKeys(
  state: DoubleRatchetState,
  until: number
): Promise<void> {
  if (state.receiving_chain_key === null || state.dh_peer_public_key === null) return

  if (until - state.receiving_message_number > MAX_SKIP_MESSAGE_KEYS) {
    throw new Error("Too many skipped messages")
  }

  while (state.receiving_message_number < until) {
    const { messageKey, nextChainKey } = await deriveMessageKey(state.receiving_chain_key)

    const keyId = createSkippedKeyId(state.dh_peer_public_key, state.receiving_message_number)
    state.skipped_message_keys.set(keyId, messageKey)

    state.receiving_chain_key = nextChainKey
    state.receiving_message_number++
  }
}

export async function encryptMessage(
  state: DoubleRatchetState,
  plaintext: Uint8Array,
  associatedData?: Uint8Array
): Promise<EncryptedMessage> {
  if (state.dh_public_key === null) {
    throw new Error("DH public key not initialized")
  }

  const { messageKey, nextChainKey } = await deriveMessageKey(state.sending_chain_key)

  const header: MessageHeader = {
    dh_public_key: bytesToBase64(state.dh_public_key),
    message_number: state.sending_message_number,
    previous_chain_length: state.previous_sending_chain_length,
  }

  const headerBytes = new TextEncoder().encode(JSON.stringify(header))
  const aad = associatedData !== undefined ? concatBytes(associatedData, headerBytes) : headerBytes

  const { ciphertext, nonce } = await aesGcmEncrypt(messageKey, plaintext, aad)

  state.sending_chain_key = nextChainKey
  state.sending_message_number++

  return {
    ciphertext,
    nonce,
    header,
  }
}

export async function decryptMessage(
  state: DoubleRatchetState,
  message: EncryptedMessage,
  associatedData?: Uint8Array
): Promise<Uint8Array> {
  const peerPublicKey = base64ToBytes(message.header.dh_public_key)

  const skippedKeyId = createSkippedKeyId(peerPublicKey, message.header.message_number)
  const skippedKey = state.skipped_message_keys.get(skippedKeyId)

  if (skippedKey !== undefined) {
    state.skipped_message_keys.delete(skippedKeyId)

    const headerBytes = new TextEncoder().encode(JSON.stringify(message.header))
    const aad = associatedData !== undefined ? concatBytes(associatedData, headerBytes) : headerBytes

    return await aesGcmDecrypt(skippedKey, message.ciphertext, message.nonce, aad)
  }

  const isDifferentRatchetKey =
    state.dh_peer_public_key === null ||
    bytesToBase64(state.dh_peer_public_key) !== message.header.dh_public_key

  if (isDifferentRatchetKey) {
    if (state.receiving_chain_key !== null && state.dh_peer_public_key !== null) {
      await skipMessageKeys(state, message.header.previous_chain_length)
    }

    await performDHRatchet(state, peerPublicKey)
  }

  await skipMessageKeys(state, message.header.message_number)

  if (state.receiving_chain_key === null) {
    throw new Error("Receiving chain key not initialized after ratchet")
  }

  const { messageKey, nextChainKey } = await deriveMessageKey(state.receiving_chain_key)

  const headerBytes = new TextEncoder().encode(JSON.stringify(message.header))
  const aad = associatedData !== undefined ? concatBytes(associatedData, headerBytes) : headerBytes

  const plaintext = await aesGcmDecrypt(messageKey, message.ciphertext, message.nonce, aad)

  state.receiving_chain_key = nextChainKey
  state.receiving_message_number++

  return plaintext
}

export async function serializeRatchetState(
  state: DoubleRatchetState
): Promise<SerializedRatchetState> {
  let dhPrivateKey: string | null = null
  if (state.dh_private_key !== null) {
    const privateKeyBytes = await exportPrivateKey(state.dh_private_key.privateKey)
    dhPrivateKey = bytesToBase64(privateKeyBytes)
  }

  const skippedKeys: Record<string, string> = {}
  for (const [key, value] of state.skipped_message_keys) {
    skippedKeys[key] = bytesToBase64(value)
  }

  return {
    peer_id: state.peer_id,
    root_key: bytesToBase64(state.root_key),
    sending_chain_key: bytesToBase64(state.sending_chain_key),
    receiving_chain_key: state.receiving_chain_key !== null
      ? bytesToBase64(state.receiving_chain_key)
      : null,
    dh_private_key: dhPrivateKey,
    dh_public_key: state.dh_public_key !== null ? bytesToBase64(state.dh_public_key) : null,
    dh_peer_public_key: state.dh_peer_public_key !== null
      ? bytesToBase64(state.dh_peer_public_key)
      : null,
    sending_message_number: state.sending_message_number,
    receiving_message_number: state.receiving_message_number,
    previous_sending_chain_length: state.previous_sending_chain_length,
    skipped_message_keys: skippedKeys,
  }
}

export async function deserializeRatchetState(
  serialized: SerializedRatchetState
): Promise<DoubleRatchetState> {
  let dhPrivateKey: CryptoKeyPair | null = null
  if (serialized.dh_private_key && serialized.dh_public_key) {
    const privateKeyBytes = base64ToBytes(serialized.dh_private_key)
    const publicKeyBytes = base64ToBytes(serialized.dh_public_key)

    const privateKey = await importX25519PrivateKey(privateKeyBytes)
    const publicKey = await importX25519PublicKey(publicKeyBytes)

    dhPrivateKey = { privateKey, publicKey }
  }

  const skippedKeys = new Map<string, Uint8Array>()
  for (const [key, value] of Object.entries(serialized.skipped_message_keys)) {
    skippedKeys.set(key, base64ToBytes(value))
  }

  return {
    peer_id: serialized.peer_id,
    root_key: base64ToBytes(serialized.root_key),
    sending_chain_key: base64ToBytes(serialized.sending_chain_key),
    receiving_chain_key: serialized.receiving_chain_key
      ? base64ToBytes(serialized.receiving_chain_key)
      : null,
    dh_private_key: dhPrivateKey,
    dh_public_key: serialized.dh_public_key
      ? base64ToBytes(serialized.dh_public_key)
      : null,
    dh_peer_public_key: serialized.dh_peer_public_key
      ? base64ToBytes(serialized.dh_peer_public_key)
      : null,
    sending_message_number: serialized.sending_message_number,
    receiving_message_number: serialized.receiving_message_number,
    previous_sending_chain_length: serialized.previous_sending_chain_length,
    skipped_message_keys: skippedKeys,
  }
}

export function serializeMessageHeader(header: MessageHeader): string {
  return JSON.stringify(header)
}

export function deserializeMessageHeader(serialized: string): MessageHeader {
  return JSON.parse(serialized) as MessageHeader
}

export function serializeEncryptedMessage(message: EncryptedMessage): string {
  return JSON.stringify({
    ciphertext: bytesToBase64(message.ciphertext),
    nonce: bytesToBase64(message.nonce),
    header: message.header,
  })
}

interface SerializedEncryptedMessage {
  ciphertext: string
  nonce: string
  header: MessageHeader
}

export function deserializeEncryptedMessage(serialized: string): EncryptedMessage {
  const parsed = JSON.parse(serialized) as SerializedEncryptedMessage
  return {
    ciphertext: base64ToBytes(parsed.ciphertext),
    nonce: base64ToBytes(parsed.nonce),
    header: parsed.header,
  }
}
