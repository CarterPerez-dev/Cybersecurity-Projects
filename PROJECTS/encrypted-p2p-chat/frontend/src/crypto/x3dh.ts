// ===================
// © AngelaMos | 2025
// x3dh.ts
// ===================
import type {
  PreKeyBundle,
  X3DHResult,
  X3DHHeader,
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
} from "../types"
import {
  generateX25519KeyPair,
  x25519DeriveSharedSecret,
  importX25519PublicKey,
  importX25519PrivateKey,
  exportPublicKey,
  exportPrivateKey,
  generateEd25519KeyPair,
  ed25519Sign,
  ed25519Verify,
  importEd25519PublicKey,
  importEd25519PrivateKey,
  hkdfDerive,
  concatBytes,
  bytesToBase64,
  base64ToBytes,
  generateRandomBytes,
} from "./primitives"
import { HKDF_OUTPUT_SIZE, DEFAULT_ONE_TIME_PREKEY_COUNT } from "../types"

const X3DH_INFO = new TextEncoder().encode("X3DH")
const EMPTY_SALT = new Uint8Array(HKDF_OUTPUT_SIZE)

export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  const x25519KeyPair = await generateX25519KeyPair()
  const ed25519KeyPair = await generateEd25519KeyPair()

  const x25519Public = await exportPublicKey(x25519KeyPair.publicKey)
  const x25519Private = await exportPrivateKey(x25519KeyPair.privateKey)
  const ed25519Public = await exportPublicKey(ed25519KeyPair.publicKey)
  const ed25519Private = await exportPrivateKey(ed25519KeyPair.privateKey)

  return {
    x25519_public: bytesToBase64(x25519Public),
    x25519_private: bytesToBase64(x25519Private),
    ed25519_public: bytesToBase64(ed25519Public),
    ed25519_private: bytesToBase64(ed25519Private),
  }
}

export async function generateSignedPreKey(
  identityPrivateKey: string
): Promise<SignedPreKey> {
  const keyPair = await generateX25519KeyPair()
  const publicKey = await exportPublicKey(keyPair.publicKey)
  const privateKey = await exportPrivateKey(keyPair.privateKey)

  const signingKey = await importEd25519PrivateKey(base64ToBytes(identityPrivateKey))
  const signature = await ed25519Sign(signingKey, publicKey)

  const id = bytesToBase64(generateRandomBytes(16))
  const now = new Date()
  const expiresAt = new Date(now.getTime() + 48 * 60 * 60 * 1000)

  return {
    id,
    public_key: bytesToBase64(publicKey),
    private_key: bytesToBase64(privateKey),
    signature: bytesToBase64(signature),
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  }
}

export async function generateOneTimePreKeys(
  count: number = DEFAULT_ONE_TIME_PREKEY_COUNT
): Promise<OneTimePreKey[]> {
  const preKeys: OneTimePreKey[] = []

  for (let i = 0; i < count; i++) {
    const keyPair = await generateX25519KeyPair()
    const publicKey = await exportPublicKey(keyPair.publicKey)
    const privateKey = await exportPrivateKey(keyPair.privateKey)

    preKeys.push({
      id: bytesToBase64(generateRandomBytes(16)),
      public_key: bytesToBase64(publicKey),
      private_key: bytesToBase64(privateKey),
      is_used: false,
      created_at: new Date().toISOString(),
    })
  }

  return preKeys
}

export async function verifySignedPreKey(
  identityPublicKey: string,
  signedPreKeyPublic: string,
  signature: string
): Promise<boolean> {
  try {
    const verifyKey = await importEd25519PublicKey(base64ToBytes(identityPublicKey))
    const publicKeyBytes = base64ToBytes(signedPreKeyPublic)
    const signatureBytes = base64ToBytes(signature)

    return await ed25519Verify(verifyKey, signatureBytes, publicKeyBytes)
  } catch {
    return false
  }
}

export async function initiateX3DH(
  identityKeyPair: IdentityKeyPair,
  recipientBundle: PreKeyBundle
): Promise<X3DHResult> {
  const signatureValid = await verifySignedPreKey(
    recipientBundle.identity_key_ed25519,
    recipientBundle.signed_prekey,
    recipientBundle.signed_prekey_signature
  )

  if (!signatureValid) {
    throw new Error("Invalid signed prekey signature")
  }

  const ephemeralKeyPair = await generateX25519KeyPair()
  const ephemeralPublic = await exportPublicKey(ephemeralKeyPair.publicKey)

  const senderIdentityPrivate = await importX25519PrivateKey(
    base64ToBytes(identityKeyPair.x25519_private)
  )
  const recipientIdentityPublic = await importX25519PublicKey(
    base64ToBytes(recipientBundle.identity_key)
  )
  const recipientSignedPreKeyPublic = await importX25519PublicKey(
    base64ToBytes(recipientBundle.signed_prekey)
  )

  const dh1 = await x25519DeriveSharedSecret(senderIdentityPrivate, recipientSignedPreKeyPublic)
  const dh2 = await x25519DeriveSharedSecret(ephemeralKeyPair.privateKey, recipientIdentityPublic)
  const dh3 = await x25519DeriveSharedSecret(ephemeralKeyPair.privateKey, recipientSignedPreKeyPublic)

  let dhResults: Uint8Array[]
  let usedOneTimePreKey = false

  if (recipientBundle.one_time_prekey) {
    const recipientOneTimePreKeyPublic = await importX25519PublicKey(
      base64ToBytes(recipientBundle.one_time_prekey)
    )
    const dh4 = await x25519DeriveSharedSecret(ephemeralKeyPair.privateKey, recipientOneTimePreKeyPublic)
    dhResults = [dh1, dh2, dh3, dh4]
    usedOneTimePreKey = true
  } else {
    dhResults = [dh1, dh2, dh3]
  }

  const concatenated = concatBytes(...dhResults)
  const sharedKey = await hkdfDerive(concatenated, EMPTY_SALT, X3DH_INFO, 32)

  const senderIdentityPublic = base64ToBytes(identityKeyPair.x25519_public)
  const recipientIdentityBytes = base64ToBytes(recipientBundle.identity_key)
  const associatedData = concatBytes(senderIdentityPublic, recipientIdentityBytes)

  return {
    shared_key: sharedKey,
    associated_data: associatedData,
    ephemeral_public_key: bytesToBase64(ephemeralPublic),
    used_one_time_prekey: usedOneTimePreKey,
  }
}

export async function receiveX3DH(
  identityKeyPair: IdentityKeyPair,
  signedPreKey: SignedPreKey,
  oneTimePreKey: OneTimePreKey | null,
  senderIdentityKey: string,
  senderEphemeralKey: string
): Promise<Uint8Array> {
  const recipientIdentityPrivate = await importX25519PrivateKey(
    base64ToBytes(identityKeyPair.x25519_private)
  )
  const recipientSignedPreKeyPrivate = await importX25519PrivateKey(
    base64ToBytes(signedPreKey.private_key)
  )
  const senderIdentityPublic = await importX25519PublicKey(
    base64ToBytes(senderIdentityKey)
  )
  const senderEphemeralPublic = await importX25519PublicKey(
    base64ToBytes(senderEphemeralKey)
  )

  const dh1 = await x25519DeriveSharedSecret(recipientSignedPreKeyPrivate, senderIdentityPublic)
  const dh2 = await x25519DeriveSharedSecret(recipientIdentityPrivate, senderEphemeralPublic)
  const dh3 = await x25519DeriveSharedSecret(recipientSignedPreKeyPrivate, senderEphemeralPublic)

  let dhResults: Uint8Array[]

  if (oneTimePreKey !== null) {
    const recipientOneTimePreKeyPrivate = await importX25519PrivateKey(
      base64ToBytes(oneTimePreKey.private_key)
    )
    const dh4 = await x25519DeriveSharedSecret(recipientOneTimePreKeyPrivate, senderEphemeralPublic)
    dhResults = [dh1, dh2, dh3, dh4]
  } else {
    dhResults = [dh1, dh2, dh3]
  }

  const concatenated = concatBytes(...dhResults)
  const sharedKey = await hkdfDerive(concatenated, EMPTY_SALT, X3DH_INFO, 32)

  return sharedKey
}

export function createX3DHHeader(
  identityKey: string,
  ephemeralKey: string,
  oneTimePreKeyId: string | null
): X3DHHeader {
  return {
    identity_key: identityKey,
    ephemeral_key: ephemeralKey,
    one_time_prekey_id: oneTimePreKeyId,
  }
}

export function serializeX3DHHeader(header: X3DHHeader): string {
  return JSON.stringify(header)
}

export function deserializeX3DHHeader(serialized: string): X3DHHeader {
  return JSON.parse(serialized) as X3DHHeader
}
