/**
 * WebAuthn authentication service
 * Handles passkey registration and authentication flows
 */

import { api } from "../lib/api-client"
import {
  base64UrlEncode,
  base64UrlDecode,
} from "../lib/base64"
import type {
  User,
  RegistrationBeginRequest,
  AuthenticationBeginRequest,
  PublicKeyCredentialJSON,
} from "../types"
import { isPublicKeyCredential } from "../types/guards"
import { setCurrentUser, logout as storeLogout } from "../stores"
import { cryptoService } from "../crypto"

interface PublicKeyCredentialStatic {
  isUserVerifyingPlatformAuthenticatorAvailable(): Promise<boolean>
  isConditionalMediationAvailable?: () => Promise<boolean>
}

function publicKeyCredentialToJSON(
  credential: PublicKeyCredential
): PublicKeyCredentialJSON {
  const response = credential.response

  const json: PublicKeyCredentialJSON = {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: base64UrlEncode(response.clientDataJSON),
    },
    authenticatorAttachment: credential.authenticatorAttachment as "platform" | "cross-platform" | undefined,
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
  }

  if ("attestationObject" in response) {
    const attestationResponse = response as AuthenticatorAttestationResponse
    json.response.attestationObject = base64UrlEncode(attestationResponse.attestationObject)
  }

  if ("authenticatorData" in response) {
    const assertionResponse = response as AuthenticatorAssertionResponse
    json.response.authenticatorData = base64UrlEncode(assertionResponse.authenticatorData)
    json.response.signature = base64UrlEncode(assertionResponse.signature)
    if (assertionResponse.userHandle !== null) {
      json.response.userHandle = base64UrlEncode(assertionResponse.userHandle)
    }
  }

  return json
}

function toBufferSource(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
}

function preparePublicKeyOptions(
  options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions
): PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions {
  const prepared = { ...options }

  if ("challenge" in prepared && typeof prepared.challenge === "string") {
    prepared.challenge = toBufferSource(base64UrlDecode(prepared.challenge as unknown as string))
  }

  if ("user" in prepared) {
    const creationOptions = prepared as PublicKeyCredentialCreationOptions
    if (typeof creationOptions.user.id === "string") {
      creationOptions.user.id = toBufferSource(base64UrlDecode(creationOptions.user.id as unknown as string))
    }
  }

  if ("excludeCredentials" in prepared) {
    const creationOptions = prepared as PublicKeyCredentialCreationOptions
    if (creationOptions.excludeCredentials !== undefined) {
      creationOptions.excludeCredentials = creationOptions.excludeCredentials.map((cred) => ({
        ...cred,
        id: typeof cred.id === "string" ? toBufferSource(base64UrlDecode(cred.id as unknown as string)) : cred.id,
      }))
    }
  }

  if ("allowCredentials" in prepared) {
    const requestOptions = prepared as PublicKeyCredentialRequestOptions
    if (requestOptions.allowCredentials !== undefined) {
      requestOptions.allowCredentials = requestOptions.allowCredentials.map((cred) => ({
        ...cred,
        id: typeof cred.id === "string" ? toBufferSource(base64UrlDecode(cred.id as unknown as string)) : cred.id,
      }))
    }
  }

  return prepared
}

export async function register(
  username: string,
  displayName: string,
  deviceName?: string
): Promise<User> {
  const beginRequest: RegistrationBeginRequest = {
    username,
    display_name: displayName,
  }

  const beginResponse = await api.auth.beginRegistration(beginRequest)

  const publicKeyOptions = preparePublicKeyOptions(
    beginResponse as unknown as PublicKeyCredentialCreationOptions
  ) as PublicKeyCredentialCreationOptions

  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions,
  })

  if (!isPublicKeyCredential(credential)) {
    throw new Error("Failed to create credential")
  }

  const credentialJSON = publicKeyCredentialToJSON(credential)

  const user = await api.auth.completeRegistration({
    username,
    credential: credentialJSON,
    device_name: deviceName,
  })

  setCurrentUser(user)
  await cryptoService.initialize(user.id)

  return user
}

export async function login(username?: string): Promise<User> {
  const beginRequest: AuthenticationBeginRequest = {
    username,
  }

  const beginResponse = await api.auth.beginAuthentication(beginRequest)

  const publicKeyOptions = preparePublicKeyOptions(
    beginResponse as unknown as PublicKeyCredentialRequestOptions
  ) as PublicKeyCredentialRequestOptions

  const credential = await navigator.credentials.get({
    publicKey: publicKeyOptions,
  })

  if (!isPublicKeyCredential(credential)) {
    throw new Error("Failed to get credential")
  }

  const credentialJSON = publicKeyCredentialToJSON(credential)

  const user = await api.auth.completeAuthentication({
    credential: credentialJSON,
  })

  setCurrentUser(user)
  await cryptoService.initialize(user.id)

  return user
}

export function logout(): void {
  storeLogout()
}

export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials !== "undefined"
  )
}

export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    return false
  }
}

export async function isConditionalUIAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false
  }

  try {
    const pkc = PublicKeyCredential as unknown as PublicKeyCredentialStatic
    if (typeof pkc.isConditionalMediationAvailable === "function") {
      return await pkc.isConditionalMediationAvailable()
    }
    return false
  } catch {
    return false
  }
}

export const authService = {
  register,
  login,
  logout,
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  isConditionalUIAvailable,
}
