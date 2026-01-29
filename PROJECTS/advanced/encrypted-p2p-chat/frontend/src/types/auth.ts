// ===================
// © AngelaMos | 2025
// auth.ts
// ===================
export interface User {
  id: string
  username: string
  display_name: string
  is_active: boolean
  is_verified: boolean
  created_at: string
}

export interface Credential {
  id: string
  credential_id: string
  device_name: string | null
  last_used_at: string | null
  created_at: string
  backup_eligible: boolean
  backup_state: boolean
}

export interface RegistrationBeginRequest {
  username: string
  display_name: string
}

export interface RegistrationCompleteRequest {
  username: string
  credential: PublicKeyCredentialJSON
  device_name?: string
}

export interface AuthenticationBeginRequest {
  username?: string
}

export interface AuthenticationCompleteRequest {
  credential: PublicKeyCredentialJSON
}

export interface WebAuthnOptions {
  publicKey: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions
}

export interface PublicKeyCredentialJSON {
  id: string
  rawId: string
  type: "public-key"
  response: {
    clientDataJSON: string
    attestationObject?: string
    authenticatorData?: string
    signature?: string
    userHandle?: string
  }
  authenticatorAttachment?: "platform" | "cross-platform"
  clientExtensionResults: Record<string, unknown>
}

export interface Session {
  userId: string
  username: string
  displayName: string
  isActive: boolean
  authenticatedAt: string
}

export const USERNAME_MIN_LENGTH = 3
export const USERNAME_MAX_LENGTH = 50
export const DISPLAY_NAME_MIN_LENGTH = 1
export const DISPLAY_NAME_MAX_LENGTH = 100
export const DEVICE_NAME_MAX_LENGTH = 100
