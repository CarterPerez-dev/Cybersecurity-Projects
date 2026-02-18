// ===========================
// auth.types.ts
// ©AngelaMos | 2025
// ===========================

export interface RegisterRequest {
  email: string
  password: string
}

export interface RegisterResponse {
  id: number
  email: string
  is_active: boolean
  created_at: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
}

export interface AuthUser {
  id: number
  email: string
  is_active: boolean
  created_at: string
}
