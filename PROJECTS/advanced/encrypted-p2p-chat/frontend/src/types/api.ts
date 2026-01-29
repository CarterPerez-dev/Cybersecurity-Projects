// ===================
// © AngelaMos | 2025
// api.ts
// ===================
export class ApiError extends Error {
  constructor(
    public status: number,
    public data: unknown,
    message?: string
  ) {
    super(message ?? `API Error: ${status}`)
    this.name = "ApiError"
  }
}

export interface ApiResponse<T> {
  data: T
  status: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
  hasMore: boolean
}

export interface ValidationError {
  field: string
  message: string
}

export interface ApiErrorResponse {
  detail: string | ValidationError[]
  status_code?: number
}
