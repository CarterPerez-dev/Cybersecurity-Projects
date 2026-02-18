// ===========================
// errors.ts
// ©AngelaMos | 2025
// ===========================

import { isAxiosError } from 'axios'
import { toast } from 'sonner'

export const createApiErrorHandler = (context: string) => {
  return (error: unknown): void => {
    if (
      isAxiosError(error) &&
      error.response?.data !== null &&
      error.response?.data !== undefined
    ) {
      const errorData: unknown = error.response.data

      if (
        typeof errorData === 'object' &&
        errorData !== null &&
        'detail' in errorData &&
        typeof errorData.detail === 'string' &&
        errorData.detail.length > 0
      ) {
        toast.error(errorData.detail)
        return
      }
    }

    const fallbackMessage =
      error instanceof Error ? error.message : `Operation failed: ${context}`
    toast.error(fallbackMessage)
  }
}
