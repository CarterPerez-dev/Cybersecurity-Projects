// ===================
// ©AngelaMos | 2026
// error.ts
// ===================

import { type ZodType, z } from 'zod'

export const apiErrorPayloadSchema = z.object({
  code: z.string(),
  message: z.string(),
  fields: z.record(z.string(), z.string()).optional(),
})

export type ApiErrorPayload = z.infer<typeof apiErrorPayloadSchema>

export const apiErrorEnvelopeSchema = z.object({
  success: z.literal(false),
  error: apiErrorPayloadSchema,
})

export type ApiErrorEnvelope = z.infer<typeof apiErrorEnvelopeSchema>

export const successEnvelope = <T extends ZodType>(data: T) =>
  z.object({
    success: z.literal(true),
    data,
  })

export type SuccessEnvelope<T> = {
  success: true
  data: T
}
