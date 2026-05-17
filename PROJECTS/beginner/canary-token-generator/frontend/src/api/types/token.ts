// ===================
// ©AngelaMos | 2026
// token.ts
// ===================

import { z } from 'zod'

export const tokenTypeSchema = z.enum([
  'webbug',
  'slowredirect',
  'docx',
  'pdf',
  'kubeconfig',
  'envfile',
  'mysql',
])

export type TokenType = z.infer<typeof tokenTypeSchema>

export const alertChannelSchema = z.enum(['telegram', 'webhook'])

export type AlertChannel = z.infer<typeof alertChannelSchema>

export const artifactKindSchema = z.enum([
  'url',
  'file',
  'text',
  'connection_string',
])

export type ArtifactKind = z.infer<typeof artifactKindSchema>

export const tokenResponseSchema = z.object({
  id: z.string(),
  manage_id: z.string(),
  type: tokenTypeSchema,
  memo: z.string(),
  filename: z.string().nullable(),
  alert_channel: alertChannelSchema,
  created_at: z.iso.datetime(),
  trigger_count: z.number().int().nonnegative(),
  last_triggered: z.iso.datetime().nullable(),
  enabled: z.boolean(),
  trigger_url: z.string(),
  manage_url: z.string(),
  metadata: z.unknown().optional(),
})

export type TokenResponse = z.infer<typeof tokenResponseSchema>

export const manageTokenViewSchema = z.object({
  id: z.string(),
  type: tokenTypeSchema,
  memo: z.string(),
  filename: z.string().nullable(),
  alert_channel: alertChannelSchema,
  created_at: z.iso.datetime(),
  trigger_count: z.number().int().nonnegative(),
  last_triggered: z.iso.datetime().nullable(),
  enabled: z.boolean(),
  trigger_url: z.string(),
})

export type ManageTokenView = z.infer<typeof manageTokenViewSchema>

const artifactUrlSchema = z.object({
  kind: z.literal('url'),
  url: z.string().optional(),
  destination_url: z.string().optional(),
})

const artifactFileSchema = z.object({
  kind: z.literal('file'),
  filename: z.string().optional(),
  content_type: z.string().optional(),
  content_b64: z.string().optional(),
})

const artifactTextSchema = z.object({
  kind: z.literal('text'),
  filename: z.string().optional(),
  content_type: z.string().optional(),
  content: z.string().optional(),
})

const artifactConnectionStringSchema = z.object({
  kind: z.literal('connection_string'),
  connection_string: z.string().optional(),
})

export const artifactSchema = z.discriminatedUnion('kind', [
  artifactUrlSchema,
  artifactFileSchema,
  artifactTextSchema,
  artifactConnectionStringSchema,
])

export type Artifact = z.infer<typeof artifactSchema>

export const typeDescriptorSchema = z.object({
  type: tokenTypeSchema,
  name: z.string(),
  description: z.string(),
  artifact_kind: artifactKindSchema,
})

export type TypeDescriptor = z.infer<typeof typeDescriptorSchema>

export const typeDescriptorListSchema = z.array(typeDescriptorSchema)

export type TypeDescriptorList = z.infer<typeof typeDescriptorListSchema>

const MEMO_MAX_LENGTH = 256
const FILENAME_MAX_LENGTH = 128

export const createTokenRequestSchema = z
  .object({
    type: tokenTypeSchema,
    memo: z.string().max(MEMO_MAX_LENGTH).default(''),
    filename: z.string().max(FILENAME_MAX_LENGTH).optional(),
    alert_channel: alertChannelSchema,
    telegram_bot: z.string().optional(),
    telegram_chat: z.string().optional(),
    webhook_url: z.url().optional(),
    metadata: z.unknown().optional(),
    cf_turnstile_response: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.alert_channel === 'telegram') {
      if (!value.telegram_bot) {
        ctx.addIssue({
          code: 'custom',
          path: ['telegram_bot'],
          message: 'required when alert_channel is telegram',
        })
      }
      if (!value.telegram_chat) {
        ctx.addIssue({
          code: 'custom',
          path: ['telegram_chat'],
          message: 'required when alert_channel is telegram',
        })
      }
    }
    if (value.alert_channel === 'webhook' && !value.webhook_url) {
      ctx.addIssue({
        code: 'custom',
        path: ['webhook_url'],
        message: 'required when alert_channel is webhook',
      })
    }
  })

export type CreateTokenRequest = z.infer<typeof createTokenRequestSchema>
export type CreateTokenInput = z.input<typeof createTokenRequestSchema>

export const createTokenResponseSchema = z.object({
  token: tokenResponseSchema,
  artifact: artifactSchema,
})

export type CreateTokenResponse = z.infer<typeof createTokenResponseSchema>

export const slowredirectMetadataSchema = z.object({
  destination_url: z.url(),
})

export type SlowRedirectMetadata = z.infer<typeof slowredirectMetadataSchema>

export const envfileIncludeKeySchema = z.enum(['aws', 'stripe', 'github', 'db'])

export type EnvfileIncludeKey = z.infer<typeof envfileIncludeKeySchema>

export const envfileMetadataSchema = z.object({
  include_keys: z.array(envfileIncludeKeySchema),
})

export type EnvfileMetadata = z.infer<typeof envfileMetadataSchema>
