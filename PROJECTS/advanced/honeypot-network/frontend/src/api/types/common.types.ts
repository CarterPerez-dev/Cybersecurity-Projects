// ===================
// ©AngelaMos | 2026
// common.types.ts
// ===================

import { z } from 'zod'

export const SERVICE_TYPE_VALUES = [
  'ssh',
  'http',
  'ftp',
  'smb',
  'mysql',
  'redis',
] as const

export const ServiceType = {
  SSH: 'ssh',
  HTTP: 'http',
  FTP: 'ftp',
  SMB: 'smb',
  MYSQL: 'mysql',
  REDIS: 'redis',
} as const

export type ServiceType = (typeof ServiceType)[keyof typeof ServiceType]

export const EventType = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  LOGIN_SUCCESS: 'login.success',
  LOGIN_FAILED: 'login.failed',
  COMMAND_INPUT: 'command.input',
  COMMAND_OUTPUT: 'command.output',
  FILE_UPLOAD: 'file.upload',
  FILE_DOWNLOAD: 'file.download',
  REQUEST: 'request',
  EXPLOIT_ATTEMPT: 'exploit.attempt',
  SCAN_DETECTED: 'scan.detected',
} as const

export type EventType = (typeof EventType)[keyof typeof EventType]

export const geoInfoSchema = z.object({
  country_code: z.string(),
  country: z.string(),
  city: z.string(),
  latitude: z.number(),
  longitude: z.number(),
  asn: z.number(),
  org: z.string(),
})

export type GeoInfo = z.infer<typeof geoInfoSchema>

export const apiResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    data: dataSchema,
  })

export type ApiResponse<T> = {
  data: T
}

export const paginatedResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    data: dataSchema,
    total: z.number(),
    limit: z.number(),
    offset: z.number(),
  })

export type PaginatedResponse<T> = {
  data: T
  total: number
  limit: number
  offset: number
}

export const isValidGeoInfo = (data: unknown): data is GeoInfo => {
  return geoInfoSchema.safeParse(data).success
}
