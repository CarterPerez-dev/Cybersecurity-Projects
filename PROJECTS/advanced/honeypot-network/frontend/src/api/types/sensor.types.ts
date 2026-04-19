// ===================
// ©AngelaMos | 2026
// sensor.types.ts
// ===================

import { z } from 'zod'

export const sensorInfoSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  region: z.string(),
  services: z.array(z.string()),
  started_at: z.string(),
  status: z.string(),
})

export type SensorInfo = z.infer<typeof sensorInfoSchema>

export const isValidSensorInfo = (data: unknown): data is SensorInfo => {
  return sensorInfoSchema.safeParse(data).success
}
