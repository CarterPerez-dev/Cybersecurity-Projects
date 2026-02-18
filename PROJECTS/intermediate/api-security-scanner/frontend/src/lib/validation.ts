// ===========================
// ©AngelaMos | 2025
// Zod Validation Schemas
// ===========================

import { z } from 'zod'

export const loginSchema = z.object({
  email: z
    .email('Invalid email format')
    .min(1, 'Email is required')
    .max(255, 'Email too long'),
  password: z.string().min(1, 'Password is required'),
})

export const registerSchema = z
  .object({
    email: z
      .email('Invalid email format')
      .min(1, 'Email is required')
      .max(255, 'Email too long'),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .max(100, 'Password must be less than 100 characters')
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })

export const scanSchema = z.object({
  targetUrl: z
    .url('Invalid URL format')
    .min(1, 'Target URL is required')
    .max(2048, 'URL too long'),
  authToken: z.string().max(1000, 'Token too long').optional(),
  testsToRun: z
    .array(z.enum(['rate_limit', 'auth', 'sqli', 'idor']))
    .min(1, 'Select at least one test'),
  maxRequests: z
    .number()
    .int('Must be a whole number')
    .min(1, 'Must be at least 1')
    .max(50, 'Maximum 50 requests allowed'),
})

export type LoginFormData = z.infer<typeof loginSchema>
export type RegisterFormData = z.infer<typeof registerSchema>
export type ScanFormData = z.infer<typeof scanSchema>
