// ===========================
// RegisterForm.tsx
// ©AngelaMos | 2025
// ===========================

import { isAxiosError } from 'axios'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { useRegister } from '@/hooks/useAuth'
import { registerSchema } from '@/lib/validation'
import { useUIStore } from '@/store/uiStore'
import './AuthForm.css'

export const RegisterForm = (): React.ReactElement => {
  const registerFormState = useUIStore((state) => state.registerForm)
  const setRegisterFormField = useUIStore((state) => state.setRegisterFormField)
  const clearRegisterForm = useUIStore((state) => state.clearRegisterForm)
  const clearExpiredData = useUIStore((state) => state.clearExpiredData)

  const [email, setEmail] = useState<string>('')
  const [password, setPassword] = useState<string>('')
  const [confirmPassword, setConfirmPassword] = useState<string>('')
  const [errors, setErrors] = useState<{
    email?: string
    password?: string
    confirmPassword?: string
  }>({})

  const { mutate: register, isPending, error } = useRegister()

  useEffect(() => {
    clearExpiredData()
    setEmail(registerFormState.email)
    setPassword(registerFormState.password)
    setConfirmPassword(registerFormState.confirmPassword)
  }, [
    clearExpiredData,
    registerFormState.email,
    registerFormState.password,
    registerFormState.confirmPassword,
  ])

  const handleEmailChange = (value: string): void => {
    setEmail(value)
    setRegisterFormField('email', value)
    if (errors.email !== null && errors.email !== undefined) {
      validateField('email', value)
    }
  }

  const handlePasswordChange = (value: string): void => {
    setPassword(value)
    setRegisterFormField('password', value)
    if (errors.password !== null && errors.password !== undefined) {
      validateField('password', value)
    }
  }

  const handleConfirmPasswordChange = (value: string): void => {
    setConfirmPassword(value)
    setRegisterFormField('confirmPassword', value)
    if (errors.confirmPassword !== null && errors.confirmPassword !== undefined) {
      validateField('confirmPassword', value)
    }
  }

  const validateField = (
    field: 'email' | 'password' | 'confirmPassword',
    value: string
  ): void => {
    const result = registerSchema.safeParse({
      email: field === 'email' ? value : email,
      password: field === 'password' ? value : password,
      confirmPassword: field === 'confirmPassword' ? value : confirmPassword,
    })

    if (!result.success) {
      const fieldError = result.error.issues.find((err) => err.path[0] === field)
      if (fieldError !== null && fieldError !== undefined) {
        setErrors((prev) => ({ ...prev, [field]: fieldError.message }))
      } else {
        setErrors((prev) => {
          const { [field]: _, ...rest } = prev
          return rest
        })
      }
    } else {
      setErrors((prev) => {
        const { [field]: _, ...rest } = prev
        return rest
      })
    }
  }

  const handleBlur = (field: 'email' | 'password' | 'confirmPassword'): void => {
    let value: string
    if (field === 'email') {
      value = email
    } else if (field === 'password') {
      value = password
    } else {
      value = confirmPassword
    }
    validateField(field, value)
  }

  const validateForm = (): boolean => {
    const result = registerSchema.safeParse({
      email,
      password,
      confirmPassword,
    })

    if (!result.success) {
      const newErrors: {
        email?: string
        password?: string
        confirmPassword?: string
      } = {}

      result.error.issues.forEach((err) => {
        const field = err.path[0] as keyof typeof newErrors
        if (field !== null && field !== undefined) {
          newErrors[field] = err.message
        }
      })

      setErrors(newErrors)
      return false
    }

    setErrors({})
    return true
  }

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault()

    if (!validateForm()) {
      return
    }

    register(
      { email, password },
      {
        onSuccess: () => {
          clearRegisterForm()
        },
      }
    )
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <div className="auth-form__header">
        <h1 className="auth-form__title">Create Account</h1>
        <p className="auth-form__subtitle">
          Get started with API Security Scanner
        </p>
      </div>

      <div className="auth-form__fields">
        <Input
          label="Email"
          type="email"
          value={email}
          onChange={(e) => handleEmailChange(e.target.value)}
          onBlur={() => handleBlur('email')}
          error={errors.email}
          placeholder="you@example.com"
          autoComplete="email"
          required
        />

        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => handlePasswordChange(e.target.value)}
          onBlur={() => handleBlur('password')}
          error={errors.password}
          placeholder="Enter your password"
          autoComplete="new-password"
          required
        />

        <Input
          label="Confirm Password"
          type="password"
          value={confirmPassword}
          onChange={(e) => handleConfirmPasswordChange(e.target.value)}
          onBlur={() => handleBlur('confirmPassword')}
          error={errors.confirmPassword}
          placeholder="Confirm your password"
          autoComplete="new-password"
          required
        />
      </div>

      {error !== null && error !== undefined && isAxiosError(error) ? (
        <div className="auth-form__error-message" role="alert">
          {(error.response?.data as { detail?: string } | undefined)?.detail ??
            'Registration failed. Please try again.'}
        </div>
      ) : null}

      <Button type="submit" isLoading={isPending} disabled={isPending}>
        Create Account
      </Button>

      <p className="auth-form__link">
        Already have an account?{' '}
        <Link to="/login" className="auth-form__link-text">
          Sign in
        </Link>
      </p>
    </form>
  )
}
