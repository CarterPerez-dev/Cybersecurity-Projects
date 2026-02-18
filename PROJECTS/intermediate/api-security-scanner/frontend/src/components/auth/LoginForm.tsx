// ===========================
// LoginForm.tsx
// ©AngelaMos | 2025
// ===========================

import { isAxiosError } from 'axios'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { useLogin } from '@/hooks/useAuth'
import { loginSchema } from '@/lib/validation'
import { useUIStore } from '@/store/uiStore'
import './AuthForm.css'

export const LoginForm = (): React.ReactElement => {
  const loginFormState = useUIStore((state) => state.loginForm)
  const setLoginFormField = useUIStore((state) => state.setLoginFormField)
  const clearLoginForm = useUIStore((state) => state.clearLoginForm)
  const clearExpiredData = useUIStore((state) => state.clearExpiredData)

  const [email, setEmail] = useState<string>('')
  const [password, setPassword] = useState<string>('')
  const [errors, setErrors] = useState<{
    email?: string
    password?: string
  }>({})

  const { mutate: login, isPending, error } = useLogin()

  useEffect(() => {
    clearExpiredData()
    setEmail(loginFormState.email)
    setPassword(loginFormState.password)
  }, [clearExpiredData, loginFormState.email, loginFormState.password])

  const handleEmailChange = (value: string): void => {
    setEmail(value)
    setLoginFormField('email', value)
    if (errors.email !== null && errors.email !== undefined) {
      validateField('email', value)
    }
  }

  const handlePasswordChange = (value: string): void => {
    setPassword(value)
    setLoginFormField('password', value)
    if (errors.password !== null && errors.password !== undefined) {
      validateField('password', value)
    }
  }

  const validateField = (field: 'email' | 'password', value: string): void => {
    const result = loginSchema.safeParse({
      email: field === 'email' ? value : email,
      password: field === 'password' ? value : password,
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

  const handleBlur = (field: 'email' | 'password'): void => {
    const value = field === 'email' ? email : password
    validateField(field, value)
  }

  const validateForm = (): boolean => {
    const result = loginSchema.safeParse({
      email,
      password,
    })

    if (!result.success) {
      const newErrors: { email?: string; password?: string } = {}

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

    login(
      { email, password },
      {
        onSuccess: () => {
          clearLoginForm()
        },
      }
    )
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <div className="auth-form__header">
        <h1 className="auth-form__title">Welcome Back</h1>
        <p className="auth-form__subtitle">Sign in to your account</p>
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
          autoComplete="current-password"
          required
        />
      </div>

      {error !== null && error !== undefined && isAxiosError(error) ? (
        <div className="auth-form__error-message" role="alert">
          {(error.response?.data as { detail?: string } | undefined)?.detail ??
            'Login failed. Please try again.'}
        </div>
      ) : null}

      <Button type="submit" isLoading={isPending} disabled={isPending}>
        Sign In
      </Button>

      <p className="auth-form__link">
        Don&apos;t have an account?{' '}
        <Link to="/register" className="auth-form__link-text">
          Sign up
        </Link>
      </p>
    </form>
  )
}
