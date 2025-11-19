'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Login failed')
      }

      const user = await response.json()
      // Redirect to dashboard after login
      router.push('/dashboard')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 animate-fade-in">
        {/* Header */}
        <div className="text-center">
          <Link href="/" className="inline-block mb-6">
            <div className="w-16 h-16 gradient-bg rounded-2xl flex items-center justify-center shadow-glow mx-auto">
              <span className="text-white text-3xl font-bold">🔒</span>
            </div>
          </Link>
          <h2 className="text-4xl font-extrabold text-foreground mb-2">
            Welcome Back
          </h2>
          <p className="text-muted-foreground">
            Sign in to your account to continue
          </p>
        </div>

        {/* Form Card */}
        <div className="glass-card p-8 rounded-2xl card-hover">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-semibold text-muted-foreground mb-2">
                  Email address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <span className="text-muted-foreground">📧</span>
                  </div>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-12 pr-4 py-3 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary transition-all text-foreground placeholder-muted-foreground"
                    placeholder="you@example.com"
                  />
                </div>
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-semibold text-muted-foreground mb-2">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <span className="text-muted-foreground">🔐</span>
                  </div>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-12 pr-4 py-3 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary transition-all text-foreground placeholder-muted-foreground"
                    placeholder="Enter your password"
                  />
                </div>
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg flex items-center space-x-2 animate-fade-in">
                <span>⚠️</span>
                <span>{error}</span>
              </div>
            )}

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full gradient-bg text-white py-3.5 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105 flex items-center justify-center space-x-2"
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                    <span>Signing in...</span>
                  </>
                ) : (
                  <>
                    <span>Sign in</span>
                    <span>→</span>
                  </>
                )}
              </button>
            </div>

            <div className="text-center space-y-2">
              <p className="text-sm text-muted-foreground">
                Don't have an account?{' '}
                <Link
                  href="/auth/register"
                  className="font-semibold text-primary hover:text-primary/80 transition-colors"
                >
                  Create one now
                </Link>
              </p>
              <Link
                href="/"
                className="inline-flex items-center space-x-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                <span>←</span>
                <span>Back to dashboard</span>
              </Link>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
