'use client'

import Link from 'next/link'
import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function HomePage() {
  const router = useRouter()
  const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null)

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/auth/me')
      setIsLoggedIn(response.ok)
    } catch (err) {
      setIsLoggedIn(false)
    }
  }

  if (isLoggedIn === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="glass sticky top-0 z-50 border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-20">
            <div className="flex items-center">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-lg">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <div>
                  <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    Vulnerability Scanner
                  </h1>
                  <p className="text-xs text-gray-500">Enterprise Security Analysis</p>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {isLoggedIn ? (
                <>
                  <Link
                    href="/dashboard"
                    className="text-gray-600 hover:text-gray-900 px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-gray-100"
                  >
                    Dashboard
                  </Link>
                  <button
                    onClick={async () => {
                      await fetch('/api/auth/logout', { method: 'POST' })
                      router.push('/')
                      setIsLoggedIn(false)
                    }}
                    className="gradient-bg text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg hover:shadow-xl transition-all"
                  >
                    Logout
                  </button>
                </>
              ) : (
                <>
                  <Link
                    href="/auth/login"
                    className="text-gray-600 hover:text-gray-900 px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-gray-100"
                  >
                    Login
                  </Link>
                  <Link
                    href="/auth/register"
                    className="gradient-bg text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg hover:shadow-xl transition-all"
                  >
                    Get Started
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden py-20 sm:py-32">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-5xl md:text-7xl font-extrabold text-gray-900 mb-6 animate-fade-in">
              Secure Your Digital
              <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent"> Assets</span>
            </h1>
            <p className="text-xl md:text-2xl text-gray-600 mb-8 max-w-3xl mx-auto animate-slide-up">
              Comprehensive security scanning for vulnerabilities, headers, SSL, XSS, and open ports.
              Protect your websites with enterprise-grade security analysis.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center animate-slide-up">
              {!isLoggedIn ? (
                <>
                  <Link
                    href="/auth/register"
                    className="gradient-bg text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
                  >
                    Start Scanning Free
                  </Link>
                  <Link
                    href="/auth/login"
                    className="bg-white text-gray-900 px-8 py-4 rounded-xl font-semibold text-lg border-2 border-gray-200 hover:border-gray-300 transition-all"
                  >
                    Sign In
                  </Link>
                </>
              ) : (
                <Link
                  href="/dashboard"
                  className="gradient-bg text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
                >
                  Go to Dashboard
                </Link>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-50/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Powerful Security Features
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Everything you need to identify and fix security vulnerabilities
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Feature 1 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-blue-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">🛡️</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Security Headers</h3>
              <p className="text-gray-600">
                Check for critical security headers like CSP, X-Frame-Options, HSTS, and more. 
                Validate header quality, not just presence.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-green-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">🔐</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">SSL/TLS Analysis</h3>
              <p className="text-gray-600">
                Verify HTTPS implementation and SSL certificate validity. 
                Detect mixed content and insecure connections.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-red-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">⚠️</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">XSS Detection</h3>
              <p className="text-gray-600">
                Identify XSS vulnerabilities by detecting inline scripts, event handlers, 
                and reflected input. Advanced probing for reflected XSS.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-yellow-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">🔌</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Port Scanning</h3>
              <p className="text-gray-600">
                Detect open ports that may expose sensitive services. 
                Identify suspicious ports like FTP, SSH, and database ports.
              </p>
            </div>

            {/* Feature 5 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-purple-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">📊</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Risk Scoring</h3>
              <p className="text-gray-600">
                Get comprehensive risk scores with detailed breakdowns. 
                Understand your security posture with actionable insights.
              </p>
            </div>

            {/* Feature 6 */}
            <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 card-hover">
              <div className="w-16 h-16 bg-indigo-100 rounded-xl flex items-center justify-center mb-6">
                <span className="text-3xl">📄</span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">PDF Reports</h3>
              <p className="text-gray-600">
                Download detailed PDF reports with all findings, risk scores, 
                and recommendations. Perfect for compliance and documentation.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Additional Features */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-4xl font-bold text-gray-900 mb-6">
                Advanced Vulnerability Detection
              </h2>
              <ul className="space-y-4">
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">Directory Listing Detection</h4>
                    <p className="text-gray-600">Identify exposed directory listings on common paths</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">HTTP Methods Enumeration</h4>
                    <p className="text-gray-600">Detect unsafe HTTP methods like PUT, DELETE, TRACE</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">SQL Injection Probing</h4>
                    <p className="text-gray-600">Test for SQL injection vulnerabilities in query parameters</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">Tech Fingerprinting</h4>
                    <p className="text-gray-600">Identify exposed technology stack and versions</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">Scheduled Scans</h4>
                    <p className="text-gray-600">Automate security scans with daily, weekly, or monthly schedules</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h4 className="font-semibold text-gray-900">Email Alerts</h4>
                    <p className="text-gray-600">Get notified when high-risk vulnerabilities are detected</p>
                  </div>
                </li>
              </ul>
            </div>
            <div className="bg-gradient-to-br from-blue-50 to-purple-50 rounded-3xl p-12 border-2 border-blue-200">
              <div className="space-y-6">
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
                    <span className="text-white text-2xl">🔍</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900">Real-time Scanning</h3>
                    <p className="text-gray-600">Get results in seconds</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-green-600 rounded-xl flex items-center justify-center">
                    <span className="text-white text-2xl">📈</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900">Comprehensive Reports</h3>
                    <p className="text-gray-600">Detailed findings with actionable recommendations</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-purple-600 rounded-xl flex items-center justify-center">
                    <span className="text-white text-2xl">🔔</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900">Smart Alerts</h3>
                    <p className="text-gray-600">Stay informed about security issues</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Ready to Secure Your Websites?
          </h2>
          <p className="text-xl text-blue-100 mb-8">
            Start scanning your websites for vulnerabilities today. 
            Get instant results and actionable security insights.
          </p>
          {!isLoggedIn ? (
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                href="/auth/register"
                className="bg-white text-blue-600 px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
              >
                Create Free Account
              </Link>
              <Link
                href="/auth/login"
                className="bg-blue-700 text-white px-8 py-4 rounded-xl font-semibold text-lg border-2 border-blue-500 hover:bg-blue-800 transition-all"
              >
                Sign In
              </Link>
            </div>
          ) : (
            <Link
              href="/dashboard"
              className="inline-block bg-white text-blue-600 px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
            >
              Go to Dashboard
            </Link>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-300 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <h3 className="text-xl font-bold text-white">Vulnerability Scanner</h3>
              </div>
              <p className="text-gray-400">
                Enterprise-grade security scanning for your websites and applications.
              </p>
            </div>
            <div>
              <h4 className="font-semibold text-white mb-4">Features</h4>
              <ul className="space-y-2">
                <li><Link href="/dashboard" className="hover:text-white transition-colors">Security Scanning</Link></li>
                <li><Link href="/dashboard" className="hover:text-white transition-colors">Risk Analysis</Link></li>
                <li><Link href="/dashboard" className="hover:text-white transition-colors">PDF Reports</Link></li>
                <li><Link href="/dashboard" className="hover:text-white transition-colors">Scheduled Scans</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold text-white mb-4">Account</h4>
              <ul className="space-y-2">
                {isLoggedIn ? (
                  <>
                    <li><Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link></li>
                    <li><Link href="/schedules" className="hover:text-white transition-colors">Schedules</Link></li>
                    <li><Link href="/settings/alerts" className="hover:text-white transition-colors">Settings</Link></li>
                  </>
                ) : (
                  <>
                    <li><Link href="/auth/login" className="hover:text-white transition-colors">Login</Link></li>
                    <li><Link href="/auth/register" className="hover:text-white transition-colors">Register</Link></li>
                  </>
                )}
              </ul>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-gray-800 text-center text-gray-400">
            <p>&copy; {new Date().getFullYear()} Vulnerability Scanner. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
