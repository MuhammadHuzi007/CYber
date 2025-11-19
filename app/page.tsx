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
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Navigation */}
      <nav className="glass sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-20">
            <div className="flex items-center">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-glow">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <div>
                  <h1 className="text-xl font-bold gradient-text">
                    Vulnerability Scanner
                  </h1>
                  <p className="text-xs text-muted-foreground">Enterprise Security Analysis</p>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {isLoggedIn ? (
                <>
                  <Link
                    href="/dashboard"
                    className="text-muted-foreground hover:text-foreground px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
                  >
                    Dashboard
                  </Link>
                  <button
                    onClick={async () => {
                      await fetch('/api/auth/logout', { method: 'POST' })
                      router.push('/')
                      setIsLoggedIn(false)
                    }}
                    className="gradient-bg text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg hover:shadow-glow transition-all"
                  >
                    Logout
                  </button>
                </>
              ) : (
                <>
                  <Link
                    href="/auth/login"
                    className="text-muted-foreground hover:text-foreground px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
                  >
                    Login
                  </Link>
                  <Link
                    href="/auth/register"
                    className="gradient-bg text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg hover:shadow-glow transition-all"
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
        {/* Background Elements */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full overflow-hidden -z-10 pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl animate-pulse-slow"></div>
          <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse-slow delay-1000"></div>
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="inline-block mb-4 px-4 py-1.5 rounded-full glass-card border-blue-500/30 text-blue-400 text-sm font-medium animate-fade-in">
              🚀 Next-Gen Security Scanning
            </div>
            <h1 className="text-5xl md:text-7xl font-extrabold text-foreground mb-6 animate-fade-in tracking-tight">
              Secure Your Digital
              <br />
              <span className="gradient-text">Assets & Infrastructure</span>
            </h1>
            <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto animate-slide-up leading-relaxed">
              Comprehensive security scanning for vulnerabilities, headers, SSL, XSS, and open ports.
              Protect your websites with enterprise-grade security analysis.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center animate-slide-up">
              {!isLoggedIn ? (
                <>
                  <Link
                    href="/auth/register"
                    className="gradient-bg text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-glow hover:shadow-glow-lg transition-all transform hover:scale-105"
                  >
                    Start Scanning Free
                  </Link>
                  <Link
                    href="/auth/login"
                    className="glass-card text-foreground px-8 py-4 rounded-xl font-semibold text-lg hover:bg-white/5 transition-all border border-white/10"
                  >
                    Sign In
                  </Link>
                </>
              ) : (
                <Link
                  href="/dashboard"
                  className="gradient-bg text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-glow hover:shadow-glow-lg transition-all transform hover:scale-105"
                >
                  Go to Dashboard
                </Link>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-foreground mb-4">
              Powerful Security Features
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Everything you need to identify and fix security vulnerabilities
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Feature 1 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-blue-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-blue-500/20 transition-colors">
                <span className="text-3xl">🛡️</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">Security Headers</h3>
              <p className="text-muted-foreground">
                Check for critical security headers like CSP, X-Frame-Options, HSTS, and more.
                Validate header quality, not just presence.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-green-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-green-500/20 transition-colors">
                <span className="text-3xl">🔐</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">SSL/TLS Analysis</h3>
              <p className="text-muted-foreground">
                Verify HTTPS implementation and SSL certificate validity.
                Detect mixed content and insecure connections.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-red-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-red-500/20 transition-colors">
                <span className="text-3xl">⚠️</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">XSS Detection</h3>
              <p className="text-muted-foreground">
                Identify XSS vulnerabilities by detecting inline scripts, event handlers,
                and reflected input. Advanced probing for reflected XSS.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-yellow-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-yellow-500/20 transition-colors">
                <span className="text-3xl">🔌</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">Port Scanning</h3>
              <p className="text-muted-foreground">
                Detect open ports that may expose sensitive services.
                Identify suspicious ports like FTP, SSH, and database ports.
              </p>
            </div>

            {/* Feature 5 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-purple-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-purple-500/20 transition-colors">
                <span className="text-3xl">📊</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">Risk Scoring</h3>
              <p className="text-muted-foreground">
                Get comprehensive risk scores with detailed breakdowns.
                Understand your security posture with actionable insights.
              </p>
            </div>

            {/* Feature 6 */}
            <div className="glass-card p-8 rounded-2xl card-hover group">
              <div className="w-16 h-16 bg-indigo-500/10 rounded-xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition-colors">
                <span className="text-3xl">📄</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-3">PDF Reports</h3>
              <p className="text-muted-foreground">
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
              <h2 className="text-4xl font-bold text-foreground mb-6">
                Advanced Vulnerability Detection
              </h2>
              <ul className="space-y-4">
                {[
                  { title: 'Directory Listing Detection', desc: 'Identify exposed directory listings on common paths' },
                  { title: 'HTTP Methods Enumeration', desc: 'Detect unsafe HTTP methods like PUT, DELETE, TRACE' },
                  { title: 'SQL Injection Probing', desc: 'Test for SQL injection vulnerabilities in query parameters' },
                  { title: 'Tech Fingerprinting', desc: 'Identify exposed technology stack and versions' },
                  { title: 'Scheduled Scans', desc: 'Automate security scans with daily, weekly, or monthly schedules' },
                  { title: 'Email Alerts', desc: 'Get notified when high-risk vulnerabilities are detected' },
                ].map((item, index) => (
                  <li key={index} className="flex items-start space-x-3 p-4 rounded-xl hover:bg-white/5 transition-colors">
                    <span className="text-2xl">✅</span>
                    <div>
                      <h4 className="font-semibold text-foreground">{item.title}</h4>
                      <p className="text-muted-foreground">{item.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
            <div className="glass-card rounded-3xl p-12 border border-blue-500/20 relative overflow-hidden">
              <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2"></div>
              <div className="space-y-8 relative z-10">
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-glow">
                    <span className="text-white text-2xl">🔍</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-foreground">Real-time Scanning</h3>
                    <p className="text-muted-foreground">Get results in seconds</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-green-600 rounded-xl flex items-center justify-center shadow-glow">
                    <span className="text-white text-2xl">📈</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-foreground">Comprehensive Reports</h3>
                    <p className="text-muted-foreground">Detailed findings with actionable recommendations</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-purple-600 rounded-xl flex items-center justify-center shadow-glow">
                    <span className="text-white text-2xl">🔔</span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-foreground">Smart Alerts</h3>
                    <p className="text-muted-foreground">Stay informed about security issues</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative overflow-hidden">
        <div className="absolute inset-0 gradient-bg opacity-10"></div>
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative z-10">
          <h2 className="text-4xl md:text-5xl font-bold text-foreground mb-6">
            Ready to Secure Your Websites?
          </h2>
          <p className="text-xl text-muted-foreground mb-8">
            Start scanning your websites for vulnerabilities today.
            Get instant results and actionable security insights.
          </p>
          {!isLoggedIn ? (
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                href="/auth/register"
                className="bg-foreground text-background px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
              >
                Create Free Account
              </Link>
              <Link
                href="/auth/login"
                className="glass-card text-foreground px-8 py-4 rounded-xl font-semibold text-lg border border-white/10 hover:bg-white/5 transition-all"
              >
                Sign In
              </Link>
            </div>
          ) : (
            <Link
              href="/dashboard"
              className="inline-block bg-foreground text-background px-8 py-4 rounded-xl font-semibold text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
            >
              Go to Dashboard
            </Link>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 bg-black/20 py-12 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-glow">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <h3 className="text-xl font-bold text-foreground">Vulnerability Scanner</h3>
              </div>
              <p className="text-muted-foreground">
                Enterprise-grade security scanning for your websites and applications.
              </p>
            </div>
            <div>
              <h4 className="font-semibold text-foreground mb-4">Features</h4>
              <ul className="space-y-2">
                <li><Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">Security Scanning</Link></li>
                <li><Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">Risk Analysis</Link></li>
                <li><Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">PDF Reports</Link></li>
                <li><Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">Scheduled Scans</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold text-foreground mb-4">Account</h4>
              <ul className="space-y-2">
                {isLoggedIn ? (
                  <>
                    <li><Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">Dashboard</Link></li>
                    <li><Link href="/schedules" className="text-muted-foreground hover:text-primary transition-colors">Schedules</Link></li>
                    <li><Link href="/settings/alerts" className="text-muted-foreground hover:text-primary transition-colors">Settings</Link></li>
                  </>
                ) : (
                  <>
                    <li><Link href="/auth/login" className="text-muted-foreground hover:text-primary transition-colors">Login</Link></li>
                    <li><Link href="/auth/register" className="text-muted-foreground hover:text-primary transition-colors">Register</Link></li>
                  </>
                )}
              </ul>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-white/10 text-center text-muted-foreground">
            <p>&copy; {new Date().getFullYear()} Vulnerability Scanner. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
