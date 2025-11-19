'use client'

import { useState, useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'

interface Finding {
  id: string
  type: string
  title: string
  severity: string
  passed: boolean
  details: string | null
}

interface Scan {
  id: string
  url: string
  riskScore: number
  riskLevel: string
  status: string
  startedAt: string
  completedAt: string | null
  findings: Finding[]
}

export default function ScanDetailsPage() {
  const params = useParams()
  const router = useRouter()
  const [scan, setScan] = useState<Scan | null>(null)
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [user, setUser] = useState<{ id: string; email: string } | null>(null)

  useEffect(() => {
    checkAuth()
    if (params.id) {
      fetchScan(params.id as string)
    }
  }, [params.id])

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/auth/me')
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
      } else {
        router.push('/auth/login')
      }
    } catch (err) {
      router.push('/auth/login')
    }
  }

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      router.push('/auth/login')
    } catch (err) {
      console.error('Logout error:', err)
    }
  }

  const fetchScan = async (id: string) => {
    try {
      const response = await fetch(`/api/scans/${id}`)
      if (!response.ok) {
        throw new Error('Failed to fetch scan')
      }
      const data = await response.json()
      setScan(data)
    } catch (error) {
      console.error('Error fetching scan:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleDownloadReport = async () => {
    if (!scan) return

    setDownloading(true)
    try {
      const response = await fetch(`/api/scans/${scan.id}/report`)
      if (!response.ok) {
        throw new Error('Failed to generate report')
      }

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan-report-${scan.id}.pdf`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error('Error downloading report:', error)
      alert('Failed to download report')
    } finally {
      setDownloading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'HIGH':
        return 'bg-red-500/10 text-red-400 border-red-500/30'
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
      case 'LOW':
        return 'bg-green-500/10 text-green-400 border-green-500/30'
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/30'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return 'bg-red-500/10 text-red-400 border-red-500/30'
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
      case 'LOW':
        return 'bg-green-500/10 text-green-400 border-green-500/30'
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/30'
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-16 w-16 border-4 border-primary/30 border-t-primary mx-auto"></div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-2xl">🔒</span>
            </div>
          </div>
          <p className="mt-6 text-muted-foreground font-medium">Loading scan details...</p>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center glass-card p-12 rounded-2xl">
          <div className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
            <span className="text-4xl">⚠️</span>
          </div>
          <h1 className="text-3xl font-bold text-foreground mb-4">Scan not found</h1>
          <p className="text-muted-foreground mb-6">The scan you're looking for doesn't exist or has been removed.</p>
          <Link
            href="/dashboard"
            className="inline-flex items-center space-x-2 gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg transition-all transform hover:scale-105"
          >
            <span>←</span>
            <span>Return to dashboard</span>
          </Link>
        </div>
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
              <Link href="/dashboard" className="flex items-center space-x-3 group">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-glow group-hover:scale-110 transition-transform">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <div>
                  <h1 className="text-xl font-bold gradient-text">
                    Vulnerability Scanner
                  </h1>
                  <p className="text-xs text-muted-foreground">Security Analysis</p>
                </div>
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              {user && (
                <span className="text-sm text-muted-foreground hidden sm:block">{user.email}</span>
              )}
              <Link
                href="/dashboard"
                className="flex items-center space-x-2 text-muted-foreground hover:text-foreground px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
              >
                <span>←</span>
                <span>Back to Dashboard</span>
              </Link>
              {user && (
                <button
                  onClick={handleLogout}
                  className="text-muted-foreground hover:text-foreground px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
                >
                  Logout
                </button>
              )}
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Scan Header */}
        <div className="glass-card p-8 mb-8 rounded-2xl animate-slide-up">
          <div className="flex justify-between items-start mb-6">
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-12 h-12 gradient-bg rounded-xl flex items-center justify-center shadow-glow">
                  <span className="text-white text-2xl">📋</span>
                </div>
                <div>
                  <h1 className="text-3xl font-extrabold text-foreground mb-1">
                    Scan Details
                  </h1>
                  <p className="text-lg text-muted-foreground flex items-center space-x-2">
                    <span>🌐</span>
                    <span className="font-medium text-foreground">{scan.url}</span>
                  </p>
                </div>
              </div>
            </div>
            <button
              onClick={handleDownloadReport}
              disabled={downloading}
              className="gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105 flex items-center space-x-2"
            >
              {downloading ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <span>📄</span>
                  <span>Download PDF</span>
                </>
              )}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
            <div className="bg-blue-500/10 rounded-xl p-6 border border-blue-500/30">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-blue-400 uppercase tracking-wide">Risk Score</div>
                <span className="text-2xl">🎯</span>
              </div>
              <div className="text-4xl font-extrabold text-blue-400">
                {scan.riskScore}
              </div>
              <div className="mt-3 w-full h-2 bg-blue-900/30 rounded-full overflow-hidden">
                <div
                  className={`h-full ${scan.riskLevel === 'HIGH' ? 'bg-red-500' :
                      scan.riskLevel === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                  style={{ width: `${Math.min((scan.riskScore / 10) * 100, 100)}%` }}
                ></div>
              </div>
            </div>
            <div className="bg-purple-500/10 rounded-xl p-6 border border-purple-500/30">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-purple-400 uppercase tracking-wide">Risk Level</div>
                <span className="text-2xl">⚠️</span>
              </div>
              <div className="mt-2">
                <span
                  className={`inline-block px-4 py-2 text-sm font-bold rounded-xl border ${getRiskColor(
                    scan.riskLevel
                  )} shadow-sm`}
                >
                  {scan.riskLevel}
                </span>
              </div>
            </div>
            <div className="bg-secondary/20 rounded-xl p-6 border border-border">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Scan Date</div>
                <span className="text-2xl">📅</span>
              </div>
              <div className="text-lg font-bold text-foreground">
                {new Date(scan.startedAt).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                })}
              </div>
              <div className="text-sm text-muted-foreground mt-1">
                {new Date(scan.startedAt).toLocaleTimeString('en-US', {
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Findings - Grouped by Type */}
        <div className="glass-card rounded-2xl overflow-hidden">
          <div className="px-8 py-6 border-b border-white/5 bg-white/5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-red-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-red-400 text-xl">🔍</span>
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-foreground">
                    Security Findings
                  </h2>
                  <p className="text-sm text-muted-foreground">{scan.findings.length} checks performed</p>
                </div>
              </div>
            </div>
          </div>

          {scan.findings.length === 0 ? (
            <div className="px-8 py-16 text-center">
              <div className="w-20 h-20 bg-secondary/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-4xl">✅</span>
              </div>
              <p className="text-muted-foreground font-medium">No findings available</p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {['HEADER', 'SSL', 'PORT', 'XSS', 'OTHER'].map((type) => {
                const typeFindings = scan.findings.filter(f => f.type === type)
                if (typeFindings.length === 0) return null

                const typeLabels: Record<string, string> = {
                  HEADER: 'Security Headers',
                  SSL: 'SSL/TLS',
                  PORT: 'Port Scanning',
                  XSS: 'XSS Surface',
                  OTHER: 'Other',
                }

                const typeIcons: Record<string, string> = {
                  HEADER: '🛡️',
                  SSL: '🔐',
                  PORT: '🔌',
                  XSS: '⚠️',
                  OTHER: '📋',
                }

                return (
                  <div key={type} className="px-8 py-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <span className="text-2xl">{typeIcons[type]}</span>
                      <h3 className="text-xl font-bold text-foreground">{typeLabels[type]}</h3>
                      <span className="px-2 py-1 text-xs font-semibold bg-secondary/30 text-muted-foreground rounded">
                        {typeFindings.length}
                      </span>
                    </div>
                    <div className="space-y-4 ml-11">
                      {typeFindings.map((finding) => (
                        <div
                          key={finding.id}
                          className="p-4 bg-secondary/10 rounded-xl border border-white/5 hover:bg-secondary/20 transition-colors"
                        >
                          <div className="flex items-start space-x-4">
                            <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-xl font-bold shadow-sm ${finding.passed
                                ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                                : 'bg-red-500/10 text-red-400 border border-red-500/30'
                              }`}>
                              {finding.passed ? '✓' : '✗'}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-start justify-between mb-2">
                                <h4 className="text-base font-bold text-foreground pr-4">
                                  {finding.title}
                                </h4>
                              </div>
                              <div className="flex items-center gap-2 mb-2 flex-wrap">
                                <span
                                  className={`px-2.5 py-1 text-xs font-bold rounded-lg border ${getSeverityColor(
                                    finding.severity
                                  )} shadow-sm`}
                                >
                                  {finding.severity}
                                </span>
                              </div>
                              {finding.details && (
                                <div className="mt-2 p-3 bg-black/20 rounded-lg border border-white/5">
                                  <p className="text-sm text-muted-foreground leading-relaxed">
                                    {finding.details}
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
