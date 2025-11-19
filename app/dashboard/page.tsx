'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'

interface Scan {
  id: string
  url: string
  riskScore: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  scanType?: 'QUICK' | 'STANDARD' | 'DEEP' | 'CUSTOM'
  progress?: number
  duration?: number
  startedAt: string
  completedAt?: string
}

interface Stats {
  totalScans: number
  byRisk: {
    LOW: number
    MEDIUM: number
    HIGH: number
  }
  recentScans: Scan[]
}

export default function Dashboard() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [scans, setScans] = useState<Scan[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [error, setError] = useState('')
  const [user, setUser] = useState<{ id: string; email: string } | null>(null)
  const [scanType, setScanType] = useState<'QUICK' | 'STANDARD' | 'DEEP'>('STANDARD')
  const [scanProgress, setScanProgress] = useState<{ progress: number; currentCheck: string } | null>(null)
  const [scanningScanId, setScanningScanId] = useState<string | null>(null)

  // Filters
  const [riskFilter, setRiskFilter] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  useEffect(() => {
    checkAuth()
  }, [])

  useEffect(() => {
    if (user) {
      fetchStats()
      fetchScans()
    }
  }, [user])

  useEffect(() => {
    fetchScans()
  }, [riskFilter, searchQuery, dateFrom, dateTo])

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
      router.push('/')
    } catch (err) {
      console.error('Logout error:', err)
    }
  }

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats')
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (err) {
      console.error('Error fetching stats:', err)
    }
  }

  const fetchScans = async () => {
    try {
      const params = new URLSearchParams()
      if (riskFilter) params.append('riskLevel', riskFilter)
      if (searchQuery) params.append('q', searchQuery)
      if (dateFrom) params.append('from', dateFrom)
      if (dateTo) params.append('to', dateTo)

      const response = await fetch(`/api/scans?${params.toString()}`)
      if (response.ok) {
        const data = await response.json()
        setScans(data.scans || [])
      }
    } catch (err) {
      console.error('Error fetching scans:', err)
    }
  }

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setScanProgress({ progress: 0, currentCheck: 'Initializing...' })

    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url, scanType }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to start scan')
      }

      const scanData = await response.json()
      setScanningScanId(scanData.id)
      setUrl('')

      // Poll for progress updates
      const progressInterval = setInterval(async () => {
        try {
          const progressResponse = await fetch(`/api/scans/${scanData.id}`)
          if (progressResponse.ok) {
            const scan = await progressResponse.json()
            if (scan.status === 'RUNNING') {
              setScanProgress({
                progress: scan.progress || 0,
                currentCheck: `Scanning... ${scan.progress || 0}%`
              })
            } else if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
              clearInterval(progressInterval)
              setScanProgress(null)
              setScanningScanId(null)
              fetchScans()
              fetchStats()
            }
          }
        } catch (err) {
          // Ignore errors
        }
      }, 1000) // Poll every second

      // Cleanup interval after 5 minutes
      setTimeout(() => {
        clearInterval(progressInterval)
        setScanProgress(null)
        setScanningScanId(null)
      }, 300000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
      setScanProgress(null)
      setScanningScanId(null)
    } finally {
      setLoading(false)
    }
  }

  const clearFilters = () => {
    setRiskFilter('')
    setSearchQuery('')
    setDateFrom('')
    setDateTo('')
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'text-green-400 bg-green-500/10'
      case 'FAILED':
        return 'text-red-400 bg-red-500/10'
      case 'PENDING':
        return 'text-yellow-400 bg-yellow-500/10'
      default:
        return 'text-muted-foreground bg-secondary/50'
    }
  }

  if (!user) {
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
              <Link href="/" className="flex items-center space-x-3 group">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-glow group-hover:scale-110 transition-transform">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <div>
                  <h1 className="text-xl font-bold gradient-text">
                    Vulnerability Scanner
                  </h1>
                  <p className="text-xs text-muted-foreground">Enterprise Security Analysis</p>
                </div>
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-muted-foreground hidden sm:block">{user.email}</span>
              <Link
                href="/schedules"
                className="text-muted-foreground hover:text-foreground px-3 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
              >
                Schedules
              </Link>
              <Link
                href="/settings/alerts"
                className="text-muted-foreground hover:text-foreground px-3 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
              >
                Alerts
              </Link>
              <button
                onClick={handleLogout}
                className="text-muted-foreground hover:text-foreground px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Stats Section */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="glass-card p-6 rounded-2xl">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Total Scans</p>
                  <p className="text-3xl font-bold text-foreground">{stats.totalScans}</p>
                </div>
                <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">📊</span>
                </div>
              </div>
            </div>
            <div className="glass-card p-6 rounded-2xl">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Low Risk</p>
                  <p className="text-3xl font-bold text-green-400">{stats.byRisk.LOW}</p>
                </div>
                <div className="w-12 h-12 bg-green-500/10 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">✅</span>
                </div>
              </div>
            </div>
            <div className="glass-card p-6 rounded-2xl">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Medium Risk</p>
                  <p className="text-3xl font-bold text-yellow-400">{stats.byRisk.MEDIUM}</p>
                </div>
                <div className="w-12 h-12 bg-yellow-500/10 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">⚠️</span>
                </div>
              </div>
            </div>
            <div className="glass-card p-6 rounded-2xl">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">High Risk</p>
                  <p className="text-3xl font-bold text-red-400">{stats.byRisk.HIGH}</p>
                </div>
                <div className="w-12 h-12 bg-red-500/10 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">🔴</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Scan Form */}
        <div className="mb-12">
          <div className="text-center mb-8 animate-fade-in">
            <h2 className="text-4xl md:text-5xl font-extrabold text-foreground mb-4">
              Secure Your Digital Assets
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Comprehensive security scanning for vulnerabilities, headers, SSL, and open ports
            </p>
          </div>

          <div className="glass-card p-8 rounded-2xl mb-8 animate-slide-up">
            <div className="flex items-center space-x-2 mb-6">
              <div className="w-2 h-2 bg-green-500 rounded-full pulse-ring"></div>
              <h3 className="text-2xl font-bold text-foreground">New Security Scan</h3>
            </div>
            <form onSubmit={handleScan} className="space-y-6">
              <div>
                <label
                  htmlFor="url"
                  className="block text-sm font-semibold text-muted-foreground mb-3"
                >
                  Enter URL to scan
                </label>
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <span className="text-muted-foreground text-lg">🌐</span>
                    </div>
                    <input
                      type="text"
                      id="url"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="w-full pl-12 pr-4 py-4 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary transition-all text-foreground placeholder-muted-foreground"
                      required
                      disabled={loading}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="gradient-bg text-white px-8 py-4 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105 flex items-center space-x-2 min-w-[140px] justify-center"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                        <span>Scanning...</span>
                      </>
                    ) : (
                      <>
                        <span>🔍</span>
                        <span>Scan Now</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div>
                <label
                  htmlFor="scanType"
                  className="block text-sm font-semibold text-muted-foreground mb-3"
                >
                  Scan Type
                </label>
                <div className="grid grid-cols-3 gap-3">
                  <button
                    type="button"
                    onClick={() => setScanType('QUICK')}
                    disabled={loading}
                    className={`px-4 py-3 rounded-xl font-medium transition-all border ${scanType === 'QUICK'
                        ? 'gradient-bg text-white border-transparent shadow-glow'
                        : 'bg-secondary/20 text-muted-foreground border-border hover:bg-secondary/40'
                      }`}
                  >
                    <div className="text-sm font-bold">⚡ Quick</div>
                    <div className="text-xs opacity-80">Basic checks (~30s)</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanType('STANDARD')}
                    disabled={loading}
                    className={`px-4 py-3 rounded-xl font-medium transition-all border ${scanType === 'STANDARD'
                        ? 'gradient-bg text-white border-transparent shadow-glow'
                        : 'bg-secondary/20 text-muted-foreground border-border hover:bg-secondary/40'
                      }`}
                  >
                    <div className="text-sm font-bold">🔍 Standard</div>
                    <div className="text-xs opacity-80">Comprehensive (~2min)</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanType('DEEP')}
                    disabled={loading}
                    className={`px-4 py-3 rounded-xl font-medium transition-all border ${scanType === 'DEEP'
                        ? 'gradient-bg text-white border-transparent shadow-glow'
                        : 'bg-secondary/20 text-muted-foreground border-border hover:bg-secondary/40'
                      }`}
                  >
                    <div className="text-sm font-bold">🔬 Deep</div>
                    <div className="text-xs opacity-80">Full analysis (~5min)</div>
                  </button>
                </div>
              </div>

              {scanProgress && (
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-semibold text-blue-400">{scanProgress.currentCheck}</span>
                    <span className="text-sm font-bold text-blue-400">{scanProgress.progress}%</span>
                  </div>
                  <div className="w-full bg-blue-900/30 rounded-full h-3 overflow-hidden">
                    <div
                      className="gradient-bg h-full transition-all duration-300 ease-out"
                      style={{ width: `${scanProgress.progress}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {error && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg flex items-center space-x-2 animate-fade-in">
                  <span>⚠️</span>
                  <span>{error}</span>
                </div>
              )}
            </form>
          </div>
        </div>

        {/* Filters */}
        <div className="glass-card p-6 rounded-2xl mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-bold text-foreground">Filters</h3>
            <button
              onClick={clearFilters}
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Clear all
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-muted-foreground mb-2">
                Risk Level
              </label>
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="w-full px-4 py-2 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground"
              >
                <option value="">All</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-muted-foreground mb-2">
                Search URL
              </label>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by URL..."
                className="w-full px-4 py-2 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground placeholder-muted-foreground"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-muted-foreground mb-2">
                From Date
              </label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="w-full px-4 py-2 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-muted-foreground mb-2">
                To Date
              </label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="w-full px-4 py-2 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground"
              />
            </div>
          </div>
        </div>

        {/* Scan History */}
        <div className="glass-card rounded-2xl overflow-hidden">
          <div className="px-8 py-6 border-b border-white/5 bg-white/5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-blue-400 text-xl">📊</span>
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Scan History</h2>
                  <p className="text-sm text-muted-foreground">View all your security scans</p>
                </div>
              </div>
              <div className="text-sm text-muted-foreground">
                {scans.length} {scans.length === 1 ? 'scan' : 'scans'}
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-white/5">
              <thead className="bg-white/5">
                <tr>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    URL
                  </th>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    Risk Score
                  </th>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    Risk Level
                  </th>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-8 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {scans.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-8 py-16 text-center"
                    >
                      <div className="flex flex-col items-center space-y-4">
                        <div className="w-20 h-20 bg-secondary/20 rounded-full flex items-center justify-center">
                          <span className="text-4xl">🔍</span>
                        </div>
                        <div>
                          <p className="text-muted-foreground font-medium">No scans found</p>
                          <p className="text-sm text-muted-foreground/60 mt-1">Start by scanning a URL above</p>
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : (
                  scans.map((scan, index) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-white/5 transition-all duration-200"
                    >
                      <td className="px-8 py-5 whitespace-nowrap">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                          <div className="text-sm font-semibold text-foreground max-w-xs truncate">
                            {scan.url}
                          </div>
                        </div>
                      </td>
                      <td className="px-8 py-5 whitespace-nowrap">
                        <div className="text-sm text-muted-foreground">
                          {new Date(scan.startedAt).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            year: 'numeric'
                          })}
                        </div>
                        <div className="text-xs text-muted-foreground/60">
                          {new Date(scan.startedAt).toLocaleTimeString('en-US', {
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </div>
                        {scan.duration && (
                          <div className="text-xs text-blue-400 mt-1 font-medium">
                            ⏱️ {scan.duration}s
                          </div>
                        )}
                        {scan.scanType && (
                          <div className="text-xs text-purple-400 mt-1 font-medium">
                            {scan.scanType}
                          </div>
                        )}
                      </td>
                      <td className="px-8 py-5 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          <div className="text-lg font-bold text-foreground">
                            {scan.riskScore}
                          </div>
                          <div className="w-16 h-2 bg-secondary/30 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${scan.riskLevel === 'HIGH' ? 'bg-red-500' :
                                  scan.riskLevel === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                                }`}
                              style={{ width: `${Math.min((scan.riskScore / 10) * 100, 100)}%` }}
                            ></div>
                          </div>
                        </div>
                      </td>
                      <td className="px-8 py-5 whitespace-nowrap">
                        <span
                          className={`px-3 py-1.5 text-xs font-bold rounded-full border ${getRiskColor(
                            scan.riskLevel
                          )} shadow-sm`}
                        >
                          {scan.riskLevel}
                        </span>
                      </td>
                      <td className="px-8 py-5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-semibold ${getStatusColor(
                            scan.status
                          )}`}
                        >
                          <span className={`w-2 h-2 rounded-full mr-2 ${scan.status === 'COMPLETED' ? 'bg-green-500' :
                              scan.status === 'FAILED' ? 'bg-red-500' : 'bg-yellow-500'
                            }`}></span>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-8 py-5 whitespace-nowrap text-sm font-medium">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="inline-flex items-center space-x-2 text-blue-400 hover:text-blue-300 font-semibold transition-colors"
                        >
                          <span>View Details</span>
                          <span>→</span>
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  )
}
