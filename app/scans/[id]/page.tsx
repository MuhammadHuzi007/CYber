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

  useEffect(() => {
    if (params.id) {
      fetchScan(params.id as string)
    }
  }, [params.id])

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
        return 'bg-red-50 text-red-700 border-red-300 shadow-sm'
      case 'MEDIUM':
        return 'bg-yellow-50 text-yellow-700 border-yellow-300 shadow-sm'
      case 'LOW':
        return 'bg-green-50 text-green-700 border-green-300 shadow-sm'
      default:
        return 'bg-gray-50 text-gray-700 border-gray-300 shadow-sm'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return 'bg-red-50 text-red-700 border-red-300'
      case 'MEDIUM':
        return 'bg-yellow-50 text-yellow-700 border-yellow-300'
      case 'LOW':
        return 'bg-green-50 text-green-700 border-green-300'
      default:
        return 'bg-gray-50 text-gray-700 border-gray-300'
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600 mx-auto"></div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-2xl">🔒</span>
            </div>
          </div>
          <p className="mt-6 text-gray-600 font-medium">Loading scan details...</p>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-12">
          <div className="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-6">
            <span className="text-4xl">⚠️</span>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-4">Scan not found</h1>
          <p className="text-gray-600 mb-6">The scan you're looking for doesn't exist or has been removed.</p>
          <Link
            href="/"
            className="inline-flex items-center space-x-2 gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
          >
            <span>←</span>
            <span>Return to dashboard</span>
          </Link>
        </div>
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
              <Link href="/" className="flex items-center space-x-3 group">
                <div className="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform">
                  <span className="text-white text-xl font-bold">🔒</span>
                </div>
                <div>
                  <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    Vulnerability Scanner
                  </h1>
                  <p className="text-xs text-gray-500">Security Analysis</p>
                </div>
              </Link>
            </div>
            <div className="flex items-center">
              <Link
                href="/"
                className="flex items-center space-x-2 text-gray-700 hover:text-gray-900 px-4 py-2 rounded-lg text-sm font-medium transition-all hover:bg-gray-100"
              >
                <span>←</span>
                <span>Back to Dashboard</span>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Scan Header */}
        <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 p-8 mb-8 card-hover animate-slide-up">
          <div className="flex justify-between items-start mb-6">
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-12 h-12 gradient-bg rounded-xl flex items-center justify-center shadow-lg">
                  <span className="text-white text-2xl">📋</span>
                </div>
                <div>
                  <h1 className="text-3xl font-extrabold text-gray-900 mb-1">
                    Scan Details
                  </h1>
                  <p className="text-lg text-gray-600 flex items-center space-x-2">
                    <span>🌐</span>
                    <span className="font-medium">{scan.url}</span>
                  </p>
                </div>
              </div>
            </div>
            <button
              onClick={handleDownloadReport}
              disabled={downloading}
              className="gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105 flex items-center space-x-2"
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
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border-2 border-blue-200 shadow-sm">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-blue-700 uppercase tracking-wide">Risk Score</div>
                <span className="text-2xl">🎯</span>
              </div>
              <div className="text-4xl font-extrabold text-blue-900">
                {scan.riskScore}
              </div>
              <div className="mt-3 w-full h-2 bg-blue-200 rounded-full overflow-hidden">
                <div 
                  className={`h-full ${
                    scan.riskLevel === 'HIGH' ? 'bg-red-500' :
                    scan.riskLevel === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min((scan.riskScore / 10) * 100, 100)}%` }}
                ></div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 border-2 border-purple-200 shadow-sm">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-purple-700 uppercase tracking-wide">Risk Level</div>
                <span className="text-2xl">⚠️</span>
              </div>
              <div className="mt-2">
                <span
                  className={`inline-block px-4 py-2 text-sm font-bold rounded-xl border-2 ${getRiskColor(
                    scan.riskLevel
                  )} shadow-sm`}
                >
                  {scan.riskLevel}
                </span>
              </div>
            </div>
            <div className="bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl p-6 border-2 border-gray-200 shadow-sm">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Scan Date</div>
                <span className="text-2xl">📅</span>
              </div>
              <div className="text-lg font-bold text-gray-900">
                {new Date(scan.startedAt).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                })}
              </div>
              <div className="text-sm text-gray-600 mt-1">
                {new Date(scan.startedAt).toLocaleTimeString('en-US', {
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Findings */}
        <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-soft border border-gray-200/50 overflow-hidden">
          <div className="px-8 py-6 border-b border-gray-200/50 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
                  <span className="text-red-600 text-xl">🔍</span>
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">
                    Security Findings
                  </h2>
                  <p className="text-sm text-gray-500">{scan.findings.length} checks performed</p>
                </div>
              </div>
            </div>
          </div>
          <div className="divide-y divide-gray-200/50">
            {scan.findings.length === 0 ? (
              <div className="px-8 py-16 text-center">
                <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <span className="text-4xl">✅</span>
                </div>
                <p className="text-gray-500 font-medium">No findings available</p>
              </div>
            ) : (
              scan.findings.map((finding, index) => (
                <div
                  key={finding.id}
                  className="px-8 py-6 hover:bg-gradient-to-r hover:from-blue-50/30 hover:to-purple-50/30 transition-all duration-200"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  <div className="flex items-start space-x-4">
                    <div className={`flex-shrink-0 w-12 h-12 rounded-xl flex items-center justify-center text-2xl font-bold shadow-sm ${
                      finding.passed 
                        ? 'bg-green-100 text-green-600 border-2 border-green-200' 
                        : 'bg-red-100 text-red-600 border-2 border-red-200'
                    }`}>
                      {finding.passed ? '✓' : '✗'}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between mb-3">
                        <h3 className="text-lg font-bold text-gray-900 pr-4">
                          {finding.title}
                        </h3>
                      </div>
                      <div className="flex items-center gap-3 mb-3 flex-wrap">
                        <span
                          className={`px-3 py-1.5 text-xs font-bold rounded-lg border-2 ${getSeverityColor(
                            finding.severity
                          )} shadow-sm`}
                        >
                          {finding.severity}
                        </span>
                        <span className="px-3 py-1.5 text-xs font-semibold text-gray-700 bg-gray-100 rounded-lg border border-gray-200">
                          {finding.type}
                        </span>
                      </div>
                      {finding.details && (
                        <div className="mt-3 p-4 bg-gray-50 rounded-lg border border-gray-200">
                          <p className="text-sm text-gray-700 leading-relaxed">
                            {finding.details}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  )
}

