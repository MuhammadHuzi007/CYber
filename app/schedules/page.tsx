'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface Schedule {
  id: string
  url: string
  frequency: string
  active: boolean
  lastRunAt: string | null
  nextRunAt: string | null
  createdAt: string
}

export default function SchedulesPage() {
  const router = useRouter()
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [user, setUser] = useState<{ id: string; email: string } | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    url: '',
    frequency: 'daily' as 'daily' | 'weekly' | 'monthly',
  })
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    checkAuth()
    fetchSchedules()
  }, [])

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

  const fetchSchedules = async () => {
    try {
      const response = await fetch('/api/schedules')
      if (response.ok) {
        const data = await response.json()
        setSchedules(data.schedules || [])
      }
    } catch (err) {
      console.error('Error fetching schedules:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)

    try {
      const response = await fetch('/api/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to create schedule')
      }

      setFormData({ url: '', frequency: 'daily' })
      setShowForm(false)
      fetchSchedules()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setSubmitting(false)
    }
  }

  const handleToggle = async (id: string, currentActive: boolean) => {
    try {
      const response = await fetch(`/api/schedules/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !currentActive }),
      })

      if (response.ok) {
        fetchSchedules()
      }
    } catch (err) {
      console.error('Error toggling schedule:', err)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return

    try {
      const response = await fetch(`/api/schedules/${id}`, {
        method: 'DELETE',
      })

      if (response.ok) {
        fetchSchedules()
      }
    } catch (err) {
      console.error('Error deleting schedule:', err)
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex flex-col">
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
                  <p className="text-xs text-muted-foreground">Scheduled Scans</p>
                </div>
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/dashboard" className="text-muted-foreground hover:text-foreground px-3 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5">
                Dashboard
              </Link>
              <Link href="/settings/alerts" className="text-muted-foreground hover:text-foreground px-3 py-2 rounded-lg text-sm font-medium transition-all hover:bg-white/5">
                Alert Settings
              </Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex justify-between items-center mb-8">
          <h2 className="text-3xl font-bold text-foreground">Scheduled Scans</h2>
          <button
            onClick={() => setShowForm(!showForm)}
            className="gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg transition-all transform hover:scale-105"
          >
            {showForm ? 'Cancel' : '+ New Schedule'}
          </button>
        </div>

        {showForm && (
          <div className="glass-card p-8 mb-8 rounded-2xl animate-slide-up">
            <h3 className="text-xl font-bold text-foreground mb-6">Create New Schedule</h3>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-muted-foreground mb-2">
                  URL to scan
                </label>
                <input
                  type="text"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  placeholder="https://example.com"
                  className="w-full px-4 py-3 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground placeholder-muted-foreground"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-muted-foreground mb-2">
                  Frequency
                </label>
                <select
                  value={formData.frequency}
                  onChange={(e) => setFormData({ ...formData, frequency: e.target.value as any })}
                  className="w-full px-4 py-3 bg-secondary/20 border border-border rounded-xl focus:ring-2 focus:ring-primary focus:border-primary text-foreground"
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={submitting}
                className="gradient-bg text-white px-6 py-3 rounded-xl font-semibold shadow-glow hover:shadow-glow-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Creating...' : 'Create Schedule'}
              </button>
            </form>
          </div>
        )}

        <div className="glass-card rounded-2xl overflow-hidden">
          <div className="px-8 py-6 border-b border-white/5 bg-white/5">
            <h3 className="text-xl font-bold text-foreground">Active Schedules</h3>
          </div>
          {schedules.length === 0 ? (
            <div className="px-8 py-16 text-center">
              <p className="text-muted-foreground">No schedules yet. Create one above to get started.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {schedules.map((schedule) => (
                <div key={schedule.id} className="px-8 py-6 hover:bg-white/5 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h4 className="text-lg font-bold text-foreground">{schedule.url}</h4>
                        <span className={`px-3 py-1 rounded-lg text-xs font-semibold ${schedule.active
                            ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                            : 'bg-secondary/30 text-muted-foreground border border-white/10'
                          }`}>
                          {schedule.active ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm text-muted-foreground">
                        <div>
                          <span className="font-semibold text-foreground">Frequency:</span> {schedule.frequency}
                        </div>
                        <div>
                          <span className="font-semibold text-foreground">Last Run:</span>{' '}
                          {schedule.lastRunAt
                            ? new Date(schedule.lastRunAt).toLocaleString()
                            : 'Never'}
                        </div>
                        <div>
                          <span className="font-semibold text-foreground">Next Run:</span>{' '}
                          {schedule.nextRunAt
                            ? new Date(schedule.nextRunAt).toLocaleString()
                            : 'N/A'}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => handleToggle(schedule.id, schedule.active)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${schedule.active
                            ? 'bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20'
                            : 'bg-green-500/10 text-green-400 hover:bg-green-500/20'
                          }`}
                      >
                        {schedule.active ? 'Deactivate' : 'Activate'}
                      </button>
                      <button
                        onClick={() => handleDelete(schedule.id)}
                        className="px-4 py-2 bg-red-500/10 text-red-400 rounded-lg text-sm font-medium hover:bg-red-500/20 transition-colors"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
