import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import './Dashboard.css'

const API_BASE = import.meta.env.VITE_API_URL || ''
const AUTO_REFRESH_INTERVAL = 30000

function Dashboard({ token }) {
  const [scans, setScans] = useState([])
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(0)

  const fetchData = useCallback(async function () {
    try {
      const resp = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(data.slice(0, 5))

      let critical = 0, high = 0, medium = 0
      data.forEach(scan => {
        if (scan.findings) {
          scan.findings.forEach(f => {
            if (f.severity === 'critical') critical++
            else if (f.severity === 'high') high++
            else if (f.severity === 'medium') medium++
          })
        }
      })

      setStats({ total: data.length, critical, high, medium })
      setLastUpdated(new Date())
      setSecondsAgo(0)
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(fetchData, AUTO_REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchData])

  // Update "seconds ago" counter every second
  useEffect(() => {
    if (!lastUpdated) return
    const ticker = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastUpdated.getTime()) / 1000))
    }, 1000)
    return () => clearInterval(ticker)
  }, [lastUpdated])

  function formatTimeAgo(seconds) {
    if (seconds < 5) return 'just now'
    if (seconds < 60) return `${seconds}s ago`
    const mins = Math.floor(seconds / 60)
    return `${mins}m ${seconds % 60}s ago`
  }

  if (loading && !lastUpdated) {
    return <div className="page-container"><div className="loading">Loading dashboard...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header dashboard-header">
        <div>
          <h1>Dashboard</h1>
          <p>Security overview and recent activity</p>
        </div>
        <div className="header-actions">
          {lastUpdated && (
            <span className="last-updated">
              Last updated: {formatTimeAgo(secondsAgo)}
            </span>
          )}
          <button className="refresh-btn" onClick={fetchData} title="Refresh data">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            Refresh
          </button>
          <Link to="/scans/new" className="dashboard-new-scan">+ New Scan</Link>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Scans</div>
          <div className="stat-value">{stats.total}</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">Critical</div>
          <div className="stat-value">{stats.critical}</div>
        </div>
        <div className="stat-card high">
          <div className="stat-label">High</div>
          <div className="stat-value">{stats.high}</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-label">Medium</div>
          <div className="stat-value">{stats.medium}</div>
        </div>
      </div>

      <div className="recent-scans">
        <h2>Recent Scans</h2>
        <div className="scans-list">
          {scans.length === 0 ? (
            <div className="empty-state-card">
              <div className="empty-state-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
              </div>
              <h3 className="empty-state-title">No scans yet</h3>
              <p className="empty-state-text">
                Get started by creating your first security scan to analyze a target for vulnerabilities.
              </p>
              <Link to="/scans/new" className="empty-state-cta">Start a New Scan</Link>
            </div>
          ) : (
            scans.map(scan => (
              <div key={scan.id} className="scan-item">
                <div className="scan-title">{scan.target_url || 'Unknown'}</div>
                <div className="scan-details">
                  <span className={`status ${scan.status}`}>{scan.status}</span>
                  <span className="timestamp">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard
