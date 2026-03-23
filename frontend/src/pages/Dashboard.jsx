import { useState, useEffect } from 'react'
import './Dashboard.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function Dashboard({ token }) {
  const [scans, setScans] = useState([])
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchData()
  }, [])

  async function fetchData() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(data.slice(0, 5)) // Show 5 recent
      
      // Calculate stats
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
      
      setStats({
        total: data.length,
        critical,
        high,
        medium,
      })
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading dashboard...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p>Security overview and recent activity</p>
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
            <div className="empty-state">No scans yet</div>
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
