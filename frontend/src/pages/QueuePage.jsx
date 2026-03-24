import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import './StubPage.css'
import './QueuePage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function QueuePage({ token }) {
  const [queue, setQueue] = useState([])

  useEffect(() => {
    let cancelled = false
    async function poll() {
      try {
        const resp = await fetch(`${API_BASE}/api/scans?status=queued,running`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (resp.ok && !cancelled) {
          setQueue(await resp.json())
        }
      } catch (err) {
        if (!cancelled) console.error('Failed to fetch queue:', err)
      }
    }
    poll()
    const interval = setInterval(poll, 5000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [token])

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Scanning Queue</h1>
        <p>Monitor queued and running scans</p>
      </div>

      <div className="queue-summary">
        <div className="summary-item">
          <span className="label">Queued</span>
          <span className="count">{queue.filter(s => s.status === 'queued').length}</span>
        </div>
        <div className="summary-item">
          <span className="label">Running</span>
          <span className="count">{queue.filter(s => s.status === 'running').length}</span>
        </div>
      </div>

      {queue.length === 0 ? (
        <div className="empty-state-card">
          <div className="empty-state-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          </div>
          <h3 className="empty-state-title">Queue is clear</h3>
          <p className="empty-state-text">
            No scans are queued or running right now. Start a new scan to see it appear here.
          </p>
          <Link to="/scans/new" className="empty-state-cta">Start a New Scan</Link>
        </div>
      ) : (
        <table className="queue-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Status</th>
              <th>Position</th>
              <th>ETA</th>
            </tr>
          </thead>
          <tbody>
            {queue.map((scan, idx) => (
              <tr key={scan.id}>
                <td>{scan.target_url || 'N/A'}</td>
                <td>
                  <span className={`queue-status-badge ${scan.status}`}>
                    {scan.status}
                  </span>
                </td>
                <td className="muted">{idx + 1}</td>
                <td className="muted">~5 min</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default QueuePage
