import { useState, useEffect } from 'react'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function QueuePage({ token }) {
  const [queue, setQueue] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchQueue()
    const interval = setInterval(fetchQueue, 5000) // Poll every 5 seconds
    return () => clearInterval(interval)
  }, [])

  async function fetchQueue() {
    try {
      const resp = await fetch(`${API_BASE}/api/scans?status=queued,running`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (resp.ok) {
        const data = await resp.json()
        setQueue(data)
      }
    } catch (err) {
      console.error('Failed to fetch queue:', err)
    } finally {
      setLoading(false)
    }
  }

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
        <div className="empty-state">
          <p>No scans in queue. All systems operational.</p>
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#111420', borderBottom: '1px solid #2a2d3a' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Target</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Status</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Position</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>ETA</th>
            </tr>
          </thead>
          <tbody>
            {queue.map((scan, idx) => (
              <tr key={scan.id} style={{ borderBottom: '1px solid #2a2d3a' }}>
                <td style={{ padding: '12px 16px', color: '#e8eaed' }}>{scan.target_url || 'N/A'}</td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{
                    padding: '4px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600,
                    background: scan.status === 'running' ? '#2a3a4a' : '#3a3a2a',
                    color: scan.status === 'running' ? '#4a9eff' : '#ffaa44'
                  }}>
                    {scan.status}
                  </span>
                </td>
                <td style={{ padding: '12px 16px', color: '#888' }}>{idx + 1}</td>
                <td style={{ padding: '12px 16px', color: '#888' }}>~5 min</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default QueuePage
