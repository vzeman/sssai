import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import './ReportsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ReportsPage({ token }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchScans()
  }, [])

  async function fetchScans() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(data)
      setError('')
    } catch (err) {
      setError(err.message)
      setScans([])
    } finally {
      setLoading(false)
    }
  }

  async function generateExecutiveBrief() {
    try {
      const completedScan = scans.find(s => s.status === 'completed') || scans[0]
      if (!completedScan) {
        alert('No scans available to generate a brief from.')
        return
      }
      const scanId = completedScan.id
      const resp = await fetch(`${API_BASE}/api/reports/${scanId}/executive-brief/html/token`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to generate executive brief token')
      const data = await resp.json()
      const reportToken = data.token
      window.open(`${API_BASE}/api/reports/${scanId}/executive-brief/html?rt=${reportToken}`, '_blank')
    } catch (err) {
      alert(`Error: ${err.message}`)
    }
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading reports...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Reports</h1>
        <p>Scan reports and executive summaries</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="reports-actions">
        <button className="btn btn-primary" onClick={generateExecutiveBrief}>
          📊 Generate Executive Brief
        </button>
      </div>

      <div className="reports-grid">
        {scans.length === 0 ? (
          <div className="empty-state">
            <p>No scans available yet. Start by running a scan to generate reports.</p>
          </div>
        ) : (
          scans.map(scan => (
            <div key={scan.id} className="report-card">
              <div className="report-header">
                <h3>{scan.target_url || 'Untitled Scan'}</h3>
                <span className={`status-badge ${scan.status}`}>{scan.status}</span>
              </div>

              <div className="report-meta">
                <div className="meta-item">
                  <span className="label">Date</span>
                  <span className="value">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
                <div className="meta-item">
                  <span className="label">Findings</span>
                  <span className="value">{scan.findings?.length || 0}</span>
                </div>
              </div>

              <div className="report-findings-preview">
                {scan.findings && scan.findings.length > 0 && (
                  <>
                    <h4>Findings Summary</h4>
                    <ul className="findings-list">
                      {scan.findings.slice(0, 3).map((f, idx) => (
                        <li key={idx}>
                          <span className={`severity ${f.severity}`}>{f.severity}</span>
                          <span className="title">{f.title}</span>
                        </li>
                      ))}
                      {scan.findings.length > 3 && (
                        <li className="more">+{scan.findings.length - 3} more findings</li>
                      )}
                    </ul>
                  </>
                )}
              </div>

              <div className="report-actions">
                <Link to={`/scans/${scan.id}`} className="btn btn-secondary">
                  View Details
                </Link>
                <button className="btn btn-secondary" onClick={() => downloadReport(scan.id, 'pdf')}>
                  📄 PDF
                </button>
                <button className="btn btn-secondary" onClick={() => downloadReport(scan.id, 'html')}>
                  🌐 HTML
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )

  async function downloadReport(scanId, format) {
    try {
      const resp = await fetch(`${API_BASE}/api/scans/${scanId}/report?format=${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Download failed')
      const blob = await resp.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${scanId}.${format === 'pdf' ? 'pdf' : 'html'}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      alert(`Error: ${err.message}`)
    }
  }
}

export default ReportsPage
