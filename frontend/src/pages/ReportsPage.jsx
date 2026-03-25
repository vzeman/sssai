import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useToast } from '../components/ToastContext'
import './ReportsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ReportsPage({ token }) {
  const { showToast } = useToast()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchScans()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function fetchScans() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(Array.isArray(data) ? data : (data.items || []))
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
        showToast('No scans available to generate a brief from.', 'warning')
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
      showToast(err.message, 'error')
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
          <div className="empty-state-card">
            <div className="empty-state-icon">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <polyline points="10 9 9 9 8 9" />
              </svg>
            </div>
            <h3 className="empty-state-title">No reports available</h3>
            <p className="empty-state-text">
              Reports are generated from completed scans. Run a security scan first to create a report.
            </p>
            <Link to="/scans/new" className="empty-state-cta">Start a New Scan</Link>
          </div>
        ) : (
          scans.map(scan => (
            <div key={scan.id} className="report-card">
              <div className="report-header">
                <h3>{scan.target || 'Untitled Scan'}</h3>
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
      showToast(err.message, 'error')
    }
  }
}

export default ReportsPage
