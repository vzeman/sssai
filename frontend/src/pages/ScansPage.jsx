import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import './ScansPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ScansPage({ token }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedScan, setSelectedScan] = useState(null)

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

  function getStatusClass(status) {
    const map = {
      completed: 'status-completed',
      running: 'status-running',
      pending: 'status-pending',
      queued: 'status-pending',
      failed: 'status-failed',
      cancelled: 'status-failed',
    }
    return map[status] || ''
  }

  function getRiskLabel(score) {
    if (score == null) return { text: 'N/A', cls: '' }
    if (score >= 8) return { text: `${score} Critical`, cls: 'risk-critical' }
    if (score >= 6) return { text: `${score} High`, cls: 'risk-high' }
    if (score >= 4) return { text: `${score} Medium`, cls: 'risk-medium' }
    return { text: `${score} Low`, cls: 'risk-low' }
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading scans...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header scans-header">
        <div>
          <h1>Scans</h1>
          <p>All security scans and their results</p>
        </div>
        <Link to="/scans/new" className="btn-new-scan">+ New Scan</Link>
      </div>

      {error && <div className="error-message">{error}</div>}

      {scans.length === 0 ? (
        <div className="empty-state">
          <p>No scans found. Start your first security scan.</p>
          <Link to="/scans/new" className="btn-new-scan">+ New Scan</Link>
        </div>
      ) : (
        <div className="scans-table-wrapper">
          <table className="scans-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Risk Score</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => {
                const risk = getRiskLabel(scan.risk_score)
                return (
                  <tr key={scan.id} onClick={() => setSelectedScan(scan)} style={{cursor: 'pointer'}}>
                    <td className="scan-target">{scan.target_url || scan.target || 'Unknown'}</td>
                    <td>{scan.scan_type || scan.type || '-'}</td>
                    <td>
                      <span className={`status-badge ${getStatusClass(scan.status)}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      <span className={`risk-badge ${risk.cls}`}>{risk.text}</span>
                    </td>
                    <td className="scan-date">
                      {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '-'}
                    </td>
                    <td>
                      <Link to={`/scans/${scan.id}`} className="view-link">View</Link>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedScan && (
        <DetailModal
          title={selectedScan.target_url || selectedScan.target || 'Scan Details'}
          data={selectedScan}
          onClose={() => setSelectedScan(null)}
        />
      )}
    </div>
  )
}

export default ScansPage
