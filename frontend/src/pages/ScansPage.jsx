import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import { LoadingSkeleton } from '../components/LoadingSkeleton'
import { Pagination } from '../components/Pagination'
import './ScansPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ScansPage({ token }) {
  const [scans, setScans] = useState([])
  const [totalScans, setTotalScans] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedScan, setSelectedScan] = useState(null)
  const [exporting, setExporting] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  async function fetchScans(page, size) {
    try {
      setLoading(true)
      const skip = (page - 1) * size
      const resp = await fetch(`${API_BASE}/api/scans?skip=${skip}&limit=${size}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(data.items || [])
      setTotalScans(data.total || 0)
      setError('')
    } catch (err) {
      setError(err.message)
      setScans([])
      setTotalScans(0)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans(currentPage, pageSize)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPage, pageSize])

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

  async function handleExportCSV() {
    setExporting(true)
    try {
      const resp = await fetch(`${API_BASE}/api/export/scans?format=csv`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Export failed')
      const blob = await resp.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'scans_export.csv'
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setExporting(false)
    }
  }

  function getRiskLabel(score) {
    if (score == null) return { text: 'N/A', cls: '' }
    if (score >= 8) return { text: `${score} Critical`, cls: 'risk-critical' }
    if (score >= 6) return { text: `${score} High`, cls: 'risk-high' }
    if (score >= 4) return { text: `${score} Medium`, cls: 'risk-medium' }
    return { text: `${score} Low`, cls: 'risk-low' }
  }


  if (loading) {
    return (
      <div className="page-container">
        <div className="page-header"><h1>Scans</h1></div>
        <LoadingSkeleton rows={8} columns={6} />
      </div>
    )
  }

  return (
    <div className="page-container">
      <div className="page-header scans-header">
        <div>
          <h1>Scans</h1>
          <p>All security scans and their results</p>
        </div>
        <div className="scans-header-actions">
          {scans.length > 0 && (
            <button
              className="btn-export"
              onClick={handleExportCSV}
              disabled={exporting}
            >
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          )}
          <Link to="/scans/new" className="btn-new-scan">+ New Scan</Link>
        </div>
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
              {scans.map((scan, idx) => {
                const risk = getRiskLabel(scan.risk_score)
                // Find a previous completed scan for the same target within current page data
                const previousScan = scans.slice(idx + 1).find(
                  s => s.status === 'completed' && (s.target || s.target_url) === (scan.target || scan.target_url)
                )
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
                    <td className="scan-actions" onClick={e => e.stopPropagation()}>
                      <Link to={`/scans/${scan.id}`} className="view-link">View</Link>
                      {previousScan && scan.status === 'completed' && (
                        <Link
                          to={`/scans/${scan.id}/compare/${previousScan.id}`}
                          className="compare-link"
                        >
                          Compare
                        </Link>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          <Pagination
            totalItems={totalScans}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
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
