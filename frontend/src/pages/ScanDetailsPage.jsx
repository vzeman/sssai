import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useToast } from '../components/ToastContext'
import FindingDetailModal from '../components/FindingDetailModal'
import './ScanDetailsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ScanDetailsPage({ token }) {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const { showToast } = useToast()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [logs, setLogs] = useState('')
  const [activeTab, setActiveTab] = useState('findings')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [sorting, setSorting] = useState({ field: 'severity', order: 'asc' })
  const [selectedFinding, setSelectedFinding] = useState(null)

  useEffect(() => {
    fetchScanDetails()
  }, [scanId])

  async function fetchScanDetails() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scan details')
      const data = await resp.json()
      setScan(data)
      setFindings(data.findings || [])
      
      // Try to fetch logs if available
      if (data.logs) {
        setLogs(typeof data.logs === 'string' ? data.logs : JSON.stringify(data.logs, null, 2))
      }
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleReScan() {
    try {
      const resp = await fetch(`${API_BASE}/api/scans/${scanId}/retry`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to retry scan')
      showToast('Scan retry initiated', 'success')
      fetchScanDetails()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function downloadReport(format) {
    try {
      const resp = await fetch(`${API_BASE}/api/scans/${scanId}/report?format=${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to download report')
      const blob = await resp.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan-report-${scanId}.${format === 'pdf' ? 'pdf' : 'html'}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  const sortedFindings = [...findings].sort((a, b) => {
    const aVal = a[sorting.field] || ''
    const bVal = b[sorting.field] || ''
    const comp = aVal < bVal ? -1 : aVal > bVal ? 1 : 0
    return sorting.order === 'asc' ? comp : -comp
  })

  if (loading) {
    return <div className="page-container"><div className="loading">Loading scan details...</div></div>
  }

  if (!scan) {
    return <div className="page-container"><div className="error-message">Scan not found</div></div>
  }

  return (
    <div className="page-container scan-details">
      <div className="page-header">
        <div className="header-title">
          <button className="back-btn" onClick={() => navigate('/reports')}>← Back</button>
          <div>
            <h1>{scan.target_url || 'Scan Details'}</h1>
            <p>Target: {scan.target_url || 'Unknown'}</p>
          </div>
        </div>
        <div className="header-actions">
          <button className="btn btn-primary" onClick={handleReScan}>🔄 Re-scan</button>
          <button className="btn btn-secondary" onClick={() => downloadReport('pdf')}>📄 PDF</button>
          <button className="btn btn-secondary" onClick={() => downloadReport('html')}>🌐 HTML</button>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="scan-metadata">
        <div className="metadata-item">
          <span className="label">Status</span>
          <span className={`badge ${scan.status}`}>{scan.status}</span>
        </div>
        <div className="metadata-item">
          <span className="label">Started</span>
          <span>{new Date(scan.created_at).toLocaleString()}</span>
        </div>
        <div className="metadata-item">
          <span className="label">Duration</span>
          <span>{scan.duration || 'N/A'}</span>
        </div>
        <div className="metadata-item">
          <span className="label">Findings</span>
          <span>{findings.length}</span>
        </div>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Findings ({findings.length})
        </button>
        <button
          className={`tab ${activeTab === 'timeline' ? 'active' : ''}`}
          onClick={() => setActiveTab('timeline')}
        >
          Timeline
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs
        </button>
      </div>

      <div className="tab-content">
        {activeTab === 'findings' && (
          <div className="findings-section">
            <div className="findings-controls">
              <span className="findings-count">Found {sortedFindings.length} findings</span>
              <select
                onChange={(e) => setSorting({ ...sorting, field: e.target.value })}
                value={sorting.field}
              >
                <option value="severity">Sort by Severity</option>
                <option value="cvss_score">Sort by CVSS</option>
                <option value="title">Sort by Title</option>
              </select>
            </div>

            <table className="findings-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {sortedFindings.length === 0 ? (
                  <tr><td colSpan="4" className="empty-row">No findings in this scan</td></tr>
                ) : (
                  sortedFindings.map((f, idx) => (
                    <tr key={idx} onClick={() => setSelectedFinding(f)} style={{ cursor: 'pointer' }}>
                      <td>{f.title || 'Unknown'}</td>
                      <td>
                        <span className={`severity-badge ${f.severity}`}>
                          {f.severity || 'unknown'}
                        </span>
                      </td>
                      <td>{f.cvss_score || 'N/A'}</td>
                      <td>
                        <span className={`status-badge ${f.status || 'open'}`}>
                          {f.status || 'open'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="timeline-section">
            <div className="timeline">
              <div className="timeline-item">
                <span className="timeline-marker"></span>
                <div className="timeline-content">
                  <div className="timeline-title">Scan Started</div>
                  <div className="timeline-time">
                    {new Date(scan.created_at).toLocaleString()}
                  </div>
                </div>
              </div>

              {scan.status === 'completed' && (
                <div className="timeline-item">
                  <span className="timeline-marker completed"></span>
                  <div className="timeline-content">
                    <div className="timeline-title">Scan Completed</div>
                    <div className="timeline-time">
                      {scan.completed_at
                        ? new Date(scan.completed_at).toLocaleString()
                        : 'N/A'}
                    </div>
                  </div>
                </div>
              )}

              {scan.status === 'failed' && (
                <div className="timeline-item">
                  <span className="timeline-marker failed"></span>
                  <div className="timeline-content">
                    <div className="timeline-title">Scan Failed</div>
                    <div className="timeline-time">
                      {scan.error_message || 'Unknown error'}
                    </div>
                  </div>
                </div>
              )}

              {scan.status === 'running' && (
                <div className="timeline-item">
                  <span className="timeline-marker running"></span>
                  <div className="timeline-content">
                    <div className="timeline-title">Scan In Progress</div>
                    <div className="timeline-time">Currently running...</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="logs-section">
            <pre className="logs-viewer">{logs || 'No logs available'}</pre>
          </div>
        )}
      </div>

      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}

export default ScanDetailsPage
