import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useToast } from '../components/ToastContext'
import { useScanUpdates } from '../hooks/useWebSocket'
import FindingDetailModal from '../components/FindingDetailModal'
import './ScanDetailsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function ScanDetailsPage({ token }) {
  const { scanId } = useParams()
  const { showToast } = useToast()
  const [scan, setScan] = useState(null)
  const [report, setReport] = useState(null)
  const [findings, setFindings] = useState([])
  const [activities, setActivities] = useState([])
  const [logs, setLogs] = useState('')
  const [activeTab, setActiveTab] = useState('findings')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [sorting, setSorting] = useState({ field: 'severity', order: 'asc' })
  const [selectedFinding, setSelectedFinding] = useState(null)

  useEffect(() => {
    fetchScanDetails()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  // WebSocket: auto-update when this scan's status changes
  const handleScanUpdate = useCallback((msg) => {
    if (msg.scan_id === scanId) {
      fetchScanDetails()
      if (msg.status === 'completed') {
        showToast('Scan completed', 'success')
      } else if (msg.status === 'failed') {
        showToast('Scan failed', 'error')
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  const { wsStatus } = useScanUpdates(token, handleScanUpdate)

  async function fetchScanDetails() {
    try {
      setLoading(true)
      const headers = { Authorization: `Bearer ${token}` }

      // Fetch scan metadata
      const scanResp = await fetch(`${API_BASE}/api/scans/${scanId}`, { headers })
      if (!scanResp.ok) throw new Error('Failed to fetch scan details')
      const scanData = await scanResp.json()
      setScan(scanData)

      // Fetch report (contains findings, summary, risk details)
      try {
        const reportResp = await fetch(`${API_BASE}/api/scans/${scanId}/report`, { headers })
        if (reportResp.ok) {
          const reportData = await reportResp.json()
          setReport(reportData)
          setFindings(reportData.findings || [])
        }
      } catch {
        // Report not ready yet
      }

      // Fetch activity timeline
      try {
        const actResp = await fetch(`${API_BASE}/api/scans/${scanId}/activity`, { headers })
        if (actResp.ok) {
          const actData = await actResp.json()
          setActivities(actData.activities || [])
        }
      } catch {
        // Activity not available
      }

      // Fetch worker logs
      try {
        const logResp = await fetch(`${API_BASE}/api/logs/worker`, { headers })
        if (logResp.ok) {
          const logData = await logResp.json()
          setLogs(logData.logs || '')
        }
      } catch {
        // Logs not available
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
          <div>
            <h1>{scan.target || 'Scan Details'}</h1>
            <p>Target: {scan.target || 'Unknown'}</p>
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
          <span className={`badge ${scan.status}`}>
            {scan.status}
            {(scan.status === 'running' || scan.status === 'queued') && wsStatus === 'connected' && (
              <span className="live-indicator" title="Receiving live updates"> (live)</span>
            )}
          </span>
        </div>
        <div className="metadata-item">
          <span className="label">Risk Score</span>
          <span className={`risk-value ${(report?.risk_score || 0) >= 30 ? 'critical' : (report?.risk_score || 0) >= 15 ? 'high' : 'low'}`}>
            {report?.risk_score != null ? report.risk_score : scan.risk_score ?? 'N/A'}
          </span>
        </div>
        <div className="metadata-item">
          <span className="label">Findings</span>
          <span>{findings.length || scan.findings_count || 0}</span>
        </div>
        <div className="metadata-item">
          <span className="label">Started</span>
          <span>{new Date(scan.created_at).toLocaleString()}</span>
        </div>
        {scan.completed_at && (
          <div className="metadata-item">
            <span className="label">Completed</span>
            <span>{new Date(scan.completed_at).toLocaleString()}</span>
          </div>
        )}
        {report?.scan_metadata?.total_tool_calls && (
          <div className="metadata-item">
            <span className="label">Tool Calls</span>
            <span>{report.scan_metadata.total_tool_calls}</span>
          </div>
        )}
      </div>

      {report?.summary && (
        <div className="scan-summary">
          <h3>Summary</h3>
          <p>{report.summary}</p>
        </div>
      )}

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
            {activities.length === 0 ? (
              <p className="empty-text">No activity recorded for this scan.</p>
            ) : (
              <div className="timeline">
                {activities.map((act, idx) => (
                  <div key={idx} className={`timeline-item ${act.phase || act.type || ''}`}>
                    <span className={`timeline-marker ${act.type === 'finding' ? 'finding' : act.type === 'error' ? 'failed' : ''}`}></span>
                    <div className="timeline-content">
                      <div className="timeline-title">
                        {act.phase && <span className="timeline-phase">[{act.phase}]</span>}
                        {act.tool && <span className="timeline-tool">{act.tool}</span>}
                        {!act.phase && !act.tool && <span>{act.type || 'event'}</span>}
                      </div>
                      <div className="timeline-message">{act.message || act.result || ''}</div>
                      {act.timestamp && <div className="timeline-time">{act.timestamp}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="logs-section">
            <pre className="logs-viewer">{logs || 'No logs available. Logs are available during and shortly after scan execution.'}</pre>
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
