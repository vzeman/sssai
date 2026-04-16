import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useToast } from '../components/ToastContext'
import { useScanUpdates } from '../hooks/useWebSocket'
import FindingDetailModal from '../components/FindingDetailModal'

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

  function severityColor(sev) {
    switch (sev) {
      case 'critical': return 'bg-red-900/50 text-red-400'
      case 'high': return 'bg-orange-900/50 text-orange-400'
      case 'medium': return 'bg-yellow-900/50 text-yellow-400'
      case 'low': return 'bg-green-900/50 text-green-400'
      default: return 'bg-gray-700/50 text-gray-400'
    }
  }

  function statusBadgeColor(status) {
    switch (status) {
      case 'completed': return 'bg-green-900/50 text-green-400'
      case 'running': return 'bg-blue-900/50 text-blue-400'
      case 'failed': return 'bg-red-900/50 text-red-400'
      case 'queued': return 'bg-gray-700/50 text-gray-300'
      case 'open': return 'bg-blue-900/50 text-blue-400'
      case 'resolved': return 'bg-green-900/50 text-green-400'
      case 'false-positive': return 'bg-yellow-900/50 text-yellow-400'
      default: return 'bg-gray-700/50 text-gray-400'
    }
  }

  function riskColor(score) {
    if (score >= 30) return 'text-red-400 text-lg font-bold'
    if (score >= 15) return 'text-orange-400 text-lg font-bold'
    return 'text-emerald-400 text-lg font-bold'
  }

  if (loading) {
    return <div className="p-6 max-w-6xl mx-auto"><div className="text-gray-400 text-sm">Loading scan details...</div></div>
  }

  if (!scan) {
    return <div className="p-6 max-w-6xl mx-auto"><div className="text-red-400 text-sm">Scan not found</div></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-start mb-6 gap-6">
        <div>
          <h1 className="text-2xl font-bold text-white">{scan.target || 'Scan Details'}</h1>
          <p className="text-sm text-gray-400">Target: {scan.target || 'Unknown'}</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition" onClick={handleReScan}>Re-scan</button>
          <button className="px-4 py-2 rounded-lg text-sm font-medium transition bg-gray-700 hover:bg-gray-600 text-gray-200 border border-gray-600" onClick={() => downloadReport('pdf')}>PDF</button>
          <button className="px-4 py-2 rounded-lg text-sm font-medium transition bg-gray-700 hover:bg-gray-600 text-gray-200 border border-gray-600" onClick={() => downloadReport('html')}>HTML</button>
        </div>
      </div>

      {error && <div className="text-red-400 text-sm mb-4 px-4 py-3 bg-red-900/20 border border-red-800 rounded-lg">{error}</div>}

      <div className="flex flex-wrap gap-6 bg-gray-800/30 border border-gray-700 rounded-xl px-5 py-4 mb-5 items-center">
        <div>
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Status</div>
          <div className="mt-1">
            <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold capitalize ${statusBadgeColor(scan.status)}`}>
              {scan.status}
              {(scan.status === 'running' || scan.status === 'queued') && wsStatus === 'connected' && (
                <span className="text-green-400 text-[11px] font-medium animate-pulse"> (live)</span>
              )}
            </span>
          </div>
        </div>
        <div>
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Risk Score</div>
          <div className={`mt-1 ${riskColor(report?.risk_score || 0)}`}>
            {report?.risk_score != null ? report.risk_score : scan.risk_score ?? 'N/A'}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Findings</div>
          <div className="text-sm text-white mt-1">{findings.length || scan.findings_count || 0}</div>
        </div>
        <div>
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Started</div>
          <div className="text-sm text-white mt-1">{new Date(scan.created_at).toLocaleString()}</div>
        </div>
        {scan.completed_at && (
          <div>
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Completed</div>
            <div className="text-sm text-white mt-1">{new Date(scan.completed_at).toLocaleString()}</div>
          </div>
        )}
        {report?.scan_metadata?.total_tool_calls && (
          <div>
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Tool Calls</div>
            <div className="text-sm text-white mt-1">{report.scan_metadata.total_tool_calls}</div>
          </div>
        )}
        {report?.scan_metadata?.budget && (
          <div>
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Budget (USD)</div>
            <div className="text-sm text-white mt-1">
              ${report.scan_metadata.budget.usd_cost?.used?.toFixed(3) ?? 0}
              <span className="text-gray-500"> / ${report.scan_metadata.budget.usd_cost?.limit ?? 0}</span>
              <span className={`ml-1.5 text-xs ${report.scan_metadata.budget.status === 'exhausted' ? 'text-red-400' : report.scan_metadata.budget.status === 'warn_80' ? 'text-yellow-400' : 'text-green-400'}`}>
                ({report.scan_metadata.budget.status})
              </span>
            </div>
          </div>
        )}
        {report?.exploitation_gate?.attempted > 0 && (
          <div>
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Exploit Gate</div>
            <div className="text-sm text-white mt-1">
              <span className="text-green-400">{report.exploitation_gate.proven}</span> proven /
              <span className="text-yellow-400"> {report.exploitation_gate.demoted}</span> demoted /
              <span className="text-gray-500"> {report.exploitation_gate.attempted} attempted</span>
            </div>
          </div>
        )}
      </div>

      {report?.summary && (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-5">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Summary</h3>
          <p className="text-sm text-white leading-relaxed">{report.summary}</p>
        </div>
      )}

      <div className="flex gap-0 border-b border-gray-700 mb-5">
        <button
          className={`bg-transparent border-b-2 px-4 py-3 text-sm font-semibold cursor-pointer transition ${activeTab === 'findings' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
          onClick={() => setActiveTab('findings')}
        >
          Findings ({findings.length})
        </button>
        <button
          className={`bg-transparent border-b-2 px-4 py-3 text-sm font-semibold cursor-pointer transition ${activeTab === 'timeline' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
          onClick={() => setActiveTab('timeline')}
        >
          Timeline
        </button>
        <button
          className={`bg-transparent border-b-2 px-4 py-3 text-sm font-semibold cursor-pointer transition ${activeTab === 'logs' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs
        </button>
      </div>

      <div>
        {activeTab === 'findings' && (
          <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
            <div className="flex justify-between items-center px-4 py-3 border-b border-gray-700 bg-gray-900/50">
              <span className="text-sm text-gray-400">Found {sortedFindings.length} findings</span>
              <select
                onChange={(e) => setSorting({ ...sorting, field: e.target.value })}
                value={sorting.field}
                className="bg-gray-800 border border-gray-700 rounded text-gray-200 px-2.5 py-1.5 text-xs"
              >
                <option value="severity">Sort by Severity</option>
                <option value="cvss_score">Sort by CVSS</option>
                <option value="title">Sort by Title</option>
              </select>
            </div>

            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Title</th>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Severity</th>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">CVSS</th>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Proof</th>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Critic</th>
                  <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody>
                {sortedFindings.length === 0 ? (
                  <tr><td colSpan="6" className="text-center text-gray-500 py-10">No findings in this scan</td></tr>
                ) : (
                  sortedFindings.map((f, idx) => {
                    const exploit = f.exploitation_status;
                    const critic = f.critic_verdict?.verdict;
                    return (
                      <tr key={idx} onClick={() => setSelectedFinding(f)} className="cursor-pointer hover:bg-gray-800/50 transition">
                        <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-white">{f.title || 'Unknown'}</td>
                        <td className="border-b border-gray-700/50 px-4 py-3">
                          <span className={`inline-block px-2.5 py-1 rounded text-[11px] font-semibold capitalize ${severityColor(f.severity)}`}>
                            {f.severity || 'unknown'}
                          </span>
                          {f.severity_original && f.severity_original !== f.severity && (
                            <span className="ml-1 text-[10px] text-gray-500 line-through">{f.severity_original}</span>
                          )}
                        </td>
                        <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-gray-300">{f.cvss_score || 'N/A'}</td>
                        <td className="border-b border-gray-700/50 px-4 py-3">
                          {exploit === 'proven' && <span className="text-green-400 text-[11px] font-semibold">✓ PoC</span>}
                          {exploit === 'attempted_failed' && <span className="text-red-400 text-[11px]">✗ no PoC</span>}
                          {exploit === 'skipped_ineligible' && <span className="text-gray-500 text-[11px]">n/a</span>}
                          {!exploit && <span className="text-gray-600 text-[11px]">—</span>}
                        </td>
                        <td className="border-b border-gray-700/50 px-4 py-3">
                          {critic === 'accept' && <span className="text-green-400 text-[11px]">accept</span>}
                          {critic === 'reject' && <span className="text-red-400 text-[11px]">reject</span>}
                          {critic === 'needs_more_evidence' && <span className="text-yellow-400 text-[11px]">more evidence</span>}
                          {!critic && <span className="text-gray-600 text-[11px]">—</span>}
                        </td>
                        <td className="border-b border-gray-700/50 px-4 py-3">
                          <span className={`inline-block px-2.5 py-1 rounded text-[11px] font-semibold capitalize ${statusBadgeColor(f.status || 'open')}`}>
                            {f.status || 'open'}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="p-5 max-h-[600px] overflow-y-auto">
            {activities.length === 0 ? (
              <p className="text-gray-500 text-center py-10">No activity recorded for this scan.</p>
            ) : (
              <div className="relative pl-10 border-l-2 border-gray-700">
                {activities.map((act, idx) => (
                  <div key={idx} className="relative pl-8 pb-4 mb-4">
                    <span className={`absolute -left-[9px] top-0.5 w-4 h-4 rounded-full border-2 ${
                      act.type === 'finding' ? 'bg-orange-900/50 border-orange-400' :
                      act.type === 'error' ? 'bg-red-900/50 border-red-400' :
                      'bg-gray-700 border-gray-500'
                    }`}></span>
                    <div className="bg-gray-800/30 border border-gray-700 rounded-lg p-3">
                      <div className="text-sm font-semibold text-white mb-1">
                        {act.phase && <span className="text-cyan-400 text-[11px] mr-1.5">[{act.phase}]</span>}
                        {act.tool && <span className="text-amber-400 font-mono text-xs">{act.tool}</span>}
                        {!act.phase && !act.tool && <span>{act.type || 'event'}</span>}
                      </div>
                      <div className="text-xs text-gray-400 break-words">{act.message || act.result || ''}</div>
                      {act.timestamp && <div className="text-xs text-gray-600 mt-1">{act.timestamp}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="p-5">
            <pre className="bg-gray-950 border border-gray-700 rounded-xl p-4 font-mono text-xs text-cyan-400 max-h-96 overflow-auto leading-relaxed">{logs || 'No logs available. Logs are available during and shortly after scan execution.'}</pre>
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
