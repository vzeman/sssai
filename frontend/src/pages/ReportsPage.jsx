import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useToast } from '../components/ToastContext'

const API_BASE = import.meta.env.VITE_API_URL || ''

const SEVERITY_BADGE_CLASSES = {
  critical: 'bg-red-900/50 text-red-400',
  high: 'bg-orange-900/50 text-orange-400',
  medium: 'bg-yellow-900/50 text-yellow-400',
  low: 'bg-green-900/50 text-green-400',
  info: 'bg-blue-900/50 text-blue-400',
}

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
      const allScans = Array.isArray(data) ? data : (data.items || [])
      setScans(allScans.filter(s => s.status === 'completed'))
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
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="text-gray-400 text-sm">Loading reports...</div>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Reports</h1>
        <p className="text-sm text-gray-400 mt-1">Scan reports and executive summaries</p>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-6">{error}</div>}

      <div className="mb-6">
        <button className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition" onClick={generateExecutiveBrief}>
          Generate Executive Brief
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {scans.length === 0 ? (
          <div className="md:col-span-2 bg-gray-800/30 border border-gray-700 rounded-xl p-12 text-center">
            <div className="flex justify-center mb-4">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <polyline points="10 9 9 9 8 9" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">No reports available</h3>
            <p className="text-gray-500 mb-4">
              Reports are generated from completed scans. Run a security scan first to create a report.
            </p>
            <Link to="/scans/new" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition inline-block">Start a New Scan</Link>
          </div>
        ) : (
          scans.map(scan => (
            <div key={scan.id} className="bg-gray-800/30 border border-gray-700 rounded-xl p-5">
              <div className="flex items-start justify-between mb-4">
                <h3 className="text-base font-semibold text-white">{scan.target || 'Untitled Scan'}</h3>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-green-900/50 text-green-400">{scan.status}</span>
              </div>

              <div className="grid grid-cols-2 gap-3 mb-4">
                <div>
                  <span className="text-xs text-gray-400 uppercase block">Date</span>
                  <span className="text-sm text-gray-200">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
                <div>
                  <span className="text-xs text-gray-400 uppercase block">Findings</span>
                  <span className="text-sm text-gray-200">{scan.findings_count || scan.findings?.length || 0}</span>
                </div>
                {scan.risk_score != null && (
                  <div>
                    <span className="text-xs text-gray-400 uppercase block">Risk</span>
                    <span className="text-sm text-gray-200">{scan.risk_score}</span>
                  </div>
                )}
                <div>
                  <span className="text-xs text-gray-400 uppercase block">Type</span>
                  <span className="text-sm text-gray-200">{scan.scan_type || 'security'}</span>
                </div>
              </div>

              {scan.findings && scan.findings.length > 0 && (
                <div className="mb-4 border-t border-gray-700 pt-3">
                  <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Findings Summary</h4>
                  <ul className="space-y-1.5">
                    {scan.findings.slice(0, 3).map((f, idx) => (
                      <li key={idx} className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BADGE_CLASSES[f.severity] || 'bg-gray-700 text-gray-400'}`}>{f.severity}</span>
                        <span className="text-sm text-gray-300 truncate">{f.title}</span>
                      </li>
                    ))}
                    {scan.findings.length > 3 && (
                      <li className="text-xs text-gray-500">+{scan.findings.length - 3} more findings</li>
                    )}
                  </ul>
                </div>
              )}

              <div className="flex items-center gap-2 pt-2 border-t border-gray-700">
                <Link to={`/scans/${scan.id}`} className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition">
                  View Details
                </Link>
                <button className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition" onClick={() => downloadReport(scan.id, 'pdf')}>
                  PDF
                </button>
                <button className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition" onClick={() => downloadReport(scan.id, 'html')}>
                  HTML
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
