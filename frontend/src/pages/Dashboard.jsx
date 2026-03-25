import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { LoadingSkeleton } from '../components/LoadingSkeleton'
import { Pagination } from '../components/Pagination'
import { useToast } from '../components/ToastContext'
import { useScanUpdates } from '../hooks/useWebSocket'

const API_BASE = import.meta.env.VITE_API_URL || ''
const AUTO_REFRESH_INTERVAL = 30000

function Dashboard({ token }) {
  const [scans, setScans] = useState([])
  const [totalScans, setTotalScans] = useState(0)
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(0)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const { showToast } = useToast()

  const fetchData = useCallback(async function () {
    try {
      const skip = (currentPage - 1) * pageSize
      const resp = await fetch(`${API_BASE}/api/scans/?skip=${skip}&limit=${pageSize}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      const items = Array.isArray(data) ? data : (data.items || [])
      const total = Array.isArray(data) ? data.length : (data.total || 0)
      setScans(items)
      setTotalScans(total)

      let critical = 0, high = 0, medium = 0
      items.forEach(scan => {
        if (scan.findings) {
          scan.findings.forEach(f => {
            if (f.severity === 'critical') critical++
            else if (f.severity === 'high') high++
            else if (f.severity === 'medium') medium++
          })
        }
      })

      setStats({ total, critical, high, medium })
      setLastUpdated(new Date())
      setSecondsAgo(0)
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [token, currentPage, pageSize])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(fetchData, AUTO_REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchData])

  // WebSocket: auto-refresh on scan status changes
  const handleScanUpdate = useCallback((msg) => {
    fetchData()
    const status = msg.status || ''
    if (status === 'completed') {
      showToast(`Scan completed: ${msg.scan_id?.slice(0, 8) || 'unknown'}`, 'success')
    } else if (status === 'failed') {
      showToast(`Scan failed: ${msg.scan_id?.slice(0, 8) || 'unknown'}`, 'error')
    }
  }, [fetchData, showToast])

  const { wsStatus } = useScanUpdates(token, handleScanUpdate)

  // Update "seconds ago" counter every second
  useEffect(() => {
    if (!lastUpdated) return
    const ticker = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastUpdated.getTime()) / 1000))
    }, 1000)
    return () => clearInterval(ticker)
  }, [lastUpdated])

  function formatTimeAgo(seconds) {
    if (seconds < 5) return 'just now'
    if (seconds < 60) return `${seconds}s ago`
    const mins = Math.floor(seconds / 60)
    return `${mins}m ${seconds % 60}s ago`
  }


  if (loading && !lastUpdated) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Dashboard</h1>
        <div className="text-gray-400 text-center py-12">Loading...</div>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">Security overview and recent activity</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 text-xs ${wsStatus === 'connected' ? 'text-green-400' : 'text-gray-500'}`}>
            <span className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-green-400' : 'bg-gray-500'}`} />
            {wsStatus === 'connected' ? 'Live' : 'Offline'}
          </span>
          {lastUpdated && <span className="text-xs text-gray-500">Updated: {formatTimeAgo(secondsAgo)}</span>}
          <button onClick={fetchData} className="px-4 py-2 bg-gray-800 text-gray-300 hover:bg-gray-700 rounded-lg text-sm border border-gray-700 transition">Refresh</button>
          <Link to="/scans/new" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">+ New Scan</Link>
        </div>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-6">{error}</div>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-5">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Total Scans</div>
          <div className="text-3xl font-bold text-white mt-2">{stats.total}</div>
        </div>
        <div className="bg-gray-800/50 border border-red-900/50 rounded-xl p-5">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Critical</div>
          <div className="text-3xl font-bold text-red-400 mt-2">{stats.critical}</div>
        </div>
        <div className="bg-gray-800/50 border border-orange-900/50 rounded-xl p-5">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">High</div>
          <div className="text-3xl font-bold text-orange-400 mt-2">{stats.high}</div>
        </div>
        <div className="bg-gray-800/50 border border-yellow-900/50 rounded-xl p-5">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Medium</div>
          <div className="text-3xl font-bold text-yellow-400 mt-2">{stats.medium}</div>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        <div className="space-y-3">
          {scans.length === 0 ? (
            <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-12 text-center">
              <div className="text-gray-500 text-5xl mb-4">&#128269;</div>
              <h3 className="text-lg font-semibold text-gray-300 mb-2">No scans yet</h3>
              <p className="text-gray-500 text-sm mb-4">Start your first security scan to analyze vulnerabilities.</p>
              <Link to="/scans/new" className="inline-block px-6 py-2.5 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">Start a New Scan</Link>
            </div>
          ) : (
            scans.map(scan => (
              <div key={scan.id} className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 hover:bg-gray-800/60 transition cursor-pointer">
                <div className="font-medium text-white text-sm mb-2">{scan.target || 'Unknown'}</div>
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  <span className={`px-2 py-0.5 rounded-full font-semibold ${
                    scan.status === 'completed' ? 'bg-green-900/50 text-green-400' :
                    scan.status === 'running' ? 'bg-blue-900/50 text-blue-400' :
                    scan.status === 'failed' ? 'bg-red-900/50 text-red-400' :
                    'bg-yellow-900/50 text-yellow-400'
                  }`}>{scan.status}</span>
                  <span className="text-gray-500">|</span>
                  <span className="text-gray-400">{scan.scan_type || 'security'}</span>
                  {scan.findings_count > 0 && (
                    <>
                      <span className="text-gray-500">|</span>
                      <span className="text-gray-300">{scan.findings_count} findings</span>
                    </>
                  )}
                  {scan.risk_score != null && (
                    <>
                      <span className="text-gray-500">|</span>
                      <span className={scan.risk_score >= 30 ? 'text-red-400' : scan.risk_score >= 15 ? 'text-orange-400' : 'text-green-400'}>Risk: {scan.risk_score}</span>
                    </>
                  )}
                  <span className="text-gray-500">|</span>
                  <span className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
        {scans.length > 0 && (
          <Pagination
            totalItems={totalScans}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        )}
      </div>
    </div>
  )
}

export default Dashboard
