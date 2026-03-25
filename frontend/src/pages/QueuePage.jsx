import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

const API_BASE = import.meta.env.VITE_API_URL || ''

function QueuePage({ token }) {
  const [queue, setQueue] = useState([])

  useEffect(() => {
    let cancelled = false
    async function poll() {
      try {
        const resp = await fetch(`${API_BASE}/api/scans/?status=queued,running`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (resp.ok && !cancelled) {
          const qData = await resp.json()
          setQueue(Array.isArray(qData) ? qData : (qData.items || []))
        }
      } catch (err) {
        if (!cancelled) console.error('Failed to fetch queue:', err)
      }
    }
    poll()
    const interval = setInterval(poll, 5000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [token])

  const queuedCount = queue.filter(s => s.status === 'queued').length
  const runningCount = queue.filter(s => s.status === 'running').length

  function statusBadgeColor(status) {
    switch (status) {
      case 'queued': return 'bg-yellow-900/50 text-yellow-400'
      case 'running': return 'bg-blue-900/50 text-blue-400'
      case 'completed': return 'bg-green-900/50 text-green-400'
      case 'failed': return 'bg-red-900/50 text-red-400'
      default: return 'bg-gray-700/50 text-gray-400'
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Scanning Queue</h1>
        <p className="text-sm text-gray-400">Monitor queued and running scans</p>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 text-center">
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Queued</div>
          <div className="text-3xl font-bold text-yellow-400">{queuedCount}</div>
        </div>
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 text-center">
          <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Running</div>
          <div className="text-3xl font-bold text-blue-400">{runningCount}</div>
        </div>
      </div>

      {queue.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-10 text-center">
          <div className="mb-4">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="inline-block">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          </div>
          <h3 className="text-white font-semibold mb-2">Queue is clear</h3>
          <p className="text-gray-400 text-sm mb-4">
            No scans are queued or running right now. Start a new scan to see it appear here.
          </p>
          <Link to="/scans/new" className="inline-block px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">Start a New Scan</Link>
        </div>
      ) : (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Target</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Position</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">ETA</th>
              </tr>
            </thead>
            <tbody>
              {queue.map((scan, idx) => (
                <tr key={scan.id} className={`hover:bg-gray-800/50 transition ${scan.status === 'completed' ? 'text-gray-500' : ''}`}>
                  <td className={`border-b border-gray-700/50 px-4 py-3 text-sm ${scan.status === 'completed' ? 'text-gray-500' : 'text-white'}`}>{scan.target || 'N/A'}</td>
                  <td className="border-b border-gray-700/50 px-4 py-3">
                    <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold capitalize ${statusBadgeColor(scan.status)}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className={`border-b border-gray-700/50 px-4 py-3 text-sm ${scan.status === 'completed' ? 'text-gray-500' : 'text-gray-400'}`}>{idx + 1}</td>
                  <td className={`border-b border-gray-700/50 px-4 py-3 text-sm ${scan.status === 'completed' ? 'text-gray-500' : 'text-gray-400'}`}>~5 min</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default QueuePage
