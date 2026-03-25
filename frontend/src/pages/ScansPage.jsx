import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import { LoadingSkeleton } from '../components/LoadingSkeleton'
import { Pagination } from '../components/Pagination'

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
      const resp = await fetch(`${API_BASE}/api/scans/?skip=${skip}&limit=${size}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      const items = Array.isArray(data) ? data : (data.items || [])
      const total = Array.isArray(data) ? data.length : (data.total || 0)
      setScans(items)
      setTotalScans(total)
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

  if (loading) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Scans</h1>
        <div className="text-gray-400 text-center py-12">Loading...</div>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Scans</h1>
          <p className="text-sm text-gray-400 mt-1">All security scans and their results</p>
        </div>
        <div className="flex items-center gap-3">
          {scans.length > 0 && (
            <button onClick={handleExportCSV} disabled={exporting} className="px-4 py-2 text-sm border border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition disabled:opacity-50">
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          )}
          <Link to="/scans/new" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">+ New Scan</Link>
        </div>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-6">{error}</div>}

      {scans.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-12 text-center">
          <p className="text-gray-400 mb-4">No scans found. Start your first security scan.</p>
          <Link to="/scans/new" className="inline-block px-6 py-2.5 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">+ New Scan</Link>
        </div>
      ) : (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Target</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Type</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Risk Score</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Created</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan, idx) => {
                const previousScan = scans.slice(idx + 1).find(
                  s => s.status === 'completed' && (s.target || s.target_url) === (scan.target || scan.target_url)
                )
                return (
                  <tr key={scan.id} onClick={() => setSelectedScan(scan)} className="border-b border-gray-800 hover:bg-gray-800/50 cursor-pointer transition">
                    <td className="px-4 py-3 text-gray-200 font-medium max-w-xs truncate">{scan.target_url || scan.target || 'Unknown'}</td>
                    <td className="px-4 py-3 text-gray-400">{scan.scan_type || scan.type || '-'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                        scan.status === 'completed' ? 'bg-green-900/50 text-green-400' :
                        scan.status === 'running' ? 'bg-blue-900/50 text-blue-400' :
                        scan.status === 'failed' ? 'bg-red-900/50 text-red-400' :
                        'bg-yellow-900/50 text-yellow-400'
                      }`}>{scan.status}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-semibold ${
                        (scan.risk_score || 0) >= 30 ? 'text-red-400' :
                        (scan.risk_score || 0) >= 15 ? 'text-orange-400' : 'text-green-400'
                      }`}>{scan.risk_score != null ? scan.risk_score : 'N/A'}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-500 whitespace-nowrap">{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '-'}</td>
                    <td className="px-4 py-3 text-right" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-2 justify-end">
                        <Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline text-xs font-medium">View</Link>
                        {previousScan && scan.status === 'completed' && (
                          <Link to={`/scans/${scan.id}/compare/${previousScan.id}`} className="text-yellow-400 hover:underline text-xs font-medium">Compare</Link>
                        )}
                      </div>
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
