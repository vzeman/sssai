import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import ConfirmDialog from '../components/ConfirmDialog'
import FindingDetailModal from '../components/FindingDetailModal'
import { LoadingSkeleton } from '../components/LoadingSkeleton'
import { Pagination } from '../components/Pagination'
import { useToast } from '../components/ToastContext'

const API_BASE = import.meta.env.VITE_API_URL || ''

const FINDING_STATUSES = [
  { value: 'new', label: 'New', color: '#4a9eff', bg: '#2a3a4a' },
  { value: 'confirmed', label: 'Confirmed', color: '#ff8844', bg: '#4a3a2a' },
  { value: 'in_progress', label: 'In Progress', color: '#ffcc44', bg: '#4a4a2a' },
  { value: 'resolved', label: 'Resolved', color: '#44ff44', bg: '#2a4a2a' },
  { value: 'false_positive', label: 'False Positive', color: '#b0b4c0', bg: '#2a2d3a' },
  { value: 'accepted_risk', label: 'Accepted Risk', color: '#bb77ff', bg: '#3a2a4a' },
]

const STATUS_MAP = Object.fromEntries(FINDING_STATUSES.map(s => [s.value, s]))

const SEVERITY_BADGE_CLASSES = {
  critical: 'bg-red-900/50 text-red-400',
  high: 'bg-orange-900/50 text-orange-400',
  medium: 'bg-yellow-900/50 text-yellow-400',
  low: 'bg-green-900/50 text-green-400',
  info: 'bg-blue-900/50 text-blue-400',
}

function StatusBadge({ status }) {
  const info = STATUS_MAP[status] || STATUS_MAP['new']
  return (
    <span
      className="px-2.5 py-0.5 rounded-full text-xs font-semibold"
      style={{ background: info.bg, color: info.color }}
    >
      {info.label}
    </span>
  )
}

function StatusDropdown({ finding, token, onStatusChange }) {
  const { showToast } = useToast()
  const [changing, setChanging] = useState(false)
  const [showReason, setShowReason] = useState(false)
  const [pendingStatus, setPendingStatus] = useState('')
  const [reason, setReason] = useState('')
  const [showConfirm, setShowConfirm] = useState(false)

  const CONFIRM_DESCRIPTIONS = {
    false_positive: 'This will mark the finding as a false positive. The finding will be excluded from future reports.',
    accepted_risk: 'This will mark the finding as an accepted risk. Ensure this has been reviewed and approved.',
  }

  async function handleChange(e) {
    const newStatus = e.target.value
    const currentStatus = finding.finding_status || 'new'
    if (newStatus === currentStatus) return

    // For false_positive and accepted_risk, confirm first
    if (newStatus === 'false_positive' || newStatus === 'accepted_risk') {
      setPendingStatus(newStatus)
      setShowConfirm(true)
      return
    }

    await submitStatusChange(newStatus, '')
  }

  function handleConfirmAccept() {
    setShowConfirm(false)
    setShowReason(true)
  }

  function handleConfirmCancel() {
    setShowConfirm(false)
    setPendingStatus('')
  }

  async function submitStatusChange(status, changeReason) {
    setChanging(true)
    setShowReason(false)
    try {
      const resp = await fetch(`${API_BASE}/api/findings/${finding.id}/status`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status, reason: changeReason }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.detail || 'Failed to update status')
      }
      onStatusChange(finding.id, status)
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setChanging(false)
      setReason('')
      setPendingStatus('')
    }
  }

  function handleReasonSubmit(e) {
    e.preventDefault()
    submitStatusChange(pendingStatus, reason)
  }

  function handleReasonCancel() {
    setShowReason(false)
    setPendingStatus('')
    setReason('')
  }

  const currentStatus = finding.finding_status || 'new'

  return (
    <div className="relative">
      <select
        className="w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500"
        value={currentStatus}
        onChange={handleChange}
        disabled={changing}
        onClick={(e) => e.stopPropagation()}
      >
        {FINDING_STATUSES.map(s => (
          <option key={s.value} value={s.value}>{s.label}</option>
        ))}
      </select>
      {showReason && (
        <div className="absolute z-50 top-full left-0 mt-2 w-72 bg-gray-800 border border-gray-700 rounded-lg p-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
          <form onSubmit={handleReasonSubmit}>
            <label className="block text-sm text-gray-300 mb-2">Reason for marking as {STATUS_MAP[pendingStatus]?.label}:</label>
            <textarea
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why this is a false positive or accepted risk..."
              rows={3}
              autoFocus
            />
            <div className="flex justify-end gap-2 mt-3">
              <button type="button" className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition" onClick={handleReasonCancel}>Cancel</button>
              <button type="submit" className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg text-xs font-semibold transition">Confirm</button>
            </div>
          </form>
        </div>
      )}
      <ConfirmDialog
        open={showConfirm}
        title={`Mark as ${STATUS_MAP[pendingStatus]?.label || ''}?`}
        description={CONFIRM_DESCRIPTIONS[pendingStatus] || ''}
        confirmLabel="Continue"
        confirmVariant="warning"
        onConfirm={handleConfirmAccept}
        onCancel={handleConfirmCancel}
      />
    </div>
  )
}

function FindingsPage({ token }) {
  const [findings, setFindings] = useState([])
  const [filteredFindings, setFilteredFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [successMessage, setSuccessMessage] = useState('')
  const [exporting, setExporting] = useState(false)
  const [hideFalsePositives, setHideFalsePositives] = useState(false)

  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  const [filters, setFilters] = useState({
    severity: 'all',
    cvssMin: 0,
    cvssMax: 10,
    status: 'all',
    search: '',
    category: 'all',
  })
  const [savedFilters, setSavedFilters] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('sssai_saved_filters') || '[]')
    } catch {
      return []
    }
  })
  const [saveFilterName, setSaveFilterName] = useState('')
  const [showSaveInput, setShowSaveInput] = useState(false)

  useEffect(() => {
    fetchFindings()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    applyFilters()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, filters, hideFalsePositives])

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(''), 4000)
      return () => clearTimeout(timer)
    }
  }, [successMessage])

  async function fetchFindings() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/search/findings`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch findings')
      const data = await resp.json()
      setFindings(data.findings || data.items || [])
      setError('')
    } catch (err) {
      setError(err.message)
      setFindings([])
    } finally {
      setLoading(false)
    }
  }

  function applyFilters() {
    let filtered = findings.filter(f => {
      if (filters.severity !== 'all' && f.severity !== filters.severity) return false
      if (filters.status !== 'all' && f.finding_status !== filters.status) return false
      if (filters.category !== 'all' && f.category !== filters.category) return false
      const cvss = parseFloat(f.cvss_score) || 0
      if (cvss < filters.cvssMin || cvss > filters.cvssMax) return false
      if (hideFalsePositives && f.finding_status === 'false_positive') return false
      if (filters.search) {
        const term = filters.search.toLowerCase()
        const title = (f.title || '').toLowerCase()
        const desc = (f.description || '').toLowerCase()
        if (!title.includes(term) && !desc.includes(term)) return false
      }
      return true
    })
    setFilteredFindings(filtered)
  }

  const categories = [...new Set(findings.map(f => f.category).filter(Boolean))].sort()

  function persistSavedFilters(updated) {
    setSavedFilters(updated)
    localStorage.setItem('sssai_saved_filters', JSON.stringify(updated))
  }

  function handleSaveFilter() {
    const name = saveFilterName.trim()
    if (!name) return
    const preset = { name, filters: { ...filters } }
    const updated = [...savedFilters.filter(f => f.name !== name), preset]
    persistSavedFilters(updated)
    setSaveFilterName('')
    setShowSaveInput(false)
    setSuccessMessage(`Filter "${name}" saved`)
  }

  function handleLoadFilter(preset) {
    setFilters(preset.filters)
    setCurrentPage(1)
  }

  function handleDeleteFilter(name) {
    const updated = savedFilters.filter(f => f.name !== name)
    persistSavedFilters(updated)
  }

  function handleFilterChange(e) {
    const { name, value } = e.target
    setFilters(prev => ({ ...prev, [name]: value }))
    setCurrentPage(1)
  }

  function handleStatusChange(findingId, newStatus) {
    setFindings(prev =>
      prev.map(f => f.id === findingId ? { ...f, finding_status: newStatus } : f)
    )
    setSuccessMessage(`Finding status updated to "${newStatus}"`)
  }

  async function handleExportCSV() {
    if (!findings.length) return
    setExporting(true)
    try {
      const scanId = findings[0]?.scan_id
      if (!scanId) return
      const resp = await fetch(`${API_BASE}/api/export/findings?scan_id=${scanId}&format=csv`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Export failed')
      const blob = await resp.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `findings_${scanId.substring(0, 8)}.csv`
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

  const paginatedFindings = filteredFindings.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  )

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="mb-6"><h1 className="text-2xl font-bold text-white">Findings</h1></div>
        <LoadingSkeleton rows={8} columns={6} />
      </div>
    )
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="text-sm text-gray-400 mt-1">Security findings and vulnerabilities across all scans</p>
        </div>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={hideFalsePositives}
              onChange={(e) => {
                setHideFalsePositives(e.target.checked)
                setCurrentPage(1)
              }}
              className="rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-sm text-gray-300">Hide False Positives</span>
          </label>
          {findings.length > 0 && (
            <button
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition"
              onClick={handleExportCSV}
              disabled={exporting}
            >
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          )}
        </div>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-4">{error}</div>}

      {successMessage && (
        <div className="bg-green-900/20 border border-green-800 text-green-400 px-4 py-3 rounded-lg text-sm mb-4">{successMessage}</div>
      )}

      <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="sm:col-span-2 lg:col-span-2">
            <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1 block">Search</label>
            <input
              type="text"
              name="search"
              value={filters.search}
              onChange={handleFilterChange}
              placeholder="Search by title or description..."
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1 block">Severity</label>
            <select name="severity" value={filters.severity} onChange={handleFilterChange} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1 block">Category</label>
            <select name="category" value={filters.category} onChange={handleFilterChange} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
              <option value="all">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1 block">CVSS Score</label>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="0"
                max="10"
                step="0.5"
                name="cvssMin"
                value={filters.cvssMin}
                onChange={handleFilterChange}
                placeholder="Min"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              <span className="text-gray-500">-</span>
              <input
                type="number"
                min="0"
                max="10"
                step="0.5"
                name="cvssMax"
                value={filters.cvssMax}
                onChange={handleFilterChange}
                placeholder="Max"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
          </div>
        </div>

        <div className="mt-4">
          <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1 block">Status</label>
          <select name="status" value={filters.status} onChange={handleFilterChange} className="w-full sm:w-48 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
            <option value="all">All Statuses</option>
            {FINDING_STATUSES.map(s => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex items-center gap-2">
          {!showSaveInput ? (
            <button className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition" onClick={() => setShowSaveInput(true)}>
              Save Current Filter
            </button>
          ) : (
            <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); handleSaveFilter(); }}>
              <input
                type="text"
                value={saveFilterName}
                onChange={(e) => setSaveFilterName(e.target.value)}
                placeholder="Filter preset name..."
                className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500"
                autoFocus
              />
              <button type="submit" className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg text-xs font-semibold transition" disabled={!saveFilterName.trim()}>
                Save
              </button>
              <button type="button" className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition" onClick={() => { setShowSaveInput(false); setSaveFilterName(''); }}>
                Cancel
              </button>
            </form>
          )}
        </div>
        {savedFilters.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-gray-500">Saved:</span>
            {savedFilters.map(preset => (
              <div key={preset.name} className="flex items-center bg-gray-800 border border-gray-700 rounded-full overflow-hidden">
                <button
                  className="px-3 py-1 text-xs text-cyan-400 hover:text-cyan-300 transition"
                  onClick={() => handleLoadFilter(preset)}
                  title={`Load filter: ${preset.name}`}
                >
                  {preset.name}
                </button>
                <button
                  className="px-2 py-1 text-xs text-gray-500 hover:text-red-400 transition border-l border-gray-700"
                  onClick={() => handleDeleteFilter(preset.name)}
                  title={`Delete filter: ${preset.name}`}
                >
                  x
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="text-sm text-gray-400 mb-4">
        Found {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
        {hideFalsePositives && ' (false positives hidden)'}
      </div>

      {findings.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-12 text-center">
          <div className="flex justify-center mb-4">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">No findings yet</h3>
          <p className="text-gray-500 mb-4">
            Run a security scan to discover vulnerabilities and findings across your targets.
          </p>
          <Link to="/scans/new" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition inline-block">Start a New Scan</Link>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-12 text-center">
          <div className="flex justify-center mb-4">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">No findings match your filters</h3>
          <p className="text-gray-500">
            Try adjusting the severity, CVSS score range, or status filters to see more results.
          </p>
        </div>
      ) : (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Title</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">CVSS</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Scan</th>
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedFindings.map((finding, idx) => (
                <tr key={finding.id || idx} className="border-b border-gray-800 hover:bg-gray-800/50 transition cursor-pointer" onClick={() => setSelectedFinding(finding)}>
                  <td className="px-4 py-3 text-gray-200 font-medium max-w-xs truncate">
                    {finding.title || 'Unknown'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${SEVERITY_BADGE_CLASSES[finding.severity] || 'bg-gray-700 text-gray-400'}`}>
                      {finding.severity || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BADGE_CLASSES[finding.severity] || 'bg-gray-700 text-gray-400'}`}>
                      {finding.cvss_score || 'N/A'}
                    </span>
                  </td>
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    <StatusDropdown
                      finding={finding}
                      token={token}
                      onStatusChange={handleStatusChange}
                    />
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-sm font-mono">{finding.scan_id?.substring(0, 8) || 'N/A'}</td>
                  <td className="px-4 py-3">
                    <button
                      className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg text-xs font-medium transition"
                      onClick={(e) => { e.stopPropagation(); setSelectedFinding(finding); }}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            totalItems={filteredFindings.length}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        </div>
      )}

      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}

export default FindingsPage
