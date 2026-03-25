import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import ConfirmDialog from '../components/ConfirmDialog'
import FindingDetailModal from '../components/FindingDetailModal'
import { LoadingSkeleton } from '../components/LoadingSkeleton'
import { Pagination } from '../components/Pagination'
import { useToast } from '../components/ToastContext'
import './FindingsPage.css'

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

function StatusBadge({ status }) {
  const info = STATUS_MAP[status] || STATUS_MAP['new']
  return (
    <span
      className="finding-status-badge"
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
    <div className="status-dropdown-wrapper">
      <select
        className="status-select"
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
        <div className="reason-popover" onClick={(e) => e.stopPropagation()}>
          <form onSubmit={handleReasonSubmit}>
            <label>Reason for marking as {STATUS_MAP[pendingStatus]?.label}:</label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why this is a false positive or accepted risk..."
              rows={3}
              autoFocus
            />
            <div className="reason-actions">
              <button type="button" className="btn btn-secondary" onClick={handleReasonCancel}>Cancel</button>
              <button type="submit" className="btn btn-primary">Confirm</button>
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
      const resp = await fetch(`${API_BASE}/api/search?q=severity:*`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch findings')
      const data = await resp.json()
      setFindings(data.findings || [])
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
      <div className="page-container">
        <div className="page-header"><h1>Findings</h1></div>
        <LoadingSkeleton rows={8} columns={6} />
      </div>
    )
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1>Findings</h1>
          <p>Security findings and vulnerabilities across all scans</p>
        </div>
        <div className="header-actions">
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={hideFalsePositives}
              onChange={(e) => {
                setHideFalsePositives(e.target.checked)
                setCurrentPage(1)
              }}
            />
            <span className="toggle-text">Hide False Positives</span>
          </label>
          {findings.length > 0 && (
            <button
              className="btn-export"
              onClick={handleExportCSV}
              disabled={exporting}
            >
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          )}
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      {successMessage && (
        <div className="success-message">{successMessage}</div>
      )}

      <div className="filters-section">
        <div className="filter-group filter-group-wide">
          <label>Search</label>
          <input
            type="text"
            name="search"
            value={filters.search}
            onChange={handleFilterChange}
            placeholder="Search by title or description..."
          />
        </div>

        <div className="filter-group">
          <label>Severity</label>
          <select name="severity" value={filters.severity} onChange={handleFilterChange}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Category</label>
          <select name="category" value={filters.category} onChange={handleFilterChange}>
            <option value="all">All Categories</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label>CVSS Score</label>
          <div className="cvss-range">
            <input
              type="number"
              min="0"
              max="10"
              step="0.5"
              name="cvssMin"
              value={filters.cvssMin}
              onChange={handleFilterChange}
              placeholder="Min"
            />
            <span>-</span>
            <input
              type="number"
              min="0"
              max="10"
              step="0.5"
              name="cvssMax"
              value={filters.cvssMax}
              onChange={handleFilterChange}
              placeholder="Max"
            />
          </div>
        </div>

        <div className="filter-group">
          <label>Status</label>
          <select name="status" value={filters.status} onChange={handleFilterChange}>
            <option value="all">All Statuses</option>
            {FINDING_STATUSES.map(s => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="saved-filters-section">
        <div className="saved-filters-actions">
          {!showSaveInput ? (
            <button className="btn-save-filter" onClick={() => setShowSaveInput(true)}>
              Save Current Filter
            </button>
          ) : (
            <form className="save-filter-form" onSubmit={(e) => { e.preventDefault(); handleSaveFilter(); }}>
              <input
                type="text"
                value={saveFilterName}
                onChange={(e) => setSaveFilterName(e.target.value)}
                placeholder="Filter preset name..."
                className="save-filter-input"
                autoFocus
              />
              <button type="submit" className="btn-save-confirm" disabled={!saveFilterName.trim()}>
                Save
              </button>
              <button type="button" className="btn-save-cancel" onClick={() => { setShowSaveInput(false); setSaveFilterName(''); }}>
                Cancel
              </button>
            </form>
          )}
        </div>
        {savedFilters.length > 0 && (
          <div className="saved-filters-list">
            <span className="saved-filters-label">Saved:</span>
            {savedFilters.map(preset => (
              <div key={preset.name} className="saved-filter-chip">
                <button
                  className="saved-filter-chip-name"
                  onClick={() => handleLoadFilter(preset)}
                  title={`Load filter: ${preset.name}`}
                >
                  {preset.name}
                </button>
                <button
                  className="saved-filter-chip-delete"
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

      <div className="findings-summary">
        Found {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
        {hideFalsePositives && ' (false positives hidden)'}
      </div>

      {findings.length === 0 ? (
        <div className="empty-state-card">
          <div className="empty-state-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <h3 className="empty-state-title">No findings yet</h3>
          <p className="empty-state-text">
            Run a security scan to discover vulnerabilities and findings across your targets.
          </p>
          <Link to="/scans/new" className="empty-state-cta">Start a New Scan</Link>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="empty-state-card">
          <div className="empty-state-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </div>
          <h3 className="empty-state-title">No findings match your filters</h3>
          <p className="empty-state-text">
            Try adjusting the severity, CVSS score range, or status filters to see more results.
          </p>
        </div>
      ) : (
        <div className="findings-table">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Status</th>
                <th>Scan</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedFindings.map((finding, idx) => (
                <tr key={finding.id || idx} className="finding-row" onClick={() => setSelectedFinding(finding)} style={{cursor: 'pointer'}}>
                  <td className="title-cell">
                    <span className="finding-title">{finding.title || 'Unknown'}</span>
                  </td>
                  <td>
                    <span className={`severity-badge ${finding.severity}`}>
                      {finding.severity || 'unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`cvss-badge ${finding.severity}`}>
                      {finding.cvss_score || 'N/A'}
                    </span>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <StatusDropdown
                      finding={finding}
                      token={token}
                      onStatusChange={handleStatusChange}
                    />
                  </td>
                  <td className="scan-ref">{finding.scan_id?.substring(0, 8) || 'N/A'}</td>
                  <td>
                    <button
                      className="action-btn"
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
