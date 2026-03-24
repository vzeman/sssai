import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import './FindingsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function FindingDetailsModal({ finding, onClose, onUpdateStatus }) {
  if (!finding) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{finding.title || 'Finding Details'}</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="detail-section">
            <h3>CVSS Score</h3>
            <div className="cvss-display">
              <div className={`cvss-score severity-${finding.severity}`}>
                {finding.cvss_score || 'N/A'}
              </div>
              <div className="cvss-vector">{finding.cvss_vector || 'N/A'}</div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Severity</h3>
            <span className={`severity-badge ${finding.severity}`}>
              {finding.severity || 'Unknown'}
            </span>
          </div>

          <div className="detail-section">
            <h3>Description</h3>
            <p>{finding.description || 'No description available'}</p>
          </div>

          <div className="detail-section">
            <h3>Remediation</h3>
            <p>{finding.remediation || 'No remediation steps available'}</p>
          </div>

          {finding.history && finding.history.length > 0 && (
            <div className="detail-section">
              <h3>History</h3>
              <div className="history-list">
                {finding.history.map((entry, idx) => (
                  <div key={idx} className="history-item">
                    <span className="history-date">
                      {new Date(entry.timestamp).toLocaleDateString()}
                    </span>
                    <span className="history-status">{entry.status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
          <button
            className="btn btn-success"
            onClick={() => onUpdateStatus(finding, 'resolved')}
          >
            Mark as Resolved
          </button>
          <button
            className="btn btn-warning"
            onClick={() => onUpdateStatus(finding, 'false-positive')}
          >
            Mark as False Positive
          </button>
        </div>
      </div>
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

  const [filters, setFilters] = useState({
    severity: 'all',
    cvssMin: 0,
    cvssMax: 10,
    status: 'all',
  })

  useEffect(() => {
    fetchFindings()
  }, [])

  useEffect(() => {
    applyFilters()
  }, [findings, filters])

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
      if (filters.status !== 'all' && f.status !== filters.status) return false
      const cvss = parseFloat(f.cvss_score) || 0
      if (cvss < filters.cvssMin || cvss > filters.cvssMax) return false
      return true
    })
    setFilteredFindings(filtered)
  }

  function handleFilterChange(e) {
    const { name, value } = e.target
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading findings...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Findings</h1>
        <p>Security findings and vulnerabilities across all scans</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      {successMessage && (
        <div className="success-message">{successMessage}</div>
      )}

      <div className="filters-section">
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
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="false-positive">False Positive</option>
          </select>
        </div>
      </div>

      <div className="findings-summary">
        Found {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
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
              {filteredFindings.map((finding, idx) => (
                <tr key={idx} className="finding-row" onClick={() => setSelectedFinding(finding)} style={{cursor: 'pointer'}}>
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
                  <td>
                    <span className={`status-badge ${finding.status || 'open'}`}>
                      {finding.status || 'open'}
                    </span>
                  </td>
                  <td className="scan-ref">{finding.scan_id?.substring(0, 8) || 'N/A'}</td>
                  <td>
                    <button
                      className="action-btn"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedFinding && (
        <DetailModal
          title={selectedFinding.title}
          data={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}

export default FindingsPage
