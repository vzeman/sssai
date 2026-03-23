import React, { useState, useEffect } from 'react'
import '../styles/AuditLogViewer.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

export default function AuditLogViewer({ token }) {
  const [logs, setLogs] = useState([])
  const [totalCount, setTotalCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(25)

  // Filters
  const [filters, setFilters] = useState({
    action: '',
    resource_type: '',
    status: '',
  })

  // Load audit logs
  useEffect(() => {
    if (!token) return

    const loadLogs = async () => {
      try {
        setLoading(true)
        setError('')

        const params = new URLSearchParams({
          limit: pageSize,
          offset: page * pageSize,
        })

        // Add filters
        if (filters.action) params.append('action', filters.action)
        if (filters.resource_type) params.append('resource_type', filters.resource_type)
        if (filters.status) params.append('status', filters.status)

        const res = await fetch(`${API_BASE}/api/audit/logs?${params}`, {
          headers: { Authorization: `Bearer ${token}` }
        })

        if (!res.ok) {
          throw new Error(`Failed to fetch logs: ${res.statusText}`)
        }

        const data = await res.json()
        setLogs(data.logs || [])
        setTotalCount(data.total || 0)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    loadLogs()
  }, [token, page, pageSize, filters])

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setPage(0)
  }

  const handleExport = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/audit/export?format=json&days=30`, {
        headers: { Authorization: `Bearer ${token}` }
      })

      if (!res.ok) throw new Error('Export failed')

      const data = await res.json()
      const json = JSON.stringify(data, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-logs-${new Date().toISOString()}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(`Export failed: ${err.message}`)
    }
  }

  const totalPages = Math.ceil(totalCount / pageSize)

  return (
    <div className="audit-viewer">
      <div className="audit-header">
        <h2>Audit Log Viewer</h2>
        <div className="audit-actions">
          <button className="export-btn" onClick={handleExport}>
            📥 Export
          </button>
        </div>
      </div>

      {error && (
        <div className="audit-error">
          <span>{error}</span>
          <button onClick={() => setError('')}>✕</button>
        </div>
      )}

      {/* Filters */}
      <div className="audit-filters">
        <select
          value={filters.action}
          onChange={(e) => handleFilterChange('action', e.target.value)}
          className="filter-select"
        >
          <option value="">All Actions</option>
          <option value="create">Create</option>
          <option value="read">Read</option>
          <option value="update">Update</option>
          <option value="delete">Delete</option>
          <option value="export">Export</option>
        </select>

        <select
          value={filters.resource_type}
          onChange={(e) => handleFilterChange('resource_type', e.target.value)}
          className="filter-select"
        >
          <option value="">All Resources</option>
          <option value="scan">Scan</option>
          <option value="monitor">Monitor</option>
          <option value="campaign">Campaign</option>
          <option value="user">User</option>
          <option value="asset">Asset</option>
        </select>

        <select
          value={filters.status}
          onChange={(e) => handleFilterChange('status', e.target.value)}
          className="filter-select"
        >
          <option value="">All Status</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
        </select>
      </div>

      {/* Logs Table */}
      <div className="audit-table-container">
        {loading ? (
          <div className="loading">Loading audit logs...</div>
        ) : logs.length > 0 ? (
          <table className="audit-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Status</th>
                <th>IP Address</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className={`log-row ${log.status}`}>
                  <td className="timestamp">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="action">{log.action}</td>
                  <td className="resource">
                    <span className="resource-type">{log.resource_type}</span>
                    <code className="resource-id">{log.resource_id.substring(0, 16)}...</code>
                  </td>
                  <td>
                    <span className={`status-badge ${log.status}`}>
                      {log.status === 'success' ? '✓' : '✗'} {log.status}
                    </span>
                  </td>
                  <td className="ip-address">{log.ip_address || 'N/A'}</td>
                  <td className="details">
                    {log.error_message && (
                      <span className="error-tooltip" title={log.error_message}>
                        ⚠️
                      </span>
                    )}
                    {log.before_state || log.after_state ? (
                      <span className="has-state">📋</span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">No audit logs found</div>
        )}
      </div>

      {/* Pagination */}
      <div className="audit-pagination">
        <button
          onClick={() => setPage(Math.max(0, page - 1))}
          disabled={page === 0}
          className="page-btn"
        >
          ← Previous
        </button>

        <span className="page-info">
          Page {page + 1} of {Math.max(1, totalPages)} ({totalCount} total)
        </span>

        <button
          onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
          disabled={page >= totalPages - 1}
          className="page-btn"
        >
          Next →
        </button>

        <select
          value={pageSize}
          onChange={(e) => {
            setPageSize(parseInt(e.target.value))
            setPage(0)
          }}
          className="page-size"
        >
          <option value="10">10 per page</option>
          <option value="25">25 per page</option>
          <option value="50">50 per page</option>
          <option value="100">100 per page</option>
        </select>
      </div>
    </div>
  )
}
