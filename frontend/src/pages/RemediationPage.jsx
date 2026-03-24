import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useToast } from '../components/ToastContext'
import './RemediationPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? 5
}

function RemediationPage({ token }) {
  const { showToast } = useToast()
  const [findings, setFindings] = useState([])
  const [triageBuckets, setTriageBuckets] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('severity')
  const [verifyingIds, setVerifyingIds] = useState(new Set())
  const [expandedIds, setExpandedIds] = useState(new Set())

  useEffect(() => {
    fetchScansAndFindings()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function fetchScansAndFindings() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const scansData = await resp.json()
      const completedScans = scansData.filter(s => s.status === 'completed')
      const allFindings = []
      const buckets = { immediate_action: [], this_sprint: [], backlog: [] }
      let hasBuckets = false

      for (const scan of completedScans.slice(0, 10)) {
        try {
          const reportResp = await fetch(`${API_BASE}/api/scans/${scan.id}/report`, {
            headers: { Authorization: `Bearer ${token}` },
          })
          if (!reportResp.ok) continue
          const report = await reportResp.json()
          const scanFindings = (report.findings || []).map(f => ({
            ...f,
            scanId: scan.id,
            scanTarget: scan.target_url || scan.target || 'Unknown',
            scanDate: scan.created_at,
          }))
          allFindings.push(...scanFindings)

          if (report.triage) {
            hasBuckets = true
            if (report.triage.immediate_action) {
              buckets.immediate_action.push(...report.triage.immediate_action.map(f => ({ ...f, scanId: scan.id, scanTarget: scan.target_url || scan.target })))
            }
            if (report.triage.this_sprint) {
              buckets.this_sprint.push(...report.triage.this_sprint.map(f => ({ ...f, scanId: scan.id, scanTarget: scan.target_url || scan.target })))
            }
            if (report.triage.backlog) {
              buckets.backlog.push(...report.triage.backlog.map(f => ({ ...f, scanId: scan.id, scanTarget: scan.target_url || scan.target })))
            }
          }
        } catch {
          // Skip scans with no report
        }
      }

      allFindings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
      setFindings(allFindings)
      setTriageBuckets(hasBuckets ? buckets : null)
      setError('')
    } catch (err) {
      setError(err.message)
      setFindings([])
    } finally {
      setLoading(false)
    }
  }

  async function triggerVerification(scanId) {
    if (verifyingIds.has(scanId)) return
    try {
      setVerifyingIds(prev => new Set([...prev, scanId]))
      const resp = await fetch(`${API_BASE}/api/scans/${scanId}/verify`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      })
      if (!resp.ok) {
        const data = await resp.json()
        throw new Error(data.detail || 'Verification failed')
      }
      const data = await resp.json()
      showToast(`Verification scan queued: ${data.id?.substring(0, 8)}`, 'success')
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setVerifyingIds(prev => {
        const next = new Set(prev)
        next.delete(scanId)
        return next
      })
    }
  }

  function toggleExpand(findingKey) {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(findingKey)) next.delete(findingKey)
      else next.add(findingKey)
      return next
    })
  }

  function groupBySeverity() {
    const groups = {}
    for (const f of findings) {
      const sev = f.severity || 'unknown'
      if (!groups[sev]) groups[sev] = []
      groups[sev].push(f)
    }
    return groups
  }

  function renderFindingCard(finding, idx) {
    const key = `${finding.scanId}-${idx}`
    const isExpanded = expandedIds.has(key)

    return (
      <div key={key} className={`finding-card severity-border-${finding.severity || 'unknown'}`}>
        <div className="finding-card-header" onClick={() => toggleExpand(key)}>
          <div className="finding-title-row">
            <span className={`severity-badge ${finding.severity}`}>
              {finding.severity || 'unknown'}
            </span>
            <h4 className="finding-title">{finding.title || 'Untitled Finding'}</h4>
            {finding.priority_score != null && (
              <span className="priority-score" title="Priority Score">
                P{finding.priority_score}
              </span>
            )}
          </div>
          <span className="expand-icon">{isExpanded ? '\u25B2' : '\u25BC'}</span>
        </div>

        <div className="finding-card-meta">
          {finding.url && (
            <span className="affected-url" title={finding.url}>
              {finding.url}
            </span>
          )}
          {finding.affected_url && !finding.url && (
            <span className="affected-url" title={finding.affected_url}>
              {finding.affected_url}
            </span>
          )}
          <span className="finding-scan-ref">
            Scan: <Link to={`/scans/${finding.scanId}`}>{finding.scanId?.substring(0, 8)}</Link>
          </span>
          {finding.verification_status && (
            <span className={`verification-badge ${finding.verification_status}`}>
              {finding.verification_status}
            </span>
          )}
        </div>

        {isExpanded && (
          <div className="finding-card-details">
            {finding.description && (
              <div className="detail-block">
                <h5>Description</h5>
                <p>{finding.description}</p>
              </div>
            )}
            {finding.remediation && (
              <div className="detail-block remediation-block">
                <h5>Remediation</h5>
                <p>{finding.remediation}</p>
              </div>
            )}
            {finding.cvss_score != null && (
              <div className="detail-inline">
                <span className="detail-label">CVSS:</span>
                <span className={`cvss-value ${finding.severity}`}>{finding.cvss_score}</span>
                {finding.cvss_vector && <span className="cvss-vector">{finding.cvss_vector}</span>}
              </div>
            )}
            <div className="finding-card-actions">
              <button
                className="btn btn-primary btn-sm"
                onClick={() => triggerVerification(finding.scanId)}
                disabled={verifyingIds.has(finding.scanId)}
              >
                {verifyingIds.has(finding.scanId) ? 'Verifying...' : 'Trigger Verification Scan'}
              </button>
            </div>
          </div>
        )}
      </div>
    )
  }

  function renderTriageBucket(label, items, className) {
    return (
      <div className={`triage-bucket ${className}`}>
        <div className="bucket-header">
          <h3>{label}</h3>
          <span className="bucket-count">{items.length}</span>
        </div>
        {items.length === 0 ? (
          <p className="bucket-empty">No items in this bucket</p>
        ) : (
          items.map((f, idx) => renderFindingCard(f, `triage-${className}-${idx}`))
        )}
      </div>
    )
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading remediation data...</div></div>
  }

  const severityGroups = groupBySeverity()
  const severityKeys = Object.keys(severityGroups).sort((a, b) => severityRank(a) - severityRank(b))

  const criticalCount = (severityGroups.critical || []).length
  const highCount = (severityGroups.high || []).length
  const mediumCount = (severityGroups.medium || []).length
  const lowCount = (severityGroups.low || []).length

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Remediation Tracker</h1>
        <p>Prioritize and track remediation of security findings</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="remediation-summary">
        <div className="summary-item">
          <span className="label">Total Findings</span>
          <span className="count">{findings.length}</span>
        </div>
        <div className="summary-item summary-critical">
          <span className="label">Critical</span>
          <span className="count">{criticalCount}</span>
        </div>
        <div className="summary-item summary-high">
          <span className="label">High</span>
          <span className="count">{highCount}</span>
        </div>
        <div className="summary-item summary-medium">
          <span className="label">Medium</span>
          <span className="count">{mediumCount}</span>
        </div>
        <div className="summary-item summary-low">
          <span className="label">Low</span>
          <span className="count">{lowCount}</span>
        </div>
      </div>

      {triageBuckets && (
        <div className="view-tabs">
          <button
            className={`tab-btn ${activeTab === 'severity' ? 'active' : ''}`}
            onClick={() => setActiveTab('severity')}
          >
            By Severity
          </button>
          <button
            className={`tab-btn ${activeTab === 'triage' ? 'active' : ''}`}
            onClick={() => setActiveTab('triage')}
          >
            Triage Buckets
          </button>
        </div>
      )}

      {activeTab === 'severity' && (
        <div className="severity-groups">
          {findings.length === 0 ? (
            <div className="empty-state">
              <p>No findings to remediate. Run a scan to get started.</p>
            </div>
          ) : (
            severityKeys.map(sev => (
              <div key={sev} className="severity-group">
                <div className="group-header">
                  <span className={`severity-badge ${sev}`}>{sev}</span>
                  <span className="group-count">{severityGroups[sev].length} finding{severityGroups[sev].length !== 1 ? 's' : ''}</span>
                </div>
                <div className="findings-list">
                  {severityGroups[sev].map((f, idx) => renderFindingCard(f, idx))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'triage' && triageBuckets && (
        <div className="triage-view">
          {renderTriageBucket('Immediate Action', triageBuckets.immediate_action, 'bucket-immediate')}
          {renderTriageBucket('This Sprint', triageBuckets.this_sprint, 'bucket-sprint')}
          {renderTriageBucket('Backlog', triageBuckets.backlog, 'bucket-backlog')}
        </div>
      )}
    </div>
  )
}

export default RemediationPage
