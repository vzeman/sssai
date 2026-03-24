import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import './ScanComparisonPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function SeverityBadge({ severity }) {
  const cls = `severity-badge severity-${(severity || 'info').toLowerCase()}`
  return <span className={cls}>{severity || 'info'}</span>
}

function FindingCard({ finding, variant }) {
  return (
    <div className={`comparison-finding ${variant || ''}`}>
      <div className="finding-header">
        <span className="finding-title">{finding.title || 'Untitled Finding'}</span>
        <SeverityBadge severity={finding.severity} />
      </div>
      {finding.category && <span className="finding-category">{finding.category}</span>}
      {finding.description && (
        <p className="finding-description">{finding.description.slice(0, 200)}</p>
      )}
    </div>
  )
}

function ChangedFindingCard({ current, baseline }) {
  return (
    <div className="comparison-finding finding-changed">
      <div className="finding-header">
        <span className="finding-title">{current.title || 'Untitled Finding'}</span>
        <span className="severity-change">
          <SeverityBadge severity={baseline.severity} />
          <span className="arrow">&rarr;</span>
          <SeverityBadge severity={current.severity} />
        </span>
      </div>
      {current.category && <span className="finding-category">{current.category}</span>}
    </div>
  )
}

function CollapsibleSection({ title, count, children, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen ?? true)

  return (
    <div className="collapsible-section">
      <button className="section-toggle" onClick={() => setOpen(!open)}>
        <span className="toggle-icon">{open ? '\u25BC' : '\u25B6'}</span>
        <span className="section-title">{title}</span>
        <span className="section-count">{count}</span>
      </button>
      {open && <div className="section-content">{children}</div>}
    </div>
  )
}

function ScanComparisonPage({ token }) {
  const { scanId, baselineId } = useParams()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchComparison() {
      try {
        setLoading(true)
        const resp = await fetch(
          `${API_BASE}/api/scans/${scanId}/compare/${baselineId}`,
          { headers: { Authorization: `Bearer ${token}` } }
        )
        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}))
          throw new Error(errData.detail || 'Failed to fetch comparison')
        }
        setData(await resp.json())
        setError('')
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetchComparison()
  }, [scanId, baselineId, token])

  if (loading) {
    return <div className="page-container"><div className="loading">Loading comparison...</div></div>
  }

  if (error) {
    return (
      <div className="page-container">
        <div className="error-message">{error}</div>
        <Link to="/scans" className="back-link">Back to Scans</Link>
      </div>
    )
  }

  if (!data) return null

  const { summary } = data

  return (
    <div className="page-container comparison-page">
      <div className="page-header">
        <div>
          <h1>Scan Comparison</h1>
          <p>
            Comparing scan <code>{scanId.slice(0, 8)}</code> against baseline{' '}
            <code>{baselineId.slice(0, 8)}</code>
          </p>
        </div>
        <Link to="/scans" className="back-link">Back to Scans</Link>
      </div>

      <div className="summary-cards">
        <div className="summary-card card-new">
          <div className="card-value">{summary.new_count}</div>
          <div className="card-label">New Findings</div>
        </div>
        <div className="summary-card card-resolved">
          <div className="card-value">{summary.resolved_count}</div>
          <div className="card-label">Resolved</div>
        </div>
        <div className="summary-card card-unchanged">
          <div className="card-value">{summary.unchanged_count}</div>
          <div className="card-label">Unchanged</div>
        </div>
        <div className="summary-card card-changed">
          <div className="card-value">{summary.changed_count}</div>
          <div className="card-label">Changed Severity</div>
        </div>
        <div className={`summary-card ${summary.risk_delta > 0 ? 'card-new' : summary.risk_delta < 0 ? 'card-resolved' : 'card-unchanged'}`}>
          <div className="card-value">
            {summary.risk_delta > 0 ? '+' : ''}{summary.risk_delta}
          </div>
          <div className="card-label">Risk Delta</div>
        </div>
      </div>

      {data.new_findings.length > 0 && (
        <CollapsibleSection title="New Findings" count={data.new_findings.length} defaultOpen>
          {data.new_findings.map((f, i) => (
            <FindingCard key={f.dedup_key || i} finding={f} variant="finding-new" />
          ))}
        </CollapsibleSection>
      )}

      {data.resolved_findings.length > 0 && (
        <CollapsibleSection title="Resolved Findings" count={data.resolved_findings.length} defaultOpen>
          {data.resolved_findings.map((f, i) => (
            <FindingCard key={f.dedup_key || i} finding={f} variant="finding-resolved" />
          ))}
        </CollapsibleSection>
      )}

      {data.changed_findings.length > 0 && (
        <CollapsibleSection title="Changed Severity" count={data.changed_findings.length} defaultOpen>
          {data.changed_findings.map((cf, i) => (
            <ChangedFindingCard
              key={cf.current.dedup_key || i}
              current={cf.current}
              baseline={cf.baseline}
            />
          ))}
        </CollapsibleSection>
      )}

      {data.unchanged_findings.length > 0 && (
        <CollapsibleSection title="Unchanged Findings" count={data.unchanged_findings.length} defaultOpen={false}>
          {data.unchanged_findings.map((f, i) => (
            <FindingCard key={f.dedup_key || i} finding={f} variant="finding-unchanged" />
          ))}
        </CollapsibleSection>
      )}

      {data.new_findings.length === 0 && data.resolved_findings.length === 0 &&
       data.changed_findings.length === 0 && data.unchanged_findings.length === 0 && (
        <div className="empty-state">
          <p>No findings to compare. Both scans may have no indexed findings.</p>
        </div>
      )}
    </div>
  )
}

export default ScanComparisonPage
