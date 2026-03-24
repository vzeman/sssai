import { useEffect } from 'react'
import './FindingDetailModal.css'

export default function FindingDetailModal({ finding, onClose }) {
  useEffect(() => {
    function handleEsc(e) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [onClose])

  if (!finding) return null

  const severityColors = {
    critical: '#ff4444',
    high: '#ff8844',
    medium: '#ffaa44',
    low: '#44ff44',
    info: '#4a9eff',
  }
  const color = severityColors[finding.severity] || '#888'

  return (
    <div className="fdm-overlay" onClick={onClose}>
      <div className="fdm-modal" onClick={e => e.stopPropagation()}>
        {/* Header with severity stripe */}
        <div className="fdm-header" style={{ borderTopColor: color }}>
          <div className="fdm-header-top">
            <span className={`fdm-severity-pill ${finding.severity || 'unknown'}`}>
              {finding.severity || 'Unknown'}
            </span>
            {finding.cvss_score && (
              <span className="fdm-cvss">CVSS {finding.cvss_score}</span>
            )}
            <button className="fdm-close" onClick={onClose}>&times;</button>
          </div>
          <h2 className="fdm-title">{finding.title || 'Finding Details'}</h2>
          <div className="fdm-meta-row">
            {finding.cve_id && <span className="fdm-tag fdm-tag-cve">{finding.cve_id}</span>}
            {finding.category && <span className="fdm-tag">{finding.category}</span>}
            {finding.tool && <span className="fdm-tag fdm-tag-tool">{finding.tool}</span>}
            {finding.scan_type && <span className="fdm-tag">{finding.scan_type}</span>}
          </div>
        </div>

        {/* Body */}
        <div className="fdm-body">
          {/* Description */}
          {finding.description && (
            <section className="fdm-section">
              <h3 className="fdm-section-label">Description</h3>
              <p className="fdm-text">{finding.description}</p>
            </section>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <section className="fdm-section">
              <h3 className="fdm-section-label">Evidence</h3>
              <pre className="fdm-code">{finding.evidence}</pre>
            </section>
          )}

          {/* Affected URL */}
          {finding.affected_url && (
            <section className="fdm-section">
              <h3 className="fdm-section-label">Affected URL</h3>
              <code className="fdm-url">{finding.affected_url}</code>
            </section>
          )}

          {/* Remediation - highlighted section */}
          {finding.remediation && (
            <section className="fdm-section fdm-remediation">
              <h3 className="fdm-section-label">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
                </svg>
                How to Fix
              </h3>
              <div className="fdm-remediation-text">{finding.remediation}</div>
            </section>
          )}

          {/* Metadata grid */}
          <section className="fdm-section">
            <h3 className="fdm-section-label">Details</h3>
            <div className="fdm-details-grid">
              {finding.target && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Target</span>
                  <span className="fdm-detail-value">{finding.target}</span>
                </div>
              )}
              {finding.scan_id && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Scan ID</span>
                  <span className="fdm-detail-value fdm-mono">{finding.scan_id}</span>
                </div>
              )}
              {finding.finding_status && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Status</span>
                  <span className={`fdm-status-pill ${finding.finding_status}`}>
                    {finding.finding_status}
                  </span>
                </div>
              )}
              {finding.risk_score != null && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Risk Score</span>
                  <span className="fdm-detail-value">{finding.risk_score}</span>
                </div>
              )}
              {finding.first_seen_date && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">First Seen</span>
                  <span className="fdm-detail-value">
                    {new Date(finding.first_seen_date).toLocaleDateString()}
                  </span>
                </div>
              )}
              {finding.resolved_date && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Resolved</span>
                  <span className="fdm-detail-value">
                    {new Date(finding.resolved_date).toLocaleDateString()}
                  </span>
                </div>
              )}
              {finding.timestamp && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Detected</span>
                  <span className="fdm-detail-value">
                    {new Date(finding.timestamp).toLocaleString()}
                  </span>
                </div>
              )}
              {finding.dedup_key && (
                <div className="fdm-detail-item">
                  <span className="fdm-detail-label">Dedup Key</span>
                  <span className="fdm-detail-value fdm-mono">{finding.dedup_key}</span>
                </div>
              )}
            </div>
          </section>

          {/* History */}
          {finding.history && finding.history.length > 0 && (
            <section className="fdm-section">
              <h3 className="fdm-section-label">History</h3>
              <div className="fdm-history">
                {finding.history.map((entry, idx) => (
                  <div key={idx} className="fdm-history-item">
                    <span className="fdm-history-date">
                      {new Date(entry.timestamp).toLocaleDateString()}
                    </span>
                    <span className={`fdm-history-status ${entry.status}`}>
                      {entry.status}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>

        {/* Footer */}
        <div className="fdm-footer">
          <button className="fdm-btn fdm-btn-close" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}
