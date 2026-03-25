import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import ConfirmDialog from '../components/ConfirmDialog'
import { useToast } from '../components/ToastContext'

const API_BASE = import.meta.env.VITE_API_URL || ''

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const SEVERITY_BADGE_CLASSES = {
  critical: 'bg-red-900/50 text-red-400',
  high: 'bg-orange-900/50 text-orange-400',
  medium: 'bg-yellow-900/50 text-yellow-400',
  low: 'bg-green-900/50 text-green-400',
  info: 'bg-blue-900/50 text-blue-400',
}

const SEVERITY_BORDER_CLASSES = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-500',
  medium: 'border-l-yellow-500',
  low: 'border-l-green-500',
  info: 'border-l-blue-500',
}

const SEVERITY_STAT_CLASSES = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

const VERIFICATION_BADGE_CLASSES = {
  verified: 'bg-green-900/50 text-green-400',
  unverified: 'bg-yellow-900/50 text-yellow-400',
  false_positive: 'bg-gray-700 text-gray-400',
}

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
  const [confirmVerifyScanId, setConfirmVerifyScanId] = useState(null)

  useEffect(() => {
    fetchScansAndFindings()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function fetchScansAndFindings() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const scansRaw = await resp.json()
      const scansData = Array.isArray(scansRaw) ? scansRaw : (scansRaw.items || [])
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
    const sev = finding.severity || 'unknown'

    return (
      <div key={key} className={`bg-gray-800/30 border-l-4 ${SEVERITY_BORDER_CLASSES[sev] || 'border-l-gray-500'} border border-gray-700 rounded-lg p-4 mb-2 cursor-pointer hover:bg-gray-800/60 transition`}>
        <div className="flex items-center justify-between" onClick={() => toggleExpand(key)}>
          <div className="flex items-center gap-3 min-w-0">
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold shrink-0 ${SEVERITY_BADGE_CLASSES[sev] || 'bg-gray-700 text-gray-400'}`}>
              {sev}
            </span>
            <h4 className="text-sm font-medium text-white truncate">{finding.title || 'Untitled Finding'}</h4>
            {finding.priority_score != null && (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-indigo-900/50 text-indigo-400 shrink-0" title="Priority Score">
                P{finding.priority_score}
              </span>
            )}
          </div>
          <span className="text-gray-500 text-xs ml-2 shrink-0">{isExpanded ? '\u25B2' : '\u25BC'}</span>
        </div>

        <div className="flex items-center gap-3 mt-2 text-xs text-gray-400 flex-wrap">
          {finding.url && (
            <span className="truncate max-w-xs" title={finding.url}>
              {finding.url}
            </span>
          )}
          {finding.affected_url && !finding.url && (
            <span className="truncate max-w-xs" title={finding.affected_url}>
              {finding.affected_url}
            </span>
          )}
          <span>
            Scan: <Link to={`/scans/${finding.scanId}`} className="text-cyan-400 hover:text-cyan-300 transition">{finding.scanId?.substring(0, 8)}</Link>
          </span>
          {finding.verification_status && (
            <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${VERIFICATION_BADGE_CLASSES[finding.verification_status] || 'bg-gray-700 text-gray-400'}`}>
              {finding.verification_status}
            </span>
          )}
        </div>

        {isExpanded && (
          <div className="mt-3 pt-3 border-t border-gray-700">
            {finding.description && (
              <div className="mb-3">
                <h5 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Description</h5>
                <p className="text-sm text-gray-300">{finding.description}</p>
              </div>
            )}
            {finding.remediation && (
              <div className="mb-3 bg-cyan-900/10 border border-cyan-800/30 rounded-lg p-3">
                <h5 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">Remediation</h5>
                <p className="text-sm text-gray-300">{finding.remediation}</p>
              </div>
            )}
            {finding.cvss_score != null && (
              <div className="flex items-center gap-2 mb-3 text-sm">
                <span className="text-gray-400">CVSS:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BADGE_CLASSES[sev] || 'bg-gray-700 text-gray-400'}`}>{finding.cvss_score}</span>
                {finding.cvss_vector && <span className="text-xs text-gray-500 font-mono">{finding.cvss_vector}</span>}
              </div>
            )}
            <div className="mt-3">
              <button
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-xs rounded-lg transition font-medium"
                onClick={() => setConfirmVerifyScanId(finding.scanId)}
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

  function renderTriageBucket(label, items, colorClass) {
    return (
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-3">
          <h3 className="text-lg font-semibold text-white">{label}</h3>
          <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${colorClass}`}>{items.length}</span>
        </div>
        {items.length === 0 ? (
          <p className="text-gray-500 text-sm">No items in this bucket</p>
        ) : (
          items.map((f, idx) => renderFindingCard(f, `triage-${label}-${idx}`))
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="text-gray-400 text-sm">Loading remediation data...</div>
      </div>
    )
  }

  const severityGroups = groupBySeverity()
  const severityKeys = Object.keys(severityGroups).sort((a, b) => severityRank(a) - severityRank(b))

  const criticalCount = (severityGroups.critical || []).length
  const highCount = (severityGroups.high || []).length
  const mediumCount = (severityGroups.medium || []).length
  const lowCount = (severityGroups.low || []).length

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Remediation Tracker</h1>
        <p className="text-sm text-gray-400 mt-1">Prioritize and track remediation of security findings</p>
      </div>

      {error && <div className="bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-6">{error}</div>}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 text-center">
          <span className="text-xs text-gray-400 uppercase block mb-1">Total Findings</span>
          <span className="text-2xl font-bold text-white">{findings.length}</span>
        </div>
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 text-center">
          <span className="text-xs text-gray-400 uppercase block mb-1">Critical</span>
          <span className={`text-2xl font-bold ${SEVERITY_STAT_CLASSES.critical}`}>{criticalCount}</span>
        </div>
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 text-center">
          <span className="text-xs text-gray-400 uppercase block mb-1">High</span>
          <span className={`text-2xl font-bold ${SEVERITY_STAT_CLASSES.high}`}>{highCount}</span>
        </div>
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 text-center">
          <span className="text-xs text-gray-400 uppercase block mb-1">Medium</span>
          <span className={`text-2xl font-bold ${SEVERITY_STAT_CLASSES.medium}`}>{mediumCount}</span>
        </div>
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 text-center">
          <span className="text-xs text-gray-400 uppercase block mb-1">Low</span>
          <span className={`text-2xl font-bold ${SEVERITY_STAT_CLASSES.low}`}>{lowCount}</span>
        </div>
      </div>

      {triageBuckets && (
        <div className="flex items-center gap-1 mb-6 bg-gray-800/30 border border-gray-700 rounded-lg p-1 w-fit">
          <button
            className={`px-4 py-2 rounded-md text-sm font-medium transition ${activeTab === 'severity' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            onClick={() => setActiveTab('severity')}
          >
            By Severity
          </button>
          <button
            className={`px-4 py-2 rounded-md text-sm font-medium transition ${activeTab === 'triage' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            onClick={() => setActiveTab('triage')}
          >
            Triage Buckets
          </button>
        </div>
      )}

      {activeTab === 'severity' && (
        <div>
          {findings.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500">No findings to remediate. Run a scan to get started.</p>
            </div>
          ) : (
            severityKeys.map(sev => (
              <div key={sev} className="mb-6">
                <div className="flex items-center gap-2 mb-3">
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${SEVERITY_BADGE_CLASSES[sev] || 'bg-gray-700 text-gray-400'}`}>{sev}</span>
                  <span className="text-sm text-gray-400">{severityGroups[sev].length} finding{severityGroups[sev].length !== 1 ? 's' : ''}</span>
                </div>
                <div>
                  {severityGroups[sev].map((f, idx) => renderFindingCard(f, idx))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'triage' && triageBuckets && (
        <div>
          {renderTriageBucket('Immediate Action', triageBuckets.immediate_action, 'bg-red-900/50 text-red-400')}
          {renderTriageBucket('This Sprint', triageBuckets.this_sprint, 'bg-yellow-900/50 text-yellow-400')}
          {renderTriageBucket('Backlog', triageBuckets.backlog, 'bg-blue-900/50 text-blue-400')}
        </div>
      )}

      <ConfirmDialog
        open={confirmVerifyScanId !== null}
        title="Trigger Verification Scan?"
        description="This will queue a verification scan for this finding. Verification scans are resource-intensive and may take several minutes."
        confirmLabel="Trigger Scan"
        confirmVariant="warning"
        onConfirm={() => {
          const scanId = confirmVerifyScanId
          setConfirmVerifyScanId(null)
          triggerVerification(scanId)
        }}
        onCancel={() => setConfirmVerifyScanId(null)}
        isLoading={confirmVerifyScanId !== null && verifyingIds.has(confirmVerifyScanId)}
      />
    </div>
  )
}

export default RemediationPage
