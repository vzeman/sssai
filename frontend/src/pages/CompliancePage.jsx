import { useState, useEffect } from 'react'
import { useToast } from '../components/ToastContext'
import './CompliancePage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

const FRAMEWORKS = [
  { id: 'owasp-top10', name: 'OWASP Top 10', version: '2021' },
  { id: 'pci-dss', name: 'PCI-DSS', version: '4.0' },
  { id: 'soc2', name: 'SOC 2', version: 'Type II' },
  { id: 'iso27001', name: 'ISO 27001', version: '2022' },
  { id: 'hipaa', name: 'HIPAA', version: 'Security Rule' },
  { id: 'gdpr', name: 'GDPR', version: 'Art. 32' },
]

const FRAMEWORK_CONTROLS = {
  'owasp-top10': [
    { id: 'A01', name: 'A01:2021 - Broken Access Control' },
    { id: 'A02', name: 'A02:2021 - Cryptographic Failures' },
    { id: 'A03', name: 'A03:2021 - Injection' },
    { id: 'A04', name: 'A04:2021 - Insecure Design' },
    { id: 'A05', name: 'A05:2021 - Security Misconfiguration' },
    { id: 'A06', name: 'A06:2021 - Vulnerable and Outdated Components' },
    { id: 'A07', name: 'A07:2021 - Identification and Authentication Failures' },
    { id: 'A08', name: 'A08:2021 - Software and Data Integrity Failures' },
    { id: 'A09', name: 'A09:2021 - Security Logging and Monitoring Failures' },
    { id: 'A10', name: 'A10:2021 - Server-Side Request Forgery (SSRF)' },
  ],
  'pci-dss': [
    { id: 'R1', name: 'Req 1 - Network Security Controls' },
    { id: 'R2', name: 'Req 2 - Secure Configurations' },
    { id: 'R3', name: 'Req 3 - Protect Stored Account Data' },
    { id: 'R4', name: 'Req 4 - Protect Data in Transit' },
    { id: 'R5', name: 'Req 5 - Protect from Malicious Software' },
    { id: 'R6', name: 'Req 6 - Develop Secure Systems' },
    { id: 'R7', name: 'Req 7 - Restrict Access by Business Need' },
    { id: 'R8', name: 'Req 8 - Identify Users and Authenticate' },
    { id: 'R9', name: 'Req 9 - Restrict Physical Access' },
    { id: 'R10', name: 'Req 10 - Log and Monitor Access' },
    { id: 'R11', name: 'Req 11 - Test Security Regularly' },
    { id: 'R12', name: 'Req 12 - Support InfoSec with Policies' },
  ],
  'soc2': [
    { id: 'CC1', name: 'CC1 - Control Environment' },
    { id: 'CC2', name: 'CC2 - Communication and Information' },
    { id: 'CC3', name: 'CC3 - Risk Assessment' },
    { id: 'CC4', name: 'CC4 - Monitoring Activities' },
    { id: 'CC5', name: 'CC5 - Control Activities' },
    { id: 'CC6', name: 'CC6 - Logical and Physical Access' },
    { id: 'CC7', name: 'CC7 - System Operations' },
    { id: 'CC8', name: 'CC8 - Change Management' },
    { id: 'CC9', name: 'CC9 - Risk Mitigation' },
  ],
  'iso27001': [
    { id: 'A5', name: 'A.5 - Organizational Controls' },
    { id: 'A6', name: 'A.6 - People Controls' },
    { id: 'A7', name: 'A.7 - Physical Controls' },
    { id: 'A8', name: 'A.8 - Technological Controls' },
  ],
  'hipaa': [
    { id: 'AC', name: 'Access Control (164.312(a))' },
    { id: 'AU', name: 'Audit Controls (164.312(b))' },
    { id: 'IN', name: 'Integrity (164.312(c))' },
    { id: 'PA', name: 'Person Authentication (164.312(d))' },
    { id: 'TS', name: 'Transmission Security (164.312(e))' },
  ],
  'gdpr': [
    { id: 'ENC', name: 'Encryption of Personal Data' },
    { id: 'CIA', name: 'Confidentiality, Integrity, Availability' },
    { id: 'RES', name: 'Resilience of Processing Systems' },
    { id: 'REC', name: 'Ability to Restore Availability' },
    { id: 'TST', name: 'Regular Testing and Evaluation' },
  ],
}

function mapFindingsToControls(findings, frameworkId) {
  const controls = FRAMEWORK_CONTROLS[frameworkId] || []
  const severityKeywords = {
    'owasp-top10': {
      'A01': ['access control', 'authorization', 'idor', 'privilege'],
      'A02': ['crypto', 'ssl', 'tls', 'certificate', 'encryption', 'hash'],
      'A03': ['injection', 'sqli', 'xss', 'command injection', 'ldap'],
      'A04': ['design', 'architecture', 'threat model'],
      'A05': ['misconfiguration', 'default', 'unnecessary', 'header'],
      'A06': ['outdated', 'vulnerable component', 'dependency', 'cve'],
      'A07': ['authentication', 'password', 'session', 'brute force', 'credential'],
      'A08': ['integrity', 'deserialization', 'ci/cd', 'update'],
      'A09': ['logging', 'monitoring', 'audit', 'detection'],
      'A10': ['ssrf', 'server-side request'],
    },
    'pci-dss': {
      'R1': ['firewall', 'network', 'segmentation'],
      'R2': ['default', 'configuration', 'hardening'],
      'R3': ['storage', 'encryption', 'data at rest', 'pan'],
      'R4': ['transit', 'ssl', 'tls', 'https'],
      'R5': ['malware', 'antivirus'],
      'R6': ['vulnerability', 'patch', 'secure development', 'xss', 'injection'],
      'R7': ['access', 'authorization', 'role'],
      'R8': ['authentication', 'password', 'mfa', 'credential'],
      'R9': ['physical'],
      'R10': ['log', 'monitor', 'audit trail'],
      'R11': ['scan', 'penetration test', 'ids'],
      'R12': ['policy', 'procedure', 'awareness'],
    },
  }

  return controls.map(control => {
    const keywords = (severityKeywords[frameworkId] || {})[control.id] || []
    const relatedFindings = findings.filter(f => {
      const text = `${f.title || ''} ${f.description || ''} ${f.category || ''}`.toLowerCase()
      return keywords.some(kw => text.includes(kw))
    })

    const hasCritical = relatedFindings.some(f => f.severity === 'critical')
    const hasHigh = relatedFindings.some(f => f.severity === 'high')
    const hasMedium = relatedFindings.some(f => f.severity === 'medium')

    let status = 'pass'
    if (hasCritical || hasHigh) status = 'fail'
    else if (hasMedium) status = 'partial'

    return {
      ...control,
      status,
      findingsCount: relatedFindings.length,
      findings: relatedFindings,
    }
  })
}

function computeScore(controlResults) {
  if (controlResults.length === 0) return 100
  const points = controlResults.reduce((sum, c) => {
    if (c.status === 'pass') return sum + 1
    if (c.status === 'partial') return sum + 0.5
    return sum
  }, 0)
  return Math.round((points / controlResults.length) * 100)
}

function CompliancePage({ token }) {
  const { showToast } = useToast()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedScanId, setSelectedScanId] = useState('')
  const [selectedFramework, setSelectedFramework] = useState('')
  const [controlResults, setControlResults] = useState([])
  const [score, setScore] = useState(null)
  const [generating, setGenerating] = useState(false)

  useEffect(() => {
    fetchScans()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function fetchScans() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(data)
      setError('')
    } catch (err) {
      setError(err.message)
      setScans([])
    } finally {
      setLoading(false)
    }
  }

  async function generateComplianceReport() {
    if (!selectedScanId || !selectedFramework) {
      setError('Please select both a scan and a compliance framework.')
      return
    }
    try {
      setGenerating(true)
      setError('')
      const resp = await fetch(`${API_BASE}/api/scans/${selectedScanId}/report`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scan report')
      const data = await resp.json()
      const findings = data.findings || []
      const results = mapFindingsToControls(findings, selectedFramework)
      setControlResults(results)
      setScore(computeScore(results))
    } catch (err) {
      setError(err.message)
      setControlResults([])
      setScore(null)
    } finally {
      setGenerating(false)
    }
  }

  async function downloadCompliancePdf() {
    if (!selectedScanId) return
    try {
      const resp = await fetch(`${API_BASE}/api/reports/${selectedScanId}/pdf`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to download PDF')
      const blob = await resp.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `compliance-${selectedFramework}-${selectedScanId.substring(0, 8)}.pdf`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  const completedScans = scans.filter(s => s.status === 'completed')
  const frameworkMeta = FRAMEWORKS.find(f => f.id === selectedFramework)

  if (loading) {
    return <div className="page-container"><div className="loading">Loading compliance data...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Compliance Dashboard</h1>
        <p>Evaluate scan results against industry compliance frameworks</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="compliance-controls">
        <div className="control-group">
          <label>Select Scan</label>
          <select value={selectedScanId} onChange={e => setSelectedScanId(e.target.value)}>
            <option value="">-- Select a completed scan --</option>
            {completedScans.map(scan => (
              <option key={scan.id} value={scan.id}>
                {scan.target_url || scan.target || 'Untitled'} - {new Date(scan.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          {completedScans.length === 0 && (
            <span className="control-hint">No completed scans available</span>
          )}
        </div>

        <div className="control-group">
          <label>Compliance Framework</label>
          <select value={selectedFramework} onChange={e => setSelectedFramework(e.target.value)}>
            <option value="">-- Select framework --</option>
            {FRAMEWORKS.map(fw => (
              <option key={fw.id} value={fw.id}>{fw.name} ({fw.version})</option>
            ))}
          </select>
        </div>

        <button
          className="btn btn-primary generate-btn"
          onClick={generateComplianceReport}
          disabled={generating || !selectedScanId || !selectedFramework}
        >
          {generating ? 'Generating...' : 'Generate Compliance Report'}
        </button>
      </div>

      {score !== null && (
        <div className="compliance-results">
          <div className="score-section">
            <div className="score-header">
              <h2>{frameworkMeta?.name} Compliance</h2>
              <span className="framework-version">{frameworkMeta?.version}</span>
            </div>

            <div className="score-display">
              <div className="score-circle">
                <span className={`score-value ${score >= 80 ? 'score-good' : score >= 50 ? 'score-warning' : 'score-bad'}`}>
                  {score}%
                </span>
              </div>
              <div className="score-bar-container">
                <div
                  className={`score-bar ${score >= 80 ? 'bar-good' : score >= 50 ? 'bar-warning' : 'bar-bad'}`}
                  style={{ width: `${score}%` }}
                />
              </div>
              <div className="score-summary">
                <span className="pass-count">{controlResults.filter(c => c.status === 'pass').length} passed</span>
                <span className="partial-count">{controlResults.filter(c => c.status === 'partial').length} partial</span>
                <span className="fail-count">{controlResults.filter(c => c.status === 'fail').length} failed</span>
              </div>
            </div>

            <button className="btn btn-secondary download-btn" onClick={downloadCompliancePdf}>
              Download Full Compliance PDF
            </button>
          </div>

          <div className="controls-list">
            <h3>Control Results</h3>
            <table className="controls-table">
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Status</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {controlResults.map(control => (
                  <tr key={control.id} className={`control-row status-${control.status}`}>
                    <td className="control-name">
                      <span className="control-id">{control.id}</span>
                      {control.name}
                    </td>
                    <td>
                      <span className={`compliance-status-badge ${control.status}`}>
                        {control.status === 'pass' ? 'Pass' : control.status === 'fail' ? 'Fail' : 'Partial'}
                      </span>
                    </td>
                    <td className="findings-count">
                      {control.findingsCount > 0 ? (
                        <span className="has-findings">{control.findingsCount} finding{control.findingsCount !== 1 ? 's' : ''}</span>
                      ) : (
                        <span className="no-findings">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {score === null && !generating && (
        <div className="compliance-overview">
          <h2>Supported Frameworks</h2>
          <div className="frameworks-grid">
            {FRAMEWORKS.map(fw => (
              <div key={fw.id} className="framework-card" onClick={() => setSelectedFramework(fw.id)}>
                <h3>{fw.name}</h3>
                <span className="fw-version">{fw.version}</span>
                <p className="fw-description">
                  {fw.id === 'owasp-top10' && 'Top 10 web application security risks'}
                  {fw.id === 'pci-dss' && 'Payment card industry data security standard'}
                  {fw.id === 'soc2' && 'Service organization control criteria'}
                  {fw.id === 'iso27001' && 'Information security management system'}
                  {fw.id === 'hipaa' && 'Health information privacy and security'}
                  {fw.id === 'gdpr' && 'General data protection regulation'}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default CompliancePage
