import { useState, useEffect } from 'react'
import { useToast } from '../components/ToastContext'

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
      const resp = await fetch(`${API_BASE}/api/scans/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch scans')
      const data = await resp.json()
      setScans(Array.isArray(data) ? data : (data.items || []))
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
    return <div className="p-6 max-w-6xl mx-auto"><p className="text-sm text-gray-400">Loading compliance data...</p></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Compliance Dashboard</h1>
        <p className="text-sm text-gray-400 mt-1">Evaluate scan results against industry compliance frameworks</p>
      </div>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Select Scan</label>
            <select
              value={selectedScanId}
              onChange={e => setSelectedScanId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Select a completed scan --</option>
              {completedScans.map(scan => (
                <option key={scan.id} value={scan.id}>
                  {scan.target_url || scan.target || 'Untitled'} - {new Date(scan.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
            {completedScans.length === 0 && (
              <span className="text-xs text-gray-500">No completed scans available</span>
            )}
          </div>

          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Compliance Framework</label>
            <select
              value={selectedFramework}
              onChange={e => setSelectedFramework(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Select framework --</option>
              {FRAMEWORKS.map(fw => (
                <option key={fw.id} value={fw.id}>{fw.name} ({fw.version})</option>
              ))}
            </select>
          </div>

          <button
            className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition disabled:opacity-50"
            onClick={generateComplianceReport}
            disabled={generating || !selectedScanId || !selectedFramework}
          >
            {generating ? 'Generating...' : 'Generate Compliance Report'}
          </button>
        </div>
      </div>

      {score !== null && (
        <div className="space-y-6">
          <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <h2 className="text-lg font-semibold text-white">{frameworkMeta?.name} Compliance</h2>
              <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs font-medium">{frameworkMeta?.version}</span>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-6 mb-4">
              <div className="text-center">
                <span className={`text-4xl font-bold ${score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                  {score}%
                </span>
              </div>
              <div className="flex-1 w-full">
                <div className="w-full h-3 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
              <div className="flex gap-4 text-sm">
                <span className="text-green-400">{controlResults.filter(c => c.status === 'pass').length} passed</span>
                <span className="text-yellow-400">{controlResults.filter(c => c.status === 'partial').length} partial</span>
                <span className="text-red-400">{controlResults.filter(c => c.status === 'fail').length} failed</span>
              </div>
            </div>

            <button
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition"
              onClick={downloadCompliancePdf}
            >
              Download Full Compliance PDF
            </button>
          </div>

          <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Control Results</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Control</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Status</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {controlResults.map(control => (
                    <tr key={control.id} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                      <td className="py-2 px-3 text-white">
                        <span className="text-gray-400 mr-2 font-mono text-xs">{control.id}</span>
                        {control.name}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                          control.status === 'pass' ? 'bg-green-500/20 text-green-400' :
                          control.status === 'fail' ? 'bg-red-500/20 text-red-400' :
                          'bg-yellow-500/20 text-yellow-400'
                        }`}>
                          {control.status === 'pass' ? 'Pass' : control.status === 'fail' ? 'Fail' : 'Partial'}
                        </span>
                      </td>
                      <td className="py-2 px-3">
                        {control.findingsCount > 0 ? (
                          <span className="text-red-400">{control.findingsCount} finding{control.findingsCount !== 1 ? 's' : ''}</span>
                        ) : (
                          <span className="text-gray-500">None</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {score === null && !generating && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-4">Supported Frameworks</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {FRAMEWORKS.map(fw => (
              <div
                key={fw.id}
                className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 text-center hover:bg-gray-800/60 transition cursor-pointer"
                onClick={() => setSelectedFramework(fw.id)}
              >
                <h3 className="text-base font-semibold text-white mb-1">{fw.name}</h3>
                <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs font-medium">{fw.version}</span>
                <p className="text-sm text-gray-400 mt-2">
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
