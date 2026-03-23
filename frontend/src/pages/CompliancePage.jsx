import { useState, useEffect } from 'react'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function CompliancePage({ token }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(false)
  }, [])

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Compliance Dashboard</h1>
        <p>View and manage compliance status across all systems</p>
      </div>

      <div className="stub-content">
        <div className="feature-card">
          <h2>📋 Compliance Status</h2>
          <p>Track compliance with multiple frameworks:</p>
          <ul>
            <li>OWASP Top 10</li>
            <li>CIS Controls</li>
            <li>GDPR Compliance</li>
            <li>HIPAA Requirements</li>
            <li>SOC 2 Controls</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>📊 Compliance Scoring</h2>
          <p>Real-time compliance scores and trends</p>
        </div>

        <div className="feature-card">
          <h2>📈 Metrics & Reporting</h2>
          <p>Detailed compliance metrics and audit trails</p>
        </div>
      </div>
    </div>
  )
}

export default CompliancePage
