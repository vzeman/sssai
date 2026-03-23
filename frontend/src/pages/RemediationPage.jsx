import { useState, useEffect } from 'react'
import './StubPage.css'

function RemediationPage({ token }) {
  useEffect(() => {}, [])

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Remediation Tracker</h1>
        <p>Track and manage remediation progress across all findings</p>
      </div>

      <div className="stub-content">
        <div className="feature-card">
          <h2>📌 Remediation Plans</h2>
          <p>View and manage remediation plans for each finding:</p>
          <ul>
            <li>Assigned owners and deadlines</li>
            <li>Priority and effort estimates</li>
            <li>Progress tracking and updates</li>
            <li>Verification and sign-off</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>📊 Progress Dashboard</h2>
          <p>Track remediation progress by priority and owner</p>
        </div>

        <div className="feature-card">
          <h2>📋 Remediation Roadmap</h2>
          <p>Visualize remediation timeline and dependencies</p>
        </div>
      </div>
    </div>
  )
}

export default RemediationPage
