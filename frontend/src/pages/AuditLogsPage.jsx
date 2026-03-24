import AuditLogViewer from '../components/AuditLogViewer'

function AuditLogsPage({ token }) {
  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Audit Logs</h1>
        <p>Review system activity and user actions</p>
      </div>
      <AuditLogViewer token={token} />
    </div>
  )
}

export default AuditLogsPage
