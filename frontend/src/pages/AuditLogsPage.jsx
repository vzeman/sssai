import AuditLogViewer from '../components/AuditLogViewer'

function AuditLogsPage({ token }) {
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Audit Logs</h1>
        <p className="text-sm text-gray-400 mt-1">Review system activity and user actions</p>
      </div>
      <AuditLogViewer token={token} />
    </div>
  )
}

export default AuditLogsPage
