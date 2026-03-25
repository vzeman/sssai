import { Link, useLocation } from 'react-router-dom'

const ROUTE_LABELS = {
  scans: 'Scans',
  new: 'New Scan',
  findings: 'Findings',
  reports: 'Reports',
  compliance: 'Compliance',
  remediation: 'Remediation',
  schedules: 'Schedules',
  webhooks: 'Webhooks',
  campaigns: 'Campaigns',
  queue: 'Queue',
  alerts: 'Alerts',
  assets: 'Assets',
  inventory: 'Inventory',
  posture: 'Posture',
  'audit-logs': 'Audit Logs',
  settings: 'Settings',
  advisor: 'Advisor',
  compare: 'Comparison',
}

function resolveLabel(segment) {
  if (ROUTE_LABELS[segment]) return ROUTE_LABELS[segment]
  // Dynamic segment (scan ID, baseline ID) — truncate to 8 chars
  if (segment.length > 8) return segment.substring(0, 8)
  return segment
}

export default function Breadcrumbs() {
  const { pathname } = useLocation()

  if (pathname === '/') return null

  const segments = pathname.split('/').filter(Boolean)
  const crumbs = [{ label: 'Dashboard', path: '/' }]

  let currentPath = ''
  for (let i = 0; i < segments.length; i++) {
    currentPath += `/${segments[i]}`
    crumbs.push({
      label: resolveLabel(segments[i], i, segments),
      path: currentPath,
    })
  }

  return (
    <nav className="flex items-center gap-1 text-sm mb-4 px-6 pt-4" aria-label="Breadcrumb">
      {crumbs.map((crumb, idx) => (
        <span key={crumb.path} className="flex items-center gap-1">
          {idx > 0 && <span className="text-gray-600 mx-1" aria-hidden="true">/</span>}
          {idx < crumbs.length - 1 ? (
            <Link className="text-gray-400 hover:text-gray-200 transition" to={crumb.path}>{crumb.label}</Link>
          ) : (
            <span className="text-gray-200 font-medium" aria-current="page">{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
