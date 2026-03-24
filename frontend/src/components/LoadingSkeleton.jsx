import './LoadingSkeleton.css'

export function LoadingSkeleton({ rows = 5, columns = 4 }) {
  return (
    <div className="skeleton-table">
      <div className="skeleton-header">
        {Array.from({ length: columns }, (_, i) => (
          <div key={i} className="skeleton-cell skeleton-pulse" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, rowIdx) => (
        <div key={rowIdx} className="skeleton-row">
          {Array.from({ length: columns }, (_, colIdx) => (
            <div key={colIdx} className="skeleton-cell skeleton-pulse" style={{
              animationDelay: `${(rowIdx * columns + colIdx) * 0.05}s`,
              width: colIdx === 0 ? '60%' : `${40 + Math.random() * 30}%`,
            }} />
          ))}
        </div>
      ))}
    </div>
  )
}

export default LoadingSkeleton
