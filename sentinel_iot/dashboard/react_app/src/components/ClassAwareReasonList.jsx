import React from 'react'

const ClassAwareReasonList = ({ classReasons = [], reasons = [], maxClassReasons = 2, maxReasons = 3 }) => {
  const safeClassReasons = Array.isArray(classReasons) ? classReasons : []
  const safeReasons = Array.isArray(reasons) ? reasons : []
  const hiddenReasons = [
    ...safeClassReasons.slice(maxClassReasons),
    ...safeReasons.slice(maxReasons),
  ]

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', maxWidth: '280px' }}>
      {safeClassReasons.slice(0, maxClassReasons).map((reason) => (
        <span
          key={`class-${reason}`}
          className="status-note"
          title={reason}
          style={{ padding: '3px 6px', fontSize: '0.68rem', borderColor: 'rgba(96, 165, 250, 0.35)' }}
        >
          {reason}
        </span>
      ))}
      {safeReasons.slice(0, maxReasons).map((reason) => (
        <span key={reason} className="status-note" title={reason} style={{ padding: '3px 6px', fontSize: '0.68rem' }}>
          {reason}
        </span>
      ))}
      {safeClassReasons.length === 0 && safeReasons.length === 0 && <span className="table-secondary">-</span>}
      {hiddenReasons.length > 0 && (
        <span className="table-secondary" title={hiddenReasons.join(', ')}>
          +{hiddenReasons.length}
        </span>
      )}
    </div>
  )
}

export default ClassAwareReasonList
