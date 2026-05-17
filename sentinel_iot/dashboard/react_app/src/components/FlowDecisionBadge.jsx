import React from 'react'

const DECISION_STYLES = {
  normal: {
    label: 'Normal',
    color: 'var(--success)',
    background: 'rgba(34, 197, 94, 0.14)',
    border: 'rgba(34, 197, 94, 0.28)',
  },
  suspicious: {
    label: 'Şüpheli',
    color: 'var(--warning)',
    background: 'rgba(245, 158, 11, 0.14)',
    border: 'rgba(245, 158, 11, 0.32)',
  },
  anomaly: {
    label: 'Anomali',
    color: 'var(--danger)',
    background: 'rgba(239, 68, 68, 0.15)',
    border: 'rgba(239, 68, 68, 0.3)',
  },
  unavailable: {
    label: 'Uygun Değil',
    color: 'var(--text-secondary)',
    background: 'rgba(148, 163, 184, 0.12)',
    border: 'rgba(148, 163, 184, 0.22)',
  },
}

export const getFlowDecisionMeta = (decision) => {
  const key = String(decision || 'normal').toLowerCase()
  return DECISION_STYLES[key] || DECISION_STYLES.normal
}

const FlowDecisionBadge = ({ decision, source = null, compact = false }) => {
  const meta = getFlowDecisionMeta(decision)
  return (
    <span
      title={`Karar kaynağı: ${source || 'canlı skorlama'}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: compact ? '3px 6px' : '4px 8px',
        borderRadius: '6px',
        fontSize: compact ? '0.64rem' : '0.7rem',
        fontWeight: 800,
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
        color: meta.color,
        background: meta.background,
        border: `1px solid ${meta.border}`,
      }}
    >
      {meta.label}
    </span>
  )
}

export default FlowDecisionBadge
