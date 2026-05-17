import React from 'react'

const CLASS_STYLES = {
  iot_device: {
    label: 'IoT Cihazı',
    color: 'var(--accent-secondary)',
    background: 'rgba(45, 212, 191, 0.12)',
    border: 'rgba(45, 212, 191, 0.28)',
  },
  client_device: {
    label: 'İstemci Cihaz',
    color: 'var(--info)',
    background: 'rgba(96, 165, 250, 0.12)',
    border: 'rgba(96, 165, 250, 0.28)',
  },
  network_infrastructure: {
    label: 'Ağ Altyapısı',
    color: 'var(--success)',
    background: 'rgba(34, 197, 94, 0.12)',
    border: 'rgba(34, 197, 94, 0.28)',
  },
  unknown: {
    label: 'Bilinmeyen',
    color: 'var(--text-secondary)',
    background: 'rgba(148, 163, 184, 0.1)',
    border: 'rgba(148, 163, 184, 0.2)',
  },
  unclassified: {
    label: 'Sınıflandırılmadı',
    color: 'var(--text-secondary)',
    background: 'rgba(148, 163, 184, 0.08)',
    border: 'rgba(148, 163, 184, 0.18)',
  },
}

export const getDeviceClassMeta = (deviceClass) => {
  const key = String(deviceClass || '').toLowerCase()
  return CLASS_STYLES[key] || CLASS_STYLES.unclassified
}

const DeviceClassBadge = ({ deviceClass, confidence = null, compact = false }) => {
  const meta = getDeviceClassMeta(deviceClass)
  const confidenceLabel = confidence === null || confidence === undefined
    ? 'sınıflandırma güveni yok'
    : `sınıflandırma güveni: ${Number(confidence || 0).toFixed(2)}`

  return (
    <span
      title={`${meta.label} - ${confidenceLabel}. Bu değer accuracy/F1 metriği değildir.`}
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

export default DeviceClassBadge
