const DEFAULT_LIMIT = 14

const parseEventTime = (value) => {
  if (!value || value === 'N/A') return null
  const normalized = typeof value === 'string' && value.includes(' ') ? value.replace(' ', 'T') : value
  const date = new Date(normalized)
  return Number.isNaN(date.getTime()) ? null : date
}

const toIsoTimestamp = (value, fallback = null) => {
  const parsed = parseEventTime(value)
  if (parsed) return parsed.toISOString()
  if (fallback instanceof Date && !Number.isNaN(fallback.getTime())) return fallback.toISOString()
  return null
}

const eventSortValue = (event) => {
  const parsed = parseEventTime(event.timestamp)
  return parsed ? parsed.getTime() : 0
}

const severityForRisk = (score) => {
  const risk = Number(score || 0)
  if (risk >= 70) return 'critical'
  if (risk >= 35) return 'medium'
  return 'low'
}

const severityForScanStatus = (status) => {
  if (status === 'failed') return 'critical'
  if (status === 'completed') return 'low'
  if (status === 'running' || status === 'pending') return 'info'
  return 'low'
}

const compactText = (value, fallback) => {
  const text = String(value || fallback || '').trim()
  return text.length > 140 ? `${text.slice(0, 137)}...` : text
}

const standardizeEvent = ({
  id,
  timestamp,
  type,
  severity = 'info',
  title,
  description,
  device_ip = null,
  source,
  evidence = {},
}) => ({
  id,
  timestamp,
  type,
  severity,
  title,
  description,
  device_ip,
  source,
  evidence,
})

const buildScanEvents = (scanJobs = []) => (
  scanJobs.flatMap((job) => {
    if (!job?.id) return []
    const startedAt = toIsoTimestamp(job.started_at || job.start_time)
    const updatedAt = toIsoTimestamp(job.updated_at || job.last_event_at || job.last_completed_at)
    const status = job.status || 'unknown'
    const events = []

    if (startedAt) {
      events.push(standardizeEvent({
        id: `scan-started-${job.id}`,
        timestamp: startedAt,
        type: 'SCAN_STARTED',
        severity: 'info',
        title: 'Tarama başlatıldı',
        description: compactText(job.target ? `Hedef ağ: ${job.target}.` : 'Ağ tarama işi kuyruğa alındı.'),
        source: 'scanner_jobs',
        evidence: {
          job_id: job.id,
          status,
          target: job.target || null,
          progress: job.progress ?? null,
        },
      }))
    }

    if (['completed', 'failed'].includes(status) && updatedAt) {
      const failedDevices = Number(job.summary?.failed_devices || 0)
      const scannedDevices = Number(job.summary?.devices_scanned || job.summary?.devices_found || 0)
      events.push(standardizeEvent({
        id: `scan-completed-${job.id}-${status}`,
        timestamp: updatedAt,
        type: 'SCAN_COMPLETED',
        severity: severityForScanStatus(status),
        title: status === 'failed' ? 'Tarama başarısız oldu' : 'Tarama tamamlandı',
        description: status === 'failed'
          ? compactText(job.error || job.message, 'Tarama işi hata durumuyla kapandı.')
          : `${scannedDevices} cihaz tarandı${failedDevices > 0 ? `, ${failedDevices} cihazda hata var` : ''}.`,
        source: 'scanner_jobs',
        evidence: {
          job_id: job.id,
          status,
          progress: job.progress ?? null,
          summary: job.summary || null,
        },
      }))
    }

    return events
  })
)

const buildDeviceEvents = (devices = []) => (
  devices.flatMap((device) => {
    if (!device?.ip) return []
    const timestamp = toIsoTimestamp(device.last_seen || device.timestamp)
    const openPorts = Array.isArray(device.open_ports) ? device.open_ports : []
    const events = [
      standardizeEvent({
        id: `device-discovered-${device.ip}`,
        timestamp,
        type: 'DEVICE_DISCOVERED',
        severity: severityForRisk(device.risk_score),
        title: 'Cihaz envantere alındı',
        description: `${device.ip} izlenen cihaz listesinde. Risk: ${Math.round(Number(device.risk_score || 0))}.`,
        device_ip: device.ip,
        source: 'devices',
        evidence: {
          risk_score: device.risk_score ?? 0,
          status: device.status || 'Unknown',
        },
      }),
    ]

    const vulnerablePorts = openPorts.filter((port) => Array.isArray(port.cves) && port.cves.length > 0)
    vulnerablePorts.slice(0, 4).forEach((port) => {
      events.push(standardizeEvent({
        id: `vulnerability-${device.ip}-${port.port || 'port'}-${(port.cves || []).join('-')}`,
        timestamp,
        type: 'VULNERABILITY_FOUND',
        severity: 'critical',
        title: 'Zafiyetli servis bulundu',
        description: `${device.ip}:${port.port || 'port'} servisinde ${(port.cves || []).length} CVE kaydı var.`,
        device_ip: device.ip,
        source: 'devices',
        evidence: {
          port: port.port || null,
          service: port.service || null,
          cves: port.cves || [],
        },
      }))
    })

    return events
  })
)

const buildAnomalyEvents = (anomalies = [], selectedIp = null, liveFlows = []) => {
  const deviceEvents = anomalies.slice(0, 8).map((log, index) => standardizeEvent({
    id: `device-anomaly-${selectedIp || 'unknown'}-${log.timestamp || index}-${log.type || 'event'}`,
    timestamp: toIsoTimestamp(log.timestamp),
    type: 'ANOMALY_DETECTED',
    severity: Number(log.score || 0) >= 70 ? 'critical' : 'medium',
    title: 'Anomali tespit edildi',
    description: `${log.type || 'İzleme olayı'} skoru ${Number(log.score || 0).toFixed(2)}.`,
    device_ip: selectedIp,
    source: 'device_anomalies',
    evidence: {
      score: log.score ?? null,
      type: log.type || null,
      details: log.details || null,
    },
  }))

  const liveEvents = liveFlows
    .filter((flow) => flow.label === 1 || Number(flow.anomaly_score || 0) >= 0.5)
    .slice(0, 5)
    .map((flow, index) => standardizeEvent({
      id: `live-flow-anomaly-${flow.flow_id || index}`,
      timestamp: toIsoTimestamp(flow.timestamp || flow.end_time || flow.start_time, new Date()),
      type: 'ANOMALY_DETECTED',
      severity: Number(flow.anomaly_score || 0) >= 0.8 ? 'critical' : 'medium',
      title: 'Canlı akış anomalisi',
      description: `${flow.src_ip}:${flow.src_port || '?'} -> ${flow.dst_ip}:${flow.dst_port || '?'} skor ${(Number(flow.anomaly_score || 0) * 100).toFixed(1)}%.`,
      device_ip: flow.src_ip || flow.dst_ip || null,
      source: 'monitor_flows',
      evidence: {
        flow_id: flow.flow_id || null,
        protocol: flow.protocol_name || flow.protocol || null,
        anomaly_score: flow.anomaly_score ?? null,
        label: flow.label ?? null,
      },
    }))

  return [...deviceEvents, ...liveEvents]
}

const buildRiskEvents = (riskHistory = [], selectedIp = null) => {
  const events = []
  const ordered = [...riskHistory].sort((a, b) => eventSortValue(a) - eventSortValue(b))

  ordered.forEach((point, index) => {
    const previous = ordered[index - 1]
    const currentScore = Number(point.risk_score || 0)
    const previousScore = Number(previous?.risk_score || 0)
    if (!previous || currentScore <= previousScore) return

    events.push(standardizeEvent({
      id: `risk-increased-${selectedIp || 'unknown'}-${point.timestamp || index}`,
      timestamp: toIsoTimestamp(point.timestamp),
      type: 'RISK_INCREASED',
      severity: severityForRisk(currentScore),
      title: 'Risk skoru yükseldi',
      description: `Risk ${previousScore.toFixed(1)} seviyesinden ${currentScore.toFixed(1)} seviyesine çıktı.`,
      device_ip: selectedIp,
      source: 'risk_history',
      evidence: {
        previous_risk_score: previousScore,
        risk_score: currentScore,
        vuln: point.vuln ?? null,
        anomaly: point.anomaly ?? null,
      },
    }))
  })

  return events
}

const buildAiEvents = (analysisEvents = []) => (
  analysisEvents.map((event) => standardizeEvent({
    id: event.id,
    timestamp: toIsoTimestamp(event.timestamp),
    type: 'AI_ANALYSIS_GENERATED',
    severity: 'info',
    title: 'YZ cihaz analizi üretildi',
    description: `${event.device_ip} için cihaz bağlamlı analiz hazırlandı.`,
    device_ip: event.device_ip,
    source: 'llm_device_analysis',
    evidence: {
      sections: event.sections || [],
      cached: Boolean(event.cached),
    },
  }))
)

export const buildSecurityTimelineEvents = ({
  devices = [],
  scanJobs = [],
  selectedDevice = null,
  selectedDeviceAnomalies = [],
  selectedDeviceRiskHistory = [],
  liveFlows = [],
  analysisEvents = [],
  limit = DEFAULT_LIMIT,
}) => {
  const selectedIp = selectedDevice?.ip || null
  const events = [
    ...buildScanEvents(scanJobs),
    ...buildDeviceEvents(devices),
    ...buildAnomalyEvents(selectedDeviceAnomalies, selectedIp, liveFlows),
    ...buildRiskEvents(selectedDeviceRiskHistory, selectedIp),
    ...buildAiEvents(analysisEvents),
  ]

  const unique = new Map()
  events.forEach((event) => {
    if (!event.id || unique.has(event.id)) return
    unique.set(event.id, event)
  })

  return [...unique.values()]
    .sort((a, b) => eventSortValue(b) - eventSortValue(a))
    .slice(0, limit)
}

export const formatTimelineTime = (timestamp) => {
  const parsed = parseEventTime(timestamp)
  if (!parsed) return 'zaman yok'
  return new Intl.DateTimeFormat('tr-TR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(parsed)
}
