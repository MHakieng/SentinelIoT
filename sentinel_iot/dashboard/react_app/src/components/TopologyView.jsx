import React, { useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Clock3,
  Database,
  Monitor,
  Radio,
  RefreshCw,
  Router,
  Search,
  Server,
  Shield,
  Share2,
  Wifi,
} from 'lucide-react'
import DeviceClassBadge from './DeviceClassBadge'

const REFRESH_OPTIONS = [
  { label: 'Kapalı', value: 0 },
  { label: '10 sn', value: 10000 },
  { label: '20 sn', value: 20000 },
  { label: '30 sn', value: 30000 },
]

const SCAN_PROFILES = [
  { label: 'Hızlı', value: 'quick' },
  { label: 'IoT Keşfi', value: 'iot_discovery' },
  { label: 'Zafiyet', value: 'vulnerability' },
]

const MAX_VISIBLE_LINKS = 120
const LANE_TOP = 110
const GROUP_GAP = 64
const NODE_GAP = 124
const ROW_HEADER_SPACE = 72
const ROW_BOTTOM_SPACE = 74

const CLASS_META = {
  iot_device: { label: 'IoT Cihazları', short: 'IoT', icon: Radio, tone: 'iot' },
  client_device: { label: 'İstemci Cihazlar', short: 'İstemci', icon: Monitor, tone: 'client' },
  network_infrastructure: { label: 'Ağ Altyapısı', short: 'Altyapı', icon: Router, tone: 'infra' },
  unknown: { label: 'Bilinmeyen', short: 'Bilinmeyen', icon: Shield, tone: 'unknown' },
  observed_endpoint: { label: 'Gözlenen Uç Nokta', short: 'Gözlenen', icon: Wifi, tone: 'observed' },
}

const getEndpointId = (endpoint) => {
  if (!endpoint) return ''
  return typeof endpoint === 'object' ? endpoint.id : String(endpoint)
}

const formatTime = (date) => {
  if (!date) return 'Henüz yok'
  return new Intl.DateTimeFormat('tr-TR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

const formatBytes = (value) => {
  const bytes = Number(value || 0)
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

const formatNumber = (value) => {
  const numeric = Number(value || 0)
  if (!Number.isFinite(numeric)) return '0'
  return new Intl.NumberFormat('tr-TR').format(Math.round(numeric))
}

const shortText = (value, fallback = 'Bilinmeyen') => {
  const text = String(value || fallback)
  return text.length > 34 ? `${text.slice(0, 31)}...` : text
}

const riskTone = (score) => {
  const risk = Number(score || 0)
  if (risk >= 80) return 'critical'
  if (risk >= 70) return 'high'
  if (risk >= 35) return 'medium'
  return 'low'
}

const riskLabel = (score) => {
  const tone = riskTone(score)
  if (tone === 'critical') return 'Kritik'
  if (tone === 'high') return 'Yüksek'
  if (tone === 'medium') return 'Orta'
  return 'Düşük'
}

const classOfNode = (node) => {
  if (node.type === 'observed_endpoint') return 'observed_endpoint'
  return node.device_class || 'unknown'
}

const mergeDevice = (node, devicesByIp) => {
  const inventory = devicesByIp.get(node.ip) || {}
  return {
    ...node,
    ...inventory,
    id: node.id || node.ip,
    ip: node.ip || inventory.ip || node.id,
    label: node.label || inventory.vendor || node.ip,
    vendor: inventory.vendor || node.vendor || node.label || 'Bilinmeyen üretici',
    mac: inventory.mac || node.mac || '',
    status: inventory.status || node.status || 'Unknown',
    risk_score: Number(node.risk_score ?? inventory.risk_score ?? 0),
    open_ports: Array.isArray(inventory.open_ports) ? inventory.open_ports : [],
    total_cves: Number(inventory.total_cves || 0),
    device_class: inventory.device_class || node.device_class || 'unknown',
    device_class_confidence: inventory.device_class_confidence ?? node.device_class_confidence,
  }
}

const normalizeTopology = (data, devices) => {
  const rawNodes = Array.isArray(data?.nodes) ? data.nodes : []
  const rawLinks = Array.isArray(data?.links) ? data.links : []
  const devicesByIp = new Map()

  ;(Array.isArray(devices) ? devices : []).forEach((device) => {
    if (device?.ip) devicesByIp.set(device.ip, device)
  })

  const gatewayRaw = rawNodes.find((node) => node.type === 'gateway') || {
    id: 'sentinel-gateway',
    label: 'Ağ Geçidi',
    type: 'gateway',
    ip: 'Yerel ağ',
    status: 'Safe',
    risk_score: 0,
  }

  const nodeMap = new Map()
  nodeMap.set(gatewayRaw.id, {
    ...gatewayRaw,
    id: gatewayRaw.id,
    label: 'Ağ Geçidi',
    vendor: 'SentinelIoT izleme noktası',
    device_class: 'network_infrastructure',
    risk_score: Number(gatewayRaw.risk_score || 0),
    open_ports: [],
    total_cves: 0,
  })

  rawNodes
    .filter((node) => node.type === 'device')
    .forEach((node) => {
      const merged = mergeDevice(node, devicesByIp)
      nodeMap.set(merged.id || merged.ip, merged)
    })

  ;(Array.isArray(devices) ? devices : []).forEach((device) => {
    if (!device?.ip || nodeMap.has(device.ip)) return
    nodeMap.set(device.ip, mergeDevice({
      id: device.ip,
      ip: device.ip,
      type: 'device',
      label: device.vendor || device.ip,
    }, devicesByIp))
  })

  rawLinks.forEach((link) => {
    const source = getEndpointId(link.source)
    const target = getEndpointId(link.target)
    ;[source, target].forEach((id) => {
      if (!id || nodeMap.has(id)) return
      nodeMap.set(id, {
        id,
        ip: id,
        label: id,
        vendor: 'Gözlenen uç nokta',
        type: 'observed_endpoint',
        device_class: 'unknown',
        risk_score: Number(link.anomaly ? 70 : 0),
        open_ports: [],
        total_cves: 0,
        status: 'Observed',
      })
    })
  })

  const links = rawLinks
    .map((link, index) => ({
      ...link,
      id: `${getEndpointId(link.source)}-${getEndpointId(link.target)}-${link.protocol || 'link'}-${link.dst_port || index}`,
      source: getEndpointId(link.source),
      target: getEndpointId(link.target),
      packet_count: Number(link.packet_count || 0),
      byte_count: Number(link.byte_count || 0),
      protocol: link.protocol || 'Unknown',
      score: Number(link.score || 0),
      anomaly: Boolean(link.anomaly),
    }))
    .filter((link) => link.source && link.target && nodeMap.has(link.source) && nodeMap.has(link.target))

  return {
    nodes: Array.from(nodeMap.values()),
    links,
    gatewayId: gatewayRaw.id,
  }
}

const summarize = (nodes, links) => {
  const devices = nodes.filter((node) => node.type !== 'gateway')
  return {
    devices: devices.length,
    links: links.length,
    liveLinks: links.filter((link) => Number(link.packet_count || 0) > 0).length,
    anomalyLinks: links.filter((link) => link.anomaly).length,
    riskyDevices: devices.filter((node) => Number(node.risk_score || 0) >= 70).length,
    totalPackets: links.reduce((sum, link) => sum + Number(link.packet_count || 0), 0),
  }
}

const maxLinkPackets = (links) => Math.max(1, ...links.map((link) => Number(link.packet_count || 0)))

const linkStrokeWidth = (link, maxPackets) => {
  const packets = Number(link.packet_count || 0)
  if (link.anomaly) return 4
  if (packets <= 0) return 1.5
  return Math.min(4.2, 1.8 + (packets / maxPackets) * 2.4)
}

const buildProfessionalLayout = (nodes, links, gatewayId) => {
  const gateway = nodes.find((node) => node.id === gatewayId) || nodes.find((node) => node.type === 'gateway')
  const connected = new Set()
  links.forEach((link) => {
    if (link.packet_count > 0 || link.anomaly) {
      connected.add(link.source)
      connected.add(link.target)
    }
  })

  const devices = nodes
    .filter((node) => node.id !== gateway?.id)
    .sort((a, b) => {
      const activeDelta = Number(connected.has(b.id)) - Number(connected.has(a.id))
      if (activeDelta !== 0) return activeDelta
      return Number(b.risk_score || 0) - Number(a.risk_score || 0)
    })

  const grouped = devices.reduce((acc, node) => {
    const key = classOfNode(node)
    if (!acc[key]) acc[key] = []
    acc[key].push(node)
    return acc
  }, {})

  const order = ['network_infrastructure', 'iot_device', 'client_device', 'observed_endpoint', 'unknown']
  const rows = []
  order.forEach((key) => {
    const groupNodes = grouped[key] || []
    if (groupNodes.length > 0) rows.push({ key, nodes: groupNodes })
  })

  if (rows.length === 0 && devices.length > 0) rows.push({ key: 'unknown', nodes: devices })

  const nodePositions = new Map()
  let cursorY = LANE_TOP

  rows.forEach((row) => {
    row.top = cursorY
    row.nodes.forEach((node, index) => {
      const y = cursorY + ROW_HEADER_SPACE + index * NODE_GAP
      nodePositions.set(node.id, {
        ...node,
        x: 76,
        y,
        connected: connected.has(node.id),
      })
    })
    row.height = ROW_HEADER_SPACE + Math.max(0, row.nodes.length - 1) * NODE_GAP + ROW_BOTTOM_SPACE
    cursorY += row.height + GROUP_GAP
  })

  const canvasHeight = Math.max(680, cursorY + 80)
  const layoutNodes = []
  if (gateway) {
    layoutNodes.push({
      ...gateway,
      x: 24,
      y: Math.round(canvasHeight / 2),
      connected: connected.has(gateway.id),
    })
  }
  layoutNodes.push(...Array.from(nodePositions.values()))

  return { nodes: layoutNodes, rows, canvasHeight }
}

const lineClass = (link) => {
  if (link.anomaly) return 'danger'
  if (Number(link.packet_count || 0) > 0) return 'active'
  return 'discovery'
}

const selectVisibleLinks = (links, activeLinkId) => {
  if (links.length <= MAX_VISIBLE_LINKS) return links

  const activeLink = links.find((link) => link.id === activeLinkId)
  const prioritized = [...links]
    .sort((a, b) => {
      if (a.id === activeLinkId) return -1
      if (b.id === activeLinkId) return 1
      if (a.anomaly !== b.anomaly) return Number(b.anomaly) - Number(a.anomaly)
      const packetDelta = Number(b.packet_count || 0) - Number(a.packet_count || 0)
      if (packetDelta !== 0) return packetDelta
      return Number(b.byte_count || 0) - Number(a.byte_count || 0)
    })
    .slice(0, MAX_VISIBLE_LINKS)

  if (activeLink && !prioritized.some((link) => link.id === activeLink.id)) {
    prioritized[prioritized.length - 1] = activeLink
  }

  return prioritized
}

const TopologyMapNode = ({ node, active, onSelect }) => {
  const cls = classOfNode(node)
  const meta = CLASS_META[cls] || CLASS_META.unknown
  const Icon = node.type === 'gateway' ? Router : meta.icon
  const openPortCount = Array.isArray(node.open_ports) ? node.open_ports.length : 0
  const cveCount = Number(node.total_cves || 0)

  return (
    <button
      type="button"
      className={`network-node-card ${node.type === 'gateway' ? 'gateway' : ''} ${meta.tone} ${riskTone(node.risk_score)} ${active ? 'active' : ''}`}
      style={{ left: `${node.x}%`, top: `${node.y}px` }}
      onClick={() => onSelect(node)}
      title={`${node.ip || 'IP yok'} | ${node.vendor || node.label || 'Bilinmeyen'} | Risk ${Math.round(node.risk_score || 0)}%`}
    >
      <span className="network-node-icon"><Icon size={node.type === 'gateway' ? 22 : 17} /></span>
      <span className="network-node-main">
        <strong>{node.type === 'gateway' ? 'Ağ Geçidi' : shortText(node.ip || node.id)}</strong>
        <small>{node.type === 'gateway' ? (node.ip || 'Yerel ağ') : shortText(node.vendor || node.label)}</small>
      </span>
      {node.type !== 'gateway' && (
        <span className="network-node-meta">
          <span>{meta.short}</span>
          <span>{riskLabel(node.risk_score)}</span>
          <span>{openPortCount} port</span>
          <span>{cveCount} CVE</span>
        </span>
      )}
    </button>
  )
}

const TopologyView = ({
  data,
  loading = false,
  refreshing = false,
  error = null,
  lastUpdated = null,
  refreshMs = 10000,
  onRefreshMsChange,
  onRefresh,
  onStartScan,
  scanLoading = false,
  monitoringActive = false,
  devices = [],
  onSelectDevice,
}) => {
  const [targetRange, setTargetRange] = useState('')
  const [profile, setProfile] = useState('vulnerability')
  const [formError, setFormError] = useState(null)
  const [activeNodeId, setActiveNodeId] = useState(null)
  const [activeLinkId, setActiveLinkId] = useState(null)

  const topology = useMemo(() => normalizeTopology(data, devices), [data, devices])
  const layout = useMemo(() => buildProfessionalLayout(topology.nodes, topology.links, topology.gatewayId), [topology])
  const nodeById = useMemo(() => {
    const map = new Map()
    layout.nodes.forEach((node) => map.set(node.id, node))
    return map
  }, [layout.nodes])
  const summary = useMemo(() => summarize(topology.nodes, topology.links), [topology.nodes, topology.links])
  const maxPackets = useMemo(() => maxLinkPackets(topology.links), [topology.links])
  const visibleLinks = useMemo(() => selectVisibleLinks(topology.links, activeLinkId), [topology.links, activeLinkId])
  const hiddenLinkCount = Math.max(0, topology.links.length - visibleLinks.length)

  const selectedNode = nodeById.get(activeNodeId) || layout.nodes.find((node) => node.type !== 'gateway') || layout.nodes[0]
  const selectedLinks = useMemo(() => {
    if (!selectedNode) return []
    return topology.links
      .filter((link) => link.source === selectedNode.id || link.target === selectedNode.id)
      .sort((a, b) => Number(b.packet_count || 0) - Number(a.packet_count || 0))
      .slice(0, 10)
  }, [selectedNode, topology.links])
  const selectedLink = topology.links.find((link) => link.id === activeLinkId) || selectedLinks[0]

  const handleSubmit = async (event) => {
    event.preventDefault()
    const normalizedTarget = targetRange.trim()
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/

    if (normalizedTarget && !cidrPattern.test(normalizedTarget)) {
      setFormError('CIDR formatı bekleniyor. Örnek: 192.168.1.0/24')
      return
    }

    setFormError(null)
    await onStartScan?.({ targetRange: normalizedTarget, profile })
  }

  const handleSelectNode = (node) => {
    setActiveNodeId(node.id)
    setActiveLinkId(null)
    if (node.type !== 'gateway' && node.type !== 'observed_endpoint') onSelectDevice?.(node.ip)
  }

  return (
    <div className="fade-in topology-page">
      <section className="topology-workspace network-topology-workspace">
        <div className="topology-header">
          <div>
            <h3 className="topology-title"><Share2 size={18} /> Canlı Ağ Topolojisi</h3>
            <div className="table-secondary">
              Ağ geçidi, keşfedilen cihazlar ve canlı flow bağlantıları tek ekranda gösterilir.
            </div>
          </div>
          <div className="topology-header-side">
            <div className="topology-summary-pill"><Server size={13} /> {summary.devices} cihaz</div>
            <div className="topology-summary-pill"><Activity size={13} /> {summary.liveLinks} canlı akış</div>
            <div className={`topology-summary-pill ${monitoringActive ? 'active' : ''}`}>
              <Radio size={13} /> {monitoringActive ? 'İzleme açık' : 'İzleme kapalı'}
            </div>
          </div>
        </div>

        <div className="topology-control-strip">
          <form className="topology-scan-form" onSubmit={handleSubmit}>
            <label className="topology-field">
              <span>Tarama hedefi</span>
              <div className="topology-input-shell">
                <Search size={15} />
                <input
                  value={targetRange}
                  onChange={(event) => setTargetRange(event.target.value)}
                  placeholder="Otomatik veya 192.168.1.0/24"
                  spellCheck="false"
                />
              </div>
            </label>
            <label className="topology-field topology-field-compact">
              <span>Profil</span>
              <select value={profile} onChange={(event) => setProfile(event.target.value)}>
                {SCAN_PROFILES.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
            <button className="btn btn-primary topology-action-btn" type="submit" disabled={scanLoading}>
              {scanLoading ? <RefreshCw size={16} className="spin" /> : <Search size={16} />}
              {scanLoading ? 'Taranıyor' : 'Tara'}
            </button>
          </form>

          <div className="topology-refresh-controls">
            <label className="topology-field topology-field-compact">
              <span>Yenileme</span>
              <select value={refreshMs} onChange={(event) => onRefreshMsChange?.(Number(event.target.value))}>
                {REFRESH_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
            <button className="btn topology-secondary-btn" type="button" onClick={onRefresh} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? 'spin' : ''} />
              Yenile
            </button>
          </div>
        </div>

        {formError && <div className="topology-form-error"><AlertTriangle size={14} /> {formError}</div>}

        <div className="topology-body network-topology-body">
          <div className="topology-canvas-panel network-map-panel">
            <div className="topology-canvas-toolbar">
              <div className="topology-toolbar-item"><Clock3 size={13} /> Son güncelleme: {formatTime(lastUpdated)}</div>
              <div className="topology-toolbar-item"><Database size={13} /> {summary.links} bağlantı</div>
            </div>

            {loading ? (
              <div className="empty-state topology-fill">
                <div className="skeleton skeleton-icon topology-loading-orb"></div>
                <div className="skeleton skeleton-text" style={{ width: '180px' }}></div>
              </div>
            ) : error ? (
              <div className="empty-state topology-fill">
                <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)' }} />
                <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Topoloji verisi alınamadı</div>
                <div className="empty-state-copy">Backend bağlantısını veya tarama sonucunu kontrol edin. {error}</div>
              </div>
            ) : layout.nodes.length <= 1 ? (
              <div className="empty-state topology-fill">
                <Share2 className="empty-state-icon" />
                <div className="empty-state-title">Henüz topoloji verisi yok</div>
                <div className="empty-state-copy">Önce ağ taraması başlatın.</div>
              </div>
            ) : (
              <div className="network-map-stage" style={{ height: `${layout.canvasHeight}px` }}>
                <div className="network-backbone" />
                {layout.rows.map((row) => {
                  const meta = CLASS_META[row.key] || CLASS_META.unknown
                  return (
                    <div key={row.key} className={`network-lane ${meta.tone}`} style={{ top: `${row.top}px`, height: `${row.height - 18}px` }}>
                      <span>{meta.label}</span>
                    </div>
                  )
                })}

                <svg className="network-link-layer" viewBox={`0 0 100 ${layout.canvasHeight}`} preserveAspectRatio="none" aria-hidden="true">
                  {visibleLinks.map((link) => {
                    const source = nodeById.get(link.source)
                    const target = nodeById.get(link.target)
                    if (!source || !target) return null
                    const startX = source.x + (source.type === 'gateway' ? 8 : -8)
                    const endX = target.x - (target.type === 'gateway' ? -8 : 8)
                    const midX = Math.min(62, Math.max(42, (startX + endX) / 2))
                    const path = `M ${startX} ${source.y} C ${midX} ${source.y}, ${midX} ${target.y}, ${endX} ${target.y}`
                    const isActiveLink = selectedLink?.id === link.id
                    const strokeWidth = linkStrokeWidth(link, maxPackets)
                    const linkTone = lineClass(link)
                    return (
                      <g key={link.id} className="network-link-hit" onClick={() => setActiveLinkId(link.id)}>
                        <path className="network-cable-hit-area" d={path} />
                        <path
                          className={`network-cable-base ${linkTone} ${isActiveLink ? 'selected' : ''}`}
                          d={path}
                          style={{ strokeWidth: strokeWidth + 1.2 }}
                        />
                      </g>
                    )
                  })}
                </svg>

                {hiddenLinkCount > 0 && (
                  <div className="network-link-limit-note">
                    Performans için en yoğun {visibleLinks.length} bağlantı çiziliyor. Gizlenen bağlantı: {hiddenLinkCount}
                  </div>
                )}

                {layout.nodes.map((node) => (
                  <TopologyMapNode
                    key={node.id}
                    node={node}
                    active={selectedNode?.id === node.id}
                    onSelect={handleSelectNode}
                  />
                ))}
              </div>
            )}
          </div>

          <aside className="topology-inspector network-inspector">
            <div className="soft-panel topology-side-panel topology-stat-grid">
              <div><div className="metric-label">Riskli cihaz</div><div className="metric-value danger-text">{summary.riskyDevices}</div></div>
              <div><div className="metric-label">Anomali akışı</div><div className="metric-value warning-text">{summary.anomalyLinks}</div></div>
              <div><div className="metric-label">Bağlantı</div><div className="metric-value">{summary.links}</div></div>
              <div><div className="metric-label">Paket</div><div className="metric-value">{summary.totalPackets}</div></div>
            </div>

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title"><Shield size={16} /> Seçili düğüm</h4>
              {selectedNode ? (
                <div className="topology-node-detail">
                  <div className={`topology-node-icon ${riskTone(selectedNode.risk_score)}`}>
                    {selectedNode.type === 'gateway' ? <Router size={18} /> : <Server size={18} />}
                  </div>
                  <div>
                    <div className="topology-node-name">{selectedNode.label || selectedNode.vendor || 'Ağ Geçidi'}</div>
                    <div className="topology-node-meta">{selectedNode.ip || 'IP yok'}</div>
                    {selectedNode.mac && <div className="topology-node-meta">{selectedNode.mac}</div>}
                  </div>
                  <div className="topology-risk-row"><span>Risk skoru</span><strong>{Math.round(selectedNode.risk_score || 0)}%</strong></div>
                  <div className="topology-risk-row"><span>Risk seviyesi</span><strong>{riskLabel(selectedNode.risk_score)}</strong></div>
                  {selectedNode.type !== 'gateway' && (
                    <>
                      <div className="topology-risk-row">
                        <span>Cihaz sınıfı</span>
                        <DeviceClassBadge deviceClass={selectedNode.device_class} confidence={selectedNode.device_class_confidence} compact />
                      </div>
                      <div className="topology-risk-row"><span>Açık port</span><strong>{Array.isArray(selectedNode.open_ports) ? selectedNode.open_ports.length : 0}</strong></div>
                      <div className="topology-risk-row"><span>CVE</span><strong>{Number(selectedNode.total_cves || 0)}</strong></div>
                    </>
                  )}
                </div>
              ) : (
                <div className="section-subtitle">Düğüm seçin.</div>
              )}
            </div>

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title"><Activity size={16} /> Canlı bağlantılar</h4>
              <div className="topology-flow-list">
                {selectedLinks.length > 0 ? selectedLinks.map((link, index) => (
                  <button
                    type="button"
                    className={`topology-flow-item topology-flow-button ${selectedLink?.id === link.id ? 'active' : ''}`}
                    key={`${link.id}-${index}`}
                    onClick={() => setActiveLinkId(link.id)}
                  >
                    <div>
                      <div className="topology-flow-primary">{link.source} → {link.target}</div>
                      <div className="topology-flow-secondary">{link.protocol} {link.dst_port ? `/${link.dst_port}` : ''} · {formatBytes(link.byte_count)}</div>
                    </div>
                    <div className={link.anomaly ? 'topology-flow-score danger' : 'topology-flow-score'}>{link.packet_count || 0}</div>
                  </button>
                )) : (
                  <div className="section-subtitle">Bu düğüm için bağlantı yok.</div>
                )}
              </div>
            </div>

            {selectedLink && (
              <div className="soft-panel topology-side-panel">
                <h4 className="topology-panel-title"><Activity size={16} /> Seçili akış</h4>
                <div className="network-flow-detail">
                  <div className="topology-risk-row"><span>Kaynak</span><strong>{selectedLink.source}</strong></div>
                  <div className="topology-risk-row"><span>Hedef</span><strong>{selectedLink.target}</strong></div>
                  <div className="topology-risk-row"><span>Protokol</span><strong>{selectedLink.protocol}</strong></div>
                  {selectedLink.dst_port && <div className="topology-risk-row"><span>Port</span><strong>{selectedLink.dst_port}</strong></div>}
                  <div className="topology-risk-row"><span>Paket</span><strong>{formatNumber(selectedLink.packet_count)}</strong></div>
                  <div className="topology-risk-row"><span>Veri</span><strong>{formatBytes(selectedLink.byte_count)}</strong></div>
                  <div className="topology-risk-row"><span>Durum</span><strong>{selectedLink.anomaly ? 'Anomali' : Number(selectedLink.packet_count || 0) > 0 ? 'Canlı' : 'Keşif'}</strong></div>
                </div>
              </div>
            )}

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title"><Shield size={16} /> Lejant</h4>
              <div className="topology-legend-section">
                <div className="metric-label">Risk</div>
                <div className="topology-legend">
                  <div className="topology-legend-item"><span className="legend-dot success"></span>Düşük</div>
                  <div className="topology-legend-item"><span className="legend-dot warning"></span>Orta</div>
                  <div className="topology-legend-item"><span className="legend-dot danger"></span>Yüksek / kritik</div>
                </div>
              </div>
              <div className="topology-legend-section">
                <div className="metric-label">Bağlantı</div>
                <div className="topology-legend">
                  <div className="topology-legend-item"><span className="legend-line discovery"></span>Keşif</div>
                  <div className="topology-legend-item"><span className="legend-line active"></span>Canlı akış</div>
                  <div className="topology-legend-item"><span className="legend-line danger"></span>Anomali</div>
                </div>
              </div>
            </div>
          </aside>
        </div>
      </section>
    </div>
  )
}

export default TopologyView
