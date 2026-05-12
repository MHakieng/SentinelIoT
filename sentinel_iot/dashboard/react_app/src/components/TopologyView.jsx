import React, { useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import {
  Activity,
  AlertTriangle,
  Clock3,
  Radio,
  RefreshCw,
  Router,
  Search,
  Server,
  Shield,
  Share2,
  SlidersHorizontal,
} from 'lucide-react'

const REFRESH_OPTIONS = [
  { label: 'Kapalı', value: 0 },
  { label: '10 sn', value: 10000 },
  { label: '20 sn', value: 20000 },
  { label: '30 sn', value: 30000 },
]

const SCAN_PROFILES = [
  { label: 'Hızlı', value: 'quick' },
  { label: 'IoT', value: 'iot_discovery' },
  { label: 'Zafiyet', value: 'vulnerability' },
]

const formatTime = (date) => {
  if (!date) {
    return 'Henüz yok'
  }

  return new Intl.DateTimeFormat('tr-TR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

const formatBytes = (value) => {
  const bytes = Number(value || 0)
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`
  }
  return `${bytes} B`
}

const getEndpointId = (endpoint) => {
  if (!endpoint) {
    return ''
  }
  return typeof endpoint === 'object' ? endpoint.id : endpoint
}

const getNodeColor = (node) => {
  if (node.type === 'gateway') return '#60a5fa'
  const score = Number(node.risk_score || 0)
  if (score >= 70) return '#ef4444'
  if (score >= 35) return '#f59e0b'
  return '#22c55e'
}

const getRiskLabel = (score) => {
  const risk = Number(score || 0)
  if (risk >= 70) return 'Yüksek'
  if (risk >= 35) return 'Orta'
  return 'Düşük'
}

const summarizeTopology = (data) => {
  const nodes = Array.isArray(data?.nodes) ? data.nodes : []
  const links = Array.isArray(data?.links) ? data.links : []
  const devices = nodes.filter((node) => node.type === 'device')
  const riskyDevices = devices.filter((node) => Number(node.risk_score || 0) >= 70)
  const anomalyLinks = links.filter((link) => link.anomaly)
  const liveLinks = links.filter((link) => Number(link.packet_count || 0) > 0)
  const totalPackets = liveLinks.reduce((sum, link) => sum + Number(link.packet_count || 0), 0)

  return {
    devices: devices.length,
    links: links.length,
    riskyDevices: riskyDevices.length,
    anomalyLinks: anomalyLinks.length,
    liveLinks: liveLinks.length,
    totalPackets,
  }
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
  onSelectDevice,
}) => {
  const fgRef = useRef()
  const [targetRange, setTargetRange] = useState('')
  const [profile, setProfile] = useState('vulnerability')
  const [formError, setFormError] = useState(null)
  const [activeNode, setActiveNode] = useState(null)

  const summary = useMemo(() => summarizeTopology(data), [data])
  const graphData = useMemo(() => ({
    nodes: Array.isArray(data?.nodes) ? data.nodes : [],
    links: Array.isArray(data?.links) ? data.links : [],
  }), [data])

  const busiestLinks = useMemo(() => (
    graphData.links
      .filter((link) => Number(link.packet_count || 0) > 0 || link.anomaly)
      .sort((a, b) => Number(b.packet_count || 0) - Number(a.packet_count || 0))
      .slice(0, 5)
  ), [graphData.links])

  const selectedNode = activeNode || graphData.nodes.find((node) => node.type === 'gateway') || null

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

  const handleNodeClick = (node) => {
    setActiveNode(node)
    if (node.type === 'device') {
      onSelectDevice?.(node.ip)
    }
  }

  return (
    <div className="fade-in topology-page">
      <section className="topology-workspace">
        <div className="topology-header">
          <div>
            <h3 className="topology-title">
              <Share2 size={18} /> Ağ Topolojisi
            </h3>
          </div>

          <div className="topology-header-side">
            <div className="topology-summary-pill">
              <Server size={13} /> {summary.devices} cihaz
            </div>
            <div className="topology-summary-pill">
              <Radio size={13} /> {summary.liveLinks} canlı akış
            </div>
            <div className={`topology-summary-pill ${monitoringActive ? 'active' : ''}`}>
              <Activity size={13} /> {monitoringActive ? 'İzleme açık' : 'İzleme kapalı'}
            </div>
          </div>
        </div>

        <div className="topology-control-strip">
          <form className="topology-scan-form" onSubmit={handleSubmit}>
            <label className="topology-field">
              <span>Tarama Hedefi</span>
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
                {SCAN_PROFILES.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
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
                {REFRESH_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>

            <button className="btn topology-secondary-btn" type="button" onClick={onRefresh} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? 'spin' : ''} />
              Yenile
            </button>
          </div>
        </div>

        {formError && (
          <div className="topology-form-error">
            <AlertTriangle size={14} /> {formError}
          </div>
        )}

        <div className="topology-body">
          <div className="topology-canvas-panel">
            <div className="topology-canvas-toolbar">
              <div className="topology-toolbar-item">
                <Clock3 size={13} /> Son güncelleme: {formatTime(lastUpdated)}
              </div>
              <div className="topology-toolbar-item">
                <SlidersHorizontal size={13} /> {refreshMs > 0 ? `${refreshMs / 1000} sn otomatik` : 'Manuel'}
              </div>
            </div>

            {loading ? (
              <div className="empty-state topology-fill">
                <div className="skeleton skeleton-icon topology-loading-orb"></div>
                <div className="skeleton skeleton-text" style={{ width: '150px', marginBottom: '12px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '250px' }}></div>
              </div>
            ) : error ? (
              <div className="empty-state topology-fill">
                <Activity className="empty-state-icon" style={{ color: 'var(--danger)' }} />
                <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Topoloji Yüklenemedi</div>
                <div className="empty-state-copy">{error}</div>
              </div>
            ) : !graphData.nodes.length ? (
              <div className="empty-state topology-fill">
                <Share2 className="empty-state-icon" />
                <div className="empty-state-title">Ağ Haritası Boş</div>
                <div className="empty-state-copy">Tarama başlatın.</div>
              </div>
            ) : (
              <ForceGraph2D
                ref={fgRef}
                graphData={graphData}
                nodeLabel={(node) => `${node.label}\nRisk: ${Math.round(node.risk_score || 0)} (${getRiskLabel(node.risk_score)})`}
                linkLabel={(link) => `${link.protocol} | ${link.packet_count || 0} paket | skor ${Math.round(link.score || 0)}`}
                nodeColor={getNodeColor}
                nodeVal={(node) => node.type === 'gateway' ? 16 : Math.max(6, 7 + Number(node.risk_score || 0) / 12)}
                linkWidth={(link) => link.anomaly ? 4 : Math.max(1, Math.min(3, Number(link.packet_count || 0) / 8))}
                linkColor={(link) => link.anomaly ? '#ef4444' : Number(link.packet_count || 0) > 0 ? 'rgba(45, 212, 191, 0.42)' : 'rgba(148, 163, 184, 0.16)'}
                linkDirectionalParticles={(link) => link.anomaly ? 5 : Number(link.packet_count || 0) > 0 ? 2 : 0}
                linkDirectionalParticleWidth={(link) => link.anomaly ? 3 : 1.5}
                linkDirectionalParticleSpeed={0.012}
                linkDirectionalParticleColor={(link) => link.anomaly ? '#ef4444' : '#2dd4bf'}
                backgroundColor="#0b1018"
                cooldownTicks={80}
                onNodeClick={handleNodeClick}
                onNodeHover={(node) => {
                  if (node) {
                    setActiveNode(node)
                  }
                }}
                nodeCanvasObject={(node, ctx, globalScale) => {
                  const radius = node.type === 'gateway' ? 9 : Math.max(5, 5 + Number(node.risk_score || 0) / 28)
                  const label = node.type === 'gateway' ? 'Gateway' : node.ip
                  const fontSize = Math.max(9, 12 / globalScale)

                  ctx.beginPath()
                  ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI, false)
                  ctx.fillStyle = node.type === 'gateway' ? 'rgba(96, 165, 250, 0.16)' : `${getNodeColor(node)}22`
                  ctx.fill()

                  ctx.beginPath()
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false)
                  ctx.fillStyle = getNodeColor(node)
                  ctx.fill()
                  ctx.lineWidth = 1.4
                  ctx.strokeStyle = 'rgba(255,255,255,0.68)'
                  ctx.stroke()

                  ctx.font = `600 ${fontSize}px Inter`
                  ctx.textAlign = 'center'
                  ctx.textBaseline = 'middle'
                  ctx.fillStyle = '#edf2f7'
                  ctx.fillText(label, node.x, node.y + radius + 12)
                }}
              />
            )}
          </div>

          <aside className="topology-inspector">
            <div className="soft-panel topology-side-panel topology-stat-grid">
              <div>
                <div className="metric-label">Riskli Cihaz</div>
                <div className="metric-value danger-text">{summary.riskyDevices}</div>
              </div>
              <div>
                <div className="metric-label">Anomali Akışı</div>
                <div className="metric-value warning-text">{summary.anomalyLinks}</div>
              </div>
              <div>
                <div className="metric-label">Bağlantı</div>
                <div className="metric-value">{summary.links}</div>
              </div>
              <div>
                <div className="metric-label">Paket</div>
                <div className="metric-value">{summary.totalPackets}</div>
              </div>
            </div>

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title">
                <Shield size={16} /> Seçili Düğüm
              </h4>
              {selectedNode ? (
                <div className="topology-node-detail">
                  <div className="topology-node-icon" style={{ color: getNodeColor(selectedNode), borderColor: `${getNodeColor(selectedNode)}55` }}>
                    {selectedNode.type === 'gateway' ? <Router size={18} /> : <Server size={18} />}
                  </div>
                  <div>
                    <div className="topology-node-name">{selectedNode.label}</div>
                    <div className="topology-node-meta">{selectedNode.ip}</div>
                  </div>
                  <div className="topology-risk-row">
                    <span>Risk</span>
                    <strong style={{ color: getNodeColor(selectedNode) }}>{Math.round(selectedNode.risk_score || 0)}%</strong>
                  </div>
                </div>
              ) : (
                <div className="section-subtitle">Düğüm seçin.</div>
              )}
            </div>

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title">
                <Activity size={16} /> Öne Çıkan Akışlar
              </h4>
              <div className="topology-flow-list">
                {busiestLinks.length > 0 ? busiestLinks.map((link, index) => (
                  <div className="topology-flow-item" key={`${getEndpointId(link.source)}-${getEndpointId(link.target)}-${index}`}>
                    <div>
                      <div className="topology-flow-primary">
                        {getEndpointId(link.source)} → {getEndpointId(link.target)}
                      </div>
                      <div className="topology-flow-secondary">
                        {link.protocol} {link.dst_port ? `/${link.dst_port}` : ''} · {formatBytes(link.byte_count)}
                      </div>
                    </div>
                    <div className={link.anomaly ? 'topology-flow-score danger' : 'topology-flow-score'}>
                      {link.packet_count || 0}
                    </div>
                  </div>
                )) : (
                  <div className="section-subtitle">Canlı akış yok.</div>
                )}
              </div>
            </div>

            <div className="soft-panel topology-side-panel">
              <h4 className="topology-panel-title">
                <Shield size={16} /> Lejant
              </h4>
              <div className="topology-legend">
                <div className="topology-legend-item"><span className="legend-dot success"></span>Düşük riskli cihaz</div>
                <div className="topology-legend-item"><span className="legend-dot warning"></span>Orta riskli cihaz</div>
                <div className="topology-legend-item"><span className="legend-dot danger"></span>Yüksek riskli cihaz</div>
                <div className="topology-legend-item"><span className="legend-line active"></span>Canlı akış</div>
                <div className="topology-legend-item"><span className="legend-line danger"></span>Anomali işaretli akış</div>
              </div>
            </div>
          </aside>
        </div>
      </section>
    </div>
  )
}

export default TopologyView
