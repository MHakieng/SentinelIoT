import React, { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock3,
  Database,
  Loader2,
  Radio,
  RefreshCw,
  Router,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Zap,
} from 'lucide-react'
import axios from 'axios'
import DeviceClassBadge from '../DeviceClassBadge'
import { fetchDeviceAnalysis, peekDeviceAnalysis } from '../../lib/deviceAnalysisClient'
import { getFlowFinalRisk, isHighRiskFlow } from '../../lib/flowRisk'
import { DEVICE_ANALYSIS_VIEWS, describeLlmUiFailure } from '../../lib/llmUiContent'
import { translateRiskStatus } from '../../lib/uiText'
import SecurityEventTimeline from './SecurityEventTimeline'
import { buildSecurityTimelineEvents } from './eventTimelineUtils'

const getRiskTone = (score) => {
  const risk = Number(score || 0)
  if (risk >= 70) return 'danger'
  if (risk >= 35) return 'warning'
  return 'success'
}

const formatNumber = (value) => new Intl.NumberFormat('tr-TR').format(Number(value || 0))

const formatTime = (date) => {
  if (!date) return 'Henüz yok'
  return new Intl.DateTimeFormat('tr-TR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

const CommandCenterView = ({
  devices,
  devicesLoading,
  devicesError,
  topologyData,
  topologyLoading,
  topologyRefreshing,
  topologyError,
  topologyLastUpdated,
  liveFlows,
  livePackets,
  trafficLoading,
  trafficError,
  systemMetrics,
  metricsLoading,
  scanJobs,
  scanState,
  scanStateMeta,
  scanLoading,
  scanProgress,
  scanError,
  monitorStatus,
  monitoringActive,
  monitorActionLoading,
  monitorError,
  selectedDevice,
  selectedScanProfile = 'vulnerability',
  scanProfileOptions = [],
  onScanProfileChange,
  onSelectDevice,
  onStartScan,
  onRefreshTopology,
  onToggleMonitoring,
  apiBaseUrl,
}) => {
  const [analysis, setAnalysis] = useState(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [analysisError, setAnalysisError] = useState(null)
  const [analysisEvents, setAnalysisEvents] = useState([])
  const [selectedDeviceRiskHistory, setSelectedDeviceRiskHistory] = useState([])
  const [selectedDeviceAnomalies, setSelectedDeviceAnomalies] = useState([])
  const [selectedTimelineLoading, setSelectedTimelineLoading] = useState(false)
  const [selectedTimelineError, setSelectedTimelineError] = useState(null)

  const graphData = useMemo(() => ({
    nodes: Array.isArray(topologyData.nodes) ? topologyData.nodes : [],
    links: Array.isArray(topologyData.links) ? topologyData.links : [],
  }), [topologyData])

  const priorityDevices = useMemo(() => (
    [...devices]
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
      .slice(0, 7)
  ), [devices])

  const selected = selectedDevice || null
  const riskyDevices = devices.filter((device) => Number(device.risk_score || 0) >= 70)
  const exposedServices = devices.reduce((sum, device) => sum + (Array.isArray(device.open_ports) ? device.open_ports.length : 0), 0)
  const highRiskFlows = liveFlows.filter(isHighRiskFlow)
  const hasRuntimeLabels = Boolean(systemMetrics?.runtime_detection_metrics)
  const deviceClassCounts = devices.reduce((counts, device) => {
    const key = device.device_class || 'unclassified'
    counts[key] = (counts[key] || 0) + 1
    return counts
  }, {})

  const timeline = useMemo(() => buildSecurityTimelineEvents({
    devices,
    scanJobs,
    selectedDevice: selected,
    selectedDeviceAnomalies,
    selectedDeviceRiskHistory,
    liveFlows,
    analysisEvents,
  }), [
    analysisEvents,
    devices,
    liveFlows,
    scanJobs,
    selected,
    selectedDeviceAnomalies,
    selectedDeviceRiskHistory,
  ])


  useEffect(() => {
    if (!selected?.ip) {
      setAnalysis(null)
      setAnalysisError(null)
      setAnalysisLoading(false)
      setSelectedDeviceRiskHistory([])
      setSelectedDeviceAnomalies([])
      setSelectedTimelineError(null)
      setSelectedTimelineLoading(false)
      return
    }
    setAnalysis(peekDeviceAnalysis(selected.ip))
    setAnalysisError(null)
    setAnalysisLoading(false)
  }, [selected?.ip])

  useEffect(() => {
    if (!selected?.ip || !apiBaseUrl) {
      return undefined
    }

    let cancelled = false
    const loadSelectedTimelineContext = async () => {
      setSelectedTimelineLoading(true)
      setSelectedTimelineError(null)
      try {
        const [historyResponse, anomalyResponse] = await Promise.all([
          axios.get(`${apiBaseUrl}/devices/${selected.ip}/history`, { timeout: 5000 }),
          axios.get(`${apiBaseUrl}/devices/${selected.ip}/anomalies`, { timeout: 5000 }),
        ])
        if (cancelled) return
        setSelectedDeviceRiskHistory(Array.isArray(historyResponse.data) ? historyResponse.data : [])
        setSelectedDeviceAnomalies(Array.isArray(anomalyResponse.data) ? anomalyResponse.data : [])
      } catch {
        if (cancelled) return
        setSelectedDeviceRiskHistory([])
        setSelectedDeviceAnomalies([])
        setSelectedTimelineError('Seçili cihazın risk/anomali olayları yüklenemedi.')
      } finally {
        if (!cancelled) {
          setSelectedTimelineLoading(false)
        }
      }
    }

    loadSelectedTimelineContext()

    return () => {
      cancelled = true
    }
  }, [apiBaseUrl, selected?.ip])

  const loadAnalysis = async () => {
    if (!selected?.ip) return
    setAnalysisLoading(true)
    setAnalysisError(null)
    try {
      const data = await fetchDeviceAnalysis({ apiBaseUrl, deviceIp: selected.ip })
      setAnalysis(data)
      setAnalysisEvents((current) => [
        {
          id: `ai-analysis-${selected.ip}-${Date.now()}`,
          timestamp: new Date().toISOString(),
          device_ip: selected.ip,
          sections: Object.keys(data.sections || {}),
          cached: false,
        },
        ...current,
      ].slice(0, 8))
    } catch (err) {
      setAnalysisError(describeLlmUiFailure(err, 'Seçili cihaz için analiz yüklenemedi.'))
    } finally {
      setAnalysisLoading(false)
    }
  }

  return (
    <div className="command-center fade-in">
      <section className="command-status-bar">
        <div>
          <div className="command-kicker">Sentinel-IoT v6</div>
          <h2>Operasyon Merkezi</h2>
          <div className="table-secondary">Cihaz sınıfı, CVE kanıtları ve canlı akış skorlarıyla açıklanabilir risk önceliği.</div>
        </div>
        <div className="command-status-cluster">
          <div className={scanStateMeta[scanState].className || 'status-pill status-pill-neutral'}>
            {scanStateMeta[scanState].icon}
            {scanStateMeta[scanState].label || 'Hazır'}
          </div>
          <div className={`status-pill ${monitoringActive ? 'status-pill-success' : 'status-pill-neutral'}`}>
            <Radio size={12} />
            {monitoringActive ? 'İzleme açık' : 'İzleme kapalı'}
          </div>
          <button className="btn command-ghost-btn" type="button" onClick={onRefreshTopology} disabled={topologyRefreshing}>
            <RefreshCw size={15} className={topologyRefreshing ? 'spin' : ''} />
            Haritayı yenile
          </button>
          <label className="command-profile-select">
            <span>Tarama profili</span>
            <select value={selectedScanProfile} onChange={(event) => onScanProfileChange?.(event.target.value)} disabled={scanLoading}>
              {scanProfileOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <button className="btn btn-primary" type="button" onClick={() => onStartScan?.({ profile: selectedScanProfile })} disabled={scanLoading}>
            {scanLoading ? <Loader2 size={15} className="spin" /> : <Search size={15} />}
            {scanLoading ? `Tarama ${scanProgress}%` : 'Taramayı başlat'}
          </button>
        </div>
      </section>

      {(devicesError || scanError || monitorError) && (
        <div className="command-alert-strip">
          <AlertTriangle size={16} />
          {devicesError || scanError || monitorError}
        </div>
      )}

      <section className="command-kpi-strip">
        {[
          ['İzlenen Cihaz', devicesLoading ? '...' : formatNumber(devices.length), <Database size={18} />],
          ['Yüksek Risk', devicesLoading ? '...' : formatNumber(riskyDevices.length), <ShieldAlert size={18} />],
          ['Açık Servis', devicesLoading ? '...' : formatNumber(exposedServices), <Router size={18} />],
          ['Canlı Akış', trafficLoading ? '...' : formatNumber(liveFlows.length), <Activity size={18} />],
          ['Yüksek Riskli Akış', trafficLoading ? '...' : formatNumber(highRiskFlows.length), <Zap size={18} />],
          ['Canlı Doğrulama', metricsLoading ? '...' : (hasRuntimeLabels ? 'Etiketli veri var' : 'Metrik yok'), <BarChart3 size={18} />],
          ['IoT / Client', devicesLoading ? '...' : `${formatNumber(deviceClassCounts.iot_device || 0)} / ${formatNumber(deviceClassCounts.client_device || 0)}`, <Radio size={18} />],
          ['Infra / Unknown', devicesLoading ? '...' : `${formatNumber(deviceClassCounts.network_infrastructure || 0)} / ${formatNumber((deviceClassCounts.unknown || 0) + (deviceClassCounts.unclassified || 0))}`, <Router size={18} />],
        ].map(([label, value, icon]) => (
          <div key={label} className="command-kpi-card">
            <div className="command-kpi-icon">{icon}</div>
            <div>
              <div className="metric-label">{label}</div>
              <div className="command-kpi-value">{value}</div>
            </div>
          </div>
        ))}
      </section>

      <section className="soft-panel command-ai-positioning">
        <div className="command-kpi-icon"><Sparkles size={18} /></div>
        <div>
          <strong>AI Destekli Risk Analizi</strong>
          <p>
            SentinelIoT; cihaz sınıfı, açık portlar, CVE kanıtları ve canlı akış skorlarını birlikte değerlendirerek
            açıklanabilir risk önceliği üretir. Canlı trafikte etiketli ground-truth yoksa runtime accuracy/F1 hesaplanmaz.
          </p>
        </div>
      </section>

      <section className="command-grid">
        <div className="command-map-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Shield size={18} /> Topoloji Risk Görünümü</h3>
            </div>
            <div className="status-note">Son güncelleme: {formatTime(topologyLastUpdated)}</div>
          </div>
          <div className="command-map-canvas">
            {topologyLoading ? (
              <div className="empty-state topology-fill">
                <div className="skeleton skeleton-icon topology-loading-orb"></div>
                <div className="skeleton skeleton-text" style={{ width: '180px' }}></div>
              </div>
            ) : topologyError ? (
              <div className="empty-state topology-fill">
                <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)' }} />
                <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Topoloji yüklenemedi</div>
                <div className="empty-state-copy">{topologyError}</div>
              </div>
            ) : graphData.nodes.length === 0 ? (
              <div className="empty-state topology-fill">
                <Shield className="empty-state-icon" />
                <div className="empty-state-title">Operasyon haritası boş</div>
                <div className="empty-state-copy">Ağ taraması başlatın.</div>
              </div>
            ) : (
              <div className="command-topology-summary">
                <div className="command-gateway-summary">
                  <div className="topology-gateway-icon"><Router size={24} /></div>
                  <div>
                    <strong>Ağ Geçidi Merkezli Görünüm</strong>
                    <span>{formatNumber(devices.length)} cihaz, {formatNumber(graphData.links.length)} bağlantı</span>
                  </div>
                </div>
                <div className="command-class-summary-grid">
                  <div><DeviceClassBadge deviceClass="iot_device" compact /><strong>{formatNumber(deviceClassCounts.iot_device || 0)}</strong></div>
                  <div><DeviceClassBadge deviceClass="client_device" compact /><strong>{formatNumber(deviceClassCounts.client_device || 0)}</strong></div>
                  <div><DeviceClassBadge deviceClass="network_infrastructure" compact /><strong>{formatNumber(deviceClassCounts.network_infrastructure || 0)}</strong></div>
                  <div><DeviceClassBadge deviceClass="unknown" compact /><strong>{formatNumber((deviceClassCounts.unknown || 0) + (deviceClassCounts.unclassified || 0))}</strong></div>
                </div>
                <div className="command-top-risk-list">
                  <div className="metric-label">En riskli cihazlar</div>
                  {priorityDevices.slice(0, 3).map((device) => (
                    <button key={`map-${device.ip}`} type="button" className="command-mini-row" onClick={() => onSelectDevice(device)}>
                      <span>{device.ip}</span>
                      <b>{Math.round(device.risk_score || 0)}%</b>
                    </button>
                  ))}
                  {priorityDevices.length === 0 && <div className="status-note">Cihaz verisi yok.</div>}
                </div>
              </div>
            )}
          </div>
        </div>

        <aside className="command-priority-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><ShieldAlert size={18} /> Öncelik Kuyruğu</h3>
            </div>
          </div>
          <div className="command-device-list">
            {priorityDevices.map((device) => {
              const tone = getRiskTone(device.risk_score)
              return (
                <button
                  key={device.ip}
                  className={`command-device-row ${selected?.ip === device.ip ? 'active' : ''}`}
                  type="button"
                  onClick={() => onSelectDevice(device)}
                >
                  <span className={`command-risk-dot ${tone}`}></span>
                  <span>
                    <strong>{device.ip}</strong>
                    <DeviceClassBadge deviceClass={device.device_class} confidence={device.device_class_confidence} compact />
                    <small>{device.vendor && device.vendor !== 'Unknown' ? device.vendor : 'Bilinmeyen Üretici'}</small>
                  </span>
                  <b>{Math.round(device.risk_score || 0)}</b>
                </button>
              )
            })}
            {!devicesLoading && priorityDevices.length === 0 && (
              <div className="state-message state-message-compact">Cihaz verisi yok.</div>
            )}
          </div>
        </aside>

        <aside className="command-intel-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Sparkles size={18} /> AI Destekli Risk Analizi</h3>
            </div>
            <button className="btn command-ghost-btn" type="button" onClick={loadAnalysis} disabled={!selected || analysisLoading}>
              {analysisLoading ? <Loader2 size={14} className="spin" /> : <Sparkles size={14} />}
              Analiz
            </button>
          </div>
          {selected ? (
            <div className="command-intel-stack">
              <div className="soft-panel command-intel-summary">
                <div>
                  <div className="metric-label">Risk</div>
                  <div className={`command-large-risk ${getRiskTone(selected.risk_score)}`}>{Math.round(selected.risk_score || 0)}</div>
                </div>
                <div>
                  <div className="metric-label">Durum</div>
                  <div className="metric-value">{translateRiskStatus(selected.status)}</div>
                </div>
              </div>
              {analysisLoading ? (
                <div className="state-message state-message-compact"><Loader2 size={16} className="spin" /> Analiz yükleniyor...</div>
              ) : analysisError ? (
                <div className="state-message state-message-danger state-message-compact">{analysisError}</div>
              ) : analysis ? (
                <div className="soft-panel ai-analysis-section">
                  <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.risk_explanation.label}</div>
                  <div className="ai-analysis-copy">{analysis.sections?.risk_explanation || 'Analiz metni yok.'}</div>
                  {Array.isArray(analysis.sections?.next_actions) && analysis.sections?.next_actions.length > 0 && (
                    <>
                      <div className="metric-label" style={{ marginTop: '14px' }}>{DEVICE_ANALYSIS_VIEWS.next_actions.label}</div>
                      <ul className="ai-analysis-list">
                        {analysis.sections?.next_actions.slice(0, 3).map((item, index) => <li key={index}>{item}</li>)}
                      </ul>
                    </>
                  )}
                </div>
              ) : (
                <div className="state-message state-message-compact">Seçili cihaz için YZ analizini yükleyin.</div>
              )}
            </div>
          ) : (
            <div className="state-message state-message-compact">Haritadan veya kuyruktan bir cihaz seçin.</div>
          )}
        </aside>

        <div className="command-events-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Clock3 size={18} /> Security Event Timeline</h3>
            </div>
          </div>
          <SecurityEventTimeline
            events={timeline}
            loading={selectedTimelineLoading}
            error={selectedTimelineError}
          />
        </div>

        <div className="command-live-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Terminal size={18} /> Canlı Akış / Paket Önizleme</h3>
            </div>
            <button className="btn command-ghost-btn" type="button" onClick={onToggleMonitoring} disabled={monitorActionLoading || monitorStatus === 'stopping'}>
              {monitorActionLoading ? <Loader2 size={14} className="spin" /> : <Activity size={14} />}
              {monitoringActive ? 'Durdur' : 'Başlat'}
            </button>
          </div>
          <div className="command-live-grid">
            <div>
              <div className="metric-label">Son akışlar</div>
              <div className="command-mini-list">
                {liveFlows.slice(0, 5).map((flow) => (
                  <div key={flow.flow_id} className="command-mini-row">
                    <span>{flow.src_ip}:{flow.src_port} {'->'} {flow.dst_ip}:{flow.dst_port}</span>
                    <b>{getFlowFinalRisk(flow).toFixed(0)}%</b>
                  </div>
                ))}
                {!trafficLoading && liveFlows.length === 0 && <div className="status-note">Canlı akış yok.</div>}
              </div>
            </div>
            <div>
              <div className="metric-label">Paket önizleme</div>
              <div className="command-mini-list">
                {livePackets.slice(0, 5).map((packet, index) => (
                  <div key={`${packet.timestamp}-${index}`} className="command-mini-row">
                    <span>{packet.source_ip} {'->'} {packet.destination_ip}</span>
                    <b>{packet.protocol}</b>
                  </div>
                ))}
                {trafficError && <div className="status-note danger-text">{trafficError}</div>}
                {!trafficLoading && !trafficError && livePackets.length === 0 && <div className="status-note">Paket önizlemesi yok.</div>}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default CommandCenterView
