import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Box,
  Cpu,
  Fingerprint,
  Loader2,
  Network,
  RefreshCcw,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from 'lucide-react'
import axios from 'axios'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { fetchDeviceAnalysis, peekDeviceAnalysis } from '../lib/deviceAnalysisClient'
import { DEVICE_ANALYSIS_VIEWS, describeLlmUiFailure } from '../lib/llmUiContent'
import { translateEvidenceSource, translateRiskStatus } from '../lib/uiText'

const cveExplanationCache = new Map()

const summarizePort = (port) => {
  if (!port) return null
  if (port.http_title) return `Web title: ${port.http_title}`
  if (port.product || port.version || port.extrainfo) {
    return [port.product, port.version, port.extrainfo].filter(Boolean).join(' ')
  }
  if (port.server_header) return `Server: ${port.server_header}`
  if (port.banner) return port.banner
  return null
}

const getRiskTone = (score) => {
  const risk = Number(score || 0)
  if (risk >= 70) return 'danger'
  if (risk >= 35) return 'warning'
  return 'success'
}

const formatScore = (value) => Number(value || 0).toFixed(1)

const getPortLabel = (port, fallback = 'Port') => (
  `${port?.port || fallback}${port?.service ? ` ${port.service}` : ''}`
)

const getLatestRiskDelta = (history) => {
  if (!Array.isArray(history) || history.length < 2) return null
  const latest = Number(history[history.length - 1]?.risk_score || 0)
  const previous = Number(history[history.length - 2]?.risk_score || 0)
  return latest - previous
}

const DeviceDetailView = ({ device, onBack, onOpenAssistant, apiBaseUrl }) => {
  const [history, setHistory] = useState([])
  const [anomalies, setAnomalies] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [selectedCveKey, setSelectedCveKey] = useState(null)
  const [selectedCveMeta, setSelectedCveMeta] = useState(null)
  const [cveExplanation, setCveExplanation] = useState(null)
  const [cveLoadingKey, setCveLoadingKey] = useState(null)
  const [cveError, setCveError] = useState(null)
  const analysisRequestRef = useRef(0)

  const openPorts = Array.isArray(device?.open_ports) ? device.open_ports : []
  const vendorLabel = device.vendor && device.vendor !== 'Unknown' ? device.vendor : 'Tanımlanamayan cihaz'
  const statusTone = device.status === 'High Risk' ? 'badge-danger' : device.status === 'Medium Risk' ? 'badge-warning' : 'badge-success'
  const riskTone = getRiskTone(device.risk_score)
  const cvePorts = openPorts.filter((port) => Array.isArray(port.cves) && port.cves.length > 0)
  const totalCves = Number(device.total_cves || cvePorts.reduce((sum, port) => sum + (port.cves || []).length, 0))
  const latestRiskDelta = getLatestRiskDelta(history)

  const topEvidence = useMemo(() => {
    if (Array.isArray(aiAnalysis?.evidence_used) && aiAnalysis.evidence_used.length > 0) {
      return aiAnalysis.evidence_used.slice(0, 3).map((item, index) => ({
        key: `ai-${index}`,
        source: translateEvidenceSource(item.source),
        detail: item.detail,
      }))
    }

    const evidence = []
    if (cvePorts.length > 0) {
      const first = cvePorts[0]
      evidence.push({
        key: 'cve',
        source: 'devices',
        detail: `${device.ip}:${first.port || 'port'} üzerinde ${(first.cves || []).length} CVE kaydı var.`,
      })
    }
    if (anomalies.length > 0) {
      evidence.push({
        key: 'anomaly',
        source: 'anomaly_logs',
        detail: `Son izleme olayı ${anomalies[0].type || 'event'} skoru ${formatScore(anomalies[0].score)}.`,
      })
    }
    if (history.length > 0) {
      evidence.push({
        key: 'history',
        source: 'risk_history',
        detail: `Son risk kaydı ${history[history.length - 1].timestamp}.`,
      })
    }
    return evidence.slice(0, 3)
  }, [aiAnalysis, anomalies, cvePorts, device.ip, history])

  useEffect(() => {
    analysisRequestRef.current += 1
    const cached = peekDeviceAnalysis(device.ip)
    setAiAnalysis(cached)
    setAiError(null)
    setAiLoading(false)
    setSelectedCveKey(null)
    setSelectedCveMeta(null)
    setCveExplanation(null)
    setCveLoadingKey(null)
    setCveError(null)
  }, [device.ip])

  useEffect(() => {
    let cancelled = false

    const fetchHistory = async () => {
      setLoading(true)
      setError(null)
      try {
        const [histRes, anomRes] = await Promise.all([
          axios.get(`${apiBaseUrl}/devices/${device.ip}/history`),
          axios.get(`${apiBaseUrl}/devices/${device.ip}/anomalies`),
        ])
        if (cancelled) return

        setHistory(Array.isArray(histRes.data) ? histRes.data : [])
        setAnomalies(Array.isArray(anomRes.data) ? anomRes.data : [])
      } catch {
        if (!cancelled) {
          setHistory([])
          setAnomalies([])
          setError('Cihaz inceleme verileri yüklenemedi.')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchHistory()

    return () => {
      cancelled = true
    }
  }, [apiBaseUrl, device.ip])

  const requestAiAnalysis = async (forceRefresh = false) => {
    const currentIp = device.ip
    const requestId = analysisRequestRef.current + 1
    analysisRequestRef.current = requestId

    if (!forceRefresh) {
      const cached = peekDeviceAnalysis(currentIp)
      if (cached) {
        setAiAnalysis(cached)
        setAiError(null)
        return
      }
    }

    setAiLoading(true)
    setAiError(null)
    try {
      const data = await fetchDeviceAnalysis({ apiBaseUrl, deviceIp: currentIp, forceRefresh })
      if (analysisRequestRef.current !== requestId || device.ip !== currentIp) return
      setAiAnalysis(data)
    } catch (err) {
      if (analysisRequestRef.current !== requestId || device.ip !== currentIp) return
      setAiError(describeLlmUiFailure(err, 'Bu cihaz için YZ analizi üretilemedi.'))
    } finally {
      if (analysisRequestRef.current === requestId && device.ip === currentIp) {
        setAiLoading(false)
      }
    }
  }

  const requestCveExplanation = async (cveId, portInfo, forceRefresh = false) => {
    const key = `${device.ip}:${portInfo.port || 'na'}:${cveId}`
    setSelectedCveKey(key)
    setSelectedCveMeta({
      cveId,
      port: portInfo.port || null,
      service: portInfo.service || null,
    })

    if (!forceRefresh) {
      const cached = cveExplanationCache.get(key)
      if (cached) {
        setCveExplanation(cached)
        setCveError(null)
        return
      }
    }

    setCveLoadingKey(key)
    setCveError(null)
    try {
      const response = await axios.post(
        `${apiBaseUrl}/llm/cve-explanation`,
        {
          device_ip: device.ip,
          cve_id: cveId,
          port: portInfo.port || undefined,
          service: portInfo.service || undefined,
        },
        { timeout: 25000 },
      )
      cveExplanationCache.set(key, response.data)
      setCveExplanation(response.data)
    } catch (err) {
      setCveExplanation(null)
      setCveError(describeLlmUiFailure(err, 'Bu servis için CVE açıklaması üretilemedi.'))
    } finally {
      setCveLoadingKey(null)
    }
  }

  if (loading) {
    return (
      <div className="device-detail device-detail-workspace fade-in">
        <div className="skeleton device-detail-loading-hero"></div>
        <div className="device-detail-grid">
          <div className="device-detail-main">
            <div className="skeleton device-detail-loading-panel"></div>
            <div className="skeleton device-detail-loading-panel"></div>
          </div>
          <div className="device-detail-side">
            <div className="skeleton device-detail-loading-side"></div>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="device-detail fade-in">
        <button className="device-back-btn" onClick={onBack} type="button">
          <ArrowLeft size={16} /> Çalışma alanına dön
        </button>
        <div className="empty-state card">
          <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)' }} />
          <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Cihaz verisi yüklenemedi</div>
          <div className="empty-state-copy">{error}</div>
        </div>
      </div>
    )
  }

  return (
    <div className="device-detail device-detail-workspace fade-in">
      <button className="device-back-btn" onClick={onBack} type="button">
        <ArrowLeft size={16} /> Command Center'a dön
      </button>

      <section className="device-risk-summary">
        <div className="device-risk-identity">
          <div className="device-risk-mark">
            <Box size={30} />
          </div>
          <div>
            <div className="command-kicker">Device Risk Summary</div>
            <h2>{device.ip}</h2>
            <div className="device-identity-meta">
              <span><Fingerprint size={14} /> {device.mac || 'MAC yok'}</span>
              <span><Cpu size={14} /> {vendorLabel}</span>
              <span className={`badge ${statusTone}`}>{translateRiskStatus(device.status)}</span>
            </div>
          </div>
        </div>
        <div className="device-risk-score-block">
          <div className="metric-label">Risk score</div>
          <div className={`device-risk-score ${riskTone}`}>{Math.round(Number(device.risk_score || 0))}</div>
          <div className="status-note">
            {latestRiskDelta === null ? 'Risk geçmişi kıyas noktası yok' : `Son değişim ${latestRiskDelta >= 0 ? '+' : ''}${latestRiskDelta.toFixed(1)}`}
          </div>
        </div>
        <div className="device-risk-kpis">
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Total CVE</div>
            <div className="metric-value">{totalCves}</div>
          </div>
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Open ports</div>
            <div className="metric-value">{openPorts.length}</div>
          </div>
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Anomaly records</div>
            <div className="metric-value">{anomalies.length}</div>
          </div>
        </div>
      </section>

      <div className="device-detail-grid">
        <main className="device-detail-main">
          <section className="card device-why-panel">
            <div className="section-header">
              <div>
                <h3 className="command-section-title"><ShieldAlert size={18} /> Why is this device risky?</h3>
                <div className="section-subtitle">Risk engine bileşenleri ve en yakın kanıtlar.</div>
              </div>
            </div>
            <div className="device-risk-components">
              <div className="risk-component-row">
                <div>
                  <div className="metric-label">Vulnerability component</div>
                  <strong>{formatScore(device.risk_breakdown?.vuln)}</strong>
                </div>
                <div className="risk-component-bar">
                  <span style={{ width: `${Math.min(100, Number(device.risk_breakdown?.vuln || 0))}%` }}></span>
                </div>
              </div>
              <div className="risk-component-row anomaly">
                <div>
                  <div className="metric-label">Anomaly component</div>
                  <strong>{formatScore(device.risk_breakdown?.anomaly)}</strong>
                </div>
                <div className="risk-component-bar">
                  <span style={{ width: `${Math.min(100, Number(device.risk_breakdown?.anomaly || 0))}%` }}></span>
                </div>
              </div>
            </div>
            <div className="device-evidence-grid">
              <div className="soft-panel device-evidence-block">
                <div className="metric-label">Open services</div>
                <div className="inline-chip-list">
                  {openPorts.length > 0 ? openPorts.slice(0, 8).map((port, index) => (
                    <span key={`${port.port || index}-${index}`} className="neutral-chip">{getPortLabel(port)}</span>
                  )) : <span className="status-note">Servis kaydı yok.</span>}
                </div>
              </div>
              <div className="soft-panel device-evidence-block">
                <div className="metric-label">Most relevant evidence</div>
                <div className="device-evidence-list">
                  {topEvidence.length > 0 ? topEvidence.map((item) => (
                    <div key={item.key} className="ai-evidence-item">
                      <span className="badge badge-neutral">{item.source}</span>
                      <div className="status-note">{item.detail}</div>
                    </div>
                  )) : <div className="status-note">Henüz kanıt kaydı yok.</div>}
                </div>
              </div>
            </div>
          </section>

          <section className="card device-chart-panel">
            <div className="section-header">
              <div>
                <h3 className="command-section-title"><TrendingUp size={18} /> Risk History</h3>
                <div className="section-subtitle">/devices/{'{ip}'}/history kaynağından gelen risk değişimi.</div>
              </div>
              <span className="badge badge-neutral">{history.length} kayıt</span>
            </div>
            <div className="device-risk-chart">
              {history.length === 0 ? (
                <div className="empty-state p-0">
                  <TrendingUp className="empty-state-icon" />
                  <div className="empty-state-copy">Bu cihaz için henüz risk geçmişi kaydedilmedi.</div>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={history} margin={{ top: 10, right: 18, left: -8, bottom: 0 }}>
                    <defs>
                      <linearGradient id="deviceRiskGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-secondary)" stopOpacity={0.28} />
                        <stop offset="95%" stopColor="var(--accent-secondary)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.12)" vertical={false} />
                    <XAxis dataKey="timestamp" stroke="var(--text-tertiary)" fontSize={11} tickLine={false} minTickGap={24} />
                    <YAxis type="number" domain={[0, 100]} stroke="var(--text-secondary)" fontSize={12} axisLine={false} tickLine={false} />
                    <Tooltip
                      contentStyle={{ background: '#0b1018', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px' }}
                      labelStyle={{ color: 'var(--text-secondary)' }}
                      itemStyle={{ color: 'var(--accent-secondary)' }}
                    />
                    <Area type="monotone" dataKey="risk_score" stroke="var(--accent-secondary)" fillOpacity={1} fill="url(#deviceRiskGradient)" strokeWidth={3} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </section>

          <section className="card device-events-panel">
            <div className="section-header">
              <div>
                <h3 className="command-section-title"><Activity size={18} /> Anomaly Records</h3>
                <div className="section-subtitle">/devices/{'{ip}'}/anomalies kaynağından gelen izleme kanıtları.</div>
              </div>
            </div>
            <div className="device-event-timeline">
              {anomalies.length > 0 ? anomalies.map((log, index) => (
                <article key={`${log.timestamp}-${index}`} className={`command-timeline-item ${Number(log.score || 0) >= 70 ? 'critical' : 'medium'}`}>
                  <div className="command-timeline-icon"><AlertTriangle size={15} /></div>
                  <div className="command-timeline-body">
                    <div className="command-timeline-head">
                      <strong>{log.type || 'İzleme olayı'}</strong>
                      <span className={`event-severity ${Number(log.score || 0) >= 70 ? 'event-severity-critical' : 'event-severity-medium'}`}>
                        {formatScore(log.score)}
                      </span>
                    </div>
                    <p>Bu cihaz için monitor kaynaklı anomali kaydı.</p>
                    <div className="command-timeline-meta">
                      <span>{log.timestamp || 'zaman yok'}</span>
                      <span>source: anomaly_logs</span>
                    </div>
                  </div>
                </article>
              )) : (
                <div className="empty-state command-timeline-empty">
                  <Activity className="empty-state-icon" />
                  <div className="empty-state-title">Anomali kaydı yok</div>
                  <div className="empty-state-copy">Bu cihaz için henüz izleme olayı kaydedilmedi.</div>
                </div>
              )}
            </div>
          </section>
        </main>

        <aside className="device-detail-side">
          <section className="card analyst-insight-panel">
            <div className="section-header">
              <div>
                <h3 className="command-section-title"><Sparkles size={18} /> Analyst Insight</h3>
                <div className="section-subtitle">Mevcut LLM device analysis akışı.</div>
              </div>
            </div>
            <div className="device-action-row">
              {onOpenAssistant && (
                <button className="btn command-ghost-btn" onClick={onOpenAssistant} type="button">
                  <Shield size={15} /> Asistan
                </button>
              )}
              <button className="btn btn-primary" onClick={() => requestAiAnalysis(Boolean(aiAnalysis))} disabled={aiLoading} type="button">
                {aiLoading ? <Loader2 size={15} className="spin" /> : aiAnalysis ? <RefreshCcw size={15} /> : <Sparkles size={15} />}
                {aiLoading ? 'Analiz...' : aiAnalysis ? 'Yenile' : 'Analiz'}
              </button>
            </div>

            {!aiAnalysis && !aiLoading && !aiError && (
              <div className="empty-state command-timeline-empty">
                <Sparkles className="empty-state-icon" />
                <div className="empty-state-copy">Risk açıklaması ve sonraki adımlar için analizi yükleyin.</div>
              </div>
            )}
            {aiLoading && (
              <div className="device-insight-loading">
                <div className="skeleton skeleton-text"></div>
                <div className="skeleton skeleton-text"></div>
                <div className="skeleton skeleton-text"></div>
              </div>
            )}
            {aiError && !aiLoading && <div className="state-message state-message-danger state-message-compact">{aiError}</div>}
            {aiAnalysis && !aiLoading && (
              <div className="ai-analysis-stack">
                {aiAnalysis.sections?.risk_explanation && (
                  <div className="soft-panel ai-analysis-section analyst-note">
                    <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.risk_explanation.label}</div>
                    <div className="ai-analysis-copy">{aiAnalysis.sections.risk_explanation}</div>
                  </div>
                )}
                {aiAnalysis.sections?.anomaly_summary && (
                  <div className="soft-panel ai-analysis-section analyst-note">
                    <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.anomaly_summary.label}</div>
                    <div className="ai-analysis-copy">{aiAnalysis.sections.anomaly_summary}</div>
                  </div>
                )}
                <div className="soft-panel ai-analysis-section analyst-note">
                  <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.next_actions.label}</div>
                  {Array.isArray(aiAnalysis.sections?.next_actions) && aiAnalysis.sections.next_actions.length > 0 ? (
                    <ul className="ai-analysis-list">
                      {aiAnalysis.sections.next_actions.map((item, index) => (
                        <li key={`${device.ip}-action-${index}`}>{item}</li>
                      ))}
                    </ul>
                  ) : <div className="status-note">Bu cihaz bağlamı için sonraki adım önerisi dönmedi.</div>}
                </div>
                <div className="analyst-grounding-grid">
                  <div className="soft-panel device-summary-tile">
                    <div className="metric-label">Risk</div>
                    <div className="metric-value">{aiAnalysis.grounding_summary?.risk_score ?? 0}</div>
                  </div>
                  <div className="soft-panel device-summary-tile">
                    <div className="metric-label">CVE</div>
                    <div className="metric-value">{aiAnalysis.grounding_summary?.total_cves ?? 0}</div>
                  </div>
                  <div className="soft-panel device-summary-tile">
                    <div className="metric-label">Services</div>
                    <div className="metric-value">{aiAnalysis.grounding_summary?.open_service_count ?? 0}</div>
                  </div>
                  <div className="soft-panel device-summary-tile">
                    <div className="metric-label">Anomalies</div>
                    <div className="metric-value">{aiAnalysis.grounding_summary?.recent_anomaly_count ?? 0}</div>
                  </div>
                </div>
              </div>
            )}
          </section>

          <section className="card service-evidence-panel">
            <div className="section-header">
              <div>
                <h3 className="command-section-title"><Server size={18} /> Technical Evidence</h3>
                <div className="section-subtitle">Servis ve CVE odaklı kanıt alanı.</div>
              </div>
            </div>
            {openPorts.length > 0 ? (
              <div className="port-meta-list compact">
                {openPorts.slice(0, 6).map((port, index) => {
                  const summary = summarizePort(port)
                  const tlsSummary = port.tls?.issuer || port.tls?.subject || null
                  const cves = Array.isArray(port.cves) ? port.cves : []

                  return (
                    <div key={`${port.port || index}-summary`} className="port-meta-item evidence-port-item">
                      <div className="port-meta-label">
                        <Network size={12} /> {getPortLabel(port)}
                      </div>
                      <div className="port-meta-value">{summary || 'Servis parmak izi sınırlı.'}</div>
                      {tlsSummary && <div className="status-note">TLS: {tlsSummary}</div>}
                      {cves.length > 0 && (
                        <div className="cve-inline-block compact">
                          <div className="cve-inline-list">
                            {cves.map((cve) => {
                              const cveKey = `${device.ip}:${port.port || 'na'}:${cve}`
                              const isActive = selectedCveKey === cveKey
                              const isLoading = cveLoadingKey === cveKey

                              return (
                                <div key={cveKey} className="cve-inline-item">
                                  <span className="badge badge-danger">{cve}</span>
                                  <button
                                    className="btn command-ghost-btn cve-explain-btn"
                                    onClick={() => requestCveExplanation(cve, port, isActive && Boolean(cveExplanation))}
                                    disabled={Boolean(cveLoadingKey) && !isLoading}
                                    type="button"
                                  >
                                    {isLoading ? <Loader2 size={14} className="spin" /> : isActive && cveExplanation ? <RefreshCcw size={14} /> : <Sparkles size={14} />}
                                    {isLoading ? 'Açıklanıyor' : isActive && cveExplanation ? 'Yenile' : 'Açıkla'}
                                  </button>
                                </div>
                              )
                            })}
                          </div>

                          {selectedCveKey && cves.some((cve) => selectedCveKey === `${device.ip}:${port.port || 'na'}:${cve}`) && (
                            <div className="cve-explanation-panel compact">
                              {cveLoadingKey === selectedCveKey && (
                                <div className="state-message state-message-compact">
                                  <Loader2 size={16} className="spin" /> CVE açıklaması üretiliyor...
                                </div>
                              )}
                              {cveError && cveLoadingKey !== selectedCveKey && (
                                <div className="state-message state-message-danger state-message-compact">{cveError}</div>
                              )}
                              {cveExplanation && cveLoadingKey !== selectedCveKey && selectedCveMeta?.cveId && (
                                <div className="soft-panel ai-analysis-section cve-brief">
                                  <div className="section-header">
                                    <div>
                                      <div className="metric-label">CVE explanation</div>
                                      <div className="table-primary">{cveExplanation.title || selectedCveMeta.cveId}</div>
                                    </div>
                                    <span className="badge badge-warning">{selectedCveMeta.cveId}</span>
                                  </div>
                                  <div className="ai-analysis-copy">{cveExplanation.plain_language_summary}</div>
                                  <div className="metric-label">Why it matters</div>
                                  <div className="ai-analysis-copy">{cveExplanation.why_it_matters_for_this_device}</div>
                                  {Array.isArray(cveExplanation.recommended_actions) && cveExplanation.recommended_actions.length > 0 && (
                                    <>
                                      <div className="metric-label">Actions</div>
                                      <ul className="ai-analysis-list">
                                        {cveExplanation.recommended_actions.slice(0, 3).map((item, itemIndex) => (
                                          <li key={`${selectedCveMeta.cveId}-action-${itemIndex}`}>{item}</li>
                                        ))}
                                      </ul>
                                    </>
                                  )}
                                  <div className="analyst-grounding-grid">
                                    <div className="soft-panel device-summary-tile">
                                      <div className="metric-label">Service</div>
                                      <div className="metric-value">{cveExplanation.grounding_summary?.service || 'Bilinmiyor'}</div>
                                    </div>
                                    <div className="soft-panel device-summary-tile">
                                      <div className="metric-label">Port</div>
                                      <div className="metric-value">{cveExplanation.grounding_summary?.port ?? 'Yok'}</div>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="state-message state-message-compact">Bu cihaz için servis detayı bulunmuyor.</div>
            )}
          </section>
        </aside>
      </div>
    </div>
  )
}

export default DeviceDetailView
