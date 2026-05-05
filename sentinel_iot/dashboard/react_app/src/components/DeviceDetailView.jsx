import React, { useState, useEffect, useRef } from 'react'
import {
  Loader2,
  ArrowLeft,
  Activity,
  AlertTriangle,
  TrendingUp,
  Box,
  Shield,
  Network,
  Sparkles,
  RefreshCcw
} from 'lucide-react'
import axios from 'axios'
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts'
import { fetchDeviceAnalysis, peekDeviceAnalysis } from '../lib/deviceAnalysisClient'
import { DEVICE_ANALYSIS_VIEWS, describeLlmUiFailure } from '../lib/llmUiContent'
import { translateEvidenceSource, translateRiskStatus } from '../lib/uiText'

const summarizePort = (port) => {
  if (!port) return null

  if (port.http_title) {
    return `Web başlığı: ${port.http_title}`
  }

  if (port.product || port.version || port.extrainfo) {
    return [port.product, port.version, port.extrainfo].filter(Boolean).join(' ')
  }

  if (port.server_header) {
    return `Sunucu: ${port.server_header}`
  }

  if (port.banner) {
    return port.banner
  }

  return null
}

const cveExplanationCache = new Map()

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
  const topServiceTags = openPorts.slice(0, 4).map((port, index) => ({
    key: `${port.port || index}-${index}`,
    label: `${port.port || 'Port'}${port.service ? ` ${port.service}` : ''}`
  }))

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
          axios.get(`${apiBaseUrl}/devices/${device.ip}/anomalies`)
        ])
        if (cancelled) {
          return
        }

        setHistory(Array.isArray(histRes.data) ? histRes.data : [])
        setAnomalies(Array.isArray(anomRes.data) ? anomRes.data : [])
      } catch (err) {
        console.error('Failed to fetch device history', err)
        if (!cancelled) {
          setHistory([])
          setAnomalies([])
          setError('Cihaz detayları yüklenemedi.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
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
      const data = await fetchDeviceAnalysis({
        apiBaseUrl,
        deviceIp: currentIp,
        forceRefresh
      })

      if (analysisRequestRef.current !== requestId || device.ip !== currentIp) {
        return
      }

      setAiAnalysis(data)
    } catch (err) {
      console.error('Failed to generate AI analysis', err)
      if (analysisRequestRef.current !== requestId || device.ip !== currentIp) {
        return
      }

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
        { timeout: 25000 }
      )
      cveExplanationCache.set(key, response.data)
      setCveExplanation(response.data)
    } catch (err) {
      console.error('Failed to generate CVE explanation', err)
      setCveExplanation(null)
      setCveError(describeLlmUiFailure(err, 'Bu servis için CVE açıklaması üretilemedi.'))
    } finally {
      setCveLoadingKey(null)
    }
  }

  return (
    <div className="device-detail fade-in">
      <button
        onClick={onBack}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          cursor: 'pointer',
          marginBottom: '24px',
          fontSize: '0.9rem',
          padding: '4px 0'
        }}
      >
        <ArrowLeft size={16} /> Çalışma alanına dön
      </button>

      {loading ? (
        <div className="flex-col gap-6">
          <div className="skeleton" style={{ height: '180px', width: '100%' }}></div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '24px' }}>
            <div className="flex-col gap-6">
              <div className="skeleton" style={{ height: '300px', width: '100%' }}></div>
              <div className="skeleton" style={{ height: '200px', width: '100%' }}></div>
            </div>
            <div className="skeleton" style={{ height: '500px', width: '100%' }}></div>
          </div>
        </div>
      ) : error ? (
        <div className="empty-state card">
          <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)' }} />
          <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Hata</div>
          <div className="empty-state-copy">{error}</div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '24px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="card" style={{ padding: '24px' }}>
              <div className="section-header" style={{ alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                  <div style={{ background: 'linear-gradient(135deg, var(--accent-primary), #6b8fff)', padding: '16px', borderRadius: '16px', color: 'white', boxShadow: '0 12px 20px -16px rgba(79, 124, 255, 0.9)' }}>
                    <Box size={32} />
                  </div>
                  <div>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '4px' }}>
                      {vendorLabel}
                    </h2>
                    <div style={{ display: 'flex', gap: '12px', color: 'var(--text-secondary)', fontSize: '0.875rem', flexWrap: 'wrap' }}>
                      <span>{device.ip}</span>
                      <span>&bull;</span>
                      <span>{device.mac || 'MAC bilgisi yok'}</span>
                    </div>
                    <div className="section-subtitle" style={{ marginTop: '8px' }}>
                      Cihaz görünürlüğünü, son risk değişimlerini ve izleme etkinliğini tek yerden inceleyin.
                    </div>
                  </div>
                </div>
                <div className="device-risk-hero">
                  <div className="metric-label">Mevcut risk</div>
                  <div style={{ fontSize: '2.5rem', fontWeight: '800', lineHeight: 1, color: device.risk_score > 70 ? 'var(--danger)' : 'var(--text-primary)' }}>
                    {device.risk_score}
                  </div>
                  <span className={`badge ${statusTone}`}>
                    {translateRiskStatus(device.status)}
                  </span>
                </div>
              </div>
              <div className="device-summary-grid" style={{ marginTop: '24px' }}>
                <div className="soft-panel device-summary-tile">
                  <div className="metric-label">Üretici</div>
                  <div className="metric-value">{vendorLabel}</div>
                  <div className="status-note">Envanter kimliği</div>
                </div>
                <div className="soft-panel device-summary-tile">
                  <div className="metric-label">MAC adresi</div>
                  <div className="metric-value">{device.mac || 'Yok'}</div>
                  <div className="status-note">Son kaydedilen donanım adresi</div>
                </div>
                <div className="soft-panel device-summary-tile">
                  <div className="metric-label">Açık servisler</div>
                  <div className="metric-value">{openPorts.length}</div>
                  <div className="inline-chip-list" style={{ marginTop: '10px' }}>
                    {topServiceTags.length > 0 ? topServiceTags.map((tag) => (
                      <span key={tag.key} className="neutral-chip">{tag.label}</span>
                    )) : <span className="status-note">Servis kaydı yok.</span>}
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: '24px' }}>
              <div className="section-header">
                <div>
                  <h3 style={{ fontSize: '1.1rem', margin: '0 0 6px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <TrendingUp size={18} color="var(--accent-primary)" /> Risk Geçmişi
                  </h3>
                  <div className="section-subtitle">
                    Bu cihaz için son tarama ve izleme güncellemeleri.
                  </div>
                </div>
              </div>
              <div style={{ height: '300px', minHeight: '300px', width: '100%' }}>
                {history.length === 0 ? (
                  <div className="empty-state p-0" style={{ height: '100%' }}>
                    <TrendingUp className="empty-state-icon" />
                    <div className="empty-state-copy">Bu cihaz için henüz risk geçmişi kaydedilmedi.</div>
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={history}>
                      <defs>
                        <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                      <XAxis dataKey="timestamp" hide />
                      <YAxis type="number" domain={[0, 100]} stroke="var(--text-secondary)" fontSize={12} axisLine={false} tickLine={false} />
                      <Tooltip
                        contentStyle={{ background: 'var(--panel-bg)', border: '1px solid var(--panel-border)', borderRadius: '8px' }}
                        itemStyle={{ color: 'var(--accent-primary)' }}
                      />
                      <Area type="monotone" dataKey="risk_score" stroke="var(--accent-primary)" fillOpacity={1} fill="url(#colorRisk)" strokeWidth={3} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="card" style={{ padding: '24px' }}>
              <div className="section-header">
                <div>
                  <h3 style={{ fontSize: '1.1rem', margin: '0 0 6px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Activity size={18} color="var(--warning)" /> İzleme Olayları
                  </h3>
                  <div className="section-subtitle">
                    Bu cihazın mevcut izleme sinyaline katkı yapan olaylar.
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {anomalies.length > 0 ? anomalies.map((log, i) => (
                  <div key={`${log.timestamp}-${i}`} className="event-row" style={{ borderBottom: i < anomalies.length - 1 ? '1px solid var(--panel-border)' : 'none' }}>
                    <div className="event-time">
                      {log.timestamp}
                    </div>
                    <div style={{ flexGrow: 1 }}>
                      <div style={{ fontWeight: '600', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <AlertTriangle size={14} color="var(--warning)" /> {log.type || 'İzleme olayı'}
                      </div>
                      <div className="table-secondary" style={{ marginTop: 0 }}>
                        İzleme puanı: <span style={{ color: 'var(--danger)' }}>{Number(log.score || 0).toFixed(2)}</span>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="empty-state p-0" style={{ minHeight: '120px' }}>
                    <Activity className="empty-state-icon" style={{ width: '32px', height: '32px', marginBottom: '12px' }} />
                    <div className="empty-state-copy">Bu cihaz için henüz izleme olayı kaydedilmedi.</div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="card" style={{ padding: '20px', background: 'linear-gradient(180deg, rgba(239, 68, 68, 0.08) 0%, rgba(20, 26, 36, 0.96) 100%)' }}>
              <h4 style={{ fontSize: '0.875rem', textTransform: 'uppercase', color: 'var(--danger)', letterSpacing: '1px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={14} /> Risk Dağılımı
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', marginBottom: '6px' }}>
                    <span>Servis görünürlüğü</span>
                    <span style={{ fontWeight: 600 }}>{device.risk_breakdown?.vuln || 0}</span>
                  </div>
                  <div style={{ height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                    <div style={{ width: `${Math.min(100, device.risk_breakdown?.vuln || 0)}%`, height: '100%', background: 'var(--danger)', borderRadius: '2px' }}></div>
                  </div>
                </div>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', marginBottom: '6px' }}>
                    <span>İzleme etkinliği</span>
                    <span style={{ fontWeight: 600 }}>{(device.risk_breakdown?.anomaly || 0).toFixed(2)}</span>
                  </div>
                  <div style={{ height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                    <div style={{ width: `${Math.min(100, device.risk_breakdown?.anomaly || 0)}%`, height: '100%', background: 'var(--warning)', borderRadius: '2px' }}></div>
                  </div>
                </div>
                <div className="status-note">
                  Toplam risk, taramalardaki servis görünürlüğü ile son izleme etkinliğini birleştirir.
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: '20px' }}>
              <div className="section-header" style={{ marginBottom: '14px' }}>
                <div>
                  <h4 style={{ fontSize: '0.96rem', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Sparkles size={16} color="var(--accent-primary)" /> YZ Analizi
                  </h4>
                  <div className="section-subtitle" style={{ marginTop: '6px' }}>
                    Mevcut risk puanı, servis görünürlüğü ve son izleme bağlamına dayalı ayrıntılı cihaz analizi.
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                  {onOpenAssistant && (
                    <button
                      className="btn"
                      onClick={onOpenAssistant}
                      type="button"
                      style={{
                        justifyContent: 'center',
                        minWidth: '170px',
                        background: 'rgba(255,255,255,0.04)',
                        color: 'var(--text-primary)',
                        border: '1px solid rgba(148, 163, 184, 0.12)'
                      }}
                    >
                      <Shield size={16} />
                      Güvenlik Asistanını Aç
                    </button>
                  )}
                  <button
                    className="btn btn-primary"
                    onClick={() => requestAiAnalysis(Boolean(aiAnalysis))}
                    disabled={aiLoading}
                    style={{ justifyContent: 'center', minWidth: '180px' }}
                  >
                    {aiLoading ? <Loader2 size={16} className="spin" /> : aiAnalysis ? <RefreshCcw size={16} /> : <Sparkles size={16} />}
                    {aiLoading ? 'Yükleniyor...' : aiAnalysis ? 'Analizi Yenile' : 'Analizi Yükle'}
                  </button>
                </div>
              </div>

              <div className="llm-surface-note">
                <span className="badge badge-neutral">Ayrıntılı görünüm</span>
                <span>
                  Tam cihaz analizi ve CVE odaklı takip için bu paneli kullanın. Güvenlik Asistanı aynı cihaza özel analizi daha hızlı bir yan panelde sunar.
                </span>
              </div>

              {!aiAnalysis && !aiLoading && !aiError && (
                <div className="empty-state p-0 mt-4" style={{ minHeight: '160px' }}>
                  <Sparkles className="empty-state-icon" />
                  <div className="empty-state-copy">Cihaz riskini açıklamak, son anomali bağlamını özetlemek ve sonraki adımları önermek için analizi yükleyin.</div>
                </div>
              )}

              {aiLoading && (
                <div className="flex-col gap-4 mt-4">
                  <div className="skeleton skeleton-text" style={{ height: '80px' }}></div>
                  <div className="skeleton skeleton-text" style={{ height: '60px' }}></div>
                  <div className="skeleton skeleton-text" style={{ height: '100px' }}></div>
                </div>
              )}

              {aiError && !aiLoading && (
                <div className="state-message state-message-danger state-message-compact">
                  {aiError}
                </div>
              )}

              {aiAnalysis && !aiLoading && (
                <div className="ai-analysis-stack">
                  {aiAnalysis.sections?.risk_explanation && (
                    <div className="soft-panel ai-analysis-section">
                      <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.risk_explanation.label}</div>
                      <div className="ai-analysis-copy">{aiAnalysis.sections.risk_explanation}</div>
                    </div>
                  )}

                  {aiAnalysis.sections?.anomaly_summary && (
                    <div className="soft-panel ai-analysis-section">
                      <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.anomaly_summary.label}</div>
                      <div className="ai-analysis-copy">{aiAnalysis.sections.anomaly_summary}</div>
                    </div>
                  )}

                  <div className="soft-panel ai-analysis-section">
                    <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.next_actions.label}</div>
                    {Array.isArray(aiAnalysis.sections?.next_actions) && aiAnalysis.sections.next_actions.length > 0 ? (
                      <ul className="ai-analysis-list">
                        {aiAnalysis.sections.next_actions.map((item, index) => (
                          <li key={`${device.ip}-action-${index}`}>{item}</li>
                        ))}
                      </ul>
                    ) : (
                      <div className="status-note" style={{ marginTop: '10px' }}>
                        Bu cihaz bağlamı için sonraki adım önerisi dönmedi.
                      </div>
                    )}
                  </div>

                  <div className="soft-panel ai-analysis-section">
                    <div className="metric-label">Dayanak özeti</div>
                    <div className="device-summary-grid" style={{ marginTop: '12px', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                      <div className="soft-panel device-summary-tile">
                        <div className="metric-label">Risk puanı</div>
                        <div className="metric-value">{aiAnalysis.grounding_summary?.risk_score ?? 0}</div>
                      </div>
                      <div className="soft-panel device-summary-tile">
                        <div className="metric-label">Kayıtlı CVE sayısı</div>
                        <div className="metric-value">{aiAnalysis.grounding_summary?.total_cves ?? 0}</div>
                      </div>
                      <div className="soft-panel device-summary-tile">
                        <div className="metric-label">Açık servisler</div>
                        <div className="metric-value">{aiAnalysis.grounding_summary?.open_service_count ?? 0}</div>
                      </div>
                      <div className="soft-panel device-summary-tile">
                        <div className="metric-label">Son anomali kayıtları</div>
                        <div className="metric-value">{aiAnalysis.grounding_summary?.recent_anomaly_count ?? 0}</div>
                      </div>
                    </div>
                  </div>

                  {Array.isArray(aiAnalysis.evidence_used) && aiAnalysis.evidence_used.length > 0 && (
                    <div className="soft-panel ai-analysis-section">
                      <div className="metric-label">Kullanılan kanıtlar</div>
                      <div className="ai-evidence-list">
                        {aiAnalysis.evidence_used.slice(0, 4).map((item, index) => (
                          <div key={`${device.ip}-evidence-${index}`} className="ai-evidence-item">
                            <span className="badge badge-neutral">{translateEvidenceSource(item.source)}</span>
                            <div className="status-note" style={{ marginTop: '8px' }}>{item.detail}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {(Array.isArray(aiAnalysis.warnings) && aiAnalysis.warnings.length > 0) || (Array.isArray(aiAnalysis.limitations) && aiAnalysis.limitations.length > 0) ? (
                    <div className="soft-panel ai-analysis-section">
                      <div className="metric-label">Sınırlamalar</div>
                      <ul className="ai-analysis-list" style={{ marginTop: '10px' }}>
                        {[...(aiAnalysis.warnings || []), ...(aiAnalysis.limitations || [])].map((item, index) => (
                          <li key={`${device.ip}-limitation-${index}`}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            <div className="card" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '0.875rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '1px', marginBottom: '16px' }}>Cihaz Özeti</h4>
              <div style={{ display: 'grid', gap: '14px' }}>
                <div className="soft-panel" style={{ padding: '14px 16px' }}>
                  <div className="metric-label">Üretici</div>
                  <div className="metric-value">{vendorLabel}</div>
                </div>
                <div className="soft-panel" style={{ padding: '14px 16px' }}>
                  <div className="metric-label">MAC adresi</div>
                  <div className="metric-value">{device.mac || 'Yok'}</div>
                </div>
                <div className="soft-panel" style={{ padding: '14px 16px' }}>
                  <div className="metric-label">Açık servisler</div>
                  <div className="metric-value">{openPorts.length}</div>
                  <div className="inline-chip-list" style={{ marginTop: '10px' }}>
                    {openPorts.length > 0 ? openPorts.slice(0, 6).map((p, i) => (
                      <span key={`${p.port || i}-${i}`} className="neutral-chip">
                        {p.port || p} {p.service ? `(${p.service})` : ''}
                      </span>
                    )) : <span className="status-note">Servis kaydı yok.</span>}
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '0.875rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '1px', marginBottom: '16px' }}>Servis Detayları</h4>
              {openPorts.some((port) => Array.isArray(port.cves) && port.cves.length > 0) && !selectedCveKey && !cveLoadingKey && !cveError && (
                <div className="state-message state-message-compact" style={{ minHeight: 'auto', marginBottom: '14px' }}>
                  Sade dilli açıklama ve anında sonraki adım önerisi üretmek için aşağıdan bir CVE seçin.
                </div>
              )}
              {openPorts.length > 0 ? (
                <div className="port-meta-list">
                  {openPorts.slice(0, 4).map((port, index) => {
                    const summary = summarizePort(port)
                    const tlsSummary = port.tls?.issuer || port.tls?.subject || null
                    const cves = Array.isArray(port.cves) ? port.cves : []

                    return (
                      <div key={`${port.port || index}-summary`} className="port-meta-item">
                        <div className="port-meta-label">
                          <Network size={12} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                          {port.port || 'Port'} {port.service ? `(${port.service})` : ''}
                        </div>
                        <div className="port-meta-value">
                          {summary || 'Ayrıntılı servis parmak izi bulunmuyor.'}
                        </div>
                        {tlsSummary && (
                          <div style={{ marginTop: '4px', fontSize: '0.72rem', color: '#c4b5fd' }}>
                            TLS: {tlsSummary}
                          </div>
                        )}
                        {cves.length > 0 && (
                          <div className="cve-inline-block">
                            <div className="metric-label" style={{ marginBottom: '10px' }}>Bilinen CVE'ler</div>
                            <div className="cve-inline-list">
                              {cves.map((cve) => {
                                const cveKey = `${device.ip}:${port.port || 'na'}:${cve}`
                                const isActive = selectedCveKey === cveKey
                                const isLoading = cveLoadingKey === cveKey

                                return (
                                  <div key={cveKey} className="cve-inline-item">
                                    <span className="badge badge-danger">{cve}</span>
                                    <button
                                      className="btn"
                                      onClick={() => requestCveExplanation(cve, port, isActive && Boolean(cveExplanation))}
                                      disabled={Boolean(cveLoadingKey) && !isLoading}
                                      style={{
                                        padding: '8px 12px',
                                        minHeight: '36px',
                                        background: isActive ? 'rgba(79, 124, 255, 0.1)' : 'rgba(255,255,255,0.04)',
                                        color: 'var(--text-primary)',
                                        border: '1px solid rgba(148, 163, 184, 0.12)'
                                      }}
                                    >
                                      {isLoading ? <Loader2 size={14} className="spin" /> : isActive && cveExplanation ? <RefreshCcw size={14} /> : <Sparkles size={14} />}
                                      {isLoading ? 'Açıklanıyor...' : isActive && cveExplanation ? 'Yenile' : 'Açıkla'}
                                    </button>
                                  </div>
                                )
                              })}
                            </div>

                            {selectedCveKey && cves.some((cve) => selectedCveKey === `${device.ip}:${port.port || 'na'}:${cve}`) && (
                              <div className="cve-explanation-panel">
                                {cveLoadingKey === selectedCveKey && (
                                  <div className="state-message state-message-compact" style={{ minHeight: 'auto' }}>
                                    <Loader2 size={16} className="spin" style={{ marginRight: '8px' }} />
                                    CVE açıklaması üretiliyor...
                                  </div>
                                )}

                                {cveError && cveLoadingKey !== selectedCveKey && (
                                  <div className="state-message state-message-danger state-message-compact" style={{ minHeight: 'auto' }}>
                                    {cveError}
                                  </div>
                                )}

                                {cveExplanation && cveLoadingKey !== selectedCveKey && selectedCveMeta?.cveId && (
                                  <div className="soft-panel ai-analysis-section" style={{ marginTop: 0 }}>
                                    <div className="section-header" style={{ marginBottom: '12px' }}>
                                      <div>
                                        <div className="metric-label">YZ CVE Açıklaması</div>
                                        <div className="table-primary" style={{ marginTop: '6px' }}>
                                          {cveExplanation.title || selectedCveMeta.cveId}
                                        </div>
                                      </div>
                                      <span className="badge badge-warning">{selectedCveMeta.cveId}</span>
                                    </div>

                                    <div className="ai-analysis-copy" style={{ marginTop: 0 }}>
                                      {cveExplanation.plain_language_summary}
                                    </div>

                                    <div className="metric-label" style={{ marginTop: '14px' }}>Bu cihaz için neden önemli?</div>
                                    <div className="ai-analysis-copy">{cveExplanation.why_it_matters_for_this_device}</div>

                                    <div className="metric-label" style={{ marginTop: '14px' }}>Önerilen adımlar</div>
                                    <ul className="ai-analysis-list" style={{ marginTop: '8px' }}>
                                      {(cveExplanation.recommended_actions || []).map((item, itemIndex) => (
                                        <li key={`${selectedCveMeta.cveId}-action-${itemIndex}`}>{item}</li>
                                      ))}
                                    </ul>

                                    <div className="device-summary-grid" style={{ marginTop: '14px', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                                      <div className="soft-panel device-summary-tile">
                                        <div className="metric-label">Servis</div>
                                        <div className="metric-value">{cveExplanation.grounding_summary?.service || 'Bilinmiyor'}</div>
                                      </div>
                                      <div className="soft-panel device-summary-tile">
                                        <div className="metric-label">Port</div>
                                        <div className="metric-value">{cveExplanation.grounding_summary?.port ?? 'Yok'}</div>
                                      </div>
                                      <div className="soft-panel device-summary-tile">
                                        <div className="metric-label">CVSS</div>
                                        <div className="metric-value">{cveExplanation.grounding_summary?.cvss_score ?? 'Not available'}</div>
                                      </div>
                                      <div className="soft-panel device-summary-tile">
                                        <div className="metric-label">Servis parmak izi</div>
                                        <div className="metric-value">
                                          {[cveExplanation.grounding_summary?.service_product, cveExplanation.grounding_summary?.service_version].filter(Boolean).join(' ') || 'Sınırlı bağlam'}
                                        </div>
                                      </div>
                                    </div>

                                    {cveExplanation.grounding_summary?.local_description && (
                                      <div style={{ marginTop: '14px' }}>
                                        <div className="metric-label">Kayıtlı zafiyet bağlamı</div>
                                        <div className="ai-analysis-copy">{cveExplanation.grounding_summary.local_description}</div>
                                      </div>
                                    )}

                                    {Array.isArray(cveExplanation.evidence_used) && cveExplanation.evidence_used.length > 0 && (
                                      <div className="ai-evidence-list" style={{ marginTop: '14px' }}>
                                        {cveExplanation.evidence_used.slice(0, 3).map((item, evidenceIndex) => (
                                          <div key={`${selectedCveMeta.cveId}-evidence-${evidenceIndex}`} className="ai-evidence-item">
                                            <span className="badge badge-neutral">{translateEvidenceSource(item.source)}</span>
                                            <div className="status-note" style={{ marginTop: '8px' }}>{item.detail}</div>
                                          </div>
                                        ))}
                                      </div>
                                    )}

                                    {Array.isArray(cveExplanation.limitations) && cveExplanation.limitations.length > 0 && (
                                      <ul className="ai-analysis-list" style={{ marginTop: '12px' }}>
                                        {cveExplanation.limitations.map((item, limitationIndex) => (
                                          <li key={`${selectedCveMeta.cveId}-limitation-${limitationIndex}`}>{item}</li>
                                        ))}
                                      </ul>
                                    )}
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
                <div className="state-message" style={{ minHeight: 'auto', padding: '20px' }}>
                  Bu cihaz için henüz servis detayı bulunmuyor.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DeviceDetailView
