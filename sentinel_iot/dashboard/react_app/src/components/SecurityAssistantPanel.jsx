import React, { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Loader2, RefreshCcw, Shield, Sparkles, X } from 'lucide-react'
import { fetchDeviceAnalysis, peekDeviceAnalysis } from '../lib/deviceAnalysisClient'
import { DEVICE_ANALYSIS_VIEWS, describeLlmUiFailure } from '../lib/llmUiContent'
import { translateRiskStatus } from '../lib/uiText'

const SecurityAssistantPanel = ({ isOpen, onClose, device, apiBaseUrl }) => {
  const [activeView, setActiveView] = useState('risk_explanation')
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const requestRef = useRef(0)

  useEffect(() => {
    if (!device?.ip) {
      requestRef.current += 1
      setAnalysis(null)
      setError(null)
      setLoading(false)
      return
    }

    requestRef.current += 1
    const cached = peekDeviceAnalysis(device.ip)
    setAnalysis(cached)
    setError(null)
    setLoading(false)
    setActiveView('risk_explanation')
  }, [device?.ip])

  const loadAnalysis = async (forceRefresh = false) => {
    if (!device?.ip) {
      return
    }

    const currentIp = device.ip
    const requestId = requestRef.current + 1
    requestRef.current = requestId

    if (!forceRefresh) {
      const cached = peekDeviceAnalysis(currentIp)
      if (cached) {
        setAnalysis(cached)
        setError(null)
        return
      }
    }

    setLoading(true)
    setError(null)
    try {
      const data = await fetchDeviceAnalysis({
        apiBaseUrl,
        deviceIp: currentIp,
        forceRefresh
      })

      if (requestRef.current !== requestId || device.ip !== currentIp) {
        return
      }

      setAnalysis(data)
    } catch (err) {
      console.error('Failed to generate global assistant analysis', err)
      if (requestRef.current !== requestId || device.ip !== currentIp) {
        return
      }

      setError(describeLlmUiFailure(err, 'Güvenlik Asistanı bu cihaz için analiz yükleyemedi.'))
    } finally {
      if (requestRef.current === requestId && device.ip === currentIp) {
        setLoading(false)
      }
    }
  }

  const renderBody = () => {
    if (!device) {
      return (
        <div className="state-message assistant-panel-empty">
          Güvenlik Asistanını kullanmak için önce Envanter veya Topoloji görünümünden bir cihaz seçin. Bu panel şu anda yalnızca cihaza özel analizi destekler.
        </div>
      )
    }

    if (loading) {
      return (
        <div className="state-message state-message-compact assistant-panel-state">
          <Loader2 size={16} className="spin" style={{ marginRight: '8px' }} />
          Seçili güvenlik eylemi için cihaz analizi yükleniyor...
        </div>
      )
    }

    if (error) {
      return (
        <div className="state-message state-message-danger state-message-compact assistant-panel-state">
          {error}
        </div>
      )
    }

    if (!analysis) {
      return (
        <div className="state-message state-message-compact assistant-panel-state">
          {DEVICE_ANALYSIS_VIEWS[activeView].empty}
        </div>
      )
    }

    return (
      <div className="ai-analysis-stack">
        {activeView !== 'next_actions' ? (
          <div className="soft-panel ai-analysis-section">
            <div className="metric-label">{DEVICE_ANALYSIS_VIEWS[activeView].label}</div>
            <div className="ai-analysis-copy">
              {analysis.sections?.[activeView] || 'Bu bölüm için analiz metni bulunmuyor.'}
            </div>
          </div>
        ) : (
          <div className="soft-panel ai-analysis-section">
            <div className="metric-label">{DEVICE_ANALYSIS_VIEWS.next_actions.label}</div>
            {Array.isArray(analysis.sections?.next_actions) && analysis.sections.next_actions.length > 0 ? (
              <ul className="ai-analysis-list">
                {analysis.sections.next_actions.map((item, index) => (
                  <li key={`${device.ip}-assistant-action-${index}`}>{item}</li>
                ))}
              </ul>
            ) : (
              <div className="status-note" style={{ marginTop: '10px' }}>
                Bu cihaz bağlamı için önerilen adım dönmedi.
              </div>
            )}
          </div>
        )}

        {analysis.grounding_summary && (
          <div className="soft-panel ai-analysis-section">
            <div className="metric-label">Dayanak özeti</div>
            <div className="assistant-grounding-grid">
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Risk puanı</div>
                <div className="metric-value">{analysis.grounding_summary.risk_score ?? 0}</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Durum</div>
                <div className="metric-value">{translateRiskStatus(analysis.grounding_summary.status)}</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Son anomaliler</div>
                <div className="metric-value">{analysis.grounding_summary.recent_anomaly_count ?? 0}</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Açık servisler</div>
                <div className="metric-value">{analysis.grounding_summary.open_service_count ?? 0}</div>
              </div>
            </div>
          </div>
        )}

        {((analysis.warnings || []).length > 0 || (analysis.limitations || []).length > 0) && (
          <div className="soft-panel ai-analysis-section">
            <div className="metric-label">Sınırlamalar</div>
            <ul className="ai-analysis-list" style={{ marginTop: '10px' }}>
              {[...(analysis.warnings || []), ...(analysis.limitations || [])].map((item, index) => (
                <li key={`${device.ip}-assistant-limit-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className={`assistant-overlay ${isOpen ? 'open' : ''}`} aria-hidden={!isOpen}>
      <div className="assistant-backdrop" onClick={onClose} />
      <aside className="assistant-panel">
        <div className="assistant-panel-header">
          <div>
            <div className="assistant-panel-kicker">Güvenlik Asistanı</div>
            <h3 className="assistant-panel-title">Yalnızca cihaza özel analiz</h3>
            <div className="section-subtitle" style={{ marginTop: '6px' }}>
              {device ? `Seçili cihaz: ${device.ip}` : 'Doğrulanmış YZ akışlarını kullanmak için bir cihaz seçin.'}
            </div>
          </div>
          <button className="assistant-close" onClick={onClose} aria-label="Güvenlik Asistanını kapat">
            <X size={18} />
          </button>
        </div>

        <div className="assistant-actions">
          {Object.entries(DEVICE_ANALYSIS_VIEWS).map(([key, config]) => (
            <button
              key={key}
              className={`assistant-chip ${activeView === key ? 'active' : ''}`}
              onClick={() => {
                setActiveView(key)
                if (!analysis && !loading && device) {
                  loadAnalysis(false)
                }
              }}
              disabled={!device}
            >
              {config.label}
            </button>
          ))}
        </div>

        <div className="assistant-toolbar">
          <div className="assistant-toolbar-note">
            <Sparkles size={14} color="var(--accent-primary)" />
            Risk açıklaması, anomali bağlamı ve sonraki adımlar için hızlı cihaz görünümü.
          </div>
          <button
            className="btn"
            onClick={() => loadAnalysis(Boolean(analysis))}
            disabled={!device || loading}
            style={{ background: 'rgba(255,255,255,0.04)', color: 'var(--text-primary)', border: '1px solid rgba(148, 163, 184, 0.12)' }}
          >
            {loading ? <Loader2 size={14} className="spin" /> : analysis ? <RefreshCcw size={14} /> : <Shield size={14} />}
            {loading ? 'Yükleniyor...' : analysis ? 'Yenile' : 'Analizi Yükle'}
          </button>
        </div>

        {device && (
          <div className="assistant-scope-note">
            <span className="badge badge-neutral">Hızlı görünüm</span>
            <span>
              Tam risk geçmişi, kanıtlar ve CVE odaklı takip için cihaz sayfasını kullanın. Bu panel doğrulanmış cihaza özel analiz akışıyla sınırlı kalır.
            </span>
          </div>
        )}

        <div className="assistant-panel-content">
          {renderBody()}
        </div>

        <div className="assistant-panel-footer">
          <div className="status-note">
            <AlertTriangle size={12} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            Serbest metin sohbet, CVE-öncelikli akışlar ve konuşma hafızası bu panelin bilinçli olarak kapsamı dışındadır.
          </div>
        </div>
      </aside>
    </div>
  )
}

export default SecurityAssistantPanel
