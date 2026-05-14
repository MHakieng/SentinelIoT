import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Loader2, MessageCircle, Send, Shield, Sparkles, X } from 'lucide-react'
import { fetchDeviceAnalysis, clearDeviceAnalysis } from '../lib/deviceAnalysisClient'
import { describeLlmUiFailure } from '../lib/llmUiContent'
import { translateRiskStatus } from '../lib/uiText'
import DeviceClassBadge from './DeviceClassBadge'

/* ------------------------------------------------------------------ */
/*  Quick-action definitions                                          */
/* ------------------------------------------------------------------ */

const QUICK_ACTIONS = [
  { id: 'explain',   label: 'Bu cihazı açıkla',        sections: ['risk_explanation'], icon: '🔍' },
  { id: 'risk',      label: 'Risk neden yüksek?',       sections: ['risk_explanation'], icon: '⚠️' },
  { id: 'ports',     label: 'Açık portları yorumla',     sections: ['risk_explanation'], icon: '🔌' },
  { id: 'cve',       label: 'CVE riskini özetle',       sections: ['risk_explanation', 'next_actions'], icon: '🛡️' },
  { id: 'actions',   label: 'Önerilen aksiyonları yaz',  sections: ['next_actions'], icon: '📋' },
  { id: 'anomaly',   label: 'Son anomalileri özetle',    sections: ['anomaly_summary'], icon: '📡' },
]

/* ------------------------------------------------------------------ */
/*  Intent matching – maps free-text user input to analysis sections   */
/* ------------------------------------------------------------------ */

const INTENT_KEYWORDS = [
  { pattern: /risk|neden.*riskli|tehlike|tehdit/i,           sections: ['risk_explanation'] },
  { pattern: /port|servis|açık.*port|hizmet/i,               sections: ['risk_explanation'] },
  { pattern: /cve|zafiyet|güvenlik açığı|vulnerability/i,    sections: ['risk_explanation', 'next_actions'] },
  { pattern: /anomali|anomaly|anormal|şüpheli|flow/i,       sections: ['anomaly_summary'] },
  { pattern: /aksiyon|öneri|adım|yapılacak|tavsiye|action/i, sections: ['next_actions'] },
  { pattern: /açıkla|anlat|özetle|nedir|durum/i,             sections: ['risk_explanation', 'anomaly_summary', 'next_actions'] },
]

const matchIntent = (text) => {
  for (const { pattern, sections } of INTENT_KEYWORDS) {
    if (pattern.test(text)) return sections
  }
  return ['risk_explanation', 'anomaly_summary', 'next_actions']
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const formatTime = () => {
  const now = new Date()
  return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`
}

const buildBotContent = (data, sections) => {
  const parts = []

  if (sections.includes('risk_explanation') && data.sections?.risk_explanation) {
    parts.push(data.sections.risk_explanation)
  }

  if (sections.includes('anomaly_summary') && data.sections?.anomaly_summary) {
    if (parts.length > 0) parts.push('')
    parts.push(data.sections.anomaly_summary)
  }

  if (sections.includes('next_actions') && Array.isArray(data.sections?.next_actions) && data.sections.next_actions.length > 0) {
    if (parts.length > 0) parts.push('')
    parts.push('Önerilen adımlar:')
    data.sections.next_actions.forEach((item, i) => {
      parts.push(`${i + 1}. ${item}`)
    })
  }

  if (data.warnings?.length > 0 || data.limitations?.length > 0) {
    const notes = [...(data.warnings || []), ...(data.limitations || [])]
    if (notes.length > 0) {
      parts.push('')
      parts.push('⚠️ ' + notes.join(' '))
    }
  }

  return parts.length > 0
    ? parts.join('\n')
    : 'Bu bağlam için analiz metni üretilemedi. Cihaz taranmış ve envanterde kayıtlı olmalıdır.'
}

const formatDeviceContext = (device) => {
  if (!device) return null
  const riskScore = Number(device.risk_score || 0)
  return {
    ip: device.ip,
    vendor: device.vendor && device.vendor !== 'Unknown' ? device.vendor : null,
    deviceClass: device.device_class || 'unknown',
    riskScore,
    status: device.status || 'Unknown',
    openPorts: Array.isArray(device.open_ports) ? device.open_ports.length : 0,
    totalCves: Number(device.total_cves || 0),
  }
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

const SecurityAssistantPanel = ({ isOpen, onClose, device, apiBaseUrl }) => {
  const [messages, setMessages] = useState([])
  const [inputValue, setInputValue] = useState('')
  const [isTyping, setIsTyping] = useState(false)
  const scrollRef = useRef(null)
  const inputRef = useRef(null)
  const prevDeviceIpRef = useRef(null)

  // Scroll to bottom when messages change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, isTyping])

  // Focus input when panel opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 250)
    }
  }, [isOpen])

  // Context change detection
  useEffect(() => {
    const prevIp = prevDeviceIpRef.current
    const newIp = device?.ip || null

    if (prevIp !== newIp) {
      prevDeviceIpRef.current = newIp

      if (newIp && prevIp !== null) {
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: 'system',
            content: `Bağlam değişti: ${newIp} cihazı seçildi.`,
            time: formatTime(),
          },
        ])
      } else if (newIp && prevIp === null) {
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: 'system',
            content: `${newIp} cihazı bağlam olarak seçildi.`,
            time: formatTime(),
          },
        ])
      }
    }
  }, [device?.ip])

  const sendToBackend = useCallback(
    async (userText, sections) => {
      if (!device?.ip) {
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: 'bot',
            content: 'Analiz için önce bir cihaz seçmeniz gerekiyor. Cihaz listesinden bir cihaz tıklayın.',
            time: formatTime(),
            isInfo: true,
          },
        ])
        return
      }

      setIsTyping(true)

      try {
        clearDeviceAnalysis(device.ip)
        const data = await fetchDeviceAnalysis({
          apiBaseUrl,
          deviceIp: device.ip,
          forceRefresh: true,
        })

        const content = buildBotContent(data, sections)

        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: 'bot',
            content,
            time: formatTime(),
            grounding: data.grounding_summary || null,
          },
        ])
      } catch (err) {
        const errorMsg = describeLlmUiFailure(
          err,
          'AI yanıtı alınamadı. Backend LLM yapılandırmasını kontrol edin.'
        )
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
            type: 'error',
            content: errorMsg,
            time: formatTime(),
          },
        ])
      } finally {
        setIsTyping(false)
      }
    },
    [device?.ip, apiBaseUrl]
  )

  const handleSend = useCallback(() => {
    const text = inputValue.trim()
    if (!text) return

    setMessages((prev) => [
      ...prev,
      { id: Date.now(), type: 'user', content: text, time: formatTime() },
    ])
    setInputValue('')

    const sections = matchIntent(text)
    sendToBackend(text, sections)
  }, [inputValue, sendToBackend])

  const handleQuickAction = useCallback(
    (action) => {
      setMessages((prev) => [
        ...prev,
        { id: Date.now(), type: 'user', content: action.label, time: formatTime() },
      ])
      sendToBackend(action.label, action.sections)
    },
    [sendToBackend]
  )

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const ctx = formatDeviceContext(device)

  return (
    <div className={`assistant-overlay ${isOpen ? 'open' : ''}`} aria-hidden={!isOpen}>
      <div className="assistant-backdrop" onClick={onClose} />
      <aside className="assistant-panel">
        {/* Header */}
        <div className="assistant-panel-header">
          <div>
            <div className="assistant-panel-kicker">AI Güvenlik Chatbotu</div>
            <h3 className="assistant-panel-title">
              <Sparkles size={18} style={{ verticalAlign: 'middle', marginRight: '6px', color: 'var(--accent-primary)' }} />
              Güvenlik Analiz Asistanı
            </h3>
            <div className="status-note" style={{ marginTop: '6px' }}>
              Cihaz, CVE, açık port ve canlı akış kanıtlarına göre güvenlik analizi yapar.
            </div>
          </div>
          <button className="assistant-close" onClick={onClose} aria-label="Chatbotu kapat">
            <X size={18} />
          </button>
        </div>

        {/* Context Card */}
        <div className="chat-context-card">
          {ctx ? (
            <>
              <div className="chat-context-main">
                <Shield size={16} style={{ color: 'var(--accent-secondary)', flexShrink: 0 }} />
                <div>
                  <div className="chat-context-ip">{ctx.ip}</div>
                  <div className="chat-context-meta">
                    {ctx.vendor && <span>{ctx.vendor}</span>}
                    <DeviceClassBadge deviceClass={ctx.deviceClass} compact />
                  </div>
                </div>
              </div>
              <div className="chat-context-stats">
                <span className={`chat-context-risk ${ctx.riskScore > 70 ? 'danger' : ctx.riskScore > 30 ? 'warning' : 'safe'}`}>
                  Risk {ctx.riskScore}%
                </span>
                <span>{ctx.openPorts} port</span>
                <span>{ctx.totalCves} CVE</span>
                <span>{translateRiskStatus(ctx.status)}</span>
              </div>
            </>
          ) : (
            <div className="chat-context-empty">
              <MessageCircle size={16} />
              <span>Analiz için bir cihaz seçin.</span>
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="chat-quick-actions">
          {QUICK_ACTIONS.map((action) => (
            <button
              key={action.id}
              className="assistant-chip"
              onClick={() => handleQuickAction(action)}
              disabled={!device || isTyping}
              title={!device ? 'Önce bir cihaz seçin' : action.label}
            >
              <span style={{ marginRight: '4px' }}>{action.icon}</span>
              {action.label}
            </button>
          ))}
        </div>

        {/* Chat Messages */}
        <div className="chat-messages" ref={scrollRef}>
          {messages.length === 0 && !isTyping && (
            <div className="chat-empty-state">
              <Sparkles size={32} style={{ color: 'var(--accent-primary)', marginBottom: '12px' }} />
              <div className="chat-empty-title">AI Güvenlik Chatbotu</div>
              <div className="chat-empty-copy">
                {device
                  ? 'Hızlı aksiyon butonlarını kullanarak veya mesaj yazarak güvenlik analizi başlatabilirsiniz.'
                  : 'Bir cihaz veya akış seçerek güvenlik analizi başlatabilirsiniz.'}
              </div>
            </div>
          )}

          {messages.map((msg) => {
            if (msg.type === 'system') {
              return (
                <div key={msg.id} className="chat-bubble-system">
                  <span>{msg.content}</span>
                  <span className="chat-bubble-time">{msg.time}</span>
                </div>
              )
            }

            if (msg.type === 'user') {
              return (
                <div key={msg.id} className="chat-bubble-row chat-bubble-row-user">
                  <div className="chat-bubble chat-bubble-user">
                    <div className="chat-bubble-text">{msg.content}</div>
                    <div className="chat-bubble-time">{msg.time}</div>
                  </div>
                </div>
              )
            }

            if (msg.type === 'error') {
              return (
                <div key={msg.id} className="chat-bubble-row chat-bubble-row-bot">
                  <div className="chat-bubble chat-bubble-error">
                    <div className="chat-bubble-text">{msg.content}</div>
                    <div className="chat-bubble-time">{msg.time}</div>
                  </div>
                </div>
              )
            }

            // bot message
            return (
              <div key={msg.id} className="chat-bubble-row chat-bubble-row-bot">
                <div className="chat-bubble-avatar">
                  <Sparkles size={14} />
                </div>
                <div className="chat-bubble chat-bubble-bot">
                  <div className="chat-bubble-text">
                    {msg.content.split('\n').map((line, i) => (
                      <React.Fragment key={i}>
                        {line}
                        {i < msg.content.split('\n').length - 1 && <br />}
                      </React.Fragment>
                    ))}
                  </div>
                  {msg.grounding && (
                    <div className="chat-grounding-strip">
                      <span>Risk: {msg.grounding.risk_score ?? 0}%</span>
                      <span>Servis: {msg.grounding.open_service_count ?? 0}</span>
                      <span>CVE: {msg.grounding.total_cves ?? 0}</span>
                      <span>Anomali: {msg.grounding.recent_anomaly_count ?? 0}</span>
                    </div>
                  )}
                  <div className="chat-bubble-time">{msg.time}</div>
                </div>
              </div>
            )
          })}

          {isTyping && (
            <div className="chat-bubble-row chat-bubble-row-bot">
              <div className="chat-bubble-avatar">
                <Sparkles size={14} />
              </div>
              <div className="chat-bubble chat-bubble-bot chat-typing">
                <Loader2 size={14} className="spin" style={{ marginRight: '8px' }} />
                AI analiz hazırlanıyor...
              </div>
            </div>
          )}
        </div>

        {/* Input Area */}
        <div className="chat-input-area">
          <div className="chat-footer-note">
            AI yanıtları mevcut SentinelIoT kanıtlarına dayanır. Bu asistan karar destek amaçlıdır.
          </div>
          <div className="chat-input-row">
            <textarea
              ref={inputRef}
              className="chat-input"
              placeholder={device ? 'Bu cihaz neden riskli? / CVE riskini özetle...' : 'Önce bir cihaz seçin...'}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isTyping}
              rows={1}
            />
            <button
              className="chat-send-btn"
              onClick={handleSend}
              disabled={!inputValue.trim() || isTyping}
              title="Gönder"
            >
              <Send size={16} />
            </button>
          </div>
        </div>
      </aside>
    </div>
  )
}

export default SecurityAssistantPanel
