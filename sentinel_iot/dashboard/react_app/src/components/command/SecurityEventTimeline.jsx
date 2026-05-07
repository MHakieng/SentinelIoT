import React from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Cpu,
  Radar,
  Search,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from 'lucide-react'
import { formatTimelineTime } from './eventTimelineUtils'

const EVENT_META = {
  SCAN_STARTED: { label: 'Scan Started', icon: Search },
  SCAN_COMPLETED: { label: 'Scan Completed', icon: CheckCircle2 },
  DEVICE_DISCOVERED: { label: 'Device', icon: Cpu },
  VULNERABILITY_FOUND: { label: 'Vulnerability', icon: ShieldAlert },
  ANOMALY_DETECTED: { label: 'Anomaly', icon: Radar },
  RISK_INCREASED: { label: 'Risk Increased', icon: TrendingUp },
  AI_ANALYSIS_GENERATED: { label: 'AI Analysis', icon: Sparkles },
}

const severityLabel = {
  critical: 'Kritik',
  medium: 'Orta',
  low: 'Düşük',
  info: 'Bilgi',
}

const SecurityEventTimeline = ({ events = [], loading = false, error = null }) => (
  <div className="command-timeline">
    {loading ? (
      <div className="state-message state-message-compact">
        <Clock3 size={16} className="spin" />
        Olay akışı hazırlanıyor...
      </div>
    ) : error ? (
      <div className="state-message state-message-danger state-message-compact">
        <AlertTriangle size={16} />
        {error}
      </div>
    ) : events.length === 0 ? (
      <div className="empty-state command-timeline-empty">
        <Activity className="empty-state-icon" />
        <div className="empty-state-title">Olay kaydı yok</div>
        <div className="empty-state-copy">Tarama, anomali, risk artışı veya YZ analizi üretildiğinde burada görünür.</div>
      </div>
    ) : (
      events.map((event) => {
        const meta = EVENT_META[event.type] || { label: event.type || 'Event', icon: Activity }
        const Icon = meta.icon
        const severity = event.severity || 'info'

        return (
          <article key={event.id} className={`command-timeline-item ${severity}`}>
            <div className="command-timeline-icon">
              <Icon size={15} />
            </div>
            <div className="command-timeline-body">
              <div className="command-timeline-head">
                <strong>{event.title}</strong>
                <span className={`event-severity event-severity-${severity}`}>{severityLabel[severity] || severity}</span>
              </div>
              <p>{event.description}</p>
              <div className="command-timeline-meta">
                <span>{formatTimelineTime(event.timestamp)}</span>
                <span>{meta.label}</span>
                {event.device_ip && <span>{event.device_ip}</span>}
                <span>source: {event.source}</span>
              </div>
            </div>
          </article>
        )
      })
    )}
  </div>
)

export default SecurityEventTimeline
