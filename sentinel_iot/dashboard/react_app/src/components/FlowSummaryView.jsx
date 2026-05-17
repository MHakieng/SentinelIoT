import React from 'react'
import { BarChart2, Info, ShieldAlert } from 'lucide-react'
import ClassAwareReasonList from './ClassAwareReasonList'
import DeviceClassBadge from './DeviceClassBadge'
import FlowDecisionBadge from './FlowDecisionBadge'
import {
  getFlowFinalRisk,
  getFlowMlScore,
  getFlowSeverity,
  isBackendAnomaly,
  isHighRiskFlow,
  isModelFlaggedFlow,
  safeNumber,
} from '../lib/flowRisk'

const formatIat = (value) => `${safeNumber(value).toFixed(3)}s`
const formatScore = (value) => `${safeNumber(value).toFixed(1)}%`
const formatRawScore = (value) => {
  if (value === null || value === undefined || value === '') return '—'
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric.toFixed(4) : '—'
}
const formatSigned = (value) => {
  const numeric = safeNumber(value)
  if (numeric > 0) return `+${numeric.toFixed(0)}`
  if (numeric < 0) return numeric.toFixed(0)
  return '0'
}

const severityMeta = (severity, score) => {
  const risk = Number(score || 0)
  const key = severity || (risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 35 ? 'medium' : 'low')
  if (key === 'critical') return { label: 'Kritik', className: 'flow-severity critical' }
  if (key === 'high') return { label: 'Yüksek', className: 'flow-severity high' }
  if (key === 'medium') return { label: 'Orta', className: 'flow-severity medium' }
  return { label: 'Düşük', className: 'flow-severity low' }
}

const FlowMetric = ({ label, value, tone = '' }) => (
  <div className={`flow-metric ${tone}`}>
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
)

const FlowSummaryView = ({ flows = [], loading = false, error = null }) => (
  <div className="card live-flow-panel">
    <div className="section-header">
      <div>
        <h3 className="command-section-title">
          <BarChart2 size={18} color="var(--accent-secondary)" /> Canlı Akış Skorları
        </h3>
        <div className="table-secondary">
          Canlı etiketli metrik yok. Bu ekran inference skoru, nihai risk ve bağlama duyarlı kararı gösterir.
        </div>
      </div>
      <span className="status-note">{flows.length} aktif akış</span>
    </div>

    <div className="runtime-limitation live-score-note">
      <div className="runtime-limitation-icon"><Info size={18} /></div>
      <p>
        Risk seviyesi high/critical olsa bile bu tek başına anomaly kararı değildir. Karar; ML skoru,
        cihaz sınıfı, penalty/reward ve kanıtlarla birlikte değerlendirilir.
      </p>
    </div>

    {loading ? (
      <div className="state-message">Canlı akış verisi yükleniyor...</div>
    ) : error ? (
      <div className="state-message state-message-danger">{error}</div>
    ) : flows.length === 0 ? (
      <div className="state-message">
        Henüz canlı akış yok. Canlı izlemeyi başlatın veya yeni paket yakalanmasını bekleyin.
      </div>
    ) : (
      <div className="flow-card-grid">
        {flows.map((flow, idx) => {
          const mlScore = getFlowMlScore(flow)
          const finalRisk = getFlowFinalRisk(flow)
          const severity = severityMeta(getFlowSeverity(flow), finalRisk)
          const backendAnomaly = isBackendAnomaly(flow)
          const highRisk = isHighRiskFlow(flow)
          const modelFlagged = isModelFlaggedFlow(flow)
          const pps = safeNumber(flow.features?.packets_per_second ?? flow.packet_rate)
          const reasons = Array.isArray(flow.reasons) ? flow.reasons : []
          const classReasons = Array.isArray(flow.class_aware_reasons) ? flow.class_aware_reasons : []
          const decision = flow.decision || (backendAnomaly ? 'anomaly' : highRisk ? 'suspicious' : 'normal')
          const adjustment = safeNumber(flow.class_aware_adjustment)

          return (
            <article key={flow.flow_id || idx} className={`flow-score-card ${backendAnomaly ? 'anomaly' : highRisk ? 'suspicious' : ''}`}>
              <div className="flow-card-head">
                <div className="flow-route">
                  {(backendAnomaly || highRisk) && <ShieldAlert size={15} color={backendAnomaly ? 'var(--danger)' : 'var(--warning)'} />}
                  <div>
                    <strong>{flow.src_ip}:{flow.src_port}</strong>
                    <span>→</span>
                    <strong>{flow.dst_ip}:{flow.dst_port}</strong>
                  </div>
                  <small>{flow.protocol_name || flow.protocol || 'UNKNOWN'}</small>
                </div>
                <div className="flow-state-stack">
                  <span className={severity.className} title="Risk seviyesi canlı precision/recall metriği değildir.">
                    {severity.label}
                  </span>
                  <FlowDecisionBadge decision={decision} source={flow.decision_source} compact />
                </div>
              </div>

              <div className="flow-class-row">
                <DeviceClassBadge deviceClass={flow.source_device_class} confidence={flow.source_device_class_confidence} compact />
                <span className="table-secondary">→</span>
                <DeviceClassBadge deviceClass={flow.destination_device_class} confidence={flow.destination_device_class_confidence} compact />
              </div>

              <div className="flow-primary-metrics">
                <FlowMetric label="ML Skoru" value={formatScore(mlScore)} tone={modelFlagged ? 'warning' : ''} />
                <FlowMetric label="Nihai Risk" value={formatScore(finalRisk)} tone={finalRisk >= 80 ? 'danger' : finalRisk >= 60 ? 'warning' : ''} />
                <FlowMetric label="Paket" value={safeNumber(flow.packet_count).toFixed(0)} />
                <FlowMetric label="Byte" value={`${(safeNumber(flow.byte_count) / 1024).toFixed(2)} KB`} />
                <FlowMetric label="PPS" value={pps.toFixed(1)} />
                <FlowMetric label="Mean IAT" value={formatIat(flow.mean_iat)} />
              </div>

              <details className="flow-detail-drawer">
                <summary>Skor kırılımı ve gerekçeler</summary>
                <div className="flow-detail-grid">
                  <FlowMetric label="Reward" value={`-${Number(flow.reward_points || 0)}`} tone="success" />
                  <FlowMetric label="Penalty" value={`+${Number(flow.penalty_points || 0)}`} tone="danger" />
                  <FlowMetric label="Sınıf Ayarı" value={formatSigned(adjustment)} tone={adjustment > 0 ? 'danger' : adjustment < 0 ? 'success' : ''} />
                  <FlowMetric label="Ham Skor" value={formatRawScore(flow.ml_raw_score)} />
                  <FlowMetric label="Model" value={flow.model_available === false ? 'Uygun değil' : 'Uygun'} />
                  <FlowMetric label="Karar Kaynağı" value={flow.decision_source || 'canlı skorlama'} />
                  <FlowMetric label="Süre" value={`${safeNumber(flow.duration ?? flow.features?.duration).toFixed(3)}s`} />
                  <FlowMetric label="Ortalama Paket" value={`${safeNumber(flow.avg_packet_size ?? flow.features?.avg_packet_size).toFixed(1)} B`} />
                  <FlowMetric label="Paket Rate" value={safeNumber(flow.packet_rate ?? flow.features?.packet_rate ?? flow.features?.packets_per_second).toFixed(2)} />
                </div>
                <div className="flow-reason-block">
                  <div className="metric-label">Gerekçeler</div>
                  <ClassAwareReasonList classReasons={classReasons} reasons={reasons} />
                </div>
                <div className="status-note">
                  Reward/Penalty yeniden eğitim veya reinforcement learning değildir; akış skorunu açıklanabilir şekilde kalibre eden kural tabanlı katkılardır.
                </div>
              </details>
            </article>
          )
        })}
      </div>
    )}
  </div>
)

export default FlowSummaryView
