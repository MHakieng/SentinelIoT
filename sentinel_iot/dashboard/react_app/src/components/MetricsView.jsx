import React from 'react'
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  GitBranch,
  Info,
  Layers,
  Radar,
  Shield,
  Zap,
} from 'lucide-react'

const percent = (value, digits = 1) => {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'Not available'
  return `${(Number(value) * 100).toFixed(digits)}%`
}

const valueOrUnknown = (value) => {
  if (value === null || value === undefined || value === '') return 'Not available'
  return String(value)
}

const renderMetricCard = (label, value, note, tone = 'neutral') => (
  <div className={`soft-panel validation-metric-card ${tone}`}>
    <div className="metric-label">{label}</div>
    <div className="validation-metric-value">{value}</div>
    {note && <div className="status-note">{note}</div>}
  </div>
)

const renderObjectEvidence = (title, value) => {
  if (!value) return null
  const rows = Array.isArray(value)
    ? value.map((item, index) => [String(index + 1), item])
    : Object.entries(value)

  if (rows.length === 0) return null

  return (
    <div className="soft-panel validation-evidence-block">
      <div className="metric-label">{title}</div>
      <div className="validation-kv-list">
        {rows.map(([key, item]) => (
          <div key={key}>
            <span>{key}</span>
            <strong>{typeof item === 'object' ? JSON.stringify(item) : valueOrUnknown(item)}</strong>
          </div>
        ))}
      </div>
    </div>
  )
}

const MetricsState = ({ type, message }) => {
  const isError = type === 'error'
  return (
    <div className={`empty-state validation-state ${isError ? 'validation-state-error' : ''}`}>
      {isError ? <AlertTriangle className="empty-state-icon" /> : <BarChart3 className="empty-state-icon" />}
      <div className="empty-state-title">{isError ? 'Metrics yüklenemedi' : 'Validation verisi bekleniyor'}</div>
      <div className="empty-state-copy">{message}</div>
    </div>
  )
}

const MetricsView = ({ systemMetrics, metricsLoading, metricsError }) => {
  const synthetic = systemMetrics?.synthetic_training_metrics || null
  const runtime = systemMetrics?.runtime_detection_metrics || null
  const runtimeMetadata = systemMetrics?.runtime_metrics_metadata || null
  const hasSyntheticMetrics = Boolean(synthetic && synthetic.validation_status !== 'unavailable')
  const hasRuntimeLabels = Boolean(runtime)

  if (metricsLoading) {
    return (
      <div className="fade-in validation-view">
        <div className="validation-hero">
          <div>
            <div className="command-kicker">Validation</div>
            <h2>Model assurance loading</h2>
          </div>
          <LoaderSkeleton />
        </div>
        <div className="validation-grid">
          <div className="skeleton validation-loading-panel"></div>
          <div className="skeleton validation-loading-panel"></div>
        </div>
      </div>
    )
  }

  if (metricsError) {
    return (
      <div className="fade-in validation-view">
        <MetricsState type="error" message={metricsError} />
      </div>
    )
  }

  if (!systemMetrics) {
    return (
      <div className="fade-in validation-view">
        <MetricsState message="Henüz /metrics yanıtı alınmadı." />
      </div>
    )
  }

  return (
    <div className="fade-in validation-view">
      <section className="validation-hero">
        <div>
          <div className="command-kicker">Sentinel-IoT v6 Validation</div>
          <h2>How was the model validated?</h2>
          <p>Bu ekran synthetic training validation ile production runtime detection durumunu ayrı raporlar.</p>
        </div>
        <div className="validation-model-meta">
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Model version</div>
            <div className="metric-value">{valueOrUnknown(systemMetrics.model_version)}</div>
          </div>
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Last training</div>
            <div className="metric-value">{valueOrUnknown(systemMetrics.last_training)}</div>
          </div>
          <div className="soft-panel device-summary-tile">
            <div className="metric-label">Runtime source</div>
            <div className="metric-value">{valueOrUnknown(runtimeMetadata?.source)}</div>
          </div>
        </div>
      </section>

      <div className="validation-grid">
        <section className="card validation-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Zap size={18} /> Synthetic Model Validation</h3>
              <div className="section-subtitle">/metrics içindeki synthetic_training_metrics alanı. Eğitim/doğrulama bağlamı production runtime değildir.</div>
            </div>
            <span className={`badge ${hasSyntheticMetrics ? 'badge-success' : 'badge-warning'}`}>
              {synthetic?.validation_status || 'unavailable'}
            </span>
          </div>

          {synthetic ? (
            <>
              <div className="validation-metric-grid">
                {renderMetricCard('Precision', percent(synthetic.precision), 'Synthetic labelled validation', 'info')}
                {renderMetricCard('Recall', percent(synthetic.recall), 'Synthetic labelled validation', 'info')}
                {renderMetricCard('F1 score', percent(synthetic.f1_score), 'Synthetic labelled validation', 'success')}
                {renderMetricCard('Accuracy', percent(synthetic.accuracy), synthetic.accuracy === undefined ? 'Not provided by /metrics' : 'Synthetic labelled validation')}
                {renderMetricCard('Average precision', percent(synthetic.average_precision), 'Available when scores and labels exist')}
              </div>
              <div className="validation-evidence-grid">
                {renderObjectEvidence('Confusion matrix', synthetic.confusion_matrix)}
                {renderObjectEvidence('Scenario breakdown', synthetic.scenario_breakdown || synthetic.scenarios)}
              </div>
            </>
          ) : (
            <MetricsState message="Synthetic training metrics alanı /metrics yanıtında bulunamadı." />
          )}
        </section>

        <section className="card validation-panel runtime-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Shield size={18} /> Runtime Detection Status</h3>
              <div className="section-subtitle">Production olayları etiketlenmediği sürece TP/FP/F1 hesaplanmaz.</div>
            </div>
            <span className={`badge ${hasRuntimeLabels ? 'badge-success' : 'badge-neutral'}`}>
              {hasRuntimeLabels ? 'labelled runtime' : 'labels unavailable'}
            </span>
          </div>

          {hasRuntimeLabels ? (
            <div className="validation-metric-grid">
              {renderMetricCard('True positives', valueOrUnknown(runtime.true_positives), 'Runtime labelled event count', 'success')}
              {renderMetricCard('False positives', valueOrUnknown(runtime.false_positives), 'Runtime labelled event count', 'warning')}
              {renderMetricCard('Precision', percent(runtime.precision), 'Only shown because runtime_detection_metrics exists')}
              {renderMetricCard('Recall', percent(runtime.recall), 'Only shown because runtime_detection_metrics exists')}
              {renderMetricCard('F1 score', percent(runtime.f1_score), 'Only shown because runtime_detection_metrics exists')}
            </div>
          ) : (
            <div className="runtime-limitation">
              <div className="runtime-limitation-icon"><AlertTriangle size={22} /></div>
              <div>
                <h4>Runtime labels are not available</h4>
                <p>Production TP/FP/F1 cannot be computed without labelled events.</p>
                <div className="status-note">{runtimeMetadata?.note || 'Runtime TP/FP/F1 metrics require labelled production events.'}</div>
              </div>
            </div>
          )}

          <div className="validation-kv-list runtime-meta">
            <div><span>Source</span><strong>{valueOrUnknown(runtimeMetadata?.source)}</strong></div>
            <div><span>Placeholder</span><strong>{runtimeMetadata?.is_placeholder ? 'yes' : 'no'}</strong></div>
          </div>
        </section>
      </div>

      <section className="card validation-panel methodology-panel">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><CheckCircle2 size={18} /> Methodology Notes</h3>
            <div className="section-subtitle">Savunmada model doğrulama sorusuna verilecek kısa teknik cevap.</div>
          </div>
        </div>
        <div className="methodology-grid">
          <div className="soft-panel methodology-item">
            <Layers size={18} />
            <div>
              <strong>Flow-based feature extraction</strong>
              <p>Paketler akış metriklerine çevrilir; model ham paket metni yerine sayısal flow feature setiyle çalışır.</p>
            </div>
          </div>
          <div className="soft-panel methodology-item">
            <Radar size={18} />
            <div>
              <strong>Isolation Forest</strong>
              <p>Anomali tespiti Isolation Forest modeliyle yapılır; runtime skorları canlı flow feature değerlerinden çıkarılır.</p>
            </div>
          </div>
          <div className="soft-panel methodology-item">
            <Database size={18} />
            <div>
              <strong>Synthetic attack scenarios</strong>
              <p>Precision, recall ve F1 yalnızca synthetic labelled validation bağlamında raporlanır.</p>
            </div>
          </div>
          <div className="soft-panel methodology-item">
            <GitBranch size={18} />
            <div>
              <strong>Runtime inference limitation</strong>
              <p>Canlı ortamda etiketli olay yoksa production TP/FP/F1 dürüst biçimde hesaplanamaz.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="card validation-panel metadata-panel">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><Cpu size={18} /> Metrics Metadata</h3>
            <div className="section-subtitle">Mevcut /metrics yanıtından okunan metadata.</div>
          </div>
        </div>
        <div className="validation-kv-list metadata-list">
          <div><span>Model version</span><strong>{valueOrUnknown(systemMetrics.model_version)}</strong></div>
          <div><span>Last training</span><strong>{valueOrUnknown(systemMetrics.last_training)}</strong></div>
          <div><span>Synthetic validation status</span><strong>{valueOrUnknown(synthetic?.validation_status)}</strong></div>
          <div><span>Runtime metrics source</span><strong>{valueOrUnknown(runtimeMetadata?.source)}</strong></div>
          <div><span>Runtime note</span><strong>{valueOrUnknown(runtimeMetadata?.note)}</strong></div>
        </div>
        <div className="validation-scope-note">
          <Info size={15} />
          Validation ekranındaki başarı oranları production performansı olarak sunulmaz; runtime labels yoksa runtime başarı metriği gösterilmez.
        </div>
      </section>
    </div>
  )
}

const LoaderSkeleton = () => (
  <div className="validation-model-meta">
    <div className="skeleton skeleton-text"></div>
    <div className="skeleton skeleton-text"></div>
    <div className="skeleton skeleton-text"></div>
  </div>
)

export default MetricsView
