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
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'Veri Yok'
  return `${(Number(value) * 100).toFixed(digits)}%`
}

const valueOrUnknown = (value) => {
  if (value === null || value === undefined || value === '') return 'Veri Yok'
  return String(value)
}

const renderMetricCard = (label, value, note, tone = 'neutral') => (
  <div className={`soft-panel validation-metric-card ${tone}`}>
    <div className="metric-label">{label}</div>
    <div className="validation-metric-value">{value}</div>
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
      <div className="empty-state-title">{isError ? 'Metrics yüklenemedi' : 'Validation verisi yok'}</div>
      <div className="empty-state-copy">{message}</div>
    </div>
  )
}

const MetricsView = ({ systemMetrics, metricsLoading, metricsError }) => {
  const synthetic = systemMetrics?.synthetic_training_metrics || null
  const runtime = systemMetrics?.runtime_detection_metrics || null
  const runtimeMetadata = systemMetrics?.runtime_metrics_metadata || null
  const nbaiot = systemMetrics?.nbaiot_benchmark || null
  const hasSyntheticMetrics = Boolean(synthetic && synthetic.validation_status !== 'unavailable')
  const hasRuntimeLabels = Boolean(runtime)
  const hasNbaiot = Boolean(nbaiot?.available && nbaiot?.results?.length > 0)

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
          <h2>Model Validation Metrics</h2>
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
            </div>
            <span className={`badge ${hasSyntheticMetrics ? 'badge-success' : 'badge-warning'}`}>
              {synthetic?.validation_status === 'validated' ? 'Doğrulandı' : 'Veri Yok'}
            </span>
          </div>

          {synthetic ? (
            <>
              <div className="validation-metric-grid">
                {renderMetricCard('Precision', percent(synthetic.precision), null, 'info')}
                {renderMetricCard('Recall', percent(synthetic.recall), null, 'info')}
                {renderMetricCard('F1 Score', percent(synthetic.f1_score), null, 'success')}
                {renderMetricCard('Accuracy', percent(synthetic.accuracy), null)}
                {renderMetricCard('Avg Precision', percent(synthetic.average_precision), null)}
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
            </div>
            <span className={`badge ${hasRuntimeLabels ? 'badge-success' : 'badge-neutral'}`}>
              {hasRuntimeLabels ? 'Canlı Doğrulama Aktif' : 'Etiketli Veri Bekleniyor'}
            </span>
          </div>

          {hasRuntimeLabels ? (
            <div className="validation-metric-grid">
              {renderMetricCard('True Positives', valueOrUnknown(runtime.true_positives), null, 'success')}
              {renderMetricCard('False Positives', valueOrUnknown(runtime.false_positives), null, 'warning')}
              {renderMetricCard('Precision', percent(runtime.precision), null)}
              {renderMetricCard('Recall', percent(runtime.recall), null)}
              {renderMetricCard('F1 Score', percent(runtime.f1_score), null)}
            </div>
          ) : (
            <div className="runtime-limitation">
              <div className="runtime-limitation-icon"><AlertTriangle size={22} /></div>
              <div>
                <h4>Canlı Metrikler Hazır Değil</h4>
              </div>
            </div>
          )}

        </section>
      </div>

      {hasNbaiot && (
        <section className="card validation-panel benchmark-panel">
          <div className="section-header">
            <div>
              <h3 className="command-section-title"><Database size={18} /> N-BaIoT Benchmark Results</h3>
            </div>
            <span className="badge badge-success">{nbaiot.results.length} model</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="validation-benchmark-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Dataset</th>
                  <th>Samples</th>
                  <th>Features</th>
                  <th>F1</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>Accuracy</th>
                  <th>FPR</th>
                </tr>
              </thead>
              <tbody>
                {nbaiot.results.map((r, idx) => (
                  <tr key={idx}>
                    <td><strong>{r.model}</strong></td>
                    <td className="table-secondary">{r.dataset || '—'}</td>
                    <td>{r.sample_count?.toLocaleString() || '—'}</td>
                    <td>{r.feature_count || '—'}</td>
                    <td className="metric-highlight">{percent(r.f1_score)}</td>
                    <td>{percent(r.precision)}</td>
                    <td>{percent(r.recall)}</td>
                    <td>{percent(r.accuracy)}</td>
                    <td>{r.false_positive_rate !== null && r.false_positive_rate !== undefined ? percent(r.false_positive_rate) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

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
