import React from 'react'
import { AlertTriangle, BarChart3, Database, Info, Shield, Zap } from 'lucide-react'

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
    {note && <div className="table-secondary">{note}</div>}
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
      <div className="empty-state-title">{isError ? 'Metrikler yüklenemedi' : 'Doğrulama verisi yok'}</div>
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
            <div className="command-kicker">Doğrulama</div>
            <h2>Model doğrulama verisi yükleniyor</h2>
          </div>
          <LoaderSkeleton />
        </div>
      </div>
    )
  }

  if (metricsError) return <div className="fade-in validation-view"><MetricsState type="error" message={metricsError} /></div>
  if (!systemMetrics) return <div className="fade-in validation-view"><MetricsState message="Henüz /metrics yanıtı alınmadı." /></div>

  return (
    <div className="fade-in validation-view">
      <section className="validation-hero">
        <div>
          <div className="command-kicker">Sentinel-IoT v6 Doğrulama</div>
          <h2>Offline Model Doğrulama ve Canlı Runtime Durumu</h2>
          <div className="table-secondary">Offline metrikler etiketli dataset sonucudur; canlı ekranlar inference skoru, risk skoru ve karar gösterir.</div>
        </div>
        <div className="validation-model-meta">
          <div className="soft-panel device-summary-tile"><div className="metric-label">Model versiyonu</div><div className="metric-value">{valueOrUnknown(systemMetrics.model_version)}</div></div>
          <div className="soft-panel device-summary-tile"><div className="metric-label">Son eğitim</div><div className="metric-value">{valueOrUnknown(systemMetrics.last_training)}</div></div>
          <div className="soft-panel device-summary-tile"><div className="metric-label">Canlı metrik kaynağı</div><div className="metric-value">{valueOrUnknown(runtimeMetadata?.source)}</div></div>
        </div>
      </section>

      <div className="validation-grid">
        <section className="card validation-panel">
          <div className="section-header">
            <h3 className="command-section-title"><Zap size={18} /> Offline Model Doğrulama</h3>
            <span className={`badge ${hasSyntheticMetrics ? 'badge-success' : 'badge-warning'}`}>
              {synthetic?.validation_status === 'validated' ? 'Doğrulandı' : 'Veri Yok'}
            </span>
          </div>
          <div className="status-note">Bu değerler yalnızca etiketli eğitim/doğrulama verisinden gelir; canlı runtime başarı metriği değildir.</div>
          {synthetic ? (
            <>
              <div className="validation-metric-grid">
                {renderMetricCard('Precision', percent(synthetic.precision), 'Etiketli offline test', 'info')}
                {renderMetricCard('Recall', percent(synthetic.recall), 'Etiketli offline test', 'info')}
                {renderMetricCard('F1 Score', percent(synthetic.f1_score), 'Etiketli offline test', 'success')}
                {renderMetricCard('Accuracy', percent(synthetic.accuracy), 'Etiketli offline test')}
                {renderMetricCard('Avg Precision', percent(synthetic.average_precision), 'Etiketli offline test')}
              </div>
              <div className="validation-evidence-grid">
                {renderObjectEvidence('Confusion matrix', synthetic.confusion_matrix)}
                {renderObjectEvidence('Dataset / senaryo kırılımı', synthetic.scenario_breakdown || synthetic.scenarios)}
              </div>
            </>
          ) : <MetricsState message="Offline validation alanı /metrics yanıtında bulunamadı." />}
        </section>

        <section className="card validation-panel runtime-panel">
          <div className="section-header">
            <h3 className="command-section-title"><Shield size={18} /> Kontrollü Canlı Doğrulama</h3>
            <span className={`badge ${hasRuntimeLabels ? 'badge-success' : 'badge-neutral'}`}>
              {hasRuntimeLabels ? 'Canlı Doğrulama Aktif' : 'Etiketli Veri Bekleniyor'}
            </span>
          </div>
          <div className="status-note">Precision, recall ve F1 yalnızca manuel etiketli canlı zaman aralıkları varsa gösterilir.</div>
          {hasRuntimeLabels ? (
            <div className="validation-metric-grid">
              {renderMetricCard('True Positives', valueOrUnknown(runtime.true_positives), 'Etiketli canlı pencere içinde', 'success')}
              {renderMetricCard('False Positives', valueOrUnknown(runtime.false_positives), 'Etiketli canlı pencere içinde', 'warning')}
              {renderMetricCard('Precision', percent(runtime.precision), 'Kontrollü canlı doğrulama')}
              {renderMetricCard('Recall', percent(runtime.recall), 'Kontrollü canlı doğrulama')}
              {renderMetricCard('F1 Score', percent(runtime.f1_score), 'Kontrollü canlı doğrulama')}
            </div>
          ) : (
            <div className="runtime-limitation">
              <div className="runtime-limitation-icon"><AlertTriangle size={22} /></div>
              <div>
                <h4>Canlı doğrulama metriği yok</h4>
                <p>Runtime scoring akışı çalışabilir, ancak etiketli olay penceresi olmadan accuracy/F1 üretilmez.</p>
              </div>
            </div>
          )}
        </section>
      </div>

      {hasNbaiot && (
        <section className="card validation-panel benchmark-panel">
          <div className="section-header">
            <h3 className="command-section-title"><Database size={18} /> Ek Offline Benchmark Sonuçları</h3>
            <span className="badge badge-success">{nbaiot.results.length} model</span>
          </div>
          <div className="status-note">Bu bölüm canlı runtime sonucu değildir; yalnızca ayrı benchmark kayıtları varsa gösterilir.</div>
          <div style={{ overflowX: 'auto' }}>
            <table className="validation-benchmark-table">
              <thead><tr><th>Model</th><th>Dataset</th><th>Samples</th><th>Features</th><th>F1</th><th>Precision</th><th>Recall</th><th>Accuracy</th><th>FPR</th></tr></thead>
              <tbody>
                {nbaiot.results.map((r, idx) => (
                  <tr key={idx}>
                    <td><strong>{r.model}</strong></td>
                    <td className="table-secondary">{r.dataset || '—'}</td>
                    <td>{r.sample_count.toLocaleString() || '—'}</td>
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

      <section className="card validation-panel">
        <div className="section-header"><h3 className="command-section-title"><Info size={18} /> Canlı Skorlama Notu</h3></div>
        <div className="status-note">
          Live flow ekranındaki ML score, reward, penalty ve final risk alanları inference sonrası operasyonel risk kalibrasyonudur.
          Bu alanlar canlı accuracy, precision, recall veya F1 metriği olarak yorumlanmamalıdır.
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
