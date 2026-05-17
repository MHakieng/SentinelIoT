import React from 'react'
import { AlertTriangle, BarChart3, CheckCircle2, Info, Shield } from 'lucide-react'

const percent = (value, digits = 2) => {
  const number = Number(value)
  if (value === null || value === undefined || value === '' || !Number.isFinite(number)) return '—'
  return `${(number * 100).toFixed(digits)}%`
}

const valueOrDash = (value) => {
  if (value === null || value === undefined || value === '') return '—'
  return String(value)
}

const metricValue = (metrics, keys) => {
  for (const key of keys) {
    if (metrics?.[key] !== null && metrics?.[key] !== undefined) return metrics[key]
  }
  return null
}

const MetricCard = ({ label, value, note }) => (
  <div className="soft-panel validation-simple-metric">
    <div className="metric-label">{label}</div>
    <strong>{value}</strong>
    {note && <span>{note}</span>}
  </div>
)

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
  const offline = systemMetrics?.synthetic_training_metrics || {}
  const runtime = systemMetrics?.runtime_detection_metrics || null
  const runtimeMetadata = systemMetrics?.runtime_metrics_metadata || null
  const hasRuntimeLabels = Boolean(runtime)

  if (metricsLoading) {
    return (
      <div className="fade-in validation-simple-page">
        <section className="card validation-simple-hero">
          <div>
            <div className="command-kicker">Doğrulama</div>
            <h2>Doğrulama bilgileri yükleniyor</h2>
            <p>Offline metrikler ve canlı runtime durumu alınıyor.</p>
          </div>
        </section>
      </div>
    )
  }

  if (metricsError) {
    return <div className="fade-in validation-simple-page"><MetricsState type="error" message={metricsError} /></div>
  }

  if (!systemMetrics) {
    return <div className="fade-in validation-simple-page"><MetricsState message="Henüz /metrics yanıtı alınmadı." /></div>
  }

  return (
    <div className="fade-in validation-simple-page">
      <section className="card validation-simple-hero">
        <div>
          <div className="command-kicker">Doğrulama</div>
          <h2>Model Metrikleri ve Canlı Durum</h2>
          <p>
            Bu sayfa sadece doğrulama için gerekli temel bilgileri gösterir. Offline metrikler etiketli veri setinden gelir;
            canlı trafik ekranındaki skorlar runtime accuracy/F1 metriği değildir.
          </p>
        </div>
        <div className="validation-simple-model">
          <div>
            <span>Aktif model</span>
            <strong>{valueOrDash(systemMetrics.model_version)}</strong>
          </div>
          <div>
            <span>Son eğitim</span>
            <strong>{valueOrDash(systemMetrics.last_training)}</strong>
          </div>
        </div>
      </section>

      <section className="card validation-simple-section">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><CheckCircle2 size={18} /> Offline Validation Metrikleri</h3>
            <div className="table-secondary">Etiketli test/veri seti üzerinde hesaplanan metrikler.</div>
          </div>
        </div>

        <div className="validation-simple-grid">
          <MetricCard label="Accuracy" value={percent(metricValue(offline, ['accuracy']))} />
          <MetricCard label="Precision" value={percent(metricValue(offline, ['precision']))} />
          <MetricCard label="Recall" value={percent(metricValue(offline, ['recall']))} />
          <MetricCard label="F1" value={percent(metricValue(offline, ['f1_score', 'f1']))} />
        </div>

        <div className="validation-simple-note">
          <Info size={16} />
          <span>
            CICIoT2023 RandomForest raporu `evaluation/results/ciciot2023_random_forest_report.json` altında tutulur.
            Bu değerler canlı runtime başarısı değildir.
          </span>
        </div>
      </section>

      <section className="card validation-simple-section">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><Shield size={18} /> Canlı Runtime Durumu</h3>
            <div className="table-secondary">Canlı izleme inference skoru, final risk ve karar üretir.</div>
          </div>
          <span className={`badge ${hasRuntimeLabels ? 'badge-success' : 'badge-neutral'}`}>
            {hasRuntimeLabels ? 'Etiketli pencere var' : 'Etiketli veri yok'}
          </span>
        </div>

        {hasRuntimeLabels ? (
          <div className="validation-simple-grid">
            <MetricCard label="Precision" value={percent(runtime.precision)} note="Kontrollü canlı doğrulama" />
            <MetricCard label="Recall" value={percent(runtime.recall)} note="Kontrollü canlı doğrulama" />
            <MetricCard label="F1" value={percent(runtime.f1_score ?? runtime.f1)} note="Kontrollü canlı doğrulama" />
            <MetricCard label="False Positive" value={valueOrDash(runtime.false_positives)} note="Etiketli pencere" />
          </div>
        ) : (
          <div className="validation-runtime-empty">
            <AlertTriangle size={22} />
            <div>
              <strong>Canlı accuracy / F1 hesaplanmaz</strong>
              <p>
                Canlı trafikte ground-truth etiketi olmadığı için runtime precision, recall veya F1 gösterilmez.
                {runtimeMetadata?.note ? ` ${runtimeMetadata.note}` : ''}
              </p>
            </div>
          </div>
        )}
      </section>

      <section className="card validation-simple-section">
        <h3 className="command-section-title"><Info size={18} /> Kısa Yorum</h3>
        <div className="validation-simple-bullets">
          <div>Offline metrikler modelin etiketli dataset üzerindeki sonucudur.</div>
          <div>Canlı ekranda görülen ML skoru, risk ve karar runtime inference çıktısıdır.</div>
          <div>Device class ve sınıflandırma güveni başarı metriği değildir; sadece bağlam sağlar.</div>
        </div>
      </section>
    </div>
  )
}

export default MetricsView
