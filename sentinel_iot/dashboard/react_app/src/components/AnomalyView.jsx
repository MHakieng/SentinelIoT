import React, { useEffect, useRef, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar
} from 'recharts'
import { Activity, AlertOctagon, TrendingUp, Zap, Target, Gauge, Play, Loader2 } from 'lucide-react'
import { translateRiskStatus } from '../lib/uiText'

const ANOMALY_ALERT_THRESHOLD = 40

const EMPTY_METRICS = {
  synthetic_training_metrics: {
    f1_score: 0,
    precision: 0,
    recall: 0,
    average_precision: 0,
    validation_status: 'unavailable',
  },
}

const formatRatioAsPercent = (value) => {
  if (value == null) {
    return 'N/A'
  }
  return `${(value * 100).toFixed(1)}%`
}

const AnomalyView = ({
  devices,
  metrics,
  metricsLoading,
  metricsError,
  livePackets,
  trafficLoading,
  trafficError,
  trafficHistory,
  historyLoading,
  historyError,
  monitoringActive = false,
  monitorStatus = 'idle',
  monitorMessage = null,
  monitorSummary = null,
  monitorActionLoading = false,
  monitorError = null,
  onToggleMonitoring
}) => {
  const [consolePackets, setConsolePackets] = useState([])
  const packetConsoleRef = useRef(null)
  const seenPacketKeys = useRef(new Set())

  const metricValues = metrics?.synthetic_training_metrics || EMPTY_METRICS.synthetic_training_metrics
  const anomalousDevices = devices.filter((device) => (device.risk_breakdown?.anomaly || 0) >= ANOMALY_ALERT_THRESHOLD)

  const packetKey = (packet) =>
    `${packet.timestamp}-${packet.source_ip}-${packet.destination_ip}-${packet.packet_length}-${packet.protocol}`

  useEffect(() => {
    if (!Array.isArray(livePackets) || livePackets.length === 0) {
      return
    }

    setConsolePackets((prev) => {
      const newPackets = livePackets.filter((packet) => {
        const key = packetKey(packet)
        if (seenPacketKeys.current.has(key)) {
          return false
        }
        seenPacketKeys.current.add(key)
        return true
      })

      if (newPackets.length === 0) {
        return prev
      }

      const combined = [...prev, ...newPackets]
      if (combined.length > 500) {
        const removed = combined.splice(0, combined.length - 500)
        removed.forEach((packet) => seenPacketKeys.current.delete(packetKey(packet)))
      }
      return combined
    })
  }, [livePackets])

  useEffect(() => {
    if (packetConsoleRef.current) {
      packetConsoleRef.current.scrollTop = packetConsoleRef.current.scrollHeight
    }
  }, [consolePackets])

  const chartLoading = historyLoading
  const chartError = historyError
  const monitorHeadline = monitorStatus === 'stopping'
    ? 'Mevcut yakalama penceresinden sonra duruyor'
    : monitoringActive
      ? 'Yakalama çalışıyor'
      : 'Başlatmaya hazır'
  const monitorBody = monitorError
    ? 'Canlı izleme kullanılamıyor.'
    : monitorMessage || ''
  const monitorButtonLabel = monitorActionLoading
    ? 'Güncelleniyor...'
    : monitorStatus === 'stopping'
      ? 'Durduruluyor...'
      : monitoringActive
        ? 'İzlemeyi Durdur'
        : 'İzlemeyi Başlat'

  const totalFlowsSeen = Number(monitorSummary?.total_flows_seen || 0)
  const flowsTracked = Number(monitorSummary?.flows_tracked || 0)
  const flowBufferLimit = Number(monitorSummary?.flow_buffer_limit || 500)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '24px' }}>
      <div className="card" style={{ gridColumn: '1 / -1', padding: '20px' }}>
        <div className="section-header" style={{ marginBottom: '16px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>İzleme Görünümü</h3>
          </div>
        </div>
        <div className="anomaly-summary-grid">
          <div className="soft-panel anomaly-monitor-panel">
            <div className="metric-label">Canlı İzleme</div>
            <div style={{ fontSize: '1.12rem', fontWeight: '700', margin: '10px 0 8px' }}>
              {monitorHeadline}
            </div>
            {monitorBody && (
              <div style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                {monitorBody}
              </div>
            )}
            {monitorError && (
              <div style={{ marginTop: '12px', fontSize: '0.78rem', color: 'var(--danger)' }}>
                {monitorError}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '12px', marginTop: '16px' }}>
              <div>
                <div className="metric-label">Toplam akis</div>
                <div style={{ fontSize: '1.45rem', fontWeight: 800, marginTop: '4px' }}>
                  {totalFlowsSeen.toLocaleString('tr-TR')}
                </div>
              </div>
              <div>
                <div className="metric-label">Bellekteki akis</div>
                <div style={{ fontSize: '1.45rem', fontWeight: 800, marginTop: '4px' }}>
                  {flowsTracked.toLocaleString('tr-TR')} / {flowBufferLimit.toLocaleString('tr-TR')}
                </div>
              </div>
            </div>

            <button
              className="btn btn-primary"
              onClick={onToggleMonitoring}
              disabled={monitorActionLoading || monitorStatus === 'stopping'}
              style={{
                marginTop: '18px',
                justifyContent: 'center',
                background: monitoringActive ? 'rgba(239, 68, 68, 0.18)' : undefined,
                color: monitoringActive ? '#fecaca' : undefined,
                border: monitoringActive ? '1px solid rgba(239, 68, 68, 0.22)' : 'none',
                opacity: monitorActionLoading ? 0.85 : 1
              }}
            >
              {monitorActionLoading ? <Loader2 className="spin" size={16} /> : monitoringActive ? <Activity className="spin" size={16} /> : <Play size={16} />}
              {monitorButtonLabel}
            </button>
          </div>

          <div className="soft-panel anomaly-alert-panel">
            <div className="metric-label">İnceleme Gerektiren Cihazlar</div>
            <div style={{ fontSize: '2rem', fontWeight: '800', lineHeight: 1, color: anomalousDevices.length > 0 ? 'var(--danger)' : 'var(--success)', marginTop: '10px' }}>
              {anomalousDevices.length}
            </div>
            <div style={{ marginTop: '6px', fontSize: '0.88rem', fontWeight: '600' }}>
              {anomalousDevices.length === 1 ? 'eşik üstünde cihaz' : 'eşik üstünde cihaz'}
            </div>
            <div className="anomaly-alert-list">
              {anomalousDevices.slice(0, 3).map((device) => (
                <div key={device.ip} className="anomaly-alert-item">
                  <div>
                    <div className="table-primary">{device.ip}</div>
                    <div className="table-secondary" style={{ marginTop: '2px' }}>{translateRiskStatus(device.status)}</div>
                  </div>
                  <div className="anomaly-alert-score">{(device.risk_breakdown?.anomaly || 0).toFixed(1)}</div>
                </div>
              ))}
              {anomalousDevices.length === 0 && (
                <div className="status-note" style={{ marginTop: '12px' }}>
                  Eşik üstü cihaz yok.
                </div>
              )}
            </div>
          </div>

          <div className="soft-panel" style={{ padding: '18px' }}>
            <div className="metric-label" style={{ marginBottom: '12px' }}>
              Model Doğrulama
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Target size={18} color="var(--accent-primary)" />
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Kesinlik</div>
                  <div style={{ fontWeight: '700' }}>{metricsLoading ? '...' : formatRatioAsPercent(metricValues.precision)}</div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Activity size={18} color="var(--accent-secondary)" />
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Duyarlılık</div>
                  <div style={{ fontWeight: '700' }}>{metricsLoading ? '...' : formatRatioAsPercent(metricValues.recall)}</div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Zap size={18} color="var(--success)" />
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>F1 Score</div>
                  <div style={{ fontWeight: '700' }}>{metricsLoading ? '...' : formatRatioAsPercent(metricValues.f1_score)}</div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Gauge size={18} color="var(--warning)" />
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Ort. Kesinlik</div>
                  <div style={{ fontWeight: '700' }}>{metricsLoading ? '...' : formatRatioAsPercent(metricValues.average_precision)}</div>
                </div>
              </div>
            </div>
            {!metricsLoading && metricValues.validation_status === 'unavailable' && (
              <div style={{ marginTop: '14px', fontSize: '0.78rem', color: 'var(--warning)' }}>
                Doğrulama etiketi yok.
              </div>
            )}
            {metricsError && (
              <div style={{ marginTop: '14px', fontSize: '0.78rem', color: 'var(--danger)' }}>
                {metricsError}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card" style={{ height: '380px', padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <div className="section-header" style={{ marginBottom: '14px' }}>
          <div>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.05rem' }}>
              <TrendingUp size={18} /> Trafik Eğilimi
            </h3>
          </div>
        </div>
        {chartLoading ? (
          <div className="state-message">Son trafik geçmişi yükleniyor...</div>
        ) : chartError ? (
          <div className="state-message state-message-danger">{chartError}</div>
        ) : trafficHistory.length === 0 ? (
          <div className="state-message">Henüz trafik geçmişi kaydedilmedi.</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%" minHeight={0}>
            <AreaChart data={trafficHistory}>
              <defs>
                <linearGradient id="colorPkts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="time" stroke="var(--text-secondary)" fontSize={11} tickMargin={12} minTickGap={20} />
              <YAxis stroke="var(--text-secondary)" fontSize={11} tickMargin={8} />
              <Tooltip contentStyle={{ background: 'var(--bg-dark)', border: '1px solid var(--panel-border)', borderRadius: '8px' }} itemStyle={{ fontSize: '12px' }} />
              <Area type="monotone" dataKey="packets" stroke="var(--accent-primary)" fillOpacity={1} fill="url(#colorPkts)" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="card" style={{ height: '380px', padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <div className="section-header" style={{ marginBottom: '14px' }}>
          <div>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.05rem' }}>
              <Zap size={18} /> İzleme Puanları
            </h3>
          </div>
        </div>
        {devices.length === 0 ? (
          <div className="state-message">Cihaz izleme puanlarını doldurmak için ağ taraması başlatın.</div>
        ) : anomalousDevices.length === 0 ? (
          <div className="state-message">Şu anda hiçbir cihaz izleme uyarı eşiğini aşmıyor.</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%" minHeight={0}>
            <BarChart data={anomalousDevices}>
              <XAxis dataKey="ip" stroke="var(--text-secondary)" fontSize={10} />
              <YAxis stroke="var(--text-secondary)" fontSize={12} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: 'var(--bg-dark)', border: '1px solid var(--panel-border)', borderRadius: '8px' }} />
              <Bar dataKey="risk_breakdown.anomaly" fill="var(--accent-secondary)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="card" style={{ gridColumn: '1 / -1', padding: '20px' }}>
        <div className="section-header" style={{ marginBottom: '14px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.05rem' }}>İnceleme Kuyruğu</h3>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {anomalousDevices.map((device, idx) => (
            <div key={idx} className="soft-panel anomaly-review-row">
              <AlertOctagon color="var(--danger)" />
              <div>
                <div style={{ fontWeight: '600' }}>{device.ip}</div>
              </div>
              <div style={{ fontWeight: '700', color: 'var(--danger)', textAlign: 'right' }}>
                {(device.risk_breakdown?.anomaly || 0).toFixed(1)}/100
              </div>
            </div>
          ))}
          {anomalousDevices.length === 0 && (
            <div className="state-message" style={{ minHeight: '100px' }}>
              Şu anda hiçbir cihaz anomali uyarı eşiğini aşmıyor.
            </div>
          )}
        </div>
      </div>

      {monitoringActive && (
        <div className="card" style={{ gridColumn: '1 / -1', background: 'rgba(12, 16, 24, 0.96)', border: '1px solid rgba(148, 163, 184, 0.12)', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', borderBottom: '1px solid rgba(148, 163, 184, 0.12)', paddingBottom: '12px' }}>
            <div>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#fff', fontSize: '1rem', margin: 0 }}>
                <Activity size={16} color="var(--danger)" /> Canlı Paket Önizlemesi
              </h3>
            </div>
            <button
              onClick={() => { setConsolePackets([]); seenPacketKeys.current.clear() }}
              style={{ background: 'transparent', border: '1px solid rgba(148, 163, 184, 0.16)', color: 'var(--text-secondary)', fontSize: '0.72rem', padding: '6px 10px', borderRadius: '8px', cursor: 'pointer', fontFamily: 'monospace' }}
            >
              TEMİZLE
            </button>
          </div>

          <div
            ref={packetConsoleRef}
            style={{
              fontFamily: '"Fira Code", "Courier New", Courier, monospace',
              fontSize: '0.84rem',
              height: '320px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              paddingRight: '8px'
            }}
          >
            {trafficLoading && consolePackets.length === 0 ? (
              <div className="state-message state-message-compact" style={{ minHeight: '160px' }}>Paket akışı yükleniyor...</div>
            ) : trafficError && consolePackets.length === 0 ? (
              <div className="state-message state-message-danger state-message-compact" style={{ minHeight: '160px' }}>{trafficError}</div>
            ) : consolePackets.length > 0 ? consolePackets.map((packet, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                  padding: '10px 12px',
                  background: 'rgba(239, 68, 68, 0.05)',
                  borderLeft: '2px solid var(--danger)',
                  borderRadius: '6px'
                }}
              >
                <div style={{ display: 'flex', gap: '16px', color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
                  <span style={{ color: '#fff' }}>[{packet.timestamp}]</span>
                  <span>{packet.source_ip}:{packet.source_port} <span style={{ color: '#666' }}>-&gt;</span> {packet.destination_ip}:{packet.destination_port}</span>
                  <span style={{
                    color: packet.protocol === 'TCP' ? 'var(--accent-primary)' : (packet.protocol === 'UDP' ? 'var(--accent-secondary)' : 'var(--success)'),
                    fontWeight: 'bold'
                  }}>[{packet.protocol}]</span>
                  <span>LEN:{packet.packet_length}</span>
                </div>
                <div style={{ color: 'var(--danger)', paddingLeft: '12px', wordBreak: 'break-all', fontSize: '0.8rem' }}>
                  &gt; {packet.info || 'Yazdırılabilir yük önizlemesi yok'}
                </div>
              </div>
            )) : (
              <div className="state-message state-message-compact" style={{ minHeight: '160px' }}>
                Paket önizlemeleri bekleniyor...
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default AnomalyView
