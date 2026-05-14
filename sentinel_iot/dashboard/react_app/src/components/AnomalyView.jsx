import React, { useEffect, useRef, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Activity, AlertOctagon, Info, Loader2, Play, Radio, TrendingUp, Zap } from 'lucide-react'
import { translateRiskStatus } from '../lib/uiText'

const ANOMALY_ALERT_THRESHOLD = 40
const truncatePacketInfo = (value, maxLength = 180) => {
  const text = String(value || '')
  if (!text) return 'Yazdırılabilir yük önizlemesi yok'
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text
}

const AnomalyView = ({
  devices,
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
  onToggleMonitoring,
}) => {
  const [consolePackets, setConsolePackets] = useState([])
  const packetConsoleRef = useRef(null)
  const seenPacketKeys = useRef(new Set())

  const anomalousDevices = devices.filter((device) => (device.risk_breakdown?.anomaly || 0) >= ANOMALY_ALERT_THRESHOLD)

  const packetKey = (packet) =>
    `${packet.timestamp}-${packet.source_ip}-${packet.destination_ip}-${packet.packet_length}-${packet.protocol}`

  useEffect(() => {
    if (!Array.isArray(livePackets) || livePackets.length === 0) return

    setConsolePackets((prev) => {
      const newPackets = livePackets.filter((packet) => {
        const key = packetKey(packet)
        if (seenPacketKeys.current.has(key)) return false
        seenPacketKeys.current.add(key)
        return true
      })

      if (newPackets.length === 0) return prev

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

  const monitorHeadline = monitorStatus === 'stopping'
    ? 'Mevcut yakalama penceresinden sonra duruyor'
    : monitoringActive
      ? 'Paket yakalama çalışıyor'
      : 'Canlı izleme başlatmaya hazır'
  const monitorBody = monitorError
    ? 'Canlı izleme kullanılamıyor.'
    : monitorMessage || 'Canlı izleme, paketleri yakalayıp akış seviyesinde gruplayarak risk skorlarını besler.'
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
    <div className="live-dashboard-grid">
      <div className="card live-overview-panel">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><Activity size={18} /> Canlı İzleme</h3>
            <div className="table-secondary">Paket yakalama, akış çıkarımı ve canlı risk skorlarını gösterir.</div>
          </div>
        </div>

        <div className="anomaly-summary-grid">
          <div className="soft-panel anomaly-monitor-panel">
            <div className="metric-label">Canlı İzleme</div>
            <div className="monitor-headline">{monitorHeadline}</div>
            <div className="status-note">{monitorBody}</div>
            {monitorError && <div className="status-note danger-text">{monitorError}</div>}

            <div className="live-counter-grid">
              <div>
                <div className="metric-label">Toplam akış</div>
                <div className="metric-value">{totalFlowsSeen.toLocaleString('tr-TR')}</div>
              </div>
              <div>
                <div className="metric-label">Bellekteki akış</div>
                <div className="metric-value">{flowsTracked.toLocaleString('tr-TR')} / {flowBufferLimit.toLocaleString('tr-TR')}</div>
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
              }}
            >
              {monitorActionLoading ? <Loader2 className="spin" size={16} /> : monitoringActive ? <Activity className="spin" size={16} /> : <Play size={16} />}
              {monitorButtonLabel}
            </button>
          </div>

          <div className="soft-panel anomaly-alert-panel">
            <div className="metric-label">İnceleme Gerektiren Cihazlar</div>
            <div className={`live-large-number ${anomalousDevices.length > 0 ? 'danger-text' : 'success-text'}`}>{anomalousDevices.length}</div>
            <div className="status-note">Risk/anomali bileşeni eşik üstünde olan cihazlar.</div>
            <div className="anomaly-alert-list">
              {anomalousDevices.slice(0, 3).map((device) => (
                <div key={device.ip} className="anomaly-alert-item">
                  <div>
                    <div className="table-primary">{device.ip}</div>
                    <div className="table-secondary">{translateRiskStatus(device.status)}</div>
                  </div>
                  <div className="anomaly-alert-score">{(device.risk_breakdown?.anomaly || 0).toFixed(1)}</div>
                </div>
              ))}
              {anomalousDevices.length === 0 && <div className="status-note">Eşik üstü cihaz yok.</div>}
            </div>
          </div>

          <div className="soft-panel live-runtime-note">
            <div className="runtime-limitation-icon"><Info size={22} /></div>
            <div>
              <div className="metric-label">Canlı metrik ayrımı</div>
              <p>
                Bu sayfada runtime accuracy, precision, recall veya F1 gösterilmez. Canlı trafikte etiketli
                ground-truth olmadığı için ekran yalnızca inference skoru, risk skoru ve kararları gösterir.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="card live-chart-card">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><TrendingUp size={18} /> Trafik Eğilimi</h3>
            <div className="table-secondary">Yakalanan paketlerin zaman içindeki sayısını gösterir; başarı metriği değildir.</div>
          </div>
        </div>
        {historyLoading ? (
          <div className="state-message">Son trafik geçmişi yükleniyor...</div>
        ) : historyError ? (
          <div className="state-message state-message-danger">{historyError}</div>
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

      <div className="card live-chart-card">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><Zap size={18} /> İzleme Puanları</h3>
            <div className="table-secondary">Cihaz risk kırılımındaki anomali bileşenine göre görselleştirilir.</div>
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

      <div className="card live-review-panel">
        <div className="section-header">
          <h3 className="command-section-title"><AlertOctagon size={18} /> İnceleme Kuyruğu</h3>
        </div>
        <div className="live-review-list">
          {anomalousDevices.map((device, idx) => (
            <div key={idx} className="soft-panel anomaly-review-row">
              <AlertOctagon color="var(--danger)" />
              <div>
                <div className="table-primary">{device.ip}</div>
                <div className="table-secondary">{translateRiskStatus(device.status)}</div>
              </div>
              <strong className="danger-text">{(device.risk_breakdown?.anomaly || 0).toFixed(1)}/100</strong>
            </div>
          ))}
          {anomalousDevices.length === 0 && <div className="state-message">Şu anda hiçbir cihaz anomali uyarı eşiğini aşmıyor.</div>}
        </div>
      </div>

      <div className="card live-packet-panel">
        <div className="section-header">
          <div>
            <h3 className="command-section-title"><Radio size={18} /> Paket Önizleme</h3>
            <div className="table-secondary">
              Canlı paket yakalama Scapy/Npcap üzerinden yapılır. Bu arayüz PCAP import/replay değil, canlı paket önizleme ve akış özeti sunar.
            </div>
          </div>
          <button
            onClick={() => { setConsolePackets([]); seenPacketKeys.current.clear() }}
            className="btn command-ghost-btn"
            type="button"
          >
            Temizle
          </button>
        </div>

        <div ref={packetConsoleRef} className="packet-preview-list">
          {trafficLoading && consolePackets.length === 0 ? (
            <div className="state-message">Paket akışı yükleniyor...</div>
          ) : trafficError && consolePackets.length === 0 ? (
            <div className="state-message state-message-danger">Paket yakalama başlatılamadı. Npcap, yetki ve ağ arayüzünü kontrol edin. {trafficError}</div>
          ) : consolePackets.length > 0 ? consolePackets.map((packet, idx) => (
            <article key={idx} className="packet-preview-item">
              <div className="packet-preview-meta">
                <span>[{packet.timestamp}]</span>
                <strong>{packet.source_ip}:{packet.source_port} → {packet.destination_ip}:{packet.destination_port}</strong>
                <b>{packet.protocol}</b>
                <span>{packet.packet_length} bayt</span>
              </div>
              <div className="packet-preview-info" title={packet.info || ''}>{truncatePacketInfo(packet.info)}</div>
            </article>
          )) : (
            <div className="state-message">Henüz paket yakalanmadı. Canlı izlemeyi başlatın.</div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AnomalyView
