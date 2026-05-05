import React from 'react'
import { ShieldAlert, BarChart2 } from 'lucide-react'

const formatDuration = (value) => `${Number(value || 0).toFixed(2)}s`
const formatIat = (value) => `${Number(value || 0).toFixed(3)}s`

const FlowSummaryView = ({ flows, loading = false, error = null }) => {
  return (
    <div className="card" style={{ minHeight: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column' }}>
      <div className="section-header">
        <div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '0 0 6px 0' }}>
            <BarChart2 size={18} color="var(--accent-secondary)" /> Canlı Akışlar
          </h3>
          <div className="section-subtitle">
            Aktif bağlantıları, trafik hacmini ve son akışlardaki izleme puanını inceleyin.
          </div>
        </div>
        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{flows.length} aktif akış</span>
      </div>

      <div className="table-surface" style={{ flexGrow: 1, overflowY: 'auto' }}>
        <table className="data-table" style={{ fontSize: '0.85rem' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'rgba(10, 11, 16, 0.95)', zIndex: 1 }}>
            <tr>
              <th>Bağlantı</th>
              <th style={{ textAlign: 'center' }}>Hacim</th>
              <th style={{ textAlign: 'center' }}>Süre</th>
              <th style={{ textAlign: 'center' }}>Ort. Paket Aralığı</th>
              <th style={{ textAlign: 'center' }}>İzleme Puanı</th>
              <th style={{ textAlign: 'center' }}>Durum</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-secondary)' }}>
                  Canlı akış verileri yükleniyor...
                </td>
              </tr>
            ) : error ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '48px', color: 'var(--danger)' }}>
                  {error}
                </td>
              </tr>
            ) : flows.length > 0 ? flows.map((flow, idx) => {
              const score = Math.min(100, Math.max(0, Number(flow.anomaly_score || 0) * 100))
              const isFlagged = flow.label === 1

              return (
                <tr
                  key={flow.flow_id || idx}
                  style={{
                    background: isFlagged ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                    transition: 'background 0.3s ease'
                  }}
                >
                  <td>
                    <div className="table-primary" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {isFlagged && <ShieldAlert size={14} color="var(--danger)" />}
                      {flow.src_ip}:{flow.src_port} <span style={{ color: 'var(--text-secondary)' }}>&rarr;</span> {flow.dst_ip}:{flow.dst_port}
                    </div>
                    <div className="table-secondary">
                      Protokol: {flow.protocol_name || flow.protocol || 'Bilinmiyor'}
                    </div>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <div className="metric-stack">
                      <div className="metric-value">{flow.packet_count} paket</div>
                      <div className="table-secondary">{(Number(flow.byte_count || 0) / 1024).toFixed(2)} KB aktarıldı</div>
                    </div>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <div className="metric-value">{formatDuration(flow.duration)}</div>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <div className="metric-value">{formatIat(flow.mean_iat)}</div>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                      <div style={{ width: '72px', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '999px', overflow: 'hidden' }}>
                        <div style={{ width: `${score}%`, height: '100%', background: isFlagged ? 'var(--danger)' : 'var(--success)' }}></div>
                      </div>
                      <span style={{ fontSize: '0.75rem', minWidth: '44px' }}>{score.toFixed(1)}%</span>
                    </div>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span
                      style={{
                        padding: '4px 8px',
                        borderRadius: '6px',
                        fontSize: '0.68rem',
                        fontWeight: 'bold',
                        background: isFlagged ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                        color: isFlagged ? 'var(--danger)' : 'var(--success)',
                        border: `1px solid ${isFlagged ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
                      }}
                    >
                      {isFlagged ? 'İnceleme gerekli' : 'Normal aralıkta'}
                    </span>
                  </td>
                </tr>
              )
            }) : (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-secondary)' }}>
                  Henüz canlı akış yok. Bu görünümü doldurmak için canlı izlemeyi başlatın.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default FlowSummaryView
