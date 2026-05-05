import React, { useRef } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Shield, Activity, Share2 } from 'lucide-react'

const TopologyView = ({ data, loading = false, error = null, onSelectDevice }) => {
  const fgRef = useRef()

  const getNodeColor = (node) => {
    if (node.type === 'gateway') return '#6366f1'
    const score = node.risk_score || 0
    if (score > 70) return '#ef4444'
    if (score > 30) return '#f59e0b'
    return '#22c55e'
  }

  return (
    <div className="fade-in" style={{ height: 'calc(100vh - 180px)' }}>
      <div className="card" style={{ height: '100%', padding: '20px', overflow: 'hidden', background: 'rgba(12, 16, 24, 0.96)', border: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div className="topology-header">
          <div>
            <h3 style={{ margin: 0, fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Share2 size={18} /> Ağ Topolojisi
            </h3>
            <div className="section-subtitle" style={{ marginTop: '6px' }}>
              Cihaz ilişkilerini inceleyin ve şu anda öne çıkan akışları belirleyin.
            </div>
          </div>
          <div className="topology-header-side">
            <div className="topology-summary-pill">
              {Math.max(0, (data?.nodes?.length || 0) - 1)} cihaz
            </div>
            <div className="topology-summary-pill">
              {data?.links?.length || 0} bağlantı
            </div>
            <div className="topology-summary-copy">
              Detay görünümünü açmak için bir cihaz düğümü seçin.
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 240px', gap: '16px', flexGrow: 1, minHeight: 0 }}>
          <div style={{ position: 'relative', border: '1px solid rgba(148, 163, 184, 0.08)', borderRadius: '16px', overflow: 'hidden', background: '#0b1018' }}>
          {loading ? (
            <div className="empty-state" style={{ height: '100%' }}>
              <div className="skeleton skeleton-icon" style={{ width: '56px', height: '56px', marginBottom: '20px', borderRadius: '50%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '140px', marginBottom: '12px' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '220px' }}></div>
            </div>
          ) : error ? (
            <div className="empty-state" style={{ height: '100%' }}>
              <Activity className="empty-state-icon" style={{ color: 'var(--danger)' }} />
              <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Topoloji Yüklenemedi</div>
              <div className="empty-state-copy">{error}</div>
            </div>
          ) : !data?.nodes?.length ? (
            <div className="empty-state" style={{ height: '100%' }}>
              <Share2 className="empty-state-icon" />
              <div className="empty-state-title">Ağ Haritası Boş</div>
              <div className="empty-state-copy">Henüz topoloji verisi oluşturulmadı. Sol menüden ağ taraması başlatarak haritayı yapılandırın.</div>
            </div>
          ) : (
            <>
              <div style={{ position: 'absolute', top: '14px', left: '14px', zIndex: 10, padding: '8px 12px', borderRadius: '999px', background: 'rgba(15, 19, 27, 0.88)', border: '1px solid rgba(148, 163, 184, 0.12)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Etkin topoloji görünümü
              </div>
              <ForceGraph2D
                ref={fgRef}
                graphData={data}
                nodeLabel="label"
                nodeColor={getNodeColor}
                nodeVal={(node) => node.type === 'gateway' ? 10 : 5}
                linkWidth={(link) => link.anomaly ? 4 : 1}
                linkColor={(link) => link.anomaly ? '#ef4444' : 'rgba(255,255,255,0.15)'}
                linkDirectionalParticles={(link) => link.anomaly ? 4 : 0}
                linkDirectionalParticleWidth={2}
                linkDirectionalParticleSpeed={0.01}
                linkDirectionalParticleColor={() => '#ef4444'}
                backgroundColor="#0b1018"
                onNodeClick={(node) => {
                  if (node.type === 'device') {
                    onSelectDevice(node.ip)
                  }
                }}
                nodeCanvasObject={(node, ctx, globalScale) => {
                  const fontSize = 12 / globalScale
                  ctx.font = `${fontSize}px Inter`

                  ctx.beginPath()
                  ctx.arc(node.x, node.y, node.type === 'gateway' ? 8 : 4.5, 0, 2 * Math.PI, false)
                  ctx.fillStyle = getNodeColor(node)
                  ctx.fill()

                  ctx.textAlign = 'center'
                  ctx.textBaseline = 'middle'
                  ctx.fillStyle = '#fff'
                  ctx.fillText(node.label, node.x, node.y + (node.type === 'gateway' ? 14 : 10))
                }}
              />
            </>
          )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="soft-panel topology-side-panel">
              <h4 style={{ margin: '0 0 12px 0', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={16} /> Topoloji Rehberi
              </h4>
              <div className="topology-legend">
                <div className="topology-legend-item">
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#22c55e' }}></div>
                  <span>Düşük riskli cihaz</span>
                </div>
                <div className="topology-legend-item">
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f59e0b' }}></div>
                  <span>Yükselmiş riskli cihaz</span>
                </div>
                <div className="topology-legend-item">
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444' }}></div>
                  <span>Yüksek riskli cihaz</span>
                </div>
                <div className="topology-legend-item">
                  <div style={{ width: '18px', height: '2px', background: '#ef4444' }}></div>
                  <span>İnceleme işaretli akış</span>
                </div>
              </div>
            </div>

            <div className="soft-panel topology-side-panel">
              <div className="metric-label" style={{ marginBottom: '10px' }}>
                Notlar
              </div>
              <div style={{ fontSize: '0.84rem', lineHeight: 1.55, color: 'var(--text-secondary)' }}>
                Ağ geçidi ve akış çizgileri cihaz ilişkileri için bağlam sağlar. Önce kümeleri grafikte belirleyin, ardından servis ve risk geçmişi için cihaz detayını açın.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default TopologyView
