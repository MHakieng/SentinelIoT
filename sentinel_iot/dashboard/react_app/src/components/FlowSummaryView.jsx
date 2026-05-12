import React from 'react'
import { BarChart2, ShieldAlert } from 'lucide-react'

const safeNumber = (value, fallback = 0) => {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}
const formatIat = (value) => `${safeNumber(value).toFixed(3)}s`
const formatScore = (value) => `${safeNumber(value).toFixed(1)}%`

const severityStyle = (severity, score) => {
  const risk = Number(score || 0)
  const label = severity || (risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 35 ? 'medium' : 'low')
  if (label === 'critical') return { label, color: 'var(--danger)', background: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.3)' }
  if (label === 'high') return { label, color: 'var(--warning)', background: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.32)' }
  if (label === 'medium') return { label, color: 'var(--accent-secondary)', background: 'rgba(45, 212, 191, 0.12)', border: 'rgba(45, 212, 191, 0.28)' }
  return { label: 'low', color: 'var(--success)', background: 'rgba(34, 197, 94, 0.15)', border: 'rgba(34, 197, 94, 0.3)' }
}

const FlowSummaryView = ({ flows, loading = false, error = null }) => {
  return (
    <div className="card" style={{ minHeight: '420px', display: 'flex', flexDirection: 'column' }}>
      <div className="section-header">
        <div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '0 0 6px 0' }}>
            <BarChart2 size={18} color="var(--accent-secondary)" /> Live Flow Scoring
          </h3>
        </div>
        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{flows.length} active flows</span>
      </div>

      <div className="table-surface" style={{ flexGrow: 1, overflow: 'auto' }}>
        <table className="data-table" style={{ fontSize: '0.8rem', minWidth: '1180px' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'rgba(10, 11, 16, 0.95)', zIndex: 1 }}>
            <tr>
              <th>Flow</th>
              <th style={{ textAlign: 'center' }}>Protocol</th>
              <th style={{ textAlign: 'center' }}>Packets</th>
              <th style={{ textAlign: 'center' }}>Bytes</th>
              <th style={{ textAlign: 'center' }}>PPS</th>
              <th style={{ textAlign: 'center' }}>Mean IAT</th>
              <th style={{ textAlign: 'center' }}>ML Score</th>
              <th style={{ textAlign: 'center' }}>Reward</th>
              <th style={{ textAlign: 'center' }}>Penalty</th>
              <th style={{ textAlign: 'center' }}>Final Risk</th>
              <th style={{ textAlign: 'center' }}>Severity</th>
              <th>Reasons</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="12" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-secondary)' }}>
                  Live flow data is loading...
                </td>
              </tr>
            ) : error ? (
              <tr>
                <td colSpan="12" style={{ textAlign: 'center', padding: '48px', color: 'var(--danger)' }}>
                  {error}
                </td>
              </tr>
            ) : flows.length > 0 ? flows.map((flow, idx) => {
              const mlScore = Math.min(100, Math.max(0, safeNumber(flow.ml_anomaly_score ?? flow.anomaly_score) * 100))
              const finalRisk = Math.min(100, Math.max(0, safeNumber(flow.final_flow_risk, mlScore)))
              const severity = severityStyle(flow.severity, finalRisk)
              const isFlagged = flow.label === 1 || finalRisk >= 60
              const pps = safeNumber(flow.features?.packets_per_second ?? flow.packet_rate)
              const reasons = Array.isArray(flow.reasons) ? flow.reasons : []

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
                      {flow.src_ip}:{flow.src_port} <span style={{ color: 'var(--text-secondary)' }}>-&gt;</span> {flow.dst_ip}:{flow.dst_port}
                    </div>
                    <div className="table-secondary">{flow.flow_id}</div>
                  </td>
                  <td style={{ textAlign: 'center' }}>{flow.protocol_name || flow.protocol || 'UNKNOWN'}</td>
                  <td style={{ textAlign: 'center' }}><div className="metric-value">{safeNumber(flow.packet_count).toFixed(0)}</div></td>
                  <td style={{ textAlign: 'center' }}><div className="metric-value">{(safeNumber(flow.byte_count) / 1024).toFixed(2)} KB</div></td>
                  <td style={{ textAlign: 'center' }}><div className="metric-value">{pps.toFixed(1)}</div></td>
                  <td style={{ textAlign: 'center' }}><div className="metric-value">{formatIat(flow.mean_iat)}</div></td>
                  <td style={{ textAlign: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                      <div style={{ width: '72px', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '999px', overflow: 'hidden' }}>
                        <div style={{ width: `${mlScore}%`, height: '100%', background: isFlagged ? 'var(--danger)' : 'var(--success)' }}></div>
                      </div>
                      <span style={{ fontSize: '0.75rem', minWidth: '44px' }}>{formatScore(mlScore)}</span>
                    </div>
                  </td>
                  <td style={{ textAlign: 'center', color: 'var(--success)', fontWeight: 700 }}>-{Number(flow.reward_points || 0)}</td>
                  <td style={{ textAlign: 'center', color: 'var(--danger)', fontWeight: 700 }}>+{Number(flow.penalty_points || 0)}</td>
                  <td style={{ textAlign: 'center', fontWeight: 800 }}>{formatScore(finalRisk)}</td>
                  <td style={{ textAlign: 'center' }}>
                    <span
                      style={{
                        padding: '4px 8px',
                        borderRadius: '6px',
                        fontSize: '0.68rem',
                        fontWeight: 'bold',
                        textTransform: 'uppercase',
                        background: severity.background,
                        color: severity.color,
                        border: `1px solid ${severity.border}`
                      }}
                    >
                      {severity.label}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', maxWidth: '280px' }}>
                      {reasons.slice(0, 3).map((reason) => (
                        <span key={reason} className="status-note" title={reason} style={{ padding: '3px 6px', fontSize: '0.68rem' }}>
                          {reason}
                        </span>
                      ))}
                      {reasons.length === 0 && <span className="table-secondary">-</span>}
                      {reasons.length > 3 && <span className="table-secondary" title={reasons.slice(3).join(', ')}>+{reasons.length - 3}</span>}
                    </div>
                  </td>
                </tr>
              )
            }) : (
              <tr>
                <td colSpan="12" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-secondary)' }}>
                  No live flows yet.
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
