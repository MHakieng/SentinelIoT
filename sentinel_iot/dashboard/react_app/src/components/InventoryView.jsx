import React from 'react'
import { Monitor, ChevronRight, HardDrive, ShieldAlert, ShieldCheck, Network, Fingerprint } from 'lucide-react'
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import DeviceClassBadge from './DeviceClassBadge'
import { translateRiskStatus } from '../lib/uiText'

const COLORS = ['var(--neon-pink)', 'rgba(255,255,255,0.05)']

const InventoryView = ({ devices, onSelectDevice, loading = false, error = null }) => {
  const totalDevices = devices.length
  const highRiskCount = devices.filter(d => d.status === 'High Risk').length
  const openPortsAvg = totalDevices > 0 ? Math.round(devices.reduce((acc, d) => acc + (Array.isArray(d.open_ports) ? d.open_ports.length : 0), 0) / totalDevices) : 0
  const avgRisk = totalDevices > 0 ? Math.round(devices.reduce((acc, d) => acc + Number(d.risk_score || 0), 0) / totalDevices) : 0
  
  const dynamicGaugeData = [
    { name: 'Risk', value: avgRisk },
    { name: 'Safe', value: 100 - avgRisk }
  ]

  return (
    <div className="fade-in">
      {/* SentinelIoT Contextualized Widgets */}
      <div className="dashboard-widgets-container">
        <div className="attack-surface-cards">
          
          <div className="widget-card">
            <div className="widget-icon-box" style={{ background: 'rgba(192, 132, 252, 0.15)', boxShadow: '0 0 12px rgba(192, 132, 252, 0.3)' }}>
              <ShieldAlert size={20} color="var(--neon-purple)" />
            </div>
            <div className="widget-value">{highRiskCount}</div>
            <div className="widget-label">Kritik Riskli Cihaz</div>
          </div>

          <div className="widget-card">
            <div className="widget-icon-box" style={{ background: 'rgba(34, 211, 238, 0.15)', boxShadow: '0 0 12px rgba(34, 211, 238, 0.3)' }}>
              <Monitor size={20} color="var(--neon-cyan)" />
            </div>
            <div className="widget-value">{totalDevices}</div>
            <div className="widget-label">Aktif Host / Cihaz</div>
          </div>

          <div className="widget-card">
            <div className="widget-icon-box" style={{ background: 'rgba(251, 146, 60, 0.15)', boxShadow: '0 0 12px rgba(251, 146, 60, 0.3)' }}>
              <Network size={20} color="var(--neon-orange)" />
            </div>
            <div className="widget-value">{openPortsAvg}</div>
            <div className="widget-label">Ort. Açık Servis</div>
          </div>

          <div className="widget-card">
            <div className="widget-icon-box" style={{ background: 'rgba(217, 70, 239, 0.15)', boxShadow: '0 0 12px rgba(217, 70, 239, 0.3)' }}>
              <ShieldCheck size={20} color="var(--neon-pink)" />
            </div>
            <div className="widget-value">{totalDevices - highRiskCount}</div>
            <div className="widget-label">İzlenen Normal Cihazlar</div>
          </div>

        </div>

        <div className="gauge-card">
          <div className="gauge-title">Ağ Risk Skoru</div>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie
                data={dynamicGaugeData}
                cx="50%"
                cy="100%"
                startAngle={180}
                endAngle={0}
                innerRadius={80}
                outerRadius={110}
                paddingAngle={2}
                dataKey="value"
                stroke="none"
              >
                {dynamicGaugeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ position: 'absolute', bottom: '20px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Ortalama Risk</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#fff' }}>{avgRisk}%</div>
          </div>
        </div>
      </div>

      <div className="card table-shell p-0">
        <div style={{ padding: '24px', borderBottom: '1px solid var(--panel-border)' }}>
        <div className="section-header mb-2">
          <h3 style={{ fontSize: '1.1rem', margin: 0 }}>Cihaz Envanteri</h3>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>{devices.length} cihaz</span>
        </div>
      </div>

      <div className="table-surface" style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Cihaz</th>
              <th>Cihaz Sınıfı</th>
              <th>Ağ</th>
              <th>Görünürlük</th>
              <th>Risk</th>
              <th>Durum</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan="7" className="p-0">
                  <div className="skeleton-row">
                    <div className="skeleton-cell" style={{ maxWidth: '40px' }}><div className="skeleton skeleton-icon"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text" style={{ width: '80%' }}></div><div className="skeleton skeleton-text" style={{ width: '40%' }}></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                  </div>
                  <div className="skeleton-row">
                    <div className="skeleton-cell" style={{ maxWidth: '40px' }}><div className="skeleton skeleton-icon"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text" style={{ width: '70%' }}></div><div className="skeleton skeleton-text" style={{ width: '50%' }}></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                    <div className="skeleton-cell"><div className="skeleton skeleton-text"></div></div>
                  </div>
                </td>
              </tr>
            )}
            {!loading && error && devices.length === 0 && (
              <tr>
                <td colSpan="7" className="p-0">
                  <div className="empty-state">
                    <ShieldAlert className="empty-state-icon" style={{ color: 'var(--danger)' }} />
                    <div className="empty-state-title" style={{ color: 'var(--danger)' }}>Yükleme Hatası</div>
                    <div className="empty-state-copy">{error}</div>
                  </div>
                </td>
              </tr>
            )}
            {!loading && devices.map((device, idx) => {
              const openPortCount = Array.isArray(device.open_ports) ? device.open_ports.length : 0
              const primaryPorts = (device.open_ports || []).slice(0, 3).map((port) => `${port.port}${port.service ? ` ${port.service}` : ''}`)
              const vendorLabel = device.vendor && device.vendor !== 'Unknown' ? device.vendor : 'Tanımlanamayan cihaz'
              const riskScore = Number(device.risk_score || 0)
              const statusTone = device.status === 'High Risk' ? 'badge-danger' : device.status === 'Medium Risk' ? 'badge-warning' : 'badge-success'
              return (
                <tr
                  key={device.ip || idx}
                  onClick={() => onSelectDevice(device)}
                  style={{ transition: 'background 0.2s', cursor: 'pointer' }}
                  className="table-row-hover"
                >
                  <td>
                    <div className="inventory-device-cell">
                      <div className="inventory-device-icon">
                        <Monitor size={18} />
                      </div>
                      <div>
                        <div className="table-primary">{vendorLabel}</div>
                        <div className="inventory-device-meta">
                          <span><Fingerprint size={12} /> {device.mac || 'MAC bilgisi yok'}</span>
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="metric-stack inventory-metric-stack">
                      <DeviceClassBadge deviceClass={device.device_class} confidence={device.device_class_confidence} compact />
                      <div className="table-secondary">
                        {device.device_class_confidence === null || device.device_class_confidence === undefined
                          ? '—'
                          : `Sınıflandırma güveni ${Number(device.device_class_confidence || 0).toFixed(2)}`}
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="metric-stack inventory-metric-stack">
                      <div className="metric-value">{device.ip}</div>
                      <div className="inventory-inline-meta">
                        <span><Network size={12} /> Host kaydı</span>
                        <span>{translateRiskStatus(device.status)}</span>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="metric-stack inventory-metric-stack">
                      <div className="metric-value">{openPortCount} açık {openPortCount === 1 ? 'servis' : 'servis'}</div>
                      {primaryPorts.length > 0 ? (
                        <div className="inline-chip-list" style={{ marginTop: '2px' }}>
                          {primaryPorts.map((entry) => (
                            <span key={`${device.ip}-${entry}`} className="neutral-chip">{entry}</span>
                          ))}
                        </div>
                      ) : (
                        <div className="table-secondary">Servis yok</div>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="inventory-risk-block">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div className="segmented-bar-container">
                          {[...Array(10)].map((_, i) => {
                            const isActive = riskScore >= (i + 1) * 10
                            let colorClass = 'active-success'
                            if (riskScore > 70) colorClass = 'active-pink'
                            else if (riskScore > 30) colorClass = 'active-purple'
                            return (
                              <div key={i} className={`segment ${isActive ? colorClass : ''}`}></div>
                            )
                          })}
                        </div>
                        <span className="inventory-risk-score">{riskScore}%</span>
                      </div>
                      <div className="table-secondary">Ağ üzerindeki potansiyel risk</div>
                    </div>
                  </td>
                  <td>
                    <span className={`badge ${statusTone}`}>
                      {translateRiskStatus(device.status)}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <ChevronRight size={18} color="var(--text-secondary)" />
                  </td>
                </tr>
              )
            })}
            {!loading && !error && devices.length === 0 && (
              <tr>
                <td colSpan="7" className="p-0">
                  <div className="empty-state">
                    <HardDrive className="empty-state-icon" />
                    <div className="empty-state-title">Envanter Boş</div>
                    <div className="empty-state-copy">Ağ taraması başlatın.</div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
    </div>
  )
}

export default InventoryView
