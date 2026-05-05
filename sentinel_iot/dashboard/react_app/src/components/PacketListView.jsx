import React, { useEffect, useState } from 'react'
import { Activity, Info, Terminal } from 'lucide-react'

const PacketListView = ({ packets, loading = false, error = null }) => {
  const [selectedPacket, setSelectedPacket] = useState(null)

  useEffect(() => {
    if (!selectedPacket) {
      return
    }

    const packetStillExists = packets.some((packet) =>
      packet.timestamp === selectedPacket.timestamp &&
      packet.source_ip === selectedPacket.source_ip &&
      packet.destination_ip === selectedPacket.destination_ip &&
      packet.packet_length === selectedPacket.packet_length &&
      packet.protocol === selectedPacket.protocol
    )

    if (!packetStillExists) {
      setSelectedPacket(null)
    }
  }, [packets, selectedPacket])

  return (
    <div className="card" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
          <Activity size={18} color="var(--accent-primary)" /> Canlı Paket Akışı
          <span style={{ fontSize: '0.75rem', fontWeight: 400, color: 'var(--text-secondary)' }}>({packets.length} son kayıt)</span>
        </h3>
      </div>

      <div style={{ flexGrow: 1, overflowY: 'auto', border: '1px solid var(--panel-border)', borderRadius: '8px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-card)', zIndex: 1, boxShadow: '0 1px 0 var(--panel-border)' }}>
            <tr>
              <th style={{ textAlign: 'left', padding: '12px' }}>Zaman</th>
              <th style={{ textAlign: 'left', padding: '12px' }}>Kaynak IP</th>
              <th style={{ textAlign: 'left', padding: '12px' }}>Hedef IP</th>
              <th style={{ textAlign: 'left', padding: '12px' }}>Protokol</th>
              <th style={{ textAlign: 'left', padding: '12px' }}>Bilgi</th>
              <th style={{ textAlign: 'center', padding: '12px' }}>Detay</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                  Canlı paket akışı yükleniyor...
                </td>
              </tr>
            ) : error ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--danger)' }}>
                  {error}
                </td>
              </tr>
            ) : packets.length > 0 ? [...packets].reverse().map((pkt, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid var(--panel-border)' }} className="table-row-hover">
                <td style={{ padding: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{pkt.timestamp}</td>
                <td style={{ padding: '12px', fontWeight: '500' }}>{pkt.source_ip}:{pkt.source_port}</td>
                <td style={{ padding: '12px', fontWeight: '500' }}>{pkt.destination_ip}:{pkt.destination_port}</td>
                <td style={{ padding: '12px' }}>
                  <span style={{ 
                    padding: '2px 6px', 
                    borderRadius: '4px', 
                    fontSize: '0.7rem', 
                    fontWeight: 'bold',
                    background: pkt.protocol === 'TCP' ? 'rgba(99, 102, 241, 0.1)' : 'rgba(168, 85, 247, 0.1)',
                    color: pkt.protocol === 'TCP' ? 'var(--accent-primary)' : 'var(--accent-secondary)'
                  }}>
                    {pkt.protocol}
                  </span>
                </td>
                <td style={{ padding: '12px', color: 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {pkt.info}
                </td>
                <td style={{ padding: '12px', textAlign: 'center' }}>
                  <button onClick={() => setSelectedPacket(pkt)} style={{ background: 'transparent', border: 'none', color: 'var(--accent-primary)', cursor: 'pointer' }}>
                    <Info size={16} />
                  </button>
                </td>
              </tr>
            )) : (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                  Henüz paket önizlemesi yok. Canlı izlemeyi başlatın ve trafiğin oluşmasını bekleyin.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedPacket && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '600px', border: '1px solid var(--accent-primary)', boxShadow: '0 0 20px rgba(99, 102, 241, 0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '12px' }}>
              <h3 style={{ margin: 0, color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={18} /> Paket Detayları
              </h3>
              <button onClick={() => setSelectedPacket(null)} style={{ background: 'transparent', border: 'none', color: 'white', cursor: 'pointer', fontSize: '1.2rem' }}>&times;</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px', fontSize: '0.9rem' }}>
              <div style={{ color: 'var(--text-secondary)' }}>Zaman Damgası:</div><div style={{ fontFamily: 'monospace' }}>{selectedPacket.timestamp}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Kaynak:</div><div>{selectedPacket.source_ip}:{selectedPacket.source_port}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Hedef:</div><div>{selectedPacket.destination_ip}:{selectedPacket.destination_port}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Protokol:</div><div>{selectedPacket.protocol}</div>
              <div style={{ color: 'var(--text-secondary)' }}>Uzunluk:</div><div>{selectedPacket.packet_length} bayt</div>
              <div style={{ color: 'var(--text-secondary)' }}>Akış ID:</div><div style={{ fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{selectedPacket.flow_id}</div>
              <div style={{ color: 'var(--text-secondary)', gridColumn: '1 / -1', marginTop: '12px' }}>Yük Bilgisi:</div>
              <div style={{ gridColumn: '1 / -1', background: '#0a0a0a', padding: '12px', borderRadius: '8px', border: '1px solid #333', color: 'var(--success)', whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.8rem', maxHeight: '200px', overflowY: 'auto' }}>
                {selectedPacket.info}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default PacketListView
